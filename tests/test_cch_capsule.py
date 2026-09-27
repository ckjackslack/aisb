"""Capsules: what create captures (secrets masked everywhere, volumes, image, DB schema/sample) and what load
recreates (fresh names/volumes, supplied secrets, image resolution), without ever touching host paths named by
the archive. Only the Docker daemon is faked; exec'd tools (pg_dump, psql) are answered at the exec endpoints."""

import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aisb import errors
from aisb.api.capsule import REDACTED, VERSION
from aisb.ops import Tier, get_op, invoke

from conftest import Reply, Seen, frame, tar_of

SECRETS = ("hunter2", "tok-XYZ", "s3cr3t-key")
MUX = "application/vnd.docker.multiplexed-stream"


def web_info(**over: Any) -> dict[str, Any]:
    d = {
        "Id": "abc123", "Name": "/web", "Image": "sha256:img1",
        "State": {"Running": True, "Status": "running", "ExitCode": 0},
        "Config": {"Image": "shop/web:1", "Cmd": ["serve"], "Tty": False, "ExposedPorts": {"8080/tcp": {}},
                   "Env": ["DB_PASSWORD=hunter2", "API_TOKEN=tok-XYZ", "AWS_SECRET_ACCESS_KEY=s3cr3t-key",
                           "PLAIN=1", "EMPTY_SECRET=", "PATH=/usr/bin"],
                   "Labels": {"team": "shop"}},
        "HostConfig": {"PortBindings": {"8080/tcp": [{"HostIp": "", "HostPort": "18080"}]}, "Binds": ["data:/data"],
                       "NetworkMode": "shop_default"},
        "Mounts": [{"Type": "volume", "Name": "data", "Destination": "/data"}, {"Type": "bind", "Source": "/nowhere"}],
        "NetworkSettings": {"Networks": {"shop_default": {"IPAddress": "10.0.0.5"}}},
    }
    d.update(over)
    return d


def serve_container(daemon, info: dict[str, Any], *, logs: bytes = b"2026-01-01T00:00:00Z booted\n",
                    image: dict[str, Any] | None = None) -> None:
    name = info["Name"].lstrip("/")
    daemon.on("GET", f"/containers/{name}/json", json=info)
    daemon.on("GET", f"/containers/{name}/logs", Reply(body=frame(1, logs), content_type=MUX))
    daemon.on("GET", "/version", json={"Version": "27.0.1"})
    daemon.on("GET", "/containers/json", json=[{"Names": [f"/{name}"]}])
    if image is not None:
        daemon.on("GET", r"/images/[^/]+/json", json=image)


def exec_by(daemon, ref: str, answer: Callable[[list[str]], tuple[bytes, int]]) -> list[list[str]]:
    """Answer every exec in `ref` from its argv (stdout, exit code); returns the argvs in order."""
    argvs: list[list[str]] = []

    def create(s: Seen) -> Reply:
        argvs.append(s.body["Cmd"])
        return Reply(201, json={"Id": f"x-{ref}-{len(argvs) - 1}"})

    def start(s: Seen) -> Reply:
        out, _ = answer(argvs[int(s.path.split("/")[2].rsplit("-", 1)[1])])
        return Reply(body=frame(1, out) if out else b"", content_type=MUX)

    def inspect(s: Seen) -> Reply:
        return Reply(json={"ExitCode": answer(argvs[int(s.path.split("/")[2].rsplit("-", 1)[1])])[1]})
    daemon.on("POST", f"/containers/{ref}/exec", create)
    daemon.on("POST", rf"/exec/x-{ref}-\d+/start", start)
    daemon.on("GET", rf"/exec/x-{ref}-\d+/json", inspect)
    return argvs


def members(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}  # type: ignore[union-attr]


def make_capsule(path: Path, manifest: dict[str, Any] | None, files: dict[str, bytes] | None = None,
                 raw: list[tarfile.TarInfo] | None = None) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in {**({"manifest.json": json.dumps(manifest).encode()} if manifest else {}),
                           **(files or {})}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in raw or []:
            tar.addfile(info, io.BytesIO(b"x" * info.size) if info.isfile() else None)
    return path


def manifest(**over: Any) -> dict[str, Any]:
    return {"aisb_capsule": VERSION, "container": "web", "mounts": [], "db": None,
            "image": {"ref": "shop/web:1", "id": "sha256:img1", "repo_digests": []}, **over}


# --- tiers -------------------------------------------------------------------------------------


def test_tiers():
    assert get_op("capsule.create").tier is Tier.READ and get_op("capsule.load").tier is Tier.MUTATE


# --- create ------------------------------------------------------------------------------------


def test_create_captures_config_logs_and_never_leaks_secrets(client, daemon, tmp_path):
    serve_container(daemon, web_info(), image={"Id": "sha256:img1", "RepoDigests": ["shop/web@sha256:d1"]})
    out = tmp_path / "web.capsule.tar.gz"
    r = client.capsule.create("web", str(out))
    assert r["container"] == "web" and r["redacted_env"] == ["API_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"]
    assert r["bytes"] == out.stat().st_size and r["mounts"] == 0 and r["db"] is None
    files = members(out)
    assert set(files) == {"spec.json", "inspect.json", "logs.txt", "doctor.json", "manifest.json"}
    for name, data in files.items():
        for secret in SECRETS:
            assert secret.encode() not in data, f"{secret} leaked into {name}"
    spec = json.loads(files["spec.json"])
    assert f"DB_PASSWORD={REDACTED}" in spec["env"] and "PLAIN=1" in spec["env"] and "EMPTY_SECRET=" in spec["env"]
    m = json.loads(files["manifest.json"])
    assert m["aisb_capsule"] == VERSION and m["docker"] == "27.0.1"
    assert m["image"] == {"ref": "shop/web:1", "id": "sha256:img1", "repo_digests": ["shop/web@sha256:d1"]}
    assert b"booted" in files["logs.txt"]
    assert not any(s.method != "GET" for s in daemon.seen)  # read tier: nothing changed


def test_create_tolerates_missing_image_and_doctor_failure(client, daemon, tmp_path):
    serve_container(daemon, web_info())
    daemon.on("GET", "/containers/json", status=500, json={"message": "doctor cannot list"})
    out = tmp_path / "c.tgz"
    client.capsule.create("web", str(out))
    files = members(out)
    assert "doctor.json" not in files and json.loads(files["manifest.json"])["image"]["repo_digests"] == []


def test_create_with_volumes_and_embedded_image(client, daemon, tmp_path):
    serve_container(daemon, web_info(), image={"RepoDigests": []})
    vol = tar_of({"data/a.txt": b"hello"}, dirs=("data",))
    daemon.on("GET", "/containers/web/archive", Reply(chunks=[vol[:100], vol[100:]], content_type="application/x-tar"))
    daemon.on("GET", "/images/sha256:img1/get", Reply(chunks=[b"IMG", b"TAR"], content_type="application/x-tar"))
    out = tmp_path / "c.tgz"
    r = client.capsule.create("web", str(out), volumes=True, image=True)
    assert r["mounts"] == 1 and r["embedded_image"] is True
    files = members(out)
    assert files["volumes/0.tar"] == vol and files["image.tar"] == b"IMGTAR"
    m = json.loads(files["manifest.json"])
    assert m["mounts"] == [{"index": 0, "destination": "/data", "type": "volume", "bytes": len(vol)}]
    assert m["image"]["tar_bytes"] == 6 and m["embedded_image"] is True
    archive = next(s for s in daemon.seen if s.path == "/containers/web/archive")
    assert archive.query == {"path": "/data"}  # the bind mount without a destination is skipped


def pg_info(running: bool = True) -> dict[str, Any]:
    return web_info(Name="/pg", Id="pg1", Image="sha256:pgimg", Mounts=[],
                    State={"Running": running, "Status": "running" if running else "exited"},
                    Config={"Image": "postgres:16", "Env": ["POSTGRES_PASSWORD=hunter2", "POSTGRES_DB=app"],
                            "ExposedPorts": {"5432/tcp": {}}})


def test_create_sql_service_includes_schema(client, daemon, tmp_path):
    serve_container(daemon, pg_info(), image={})
    argvs = exec_by(daemon, "pg", lambda argv: (b"CREATE TABLE t (id int);\n", 0))
    out = tmp_path / "pg.tgz"
    r = client.capsule.create("pg", str(out))
    assert r["db"] == {"engine": "postgres", "database": "app", "sample": None}
    files = members(out)
    assert files["db/schema.sql"] == b"CREATE TABLE t (id int);\n"
    assert argvs[0][0] == "pg_dump" and "--schema-only" in argvs[0]
    assert all(b"hunter2" not in data for data in files.values())


def test_create_sql_service_with_sample(client, daemon, tmp_path):
    serve_container(daemon, pg_info(), image={})

    def answer(argv: list[str]) -> tuple[bytes, int]:
        if argv[0] == "pg_dump":
            return b"CREATE TABLE t (id int);\n", 0
        return b"", 0  # an empty database: no tables, no relations
    exec_by(daemon, "pg", answer)
    daemon.on("PUT", "/containers/pg/archive", status=200)
    out = tmp_path / "pg.tgz"
    r = client.capsule.create("pg", str(out), db_sample=0.5)
    assert r["db"]["sample"] == {"ratio": 0.5, "rows": {}}
    assert b"session_replication_role" in members(out)["db/sample.sql"]


def test_create_skips_db_of_stopped_sql_service(client, daemon, tmp_path):
    serve_container(daemon, pg_info(running=False), image={})
    r = client.capsule.create("pg", str(tmp_path / "pg.tgz"))
    assert r["db"] is None and not any("/exec" in s.path for s in daemon.seen)


def test_create_fails_loudly_when_schema_dump_fails(client, daemon, tmp_path):
    serve_container(daemon, pg_info(), image={})
    exec_by(daemon, "pg", lambda argv: (b"", 1))
    with pytest.raises(errors.DockerError, match="pg_dump exited 1"):
        client.capsule.create("pg", str(tmp_path / "pg.tgz"))


def test_create_missing_container(client, daemon, tmp_path):
    with pytest.raises(errors.NotFound):
        client.capsule.create("ghost", str(tmp_path / "x.tgz"))
    assert not (tmp_path / "x.tgz").exists()


# --- load --------------------------------------------------------------------------------------


class Target:
    """The machine a capsule is loaded on: records creates/uploads/starts."""

    def __init__(self, daemon, *, images: set[str] = frozenset({"sha256:img1"}), pull_ok: bool = True) -> None:
        self.created: list[Seen] = []
        self.uploads: list[Seen] = []

        def image(s: Seen) -> Reply:
            ref = s.path[len("/images/"):-len("/json")]
            return Reply(json={"Id": ref}) if ref in images else Reply(404, json={"message": "no such image"})

        def create(s: Seen) -> Reply:
            self.created.append(s)
            return Reply(201, json={"Id": "new1"})

        def upload(s: Seen) -> Reply:
            self.uploads.append(s)
            return Reply(200)
        daemon.on("GET", r"/images/.+/json", image)
        daemon.on("POST", "/images/create", Reply(chunks=[b'{"status":"done"}\n']) if pull_ok else
                  Reply(500, json={"message": "pull denied"}))
        daemon.on("POST", "/images/load", Reply(json={"stream": "Loaded"}))
        daemon.on("POST", "/containers/create", create)
        daemon.on("PUT", "/containers/new1/archive", upload)
        daemon.on("POST", "/containers/new1/start", status=204)


def roundtrip(client, daemon, tmp_path, **create_kw: Any) -> Path:
    serve_container(daemon, web_info(), image={"RepoDigests": ["shop/web@sha256:d1"]})
    vol = tar_of({"data/a.txt": b"hello"})
    daemon.on("GET", "/containers/web/archive", Reply(body=vol, content_type="application/x-tar"))
    out = tmp_path / "web.tgz"
    client.capsule.create("web", str(out), **create_kw)
    daemon.routes.clear()
    daemon.seen.clear()
    return out


def test_load_recreates_with_fresh_name_volumes_and_supplied_secrets(client, daemon, tmp_path):
    cap = roundtrip(client, daemon, tmp_path, volumes=True)
    tgt = Target(daemon)
    r = client.capsule.load(str(cap), env=["DB_PASSWORD=pw", "PLAIN=2"])
    assert r["container"] == "web-capsule" and r["image"] == "sha256:img1" and r["volumes_restored"] == 1
    assert r["missing_secrets"] == ["API_TOKEN", "AWS_SECRET_ACCESS_KEY"]
    assert r["next"][1] == (f"supply secrets: aisb capsule load {cap} --env API_TOKEN=... --env AWS_SECRET_ACCESS_KEY=...")
    body = tgt.created[0].body
    assert tgt.created[0].query == {"name": "web-capsule"}
    assert "DB_PASSWORD=pw" in body["Env"] and "PLAIN=2" in body["Env"]
    assert not any(REDACTED in e for e in body["Env"])  # placeholders are never passed on as real values
    assert body["HostConfig"]["Binds"] == ["web-capsule-m0:/data"]  # never the original "data" volume
    assert "18080" not in json.dumps(body["HostConfig"].get("PortBindings") or {})  # ports not re-published
    assert body["Labels"]["aisb.capsule"] == "web" and body["Labels"]["team"] == "shop"
    assert tgt.uploads[0].query == {"path": "/"} and tgt.uploads[0].body == tar_of({"data/a.txt": b"hello"})
    assert ("POST", "/containers/new1/start") in daemon.calls()
    assert r["db_loaded"] is None


def test_load_keep_ports_and_custom_name(client, daemon, tmp_path):
    cap = roundtrip(client, daemon, tmp_path)
    tgt = Target(daemon)
    r = client.capsule.load(str(cap), name="repro", keep_ports=True,
                            env=["DB_PASSWORD=a", "API_TOKEN=b", "AWS_SECRET_ACCESS_KEY=c"])
    assert r["container"] == "repro" and r["missing_secrets"] == [] and len(r["next"]) == 1
    body = tgt.created[0].body
    assert body["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostPort"] == "18080"
    assert not body["HostConfig"].get("Binds") and tgt.uploads == []


def test_load_name_collision_fails_without_touching_the_existing_container(client, daemon, tmp_path):
    cap = roundtrip(client, daemon, tmp_path, volumes=True)
    Target(daemon)
    daemon.on("POST", "/containers/create", status=409, json={"message": "name web-capsule is already in use"})
    with pytest.raises(errors.Conflict, match="already in use"):
        client.capsule.load(str(cap))
    assert [c for c in daemon.calls() if c[0] != "GET"] == [("POST", "/containers/create")]


def test_load_dry_run_sends_nothing(client, daemon, tmp_path):
    cap = roundtrip(client, daemon, tmp_path, volumes=True)
    Target(daemon)
    out = invoke(client, get_op("capsule.load"), {"file": str(cap)}, dry_run=True)
    assert out.status == "dry-run"
    assert [(p["method"], p["path"]) for p in out.planned][:1] == [("POST", "/containers/create")]
    assert all(m == "GET" for m, _ in daemon.calls())


def test_load_embedded_image_is_loaded_first(client, daemon, tmp_path):
    cap = make_capsule(tmp_path / "c.tgz", manifest(), {"spec.json": b'{"image": "shop/web:1"}',
                                                          "image.tar": b"IMAGE-TAR"})
    Target(daemon)
    client.capsule.load(str(cap))
    load = next(s for s in daemon.seen if s.path == "/images/load")
    assert load.body == b"IMAGE-TAR" and daemon.seen.index(load) < next(
        i for i, s in enumerate(daemon.seen) if s.path == "/containers/create")


@pytest.mark.parametrize(("local", "pull_ok", "want"), [
    ({"sha256:img1"}, True, "sha256:img1"),              # the exact image id is here
    ({"shop/web@sha256:d1"}, True, "shop/web@sha256:d1"),  # pinned digest is here
    ({"shop/web:1"}, True, "shop/web:1"),                # only the tag is here
    (set(), True, "shop/web@sha256:d1"),                 # nothing local: pull by digest first
])
def test_load_image_resolution(client, daemon, tmp_path, local, pull_ok, want):
    cap = make_capsule(tmp_path / "c.tgz", manifest(image={"ref": "shop/web:1", "id": "sha256:img1",
                                                           "repo_digests": ["shop/web@sha256:d1"]}),
                       {"spec.json": b"{}"})
    tgt = Target(daemon, images=local, pull_ok=pull_ok)
    assert client.capsule.load(str(cap))["image"] == want
    assert tgt.created[0].body["Image"] == want


def test_load_unavailable_image_explains_and_creates_nothing(client, daemon, tmp_path):
    cap = make_capsule(tmp_path / "c.tgz", manifest(image={"ref": "shop/web:1", "id": None,
                                                           "repo_digests": ["shop/web@sha256:d1"]}))
    tgt = Target(daemon, images=set(), pull_ok=False)
    with pytest.raises(ValueError, match="create the capsule with --image"):
        client.capsule.load(str(cap))
    assert tgt.created == []


@pytest.mark.parametrize("m", [None, {"aisb_capsule": 99, "container": "x"}])
def test_load_rejects_non_capsules(client, daemon, tmp_path, m):
    cap = make_capsule(tmp_path / "c.tgz", m, {"spec.json": b"{}"})
    with pytest.raises(ValueError, match="is not an aisb capsule"):
        client.capsule.load(str(cap))
    assert daemon.calls() == []


def test_load_never_extracts_archive_paths_onto_the_host(client, daemon, tmp_path, monkeypatch):
    """Hostile member names (traversal, absolute, links) are only ever looked up by exact name, never extracted."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    link = tarfile.TarInfo("volumes/0.tar.link")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    evil = [tarfile.TarInfo(n) for n in ("../escaped.txt", "/tmp/aisb-cch-abs.txt", "spec.json/../../up.txt")]
    for e in evil:
        e.size = 1
    cap = make_capsule(tmp_path / "c.tgz", manifest(), {"spec.json": b"{}"}, raw=[*evil, link])
    Target(daemon)
    client.capsule.load(str(cap))
    assert not (tmp_path / "escaped.txt").exists() and not Path("/tmp/aisb-cch-abs.txt").exists()
    assert not (tmp_path / "up.txt").exists() and list(work.iterdir()) == []


def test_load_refuses_capsule_missing_a_listed_volume(client, daemon, tmp_path):
    cap = make_capsule(tmp_path / "c.tgz", manifest(mounts=[{"index": 0, "destination": "/data"}]),
                       {"spec.json": b"{}"})
    tgt = Target(daemon)
    with pytest.raises(ValueError, match="volumes/0.tar"):
        client.capsule.load(str(cap))
    assert tgt.created == [] and tgt.uploads == []


def test_load_nested_volume_destination_uploads_into_its_parent(client, daemon, tmp_path):
    cap = make_capsule(tmp_path / "c.tgz", manifest(mounts=[{"index": 0, "destination": "/var/lib/data/"}]),
                       {"spec.json": b"{}", "volumes/0.tar": b"TAR"})
    tgt = Target(daemon)
    client.capsule.load(str(cap))
    assert tgt.uploads[0].query == {"path": "/var/lib"} and tgt.uploads[0].body == b"TAR"


def test_load_db_from_volumes_is_not_replayed(client, daemon, tmp_path):
    cap = make_capsule(tmp_path / "c.tgz", manifest(mounts=[{"index": 0, "destination": "/pgdata"}],
                                                    db={"engine": "postgres"}),
                       {"spec.json": b"{}", "volumes/0.tar": b"T", "db/schema.sql": b"CREATE TABLE t();"})
    Target(daemon)
    assert client.capsule.load(str(cap))["db_loaded"].startswith("from volumes")
    assert not any("/exec" in s.path for s in daemon.seen)


def new_pg(daemon, *, exited: bool = False) -> None:
    info = pg_info()
    info.update(Name="/web-capsule", Id="new1")
    if exited:
        info["State"] = {"Running": False, "Status": "exited", "ExitCode": 1}
    daemon.on("GET", "/containers/web-capsule/json", json=info)
    daemon.on("GET", "/containers/web-capsule/logs", Reply(body=frame(1, b"ready\n"), content_type=MUX))


def test_load_replays_schema_and_sample_once_ready(client, daemon, tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr("aisb.api.services.time.sleep", lambda s: None)
    monkeypatch.setattr("aisb.api.services.time.monotonic", lambda: now.__setitem__(0, now[0] + 1) or now[0])
    cap = make_capsule(tmp_path / "c.tgz", manifest(db={"engine": "postgres"}),
                       {"spec.json": b"{}", "db/schema.sql": b"CREATE TABLE t();", "db/sample.sql": b"INSERT 1;"})
    Target(daemon)
    new_pg(daemon)
    argvs = exec_by(daemon, "web-capsule", lambda argv: (b"ok\n1\n", 0))
    daemon.on("PUT", "/containers/web-capsule/archive", status=200)
    r = client.capsule.load(str(cap))
    assert r["db_loaded"] == {"schema": True, "sample": True}
    scripts = [a for a in argvs if a[0] == "psql" and "-f" in a]
    assert len(scripts) == 2
    uploads = [s.body for s in daemon.seen if s.method == "PUT" and s.path == "/containers/web-capsule/archive"]
    assert [tarfile.open(fileobj=io.BytesIO(u)).extractfile(tarfile.open(fileobj=io.BytesIO(u)).getmembers()[0]).read()
            for u in uploads] == [b"CREATE TABLE t();", b"INSERT 1;"]


def test_load_reports_db_not_ready(client, daemon, tmp_path):
    cap = make_capsule(tmp_path / "c.tgz", manifest(db={"engine": "postgres"}),
                       {"spec.json": b"{}", "db/schema.sql": b"CREATE TABLE t();"})
    Target(daemon)
    new_pg(daemon, exited=True)
    r = client.capsule.load(str(cap))
    assert r["db_loaded"] == {"error": "container stopped (exit code 1)"}


def test_load_schema_only_and_image_without_ref(client, daemon, tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr("aisb.api.services.time.sleep", lambda s: None)
    monkeypatch.setattr("aisb.api.services.time.monotonic", lambda: now.__setitem__(0, now[0] + 1) or now[0])
    cap = make_capsule(tmp_path / "c.tgz", manifest(db={"engine": "postgres"},
                                                    image={"ref": None, "id": None, "repo_digests": ["r@sha256:1"]}),
                       {"spec.json": b"{}", "db/schema.sql": b"CREATE TABLE t();"})
    Target(daemon, images=set())
    new_pg(daemon)
    exec_by(daemon, "web-capsule", lambda argv: (b"ok\n1\n", 0))
    daemon.on("PUT", "/containers/web-capsule/archive", status=200)
    r = client.capsule.load(str(cap))
    assert r["image"] == "r@sha256:1" and r["db_loaded"] == {"schema": True, "sample": False}


def test_load_reports_schema_replay_failure(client, daemon, tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr("aisb.api.services.time.sleep", lambda s: None)
    monkeypatch.setattr("aisb.api.services.time.monotonic", lambda: now.__setitem__(0, now[0] + 1) or now[0])
    cap = make_capsule(tmp_path / "c.tgz", manifest(db={"engine": "postgres"}),
                       {"spec.json": b"{}", "db/schema.sql": b"CREATE TABLE t();"})
    Target(daemon)
    new_pg(daemon)
    exec_by(daemon, "web-capsule", lambda argv: (b"ok\n1\n", 0) if "-f" not in argv else (b"", 3))
    daemon.on("PUT", "/containers/web-capsule/archive", status=200)
    r = client.capsule.load(str(cap))
    assert set(r["db_loaded"]) == {"error"} and "3" in r["db_loaded"]["error"]
    assert r["container"] == "web-capsule"  # the container stays for inspection; the failure is reported
