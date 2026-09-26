"""Live daemon round-trips; skipped when no Docker endpoint is reachable."""

import json
import uuid
from collections.abc import Iterator

import pytest

from aisb import Docker, DockerError, NotFound, get_op, invoke
from aisb.errors import BadRequest
from aisb.models import RunSpec

IMAGE = "alpine:3.20"


def _live() -> Docker | None:
    try:
        d = Docker(timeout=120)
        d.system.ping()
        return d
    except DockerError:
        return None


pytestmark = [pytest.mark.docker, pytest.mark.skipif(_live() is None, reason="no reachable Docker daemon")]


@pytest.fixture
def docker() -> Docker:
    return _live()  # type: ignore[return-value]


@pytest.fixture
def name(docker: Docker) -> Iterator[str]:
    n = f"aisb-test-{uuid.uuid4().hex[:8]}"
    yield n
    try:
        docker.containers.rm(n, force=True, volumes=True)
    except NotFound:
        pass


def test_run_attached_roundtrip(docker):
    out = docker.containers.run(IMAGE, "sh", "-c", "echo out; echo err >&2; exit 4", rm=True)
    assert out["exit_code"] == 4
    assert sorted(out["output"].split()) == ["err", "out"]


def test_detached_lifecycle(docker, name, tmp_path):
    docker.containers.run(IMAGE, "sh", "-c", "echo ready; sleep 60", name=name, detach=True, env=["X=42"])
    assert any(c.name == name for c in docker.containers.ls(managed=True))
    assert docker.containers.inspect(name, fields="State.Running")["State.Running"] is True
    assert docker.containers.exec_(name, "sh", "-c", "echo $X")["output"] == "42\n"
    assert "ready" in docker.containers.logs(name)["output"]
    assert docker.containers.stats(name)["pids"] >= 1

    (tmp_path / "f.txt").write_text("payload")
    docker.containers.cp(str(tmp_path / "f.txt"), f"{name}:/tmp")
    docker.containers.cp(f"{name}:/tmp/f.txt", str(tmp_path / "back"))
    assert (tmp_path / "back" / "f.txt").read_text() == "payload"
    assert {"path": "/tmp/f.txt", "kind": "added"} in docker.containers.diff(name)

    assert docker.containers.stop(name, grace=1)["changed"] is True
    assert docker.containers.stop(name, grace=1)["changed"] is False


def test_destroy_requires_confirmation(docker, name):
    docker.containers.run(IMAGE, "true", name=name)
    preview = invoke(docker, get_op("containers.rm"), {"ref": name})
    assert preview.status == "confirm"
    assert docker.containers.inspect(name, fields="Name")["Name"] == f"/{name}"
    invoke(docker, get_op("containers.rm"), {"ref": name}, confirm=True)
    with pytest.raises(NotFound):
        docker.containers.inspect(name)


def test_doctor_explains_command_not_found(docker, name):
    with pytest.raises(BadRequest, match="executable file not found"):  # the daemon rejects the start itself
        docker.containers.run(IMAGE, "no-such-binary", name=name, detach=True)
    report = docker.containers.doctor(name, stats=False)
    assert report["verdict"] == "failing"
    found = {f["code"] for f in report["findings"]}
    assert {"start-error", "command-not-found"} <= found


def test_wait_fails_fast_and_matches_logs(docker, name):
    docker.containers.run(IMAGE, "sh", "-c", "echo 'server ready'; sleep 1; exit 5", name=name, detach=True)
    ok = docker.containers.wait_for(name, log="server ready", within=30, interval=0.2)
    assert ok["ok"] and ok["matched"] == "server ready"
    dead = docker.containers.wait_for(name, log="never printed", within=60, interval=0.2)
    assert not dead["ok"] and dead["exit_code"] == 5 and dead["elapsed"] < 30


def test_snapshot_changes_sees_new_container(docker, name, tmp_path):
    path = tmp_path / "before.json"
    path.write_text(json.dumps(docker.system.snapshot()))
    docker.containers.run(IMAGE, "true", name=name)
    diff = docker.system.changes(str(path))
    assert name in diff["containers"]["added"]
    assert f"aisb containers rm {name} --force --dry-run" in diff["cleanup"]


def _has_image(docker: Docker, ref: str) -> bool:
    try:
        docker.images.inspect(ref, fields="Id")
        return True
    except NotFound:
        return False


@pytest.fixture
def service(docker):
    made: list[str] = []

    def start(image: str, *cmd: str, **kw) -> str:
        if not _has_image(docker, image):
            pytest.skip(f"{image} not pulled")
        n = f"aisb-svc-{uuid.uuid4().hex[:8]}"
        docker.containers.run(image, *cmd, name=n, detach=True, **kw)
        made.append(n)
        return n
    yield start
    for n in made:
        docker.containers.rm(n, force=True, volumes=True)


def test_postgres_roundtrip(docker, service, tmp_path):
    pg = service("postgres:16-alpine", env=["POSTGRES_PASSWORD=pw", "POSTGRES_DB=shop"])
    assert docker.svc.ready(pg, within=90, stable=1)["ok"]
    docker.db.exec_(pg, "create table t (id int primary key, note text); insert into t values (1, null), (2, '')")
    rows = docker.db.query(pg, "select id, note from t order by id")["rows"]
    assert rows == [{"id": 1, "note": None}, {"id": 2, "note": ""}]
    with pytest.raises(DockerError, match="read-only transaction"):
        docker.db.query(pg, "delete from t")
    dump = tmp_path / "d.sql.gz"
    docker.db.dump(pg, str(dump))
    docker.db.exec_(pg, "create database copy")
    docker.db.restore(pg, str(dump), database="copy")
    assert docker.db.query(pg, "select count(*) n from t", database="copy")["rows"] == [{"n": 2}]
    assert [c["name"] for c in docker.db.describe(pg, "t")["columns"]] == ["id", "note"]


def test_redis_scan_and_get(docker, service):
    r = service("redis:7-alpine", "redis-server", "--requirepass", "p w")
    assert docker.svc.ready(r, within=30, stable=0.5)["ok"]
    docker.redis.cmd(r, "HSET", "user:1", "name", "Ann")
    docker.redis.cmd(r, "SET", "note", "multi\nline")
    assert docker.redis.scan(r, "user:*")["keys"][0]["type"] == "hash"
    assert docker.redis.get(r, "user:1")["value"] == {"name": "Ann"}
    assert docker.redis.get(r, "note")["value"] == "multi\nline"


def test_fs_reads_image_files_without_exec(docker, service):
    web = service("nginx:alpine")
    assert "worker_processes" in docker.fs.cat(web, "/etc/nginx/nginx.conf")["output"]
    assert any(e["path"] == "default.conf" for e in docker.fs.ls(web, "/etc/nginx/conf.d")["entries"])


def test_stack_up_ready_and_down(docker, tmp_path):
    for img in ("alpine:3.20", "redis:7-alpine"):
        if not _has_image(docker, img):
            pytest.skip(f"{img} not pulled")
    name = f"it{uuid.uuid4().hex[:6]}"
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"name": name, "services": {
        "cache": {"image": "redis:7-alpine"},
        "app": {"image": "alpine:3.20", "depends_on": ["cache"], "ready": {"log": "connected"},
                "cmd": ["sh", "-c", "until nc -z cache 6379; do sleep 0.2; done; echo connected; sleep 60"]}}}))
    try:
        up = docker.stack.up(str(f), within=60)
        assert up["ok"] and [s["service"] for s in up["services"]] == ["cache", "app"]
        assert docker.stack.up(str(f))["services"][0]["action"] == "unchanged"
        probe = docker.net.probe(f"{name}-app", "cache", port=6379)
        assert probe["ok"], probe
    finally:
        down = docker.stack.down(name)
    assert len(down["removed_containers"]) == 2 and down["removed_networks"] == [f"{name}_default"]


def test_db_clone_and_diff(docker, service):
    pg = service("postgres:16-alpine", env=["POSTGRES_PASSWORD=pw"])
    assert docker.svc.ready(pg, within=90, stable=1)["ok"]
    docker.db.exec_(pg, "create table t (id int primary key); insert into t select generate_series(1, 50)")
    clone = f"{pg}-clone"
    try:
        assert docker.db.clone(pg, clone)["ok"]
        docker.db.exec_(clone, "alter table t add column note text; delete from t where id > 40")
        diff = docker.db.diff(pg, clone, counts=True)
        assert diff["changed"]["public.t"]["columns"]["only_in_b"] == ["note"]
        assert diff["row_counts"] == {"public.t": {"a": 50, "b": 40}}
    finally:
        docker.containers.rm(clone, force=True, volumes=True)


def test_volume_backup_restore_roundtrip(docker, tmp_path):
    if not _has_image(docker, "busybox:1.36"):
        pytest.skip("busybox not pulled")
    src, dst = f"aisb-it-{uuid.uuid4().hex[:6]}", f"aisb-it-{uuid.uuid4().hex[:6]}"
    docker.volumes.create(src)
    try:
        docker.containers.run("busybox:1.36", "sh", "-c", "echo payload > /d/file; mkdir /d/sub; echo x > /d/sub/y",
                              volume=[f"{src}:/d"], rm=True)
        docker.volumes.backup(src, str(tmp_path / "b.tar.gz"))
        docker.volumes.restore(dst, str(tmp_path / "b.tar.gz"))
        out = docker.containers.run("busybox:1.36", "cat", "/d/file", "/d/sub/y", volume=[f"{dst}:/d"], rm=True)
        assert out["output"] == "payload\nx\n"
    finally:
        for v in (src, dst):
            docker.volumes.rm(v, force=True)


# --- killer features ----------------------------------------------------------------------------

def test_limit_then_rightsize(docker, name):
    docker.containers.run(IMAGE, "sleep", "300", name=name, detach=True)
    res = docker.containers.limit(name, memory="64m", cpus=0.5, pids=100)
    assert res["applied"]["Memory"] == 64 << 20
    hc = docker.containers.inspect(name)["HostConfig"]
    assert (hc["Memory"], hc["NanoCpus"], hc["PidsLimit"]) == (64 << 20, 500_000_000, 100)
    (r,) = docker.system.rightsize(seconds=1, interval=0.5, container=[name])["containers"]
    assert r["samples"] == 3 and r["limits"]["cpus"] == 0.5 and "unlimited" not in r["flags"]


def test_session_rollback_recreates_removed_container(docker, name, tmp_path, monkeypatch):
    monkeypatch.setenv("AISB_HOME", str(tmp_path))
    docker.containers.run(IMAGE, "sleep", "300", name=name, detach=True, env=["API_TOKEN=s3cret"])
    docker.session.begin()
    try:
        invoke(docker, get_op("containers.rm"), {"ref": name, "force": True}, confirm=True)
        with pytest.raises(NotFound):
            docker.containers.inspect(name)
        out = invoke(docker, get_op("session.rollback"), {}, confirm=True).result
        assert not out["failed"]
        info = docker.containers.inspect(name)
        assert info["State"]["Running"] and "API_TOKEN=s3cret" in info["Config"]["Env"]
    finally:
        docker.session.end()


def test_sbom_and_envcheck(docker, name):
    sbom = docker.images.sbom(IMAGE)
    assert sbom["os"]["id"] == "alpine" and sbom["by_ecosystem"]["apk"] > 5
    assert any(c["name"] == "musl" for c in sbom["components"])
    docker.containers.create_from(RunSpec(image=IMAGE, cmd=("sh", "-c", 'echo "${DATABASE_URL:?}"'), name=name,
                                          env=("DATABSE_URL=pg://x",)))
    r = docker.containers.envcheck(name)
    assert r["missing_required"][0]["var"] == "DATABASE_URL"
    assert r["missing_required"][0]["did_you_mean"] == "DATABSE_URL"


def test_pyinfra_connector_live(docker, name):
    pytest.importorskip("pyinfra")
    import io

    from pyinfra.api import Config, Inventory, State, StringCommand
    from pyinfra.api.connect import connect_all
    from pyinfra.facts.server import LinuxName
    docker.containers.run(IMAGE, "sleep", "300", name=name, detach=True)
    inv = Inventory(([f"@aisb/{name}"], {}))
    connect_all(State(inv, Config()))
    h = inv.get_host(f"@aisb/{name}")
    assert h.put_file(io.BytesIO(b"k=v\n"), "/etc/aisb-test.conf")
    ok, out = h.run_shell_command(StringCommand("cat", "/etc/aisb-test.conf"))
    assert ok and out.stdout == "k=v"
    assert h.get_fact(LinuxName) == "Alpine"
