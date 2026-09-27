"""Stack up/down/ps against a stateful fake daemon: dependency order, readiness gates, idempotence, and the rule
that volumes are never deleted unless asked. Also the archive-API filesystem readers (fs, rootfs)."""

import base64
import io
import json
import tarfile
import time

import pytest

from aisb import stack as stk
from aisb.api.fs import _decode_mode
from aisb.cli import EXIT_CONFIRM, EXIT_OK, main
from aisb.client import Docker
from aisb.errors import APIError
from aisb.rootfs import ChunkReader, read_file, relative, walk
from test_undo_destroy import World, do

from conftest import Reply, frame, tar_of

STACK = {"name": "shop", "volumes": ["pgdata"], "services": {
    "db": {"image": "app-db:1", "volumes": ["pgdata:/data"], "ready": "running"},
    "cache": {"image": "app-cache:1"},                                   # default "probe": no adapter -> running
    "api": {"image": "api:1", "depends_on": ["db", "cache"], "ports": ["8080:80"], "ready": {"log": "listening"}},
}}


@pytest.fixture
def world(daemon) -> World:
    w = World(daemon)
    # every container logs a ready line (multiplexed stdout, as a non-tty container does)
    daemon.on("GET", r"/containers/[^/]+/logs", Reply(body=frame(1, b"boot\nlistening on :80\n")))
    return w


@pytest.fixture
def dk(host) -> Docker:
    return Docker(host, timeout=5)


@pytest.fixture
def stack_file(tmp_path):
    f = tmp_path / "shop.json"
    f.write_text(json.dumps(STACK))
    return f


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def created_order(world: World) -> list[str]:
    return [s.query["name"] for s in world.d.seen if s.path == "/containers/create"]


# --- up --------------------------------------------------------------------------------------------

def test_up_converges_in_dependency_order_and_is_idempotent(world, dk, stack_file):
    out = do(dk, "stack.up", file=str(stack_file), within=5)
    assert out["ok"] and out["network"] == "shop_default"
    order = created_order(world)
    assert order.index("shop-api") > order.index("shop-db") and order.index("shop-api") > order.index("shop-cache")
    assert {s["service"]: s["action"] for s in out["services"]} == {"db": "created", "cache": "created",
                                                                    "api": "created"}
    api = next(s for s in out["services"] if s["service"] == "api")
    assert api["ready"]["ok"] and "listening" in api["ready"]["matched"]
    assert all(c["running"] for c in world.containers.values())
    assert set(world.volumes) == {"shop_pgdata"} and world.volumes["shop_pgdata"]["labels"]["aisb.stack"] == "shop"
    assert world.containers["shop-db"]["binds"] == ["shop_pgdata:/data"]

    mark = len(world.d.seen)
    again = do(dk, "stack.up", file=str(stack_file), within=5)
    assert again["ok"] and [s["action"] for s in again["services"]] == ["unchanged"] * 3
    assert world.mutations(mark) == []                                    # converged: nothing to do


def test_up_starts_stopped_services_and_keeps_existing_network_and_volumes(world, dk, stack_file):
    do(dk, "stack.up", file=str(stack_file), no_wait=True)
    world.containers["shop-cache"]["running"] = False
    world.volumes["shop_pgdata"]["files"]["pg"] = b"data"
    mark = len(world.d.seen)
    out = do(dk, "stack.up", file=str(stack_file), no_wait=True)
    assert {s["service"]: s["action"] for s in out["services"]}["cache"] == "started"
    assert world.mutations(mark) == [("POST", "/containers/shop-cache/start")]
    assert world.volumes["shop_pgdata"]["files"] == {"pg": b"data"}
    assert all("ready" not in s for s in out["services"])               # --no-wait


def test_up_reports_drift_without_touching_the_container(world, dk, stack_file):
    do(dk, "stack.up", file=str(stack_file), no_wait=True)
    world.containers["shop-cache"]["labels"]["aisb.hash"] = "stale"
    world.containers["shop-cache"]["running"] = False
    mark = len(world.d.seen)
    out = do(dk, "stack.up", file=str(stack_file), within=5)
    cache = next(s for s in out["services"] if s["service"] == "cache")
    assert cache["action"] == "drift" and "stack down" in cache["hint"] and "ready" not in cache
    assert not any("shop-cache" in p for _, p in world.mutations(mark))


def test_up_stops_at_first_service_that_is_not_ready(world, dk, stack_file, daemon):
    def crash(seen):
        world.containers["shop-db"]["running"] = False                   # starts, then exits at once
        return Reply(204)
    daemon.on("POST", "/containers/shop-db/start", crash)
    out = do(dk, "stack.up", file=str(stack_file), within=5)
    assert out["ok"] is False and out["reason"] == "db did not become ready"
    assert out["services"][-1]["service"] == "db" and "stopped" in out["services"][-1]["ready"]["reason"]
    assert "api" in out["not_started"] and "shop-api" not in world.containers
    assert out["next"] == ["aisb containers doctor shop-db"]


def test_up_cli_exit_code_when_not_ready(world, cli, stack_file, daemon):
    daemon.on("POST", "/containers/shop-cache/start", lambda s: Reply(204))  # never actually runs
    code, out, _ = cli("stack", "up", str(stack_file), "--within", "0.3")
    assert code != EXIT_OK and out["ok"] is False


def test_up_dry_run_plans_creates_without_sending(world, dk, stack_file):
    out = do(dk, "stack.up", file=str(stack_file), dry_run=True)
    methods = [p["method"] for p in out["planned"]]
    assert methods.count("POST") >= 5 and world.mutations() == []       # network, volume, 3 creates (+ starts)
    assert world.containers == {} and world.networks == {}


# --- down ------------------------------------------------------------------------------------------

@pytest.fixture
def running(world, dk, stack_file):
    do(dk, "stack.up", file=str(stack_file), no_wait=True)
    world.volumes["other"] = {"files": {}, "labels": {}}
    return world


@pytest.mark.parametrize("by", ["name", "file"])
def test_down_never_deletes_volumes_unless_asked(running, dk, stack_file, by):
    ref = "shop" if by == "name" else str(stack_file)
    mark = len(running.d.seen)
    out = do(dk, "stack.down", stack=ref)
    assert sorted(out["removed_containers"]) == ["shop-api", "shop-cache", "shop-db"]
    assert out["removed_networks"] == ["shop_default"] and "removed_volumes" not in out
    assert running.containers == {} and set(running.volumes) == {"shop_pgdata", "other"}
    assert not any(p.startswith("/volumes") for _, p in running.mutations(mark))


def test_down_volumes_deletes_only_the_stacks_volumes(running, dk):
    out = do(dk, "stack.down", stack="shop", volumes=True)
    assert out["removed_volumes"] == ["shop_pgdata"] and set(running.volumes) == {"other"}


def test_down_single_service_keeps_network_and_volumes(running, dk):
    out = do(dk, "stack.down", stack="shop", service=["api"], volumes=True)
    assert out == {"stack": "shop", "removed_containers": ["shop-api"]}
    assert "shop_default" in running.networks and "shop_pgdata" in running.volumes


def test_down_keeps_network_used_by_foreign_container(running, dk):
    running.add_container("debugger", networks={"shop_default": []})
    out = do(dk, "stack.down", stack="shop")
    assert out["removed_networks"] == [] and "debugger" in out["kept_networks"][0]["reason"]
    assert "shop_default" in running.networks and set(running.containers) == {"debugger"}


def test_down_without_yes_is_a_preview(running, cli):
    code, out, _ = cli("stack", "down", "shop", "--volumes")
    assert code == EXIT_CONFIRM and running.d.calls("DELETE") == []
    assert len(running.containers) == 3


def test_down_of_unknown_stack_is_a_noop(world, dk):
    assert do(dk, "stack.down", stack="ghost") == {"stack": "ghost", "removed_containers": [],
                                                   "removed_networks": [], "kept_networks": []}
    assert world.mutations() == []


# --- ps --------------------------------------------------------------------------------------------

def test_ps_with_file_reports_missing_drift_and_ports(running, dk, stack_file):
    running.containers["shop-db"]["labels"]["aisb.hash"] = "stale"
    del running.containers["shop-cache"]
    running.d.on("GET", "/containers/json", lambda seen: Reply(json=[
        {**running.row(c), "Ports": [{"PublicPort": 8080, "PrivatePort": 80}, {"PrivatePort": 9}]}
        for c in running.containers.values()]))
    out = dk.stack.ps(str(stack_file))
    by = {s["service"]: s for s in out["services"]}
    assert by["cache"] == {"service": "cache", "state": "missing", "status": None}
    assert by["db"]["drift"] is True and by["api"]["drift"] is False and by["api"]["ports"] == ["8080->80"]
    assert out["healthy"] is False


def test_ps_by_name_lists_labelled_services(running, dk):
    out = dk.stack.ps("shop")
    assert [s["service"] for s in out["services"]] == ["api", "cache", "db"]
    assert out["healthy"] is True and all("drift" not in s for s in out["services"])


# --- import ----------------------------------------------------------------------------------------

def test_import_prints_or_writes_a_valid_stack(tmp_path, dk):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services:\n  web:\n    image: nginx:1\n    ports:\n      - '8080:80'\n")
    res = dk.stack.import_(str(compose), name="demo")
    assert res["stack"]["name"] == "demo" and "web" in res["stack"]["services"]
    out = tmp_path / "demo.json"
    written = dk.stack.import_(str(compose), name="demo", out=str(out))
    assert written["services"] == ["web"] and written["next"] == [f"aisb stack up {out} --dry-run"]
    assert stk.load(out).name == "demo"


# --- stack file parsing edge cases ------------------------------------------------------------------

@pytest.mark.parametrize(("data", "error"), [
    ({"name": "x"}, "non-empty 'services'"),
    ({"name": "x", "services": []}, "non-empty 'services'"),
    ({"name": "x", "services": {"Bad!": {"image": "a"}}}, "invalid service name"),
    ({"name": "x", "services": {"a": {"image": "a", "ready": {}}}}, "'ready' must be"),
    ({"name": "x", "services": {"a": {"image": "a", "ready": {"http": "/"}}}}, "'ready' must be"),
    ({"name": "X", "services": {"a": {"image": "a"}}}, "lowercase 'name'"),
    ({"name": "x", "networks": {}, "services": {"a": {"image": "a"}}}, "unknown stack keys"),
    ({"name": "x", "services": {"a": {"image": "a", "aliases": ["b"]}}}, "managed by the stack"),
    ({"name": "x", "services": {"a": {"image": "a", "depends_on": ["z"]}}}, "unknown service"),
    ({"name": "x", "services": {"a": {"image": "a", "depends_on": ["b"]}, "b": {"image": "b", "depends_on": ["a"]}}},
     "dependency cycle"),
])
def test_stack_parse_errors(data, error):
    with pytest.raises(ValueError, match=error):
        stk.parse(data)


def test_stack_load_invalid_json(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("{nope")
    with pytest.raises(ValueError, match="invalid JSON"):
        stk.load(f)


def test_stack_volume_prefix_only_for_declared():
    s = stk.parse({"name": "x", "volumes": ["d"], "services": {"a": {"image": "i", "volumes": ["d:/d", "e:/e", "/anon"]}}})
    assert s.services["a"].spec.volumes == ("x_d:/d", "e:/e", "/anon") and s.volumes == ("x_d",)
    assert s.services["a"].ready == "probe" and s.services["a"].container == "x-a"


def test_stack_plan_classifies_rows():
    s = stk.parse(STACK)
    dig = {n: sv.digest for n, sv in s.services.items()}
    rows = [
        {"Labels": {stk.SERVICE_KEY: "db", stk.STACK_KEY: "shop", stk.HASH_KEY: dig["db"]}, "State": "running"},
        {"labels": {stk.SERVICE_KEY: "cache", stk.HASH_KEY: dig["cache"]}, "state": "exited"},
        {"Labels": {stk.SERVICE_KEY: "api", stk.STACK_KEY: "shop", stk.HASH_KEY: "old"}, "State": "running"},
        {"Labels": {stk.SERVICE_KEY: "db", stk.STACK_KEY: "other"}, "State": "running"},  # another stack
    ]
    assert stk.plan(s, rows) == {"missing": [], "stopped": ["cache"], "drift": ["api"], "ok": ["db"]}
    assert stk.plan(s, None)["missing"] == list(s.order)
    assert s.dependents("db") == ["api"] and s.dependents("api") == []


# --- fs / rootfs ---------------------------------------------------------------------------------------

def _tree() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name: str, data: bytes = b"", kind: bytes = tarfile.REGTYPE, link: str = "") -> None:
            info = tarfile.TarInfo(name)
            info.type, info.size, info.linkname, info.mode = kind, len(data), link, 0o644
            tar.addfile(info, io.BytesIO(data) if data else None)
        add("etc", kind=tarfile.DIRTYPE)
        add("etc/a.conf", b"a=1\n")
        add("etc/b.conf", b"b" * 50)
        add("etc/bin.dat", b"\0\1\2")
        add("etc/link", kind=tarfile.SYMTYPE, link="/etc/a.conf")
        add("etc/hard", kind=tarfile.LNKTYPE, link="etc/a.conf")
        add("etc/sub", kind=tarfile.DIRTYPE)
        add("etc/sub/deep.conf", b"deep")
    return buf.getvalue()


@pytest.fixture
def tree(daemon):
    daemon.on("GET", "/containers/web/archive", Reply(body=_tree(), content_type="application/x-tar"))
    return daemon


def test_fs_ls_limit_and_link_targets(tree, dk):
    out = dk.fs.ls("web", "/etc")
    by = {e["path"]: e for e in out["entries"]}
    assert out["entries"][0]["type"] == "dir" and by["link"]["target"] == "/etc/a.conf"
    assert by["hard"]["type"] == "hardlink" and "sub/deep.conf" not in by
    assert dk.fs.ls("web", "/etc", limit=2)["count"] == 2


def test_fs_find_filters_and_truncation(tree, dk):
    assert [e["path"] for e in dk.fs.find("web", "/etc", name="*.conf")["entries"]] == [
        "a.conf", "b.conf", "sub/deep.conf"]
    assert [e["path"] for e in dk.fs.find("web", "/etc", type="dir")["entries"]] == ["sub"]
    assert [e["path"] for e in dk.fs.find("web", "/etc", min_size=10)["entries"]] == ["b.conf"]
    out = dk.fs.find("web", "/etc", limit=2)
    assert out["truncated"] is True and out["count"] == 2


def test_fs_cat_variants(daemon, dk):
    def serve(files: dict[str, bytes] | None = None, raw: bytes | None = None) -> None:
        daemon.on("GET", "/containers/web/archive",
                  Reply(body=raw if raw is not None else tar_of(files or {}), content_type="application/x-tar"))
    serve({"big.txt": b"x" * 100})
    assert dk.fs.cat("web", "/big.txt", max_bytes=10, tail=True)["truncated"] is True
    head = dk.fs.cat("web", "/big.txt", max_bytes=10)
    assert head["truncated"] and head["output"].startswith("x" * 10) and "90 more bytes" in head["output"]
    serve({"b.bin": b"\0\0bin"})
    assert dk.fs.cat("web", "/b.bin")["binary"] is True
    serve(raw=_tree())
    with pytest.raises(ValueError, match="is a directory"):
        dk.fs.cat("web", "/etc")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("l")
        info.type, info.linkname = tarfile.SYMTYPE, "/target"
        tar.addfile(info)
    serve(raw=buf.getvalue())
    assert dk.fs.cat("web", "/l") == {"path": "/l", "type": "link", "target": "/target"}
    serve(raw=tar_of({}))
    with pytest.raises(ValueError, match="empty archive"):
        dk.fs.cat("web", "/nothing")


@pytest.mark.parametrize(("mode", "kind"), [(1 << 31 | 0o755, "dir"), (1 << 27 | 0o777, "link"), (0o644, "file")])
def test_fs_stat_decodes_mode(daemon, dk, mode, kind):
    st = base64.b64encode(json.dumps({"name": "x", "size": 3, "mode": mode, "mtime": "t",
                                      "linkTarget": "/y" if kind == "link" else ""}).encode()).decode()
    daemon.on("HEAD", "/containers/web/archive", Reply(headers={"X-Docker-Container-Path-Stat": st}))
    out = dk.fs.stat("web", "/x")
    assert out["type"] == kind == _decode_mode(mode) and out["target"] == ("/y" if kind == "link" else None)


def test_rootfs_budget_and_relative():
    r = ChunkReader(iter([b"a" * 10, b"b" * 10]), budget=15)
    buf = bytearray(8)
    assert r.readable() and r.readinto(buf) == 8
    r.readinto(buf)
    with pytest.raises(APIError, match="exceeded"):
        r.readinto(buf)
    assert ChunkReader(iter([]), 1).readinto(bytearray(1)) == 0
    assert relative("./etc/a", "etc") == "a" and relative("etc", "etc") == "" and relative("/x/y", "") == "x/y"
    assert relative("other/z", "etc") == "other/z"


def test_rootfs_walk_and_read_file(tree, client, daemon):
    got = {rel: data for _, rel, data in walk(client.transport, "web", "/etc", want=lambda r, m: r.endswith(".conf"))}
    assert got["a.conf"] == b"a=1\n" and got["sub/deep.conf"] == b"deep" and got["bin.dat"] is None
    assert [rel for _, rel, _ in walk(client.transport, "web", "/etc")][0] == ""
    daemon.on("GET", "/containers/one/archive", Reply(body=tar_of({"a.conf": b"x"}), content_type="application/x-tar"))
    assert read_file(client.transport, "one", "/etc/a.conf") == b"x"
    daemon.on("GET", "/containers/dir/archive", Reply(body=tar_of({}, dirs=("etc",)), content_type="application/x-tar"))
    assert read_file(client.transport, "dir", "/etc") is None
    daemon.on("GET", "/containers/empty/archive", Reply(body=tar_of({}), content_type="application/x-tar"))
    assert read_file(client.transport, "empty", "/x") is None
    assert read_file(client.transport, "ghost", "/x") is None             # 404 from the daemon


def test_fs_ls_budget_exceeded(daemon, dk):
    data = tar_of({"big": b"x" * 2_000_000, "after": b"y"})
    daemon.on("GET", "/containers/web/archive", Reply(chunks=[data[i:i + 65536] for i in range(0, len(data), 65536)],
                                                      content_type="application/x-tar"))
    t0 = time.monotonic()
    with pytest.raises(APIError, match="exceeded 1 MiB"):
        dk.fs.ls("web", "/", max_mb=1)
    assert time.monotonic() - t0 < 5
