"""Session capture and rollback fidelity: what is journaled, and that rollback brings objects back exactly as they
were (drivers, options, networks, aliases, databases, run states) without stopping early on a skipped item.

The stateful `World` daemon model from test_undo_destroy (and its exec queue) is the only thing faked.
"""

import io
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from aisb import context, state
from aisb.client import Docker
from aisb.fleet.inventory import Host
from test_undo_destroy import World, do, journal

from conftest import FakeDaemon, Reply, tar_of


@pytest.fixture
def world(daemon) -> World:
    return World(daemon)


@pytest.fixture
def dk(host) -> Docker:
    return Docker(host, timeout=5)


@pytest.fixture
def remote():
    d = Path(tempfile.mkdtemp(prefix="aisb-f-", dir="/tmp"))
    fake = FakeDaemon(d / "r.sock")
    fake.start()
    yield fake
    fake.stop()
    shutil.rmtree(d, ignore_errors=True)


def posts(world: World, since: int = 0) -> list[Any]:
    return [s for s in world.d.seen[since:] if s.method in ("POST", "PUT", "DELETE")]


def uploaded(seen: Any) -> bytes:
    """The single file inside a PUT /archive tar body."""
    with tarfile.open(fileobj=io.BytesIO(seen.body)) as tar:
        (m,) = [m for m in tar if m.isfile()]
        return tar.extractfile(m).read()  # type: ignore[union-attr]


# ================================================================================================
# _scope: a skipped item never stops the rest of the rollback
# ================================================================================================

def test_entry_without_inverse_does_not_stop_older_entries_from_being_undone(world, dk):
    world.add_container("web")
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.stop", ref="web")
    do(dk, "networks.create", name="n1")                              # newest: journaled with no inverse
    assert [e["inverse"] and e["inverse"]["kind"] for e in journal(sid)] == ["set-running", None]
    out = do(dk, "session.rollback")
    assert out["failed"] == []
    assert world.containers["web"]["running"] is True                 # the older stop is still reversed
    assert "n1" not in world.networks


def test_group_step_created_in_session_is_skipped_but_later_steps_still_run(world, dk):
    for svc in ("db", "api"):
        world.add_container(f"st-{svc}", labels={"aisb.stack": "st", "aisb.service": svc})
    do(dk, "session.begin")
    world.networks["st_default"] = {"Id": "s" * 64, "labels": {"aisb.stack": "st"}}   # born in the session
    do(dk, "stack.down", stack="st")
    assert world.containers == {} and world.networks == {}
    out = do(dk, "session.rollback")
    assert out["failed"] == []
    assert set(world.containers) == {"st-db", "st-api"}               # recreated after the skipped network step
    assert "st_default" not in world.networks                         # never in the baseline: not brought back
    assert not any(s["step"].startswith("recreate network") for s in out["steps"])


def test_volume_restored_into_during_session_skip_does_not_stop_removing_other_added_volumes(world, dk, tmp_path):
    f = tmp_path / "seed.tar"
    f.write_bytes(tar_of({"x": b"1"}))
    do(dk, "session.begin")
    do(dk, "volumes.restore", ref="aaa", file=str(f))                 # inverse: remove-volume (sorted first)
    world.volumes["zzz"] = {"files": {}, "labels": {}}                # plain added volume after it
    out = do(dk, "session.rollback")
    assert out["failed"] == []
    assert [s["step"] for s in out["steps"]] == ["remove volume aaa (it didn't exist before)",
                                                 "remove added volume zzz"]
    assert world.volumes == {}


def test_added_container_is_removed_with_its_anonymous_volumes_and_no_spurious_failure(world, dk):
    do(dk, "session.begin")
    c = world.add_container("intruder", anon={"/data": "anon9"})
    out = do(dk, "session.rollback")
    rm = next(s for s in world.d.seen if s.method == "DELETE" and s.path == f"/containers/{c['name']}")
    assert rm.query.get("force") in ("1", "true", "True") and rm.query.get("v") in ("1", "true", "True")
    assert "intruder" not in world.containers and "anon9" not in world.volumes
    # the daemon dropped the anonymous volume with its container: its own removal step is not a failure
    assert out["failed"] == []


def test_network_created_then_removed_in_session_is_not_resurrected(world, dk):
    do(dk, "session.begin")
    do(dk, "networks.create", name="tmpnet")
    do(dk, "networks.rm", ref="tmpnet")
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and out["steps"] == [] and world.networks == {}


# ================================================================================================
# capture: journal entry fields, set-running, not-undoable, names
# ================================================================================================

def test_journal_entry_fields(world, dk):
    world.add_container("web")
    sid = do(dk, "session.begin")["session"]
    t0 = time.time()
    do(dk, "containers.stop", ref="web")
    (e,) = journal(sid)
    assert len(e["id"]) >= 8 and e["id"].isalnum()
    assert t0 <= e["at"] <= time.time()
    assert e["op"] == "containers.stop" and e["tier"] == "mutate" and e["host"] is None
    assert e["args"]["ref"] == "web" and e["done"] is False
    assert e["inverse"] == {"kind": "set-running", "name": "web", "container": "web", "running": True}


def test_start_is_journaled_and_rolled_back_by_stopping(world, dk):
    world.add_container("web", running=False)
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.start", ref="web")
    assert world.containers["web"]["running"] is True
    assert journal(sid)[0]["inverse"] == {"kind": "set-running", "name": "web", "container": "web", "running": False}
    out = do(dk, "session.rollback")
    assert out["steps"] == [{"step": "stop web", "status": "done"}]
    assert world.containers["web"]["running"] is False
    assert ("POST", "/containers/web/stop") in world.mutations()


def test_restart_is_journaled_with_the_prior_run_state(world, dk):
    world.add_container("web", running=False)
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.restart", ref="web")
    assert journal(sid)[0]["inverse"]["kind"] == "set-running" and journal(sid)[0]["inverse"]["running"] is False
    assert do(dk, "session.rollback")["steps"] == [{"step": "stop web", "status": "done"}]
    assert world.containers["web"]["running"] is False


def test_names_beginning_with_x_keep_their_first_letter(world, dk):
    world.add_container("Xweb")
    world.add_container("Xapi")
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.stop", ref="Xapi")
    do(dk, "containers.rm", ref="Xweb", force=True)
    stop, rm = journal(sid)
    assert stop["inverse"]["container"] == "Xapi" and rm["inverse"]["name"] == "Xweb"
    assert do(dk, "session.rollback")["failed"] == []
    assert set(world.containers) == {"Xweb", "Xapi"} and world.containers["Xapi"]["running"]


@pytest.mark.parametrize("opname", ["images.rmi", "system.prune"])
def test_not_undoable_reason_text(world, dk, opname):
    world.d.on("DELETE", r"/images/.+", json=[{"Untagged": "x:1"}])
    for kind in ("containers", "images", "networks", "volumes"):
        world.d.on("POST", f"/{kind}/prune", json={})
    sid = do(dk, "session.begin")["session"]
    do(dk, opname, **({"ref": "x:1"} if opname == "images.rmi" else {}))
    assert journal(sid)[0]["inverse"] == {
        "kind": "not-undoable",
        "reason": f"{opname} cannot be reversed (images can be pulled again; pruned objects are gone)"}


# ================================================================================================
# capture/rollback of databases (db.restore, and db.exec under protect-data)
# ================================================================================================

def _psql_file_calls(execs: list[Any]) -> list[list[str]]:
    return [e.body["Cmd"] for e in execs if e.body["Cmd"][0] == "psql" and "-f" in e.body["Cmd"]]


@pytest.mark.parametrize("opname", ["db.restore", "db.exec"])
def test_db_change_is_dumped_first_and_rolled_back_into_the_same_database(world, dk, tmp_path, opname):
    world.add_container("pg", image="postgres:16")
    execs = world.d.execs("pg", [(b"-- dump of shop\n", b"", 0)] + [(b"", b"", 0)] * 8)
    sql = tmp_path / "new.sql"
    sql.write_bytes(b"drop table orders;")
    sid = do(dk, "session.begin", protect_data=opname == "db.exec")["session"]
    args = {"file": str(sql)} if opname == "db.restore" else {"sql": "delete from orders"}
    do(dk, opname, ref="pg", database="shop", **args)

    (entry,) = journal(sid)
    inv = entry["inverse"]
    assert inv["kind"] == "restore-db" and inv["container"] == "pg" and inv["database"] == "shop"
    assert Path(inv["dump"]).read_bytes() == b"-- dump of shop\n"
    assert Path(inv["dump"]).is_relative_to(state.home("sessions", sid, "artifacts"))
    dump = execs[0].body["Cmd"]
    assert dump[0] == "pg_dump" and "--clean" in dump and dump[dump.index("-d") + 1] == "shop"

    mark = len(world.d.seen)
    out = do(dk, "session.rollback")
    assert out["steps"] == [{"step": "restore database in pg", "status": "done"}]
    replay = _psql_file_calls(execs)[-1]
    assert replay[replay.index("-d") + 1] == "shop"
    (put,) = [s for s in posts(world, mark) if s.method == "PUT"]
    assert put.path == "/containers/pg/archive" and uploaded(put) == b"-- dump of shop\n"


def test_db_exec_without_protect_data_takes_no_dump(world, dk):
    world.add_container("pg", image="postgres:16")
    execs = world.d.execs("pg", [(b"DELETE 1\n", b"", 0)])
    sid = do(dk, "session.begin")["session"]
    do(dk, "db.exec", ref="pg", sql="delete from t")
    (entry,) = journal(sid)
    assert entry["inverse"] is None
    assert [e.body["Cmd"][0] for e in execs] == ["psql"]


def test_db_restore_capture_on_a_non_sql_service_is_reported_not_undoable(world, dk, tmp_path):
    world.add_container("cache", image="redis:7")
    sql = tmp_path / "x.sql"
    sql.write_bytes(b"select 1;")
    sid = do(dk, "session.begin")["session"]
    with pytest.raises(ValueError, match="redis"):
        do(dk, "db.restore", ref="cache", file=str(sql))
    (entry,) = journal(sid)
    assert entry["inverse"]["kind"] == "capture-failed" and "redis" in entry["inverse"]["error"]


def test_restore_db_rollback_into_a_non_sql_service_fails_cleanly(world, dk, tmp_path):
    world.add_container("cache", image="redis:7")
    sid = do(dk, "session.begin")["session"]
    dump = tmp_path / "d.sql"
    dump.write_bytes(b"select 1;")
    state.append_jsonl(state.home("sessions", sid) / "journal.jsonl", {
        "id": "x", "op": "db.restore", "host": None, "done": False,
        "inverse": {"kind": "restore-db", "container": "cache", "database": None, "dump": str(dump)}})
    out = do(dk, "session.rollback")
    (s,) = out["steps"]
    assert s["step"] == "restore database in cache" and s["status"] == "failed" and "redis" in s["error"]


# ================================================================================================
# stack.down: only the stack's own network/volumes, volumes with meta, containers without backups
# ================================================================================================

def test_stack_down_journals_only_the_stacks_objects_and_restores_volume_metadata(world, dk):
    for svc in ("db", "api"):
        world.add_container(f"st-{svc}", labels={"aisb.stack": "st", "aisb.service": svc},
                            networks={"st_default": [svc]}, binds=["st_data:/data"] if svc == "db" else None)
        world.containers[f"st-{svc}"]["mode"] = "st_default"
    world.networks["st_default"] = {"Id": "s" * 64, "labels": {"aisb.stack": "st"}}
    world.networks["othernet"] = {"Id": "o" * 64, "labels": {}}
    world.networks["other_default"] = {"Id": "p" * 64, "labels": {"aisb.stack": "other"}}
    world.volumes["st_data"] = {"files": {"f": b"1"}, "labels": {"aisb.stack": "st"},
                                "driver": "rexray", "options": {"size": "5"}}
    world.volumes["othervol"] = {"files": {}, "labels": {}}
    sid = do(dk, "session.begin")["session"]
    do(dk, "stack.down", stack="st", volumes=True)
    steps = journal(sid)[0]["inverse"]["steps"]
    assert [(s["kind"], s["name"]) for s in steps] == [
        ("recreate-network", "st_default"), ("restore-volume", "st_data"),
        ("recreate-container", "st-db"), ("recreate-container", "st-api")]
    assert steps[1]["meta"] == {"driver": "rexray", "options": {"size": "5"}, "labels": {"aisb.stack": "st"}}
    assert all("volumes" not in s for s in steps[2:])                 # stack containers: no per-container backups
    assert len(list(state.home("sessions", sid, "artifacts").glob("volume-*"))) == 1

    out = do(dk, "session.rollback")
    assert out["failed"] == []
    v = world.volumes["st_data"]
    assert v["labels"] == {"aisb.stack": "st"} and v["driver"] == "rexray" and v["options"] == {"size": "5"}
    assert v["files"] == {"f": b"1"}
    assert set(world.containers) == {"st-db", "st-api"} and set(world.networks) == {
        "st_default", "othernet", "other_default"}


# ================================================================================================
# volumes and networks come back with their driver, options and flags
# ================================================================================================

def test_removed_volume_is_recreated_with_its_driver_and_options(world, dk):
    world.volumes["pg"] = {"files": {"a": b"1"}, "labels": {"team": "db"}, "driver": "rexray",
                           "options": {"size": "20", "fs": "xfs"}}
    sid = do(dk, "session.begin")["session"]
    do(dk, "volumes.rm", ref="pg")
    assert journal(sid)[0]["inverse"]["meta"] == {"driver": "rexray", "options": {"size": "20", "fs": "xfs"},
                                                  "labels": {"team": "db"}}
    mark = len(world.d.seen)
    assert do(dk, "session.rollback")["failed"] == []
    (create,) = [s.body for s in world.d.seen[mark:] if s.path == "/volumes/create"]
    assert create == {"Name": "pg", "Driver": "rexray", "DriverOpts": {"size": "20", "fs": "xfs"},
                      "Labels": {"team": "db"}}
    assert world.volumes["pg"]["files"] == {"a": b"1"}


def test_volume_meta_defaults_when_the_daemon_reports_none(world, dk):
    world.volumes["v"] = {"files": {}, "labels": {}, "driver": ""}
    sid = do(dk, "session.begin")["session"]
    do(dk, "volumes.rm", ref="v")
    assert journal(sid)[0]["inverse"]["meta"] == {"driver": "local", "options": {}, "labels": {}}
    mark = len(world.d.seen)
    do(dk, "session.rollback")
    (create,) = [s.body for s in world.d.seen[mark:] if s.path == "/volumes/create"]
    assert create["Driver"] == "local"


def test_restore_volume_meta_without_a_driver_recreates_a_local_volume(world, dk, tmp_path):
    world.volumes["old"] = {"files": {}, "labels": {}}                # in the baseline, removed outside aisb
    sid = do(dk, "session.begin")["session"]
    backup = tmp_path / "b.tar"
    backup.write_bytes(tar_of({"v/a": b"1"}, dirs=("v",)))
    state.append_jsonl(state.home("sessions", sid) / "journal.jsonl", {
        "id": "x", "op": "volumes.rm", "host": None, "done": False,
        "inverse": {"kind": "restore-volume", "name": "old", "meta": {"labels": {"k": "v"}}, "backup": str(backup)}})
    del world.volumes["old"]
    assert do(dk, "session.rollback")["failed"] == []
    (create,) = [s.body for s in world.d.seen if s.path == "/volumes/create"]
    assert create == {"Name": "old", "Driver": "local", "DriverOpts": {}, "Labels": {"k": "v"}}
    assert world.volumes["old"]["files"] == {"a": b"1"}


def test_network_driver_defaults_to_bridge_when_the_daemon_reports_none(world, dk):
    world.networks["n"] = {"Id": "a" * 64, "labels": {}, "driver": ""}
    sid = do(dk, "session.begin")["session"]
    do(dk, "networks.rm", ref="n")
    assert journal(sid)[0]["inverse"]["driver"] == "bridge"


def test_rollback_of_restore_into_existing_volume_does_not_recreate_it(world, dk, tmp_path):
    world.volumes["cfg"] = {"files": {"a": b"old"}, "labels": {}, "driver": "rexray"}
    f = tmp_path / "new.tar"
    f.write_bytes(tar_of({"a": b"new"}))
    do(dk, "session.begin")
    do(dk, "volumes.restore", ref="cfg", file=str(f))
    mark = len(world.d.seen)
    assert do(dk, "session.rollback")["failed"] == []
    assert not any(s.path == "/volumes/create" for s in world.d.seen[mark:])
    assert world.volumes["cfg"]["files"] == {"a": b"old"} and world.volumes["cfg"]["driver"] == "rexray"


def test_removed_network_is_recreated_with_its_driver_and_internal_flag(world, dk):
    world.networks["priv"] = {"Id": "a" * 64, "labels": {"t": "1"}, "driver": "macvlan", "internal": True}
    sid = do(dk, "session.begin")["session"]
    do(dk, "networks.rm", ref="priv")
    assert journal(sid)[0]["inverse"] == {"kind": "recreate-network", "name": "priv", "driver": "macvlan",
                                          "internal": True, "labels": {"t": "1"}}
    mark = len(world.d.seen)
    assert do(dk, "session.rollback")["failed"] == []
    (create,) = [s.body for s in world.d.seen[mark:] if s.path == "/networks/create"]
    assert create == {"Name": "priv", "Driver": "macvlan", "Internal": True, "Labels": {"t": "1"}}
    assert world.networks["priv"]["driver"] == "macvlan" and world.networks["priv"]["internal"] is True


# ================================================================================================
# recreate-container: networks, aliases, image, pull, volumes
# ================================================================================================

def test_recreate_uses_the_user_network_as_primary_and_reconnects_the_rest_with_aliases(world, dk):
    world.networks.update(appnet={"Id": "n1" * 32, "labels": {}}, side={"Id": "n2" * 32, "labels": {}})
    web = world.add_container("web", networks={"bridge": [], "appnet": ["web", "0123456789ab"], "side": ["s1", "0123456789ab", "s2"]})
    web["mode"] = "appnet"
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="web", force=True)
    assert do(dk, "session.rollback")["failed"] == []
    back = world.containers["web"]
    assert back["mode"] == "appnet"
    assert back["networks"] == {"appnet": ["web"], "bridge": [], "side": ["s1", "s2"]}


def test_recreate_on_the_default_bridge_is_not_connected_twice(world, dk):
    world.add_container("web", networks={"bridge": []})
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="web", force=True)
    mark = len(world.d.seen)
    assert do(dk, "session.rollback")["failed"] == []
    assert not [s for s in world.d.seen[mark:] if s.path.endswith("/connect")]  # create already attached it
    assert world.containers["web"]["networks"] == {"bridge": []}


def test_recreate_of_bridge_container_with_a_user_network_keeps_both(world, dk):
    world.networks["side"] = {"Id": "n2" * 32, "labels": {}}
    world.add_container("web", networks={"bridge": [], "side": ["w"]})
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="web", force=True)
    assert do(dk, "session.rollback")["failed"] == []
    assert world.containers["web"]["networks"] == {"bridge": [], "side": ["w"]}


@pytest.mark.parametrize("mode", ["host", "none"])
def test_recreate_host_or_none_mode_container_connects_no_networks(world, dk, mode):
    c = world.add_container("agent", networks={mode: []})
    c["mode"] = mode
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="agent", force=True)
    mark = len(world.d.seen)
    assert do(dk, "session.rollback")["failed"] == []
    assert not [s for s in world.d.seen[mark:] if s.path.endswith("/connect")]
    assert world.containers["agent"]["mode"] == mode


def test_recreate_falls_back_to_the_spec_image_without_an_image_id(world, dk):
    world.add_container("web", image="nginx:1.25")["image_id"] = ""
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="web", force=True)
    assert do(dk, "session.rollback")["failed"] == []
    assert world.containers["web"]["image"] == "nginx:1.25"


def test_recreate_never_pulls_a_missing_image(world, dk):
    world.add_container("web")
    world.d.on("POST", "/images/create", json={})
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="web", force=True)
    world.fail[("POST", "/containers/create")] = Reply(404, json={"message": "No such image: sha256:abab"})
    out = do(dk, "session.rollback")
    (s,) = out["failed"]
    assert s["step"] == "recreate container web" and "No such image" in s["error"]
    assert not any(p.method == "POST" and p.path.startswith("/images/") for p in world.d.seen)


def test_recreate_keeps_host_binds_next_to_restored_anonymous_volumes(world, dk):
    world.add_container("db", anon={"/data": "anon1"}, binds=["/srv/cfg:/cfg:ro"])
    world.volumes["anon1"]["files"]["x"] = b"1"
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="db", force=True, volumes=True)
    assert do(dk, "session.rollback")["failed"] == []
    db = world.containers["db"]
    assert sorted(db["binds"]) == ["/srv/cfg:/cfg:ro", "anon1:/data"]
    assert world.volumes["anon1"]["files"] == {"x": b"1"}


# ================================================================================================
# fleet: per-host baseline files and step labels
# ================================================================================================

def test_fleet_baseline_file_records_when_it_was_taken(world, dk, remote):
    rw = World(remote)
    rw.add_container("web")
    sid = do(dk, "session.begin")["session"]
    h = Host("r1", docker=f"unix://{remote.sock}")
    t0 = time.time()
    with context.use(host=h):
        do(Docker(h.docker, timeout=5), "containers.stop", ref="web")
    base = state.read_json(state.home("sessions", sid) / "baseline-r1.json")
    assert base["baseline"] is not None and t0 <= base["at"] <= time.time()


def test_fleet_baseline_error_is_recorded_with_its_time(world, dk, remote):
    sid = do(dk, "session.begin")["session"]                          # the remote daemon answers nothing: 404s
    h = Host("r1", docker=f"unix://{remote.sock}")
    t0 = time.time()
    with context.use(host=h), pytest.raises(Exception):  # noqa: B017 -- the op itself fails on the dead host
        do(Docker(h.docker, timeout=5), "containers.stop", ref="web")
    base = state.read_json(state.home("sessions", sid) / "baseline-r1.json")
    assert base["baseline"] is None and base["error"] and t0 <= base["at"] <= time.time()
    out = do(dk, "session.rollback")
    assert {"step": "[r1] baseline", "status": "failed", "error": base["error"]} in out["steps"]


def test_fleet_added_volumes_and_networks_are_labelled_with_their_host(world, dk, remote):
    rw = World(remote)
    rw.add_container("web")
    do(dk, "session.begin")
    h = Host("r1", docker=f"unix://{remote.sock}")
    with context.use(host=h):
        do(Docker(h.docker, timeout=5), "containers.stop", ref="web")
    rw.volumes["scratch"] = {"files": {}, "labels": {}}
    rw.networks["tmpnet"] = {"Id": "t" * 64, "labels": {}}
    out = do(dk, "session.rollback")
    assert [s["step"] for s in out["steps"]] == [
        "[r1] start web", "[r1] remove added volume scratch", "[r1] remove added network tmpnet"]
    assert out["failed"] == [] and rw.volumes == {} and rw.networks == {}
