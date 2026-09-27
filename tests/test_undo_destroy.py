"""Undo and destructive ops: session journal/rollback invariants, volumes, networks, images, local state.

A tiny stateful Docker model (`World`) sits behind the fake daemon so rollback can be checked against what the
daemon actually ends up holding, not just the requests sent. Only the process boundary is faked.
"""

import gzip
import io
import json
import tarfile
import uuid
from pathlib import Path
from typing import Any

import pytest

from aisb import context, state
from aisb.api import session as sess
from aisb.api.images import split_tag
from aisb.cli import EXIT_CONFIRM, EXIT_DOCKER, EXIT_OK, EXIT_USAGE, main
from aisb.client import Docker
from aisb.errors import APIError, Conflict, NotFound
from aisb.fleet.inventory import Host
from aisb.ops import get_op, invoke

from conftest import FakeDaemon, Reply, tar_of

MUTATING = ("POST", "PUT", "DELETE")


def _tar_files(data: bytes, prefix: str) -> dict[str, bytes]:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for m in tar:
            if m.isfile():
                out[m.name.removeprefix(prefix)] = tar.extractfile(m).read()  # type: ignore[union-attr]
    return out


class World:
    """Containers, volumes (with file contents) and networks behind the fake daemon's routes."""

    def __init__(self, d: FakeDaemon) -> None:
        self.d = d
        self.containers: dict[str, dict[str, Any]] = {}   # name -> record
        self.volumes: dict[str, dict[str, Any]] = {}      # name -> {"files", "labels"[, "driver", "options"]}
        self.networks: dict[str, dict[str, Any]] = {}     # name -> {"Id", "labels"[, "driver", "internal"]}
        self.fail: dict[tuple[str, str], Reply] = {}      # (method, path) -> forced reply
        self._routes()

    # --- model --------------------------------------------------------------------------------
    def add_container(self, name: str, *, image: str = "nginx:1", running: bool = True,
                      labels: dict[str, str] | None = None, networks: dict[str, list[str]] | None = None,
                      anon: dict[str, str] | None = None, binds: list[str] | None = None,
                      cmd: list[str] | None = None) -> dict[str, Any]:
        cid = uuid.uuid4().hex + uuid.uuid4().hex
        rec = {"Id": cid, "name": name, "image": image, "image_id": f"sha256:{'ab' * 32}", "running": running,
               "labels": dict(labels or {}), "networks": dict(networks or {"bridge": []}),
               "anon": dict(anon or {}), "binds": list(binds or []), "cmd": cmd or ["run"], "mode": None}
        for vol in rec["anon"].values():
            self.volumes.setdefault(vol, {"files": {}, "labels": {}})
        self.containers[name] = rec
        return rec

    def find(self, ref: str) -> dict[str, Any] | None:
        if ref in self.containers:
            return self.containers[ref]
        return next((c for c in self.containers.values() if c["Id"].startswith(ref) and len(ref) >= 12), None)

    def net(self, ref: str) -> tuple[str, dict[str, Any]] | None:
        return next(((n, v) for n, v in self.networks.items() if ref in (n, v["Id"])), None)

    def _mounts(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        out = [{"Type": "volume", "Name": v, "Destination": dest} for dest, v in c["anon"].items()]
        for b in c["binds"]:
            src, _, dest = b.partition(":")
            out.append({"Type": "bind" if src.startswith("/") else "volume", "Name": None if src.startswith("/")
                        else src, "Source": src, "Destination": dest.split(":")[0]})
        return out

    def inspect(self, c: dict[str, Any]) -> dict[str, Any]:
        return {"Id": c["Id"], "Name": "/" + c["name"], "Image": c["image_id"],
                "Config": {"Image": c["image"], "Cmd": c["cmd"], "Labels": c["labels"],
                           "Volumes": {d: {} for d in c["anon"]} or None},
                "HostConfig": {"Binds": c["binds"] or None, "NetworkMode": c["mode"] or "bridge"},
                "State": {"Running": c["running"], "Status": "running" if c["running"] else "exited", "ExitCode": 0},
                "Mounts": self._mounts(c),
                "NetworkSettings": {"Networks": {n: {"Aliases": a} for n, a in c["networks"].items()}}}

    def row(self, c: dict[str, Any]) -> dict[str, Any]:
        return {"Id": c["Id"], "Names": ["/" + c["name"]], "Image": c["image"], "ImageID": c["image_id"],
                "State": "running" if c["running"] else "exited", "Status": "Up" if c["running"] else "Exited",
                "Labels": c["labels"], "Ports": []}

    def snapshot_keys(self) -> dict[str, set[str]]:
        return {"containers": set(self.containers), "volumes": set(self.volumes), "networks": set(self.networks)}

    def mutations(self, since: int = 0) -> list[tuple[str, str]]:
        return [(s.method, s.path) for s in self.d.seen[since:] if s.method in MUTATING]

    # --- routes -------------------------------------------------------------------------------
    def _routes(self) -> None:
        d, W = self.d, self

        def forced(seen) -> Reply | None:
            return W.fail.get((seen.method, seen.path))

        def label_filter(seen) -> list[str]:
            return (seen.filters() or {}).get("label") or []

        def matches(labels: dict[str, str], wanted: list[str]) -> bool:
            return all(labels.get(k) == v for k, _, v in (w.partition("=") for w in wanted))

        def ls_containers(seen):
            want = label_filter(seen)
            return Reply(json=[W.row(c) for c in W.containers.values() if matches(c["labels"], want)])

        def get_container(seen):
            c = W.find(seen.path.split("/")[2])
            return Reply(json=W.inspect(c)) if c else Reply(404, json={"message": "No such container"})

        def create_container(seen):
            if r := forced(seen):
                return r
            b = seen.body
            name = seen.query.get("name") or uuid.uuid4().hex[:10]
            if name in W.containers:
                return Reply(409, json={"message": f"name {name} in use"})
            hc = b.get("HostConfig") or {}
            eps = ((b.get("NetworkingConfig") or {}).get("EndpointsConfig") or {})
            mode = hc.get("NetworkMode")
            if mode not in (None, "bridge", "host", "none") and W.net(mode) is None:
                return Reply(404, json={"message": f"network {mode} not found"})
            nets = {mode: (eps.get(mode) or {}).get("Aliases") or []} if mode else {"bridge": []}
            anon = {dest: uuid.uuid4().hex for dest in b.get("Volumes") or {}}
            c = W.add_container(name, image=b["Image"], running=False, labels=b.get("Labels"), networks=nets,
                                anon=anon, binds=hc.get("Binds"), cmd=b.get("Cmd"))
            c["mode"] = mode
            for bind in c["binds"]:
                src = bind.split(":")[0]
                if not src.startswith("/"):
                    W.volumes.setdefault(src, {"files": {}, "labels": {}})
            return Reply(201, json={"Id": c["Id"]})

        def act(seen):
            if r := forced(seen):
                return r
            _, _, ref, what = seen.path.split("/")
            c = W.find(ref)
            if c is None:
                return Reply(404, json={"message": "No such container"})
            if what == "start" and c["cmd"][:1] == ["sh"]:  # the volume --clear helper
                W.volumes[c["binds"][0].split(":")[0]]["files"].clear()
            c["running"] = what in ("start", "restart")
            return Reply(204)

        def rm_container(seen):
            if r := forced(seen):
                return r
            c = W.find(seen.path.split("/")[2])
            if c is None:
                return Reply(404, json={"message": "No such container"})
            if c["running"] and seen.query.get("force") not in ("1", "true", "True"):
                return Reply(409, json={"message": "container is running"})
            del W.containers[c["name"]]
            if seen.query.get("v") in ("1", "true", "True"):
                for vol in c["anon"].values():
                    W.volumes.pop(vol, None)
            return Reply(204)

        def helper_vol(c: dict[str, Any]) -> str:
            return c["binds"][0].split(":")[0]

        def get_archive(seen):
            c = W.find(seen.path.split("/")[2])
            if not c or not c["binds"]:
                return Reply(404, json={"message": "Could not find the file"})
            vol = W.volumes[helper_vol(c)]
            return Reply(body=tar_of({f"v/{k}": v for k, v in vol["files"].items()}, dirs=("v",)),
                         content_type="application/x-tar")

        def put_archive(seen):
            if r := forced(seen):
                return r
            c = W.find(seen.path.split("/")[2])
            if not c["binds"]:  # an upload into a plain container (e.g. a SQL script)
                c.setdefault("uploads", []).append(seen.query.get("path"))
                return Reply(200)
            prefix = "v/" if seen.query.get("path") == "/" else ""
            W.volumes[helper_vol(c)]["files"].update(_tar_files(seen.body, prefix))
            return Reply(200)

        def ls_volumes(seen):
            want = label_filter(seen)
            return Reply(json={"Volumes": [{"Name": n, "Driver": v.get("driver", "local"), "Labels": v["labels"]}
                                           for n, v in W.volumes.items() if matches(v["labels"], want)]})

        def get_volume(seen):
            n = seen.path.split("/")[2]
            return Reply(json={"Name": n, "Driver": W.volumes[n].get("driver", "local"), "Labels": W.volumes[n]["labels"],
                               "Options": W.volumes[n].get("options") or {}}) \
                if n in W.volumes else Reply(404, json={"message": "no"})

        def create_volume(seen):
            b = seen.body
            W.volumes.setdefault(b["Name"], {"files": {}, "labels": b.get("Labels") or {},
                                             "driver": b.get("Driver") or "local", "options": b.get("DriverOpts") or {}})
            return Reply(201, json={"Name": b["Name"], "Driver": b.get("Driver") or "local"})

        def rm_volume(seen):
            if r := forced(seen):
                return r
            n = seen.path.split("/")[2]
            if n not in W.volumes:
                return Reply(404, json={"message": f"get {n}: no such volume"})
            del W.volumes[n]
            return Reply(204)

        def ls_networks(seen):
            want = label_filter(seen)
            return Reply(json=[{"Name": n, "Id": v["Id"], "Driver": v.get("driver", "bridge"),
                                "Internal": bool(v.get("internal")), "Labels": v["labels"]}
                               for n, v in W.networks.items() if matches(v["labels"], want)])

        def get_network(seen):
            hit = W.net(seen.path.split("/")[2])
            if hit is None:
                return Reply(404, json={"message": "network not found"})
            name, v = hit
            return Reply(json={"Name": name, "Id": v["Id"], "Driver": v.get("driver", "bridge"),
                               "Internal": bool(v.get("internal")), "Labels": v["labels"], "Containers": {
                c["Id"]: {"Name": c["name"]} for c in W.containers.values() if name in c["networks"]}})

        def create_network(seen):
            nid = uuid.uuid4().hex * 2
            b = seen.body
            W.networks[b["Name"]] = {"Id": nid, "labels": b.get("Labels") or {}, "driver": b.get("Driver") or "bridge",
                                     "internal": bool(b.get("Internal"))}
            return Reply(201, json={"Id": nid})

        def rm_network(seen):
            if r := forced(seen):
                return r
            hit = W.net(seen.path.split("/")[2])
            if hit is None:
                return Reply(404, json={"message": "network not found"})
            del W.networks[hit[0]]
            return Reply(204)

        def connect(seen):
            c = W.find(seen.body["Container"])
            ref = seen.path.split("/")[2]
            hit = W.net(ref)
            if hit is None and ref not in ("bridge", "host", "none"):  # the built-in networks always exist
                return Reply(404, json={"message": f"network {ref} not found"})
            name = hit[0] if hit else ref
            c["networks"][name] = (seen.body.get("EndpointConfig") or {}).get("Aliases") or []
            return Reply(200)

        seg = r"[^/]+"
        d.on("GET", "/images/json", json=[])
        d.on("GET", "/containers/json", ls_containers)
        d.on("GET", rf"/containers/{seg}/json", get_container)
        d.on("GET", rf"/containers/{seg}/logs", Reply(body=b""))
        d.on("POST", "/containers/create", create_container)
        d.on("POST", rf"/containers/{seg}/(start|stop|restart)", act)
        d.on("POST", rf"/containers/{seg}/wait", json={"StatusCode": 0})
        d.on("DELETE", rf"/containers/{seg}", rm_container)
        d.on("GET", rf"/containers/{seg}/archive", get_archive)
        d.on("PUT", rf"/containers/{seg}/archive", put_archive)
        d.on("GET", "/volumes", ls_volumes)
        d.on("GET", rf"/volumes/{seg}", get_volume)
        d.on("POST", "/volumes/create", create_volume)
        d.on("DELETE", rf"/volumes/{seg}", rm_volume)
        d.on("GET", "/networks", ls_networks)
        d.on("GET", rf"/networks/{seg}", get_network)
        d.on("POST", "/networks/create", create_network)
        d.on("DELETE", rf"/networks/{seg}", rm_network)
        d.on("POST", rf"/networks/{seg}/connect", connect)


@pytest.fixture
def world(daemon) -> World:
    return World(daemon)


@pytest.fixture
def dk(host) -> Docker:
    return Docker(host, timeout=5)


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def do(dk: Docker, qualname: str, *, confirm: bool = True, dry_run: bool = False, **kw: Any) -> Any:
    """Run an op the way every front end does (policy, session capture hook, audit)."""
    out = invoke(dk, get_op(qualname), kw, confirm=confirm, dry_run=dry_run)
    return out.result if out.status == "ok" else out.payload()


def journal(sid: str) -> list[dict[str, Any]]:
    return list(state.read_jsonl(state.home("sessions", sid) / "journal.jsonl"))


# ================================================================================================
# session: invariants
# ================================================================================================

def test_rollback_restores_exactly_what_changed_and_nothing_else(world, dk):
    world.networks.update(appnet={"Id": "n1" * 32, "labels": {}}, side={"Id": "n2" * 32, "labels": {}})
    web = world.add_container("web", networks={"appnet": ["web", "0123456789ab"], "side": []})
    world.add_container("bystander")
    world.add_container("sleepy", running=False)
    before = world.snapshot_keys()
    sid = do(dk, "session.begin", name="t")["session"]

    do(dk, "containers.rm", ref="web", force=True)
    world.add_container("intruder")                         # created during the session: must go
    world.volumes["scratch"] = {"files": {}, "labels": {}}
    world.networks["tmpnet"] = {"Id": "n3" * 32, "labels": {}}
    assert "web" not in world.containers

    mark = len(world.d.seen)
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and out["hosts"] == ["local"]
    assert [s["step"] for s in out["steps"]] == ["remove added container intruder", "recreate container web",
                                                 "remove added volume scratch", "remove added network tmpnet"]
    assert world.snapshot_keys() == before
    back = world.containers["web"]
    assert back["running"] and back["image"] == web["image_id"]      # pinned to the exact image id
    assert back["mode"] == "appnet" and back["networks"]["appnet"] == ["web"]  # the 12-char id alias is dropped
    assert "side" in back["networks"]                                 # secondary network reconnected
    touched = {p.split("/")[2] for _, p in world.mutations(mark) if p.startswith("/containers/")}
    assert not touched & {"bystander", "sleepy", world.containers["bystander"]["Id"]}
    assert world.containers["sleepy"]["running"] is False
    assert all(e["done"] for e in journal(sid))

    mark = len(world.d.seen)
    again = do(dk, "session.rollback")
    assert again["steps"] == [] and again["failed"] == []            # idempotent
    assert world.mutations(mark) == []


def test_rollback_dry_run_plans_without_changing_anything(world, dk, cli):
    world.add_container("web")
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.stop", ref="web")
    world.add_container("intruder")
    mark = len(world.d.seen)
    code, plan, _ = cli("session", "rollback")                       # DESTROY without --yes: preview, exit 3
    assert code == EXIT_CONFIRM
    assert [p["step"] for p in plan["planned"] if "step" in p] == ["remove added container intruder", "start web"]
    assert world.mutations(mark) == [] and not journal(sid)[0]["done"]
    code, plan2, _ = cli("session", "rollback", "--dry-run")
    assert code == EXIT_OK and plan2["status"] == "dry-run" and world.mutations(mark) == []
    code, out, _ = cli("session", "rollback", "--yes")
    assert code == EXIT_OK and len(out["steps"]) == 2 and world.containers["web"]["running"]
    assert "intruder" not in world.containers


def test_rollback_of_rm_volumes_restores_anonymous_volume_from_backup(world, dk):
    world.add_container("db", anon={"/data": "anon1"})
    world.volumes["anon1"]["files"].update({"rows.csv": b"1,2,3\n", "meta": b"m"})
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.rm", ref="db", force=True, volumes=True)
    assert "anon1" not in world.volumes                               # the daemon really dropped it
    (entry,) = journal(sid)
    (vol,) = entry["inverse"]["volumes"]
    assert vol["name"] == "anon1" and vol["destination"] == "/data" and Path(vol["backup"]).exists()
    assert Path(vol["backup"]).is_relative_to(state.home("sessions", sid, "artifacts"))
    with tarfile.open(vol["backup"]) as tar:                         # the backup was taken before removal
        assert sorted(tar.getnames()) == ["v", "v/meta", "v/rows.csv"]

    out = do(dk, "session.rollback")
    assert out["failed"] == []
    db = world.containers["db"]
    assert world.volumes["anon1"]["files"] == {"rows.csv": b"1,2,3\n", "meta": b"m"}
    # the recreated container mounts the restored volume (not a fresh, empty anonymous one)
    assert db["anon"] == {} and "anon1:/data" in db["binds"]
    assert set(world.volumes) == {"anon1"}


def test_rm_without_volumes_flag_takes_no_volume_backup(world, dk):
    world.add_container("db", anon={"/data": "anon1"})
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.rm", ref="db", force=True)
    (entry,) = journal(sid)
    assert "volumes" not in entry["inverse"]
    assert not any(s.path.endswith("/archive") for s in world.d.seen)
    assert "anon1" in world.volumes                                   # without -v the daemon keeps it


def test_rollback_of_volume_rm_uses_backup_taken_before_removal(world, dk):
    world.volumes["pg"] = {"files": {"base/1": b"page"}, "labels": {}}
    sid = do(dk, "session.begin")["session"]
    do(dk, "volumes.rm", ref="pg")
    assert "pg" not in world.volumes
    (entry,) = journal(sid)
    assert entry["inverse"]["kind"] == "restore-volume" and Path(entry["inverse"]["backup"]).exists()
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and [s["step"] for s in out["steps"]] == ["restore volume pg"]
    assert world.volumes["pg"]["files"] == {"base/1": b"page"}
    assert not any(c["labels"].get("aisb.helper") for c in world.containers.values())  # helpers cleaned up


def test_rollback_of_volume_restore_clears_files_added_since(world, dk, tmp_path):
    world.volumes["cfg"] = {"files": {"a.conf": b"old"}, "labels": {}}
    newer = tmp_path / "new.tar"
    newer.write_bytes(tar_of({"a.conf": b"new", "b.conf": b"extra"}))
    sid = do(dk, "session.begin")["session"]
    do(dk, "volumes.restore", ref="cfg", file=str(newer))
    assert world.volumes["cfg"]["files"] == {"a.conf": b"new", "b.conf": b"extra"}
    assert journal(sid)[0]["inverse"]["kind"] == "restore-volume"
    assert do(dk, "session.rollback")["failed"] == []
    assert world.volumes["cfg"]["files"] == {"a.conf": b"old"}        # --clear first: b.conf is gone


def test_rollback_of_restore_into_new_volume_removes_it_once(world, dk, tmp_path):
    f = tmp_path / "seed.tar.gz"
    f.write_bytes(gzip.compress(tar_of({"x": b"1"})))
    sid = do(dk, "session.begin")["session"]
    do(dk, "volumes.restore", ref="fresh", file=str(f))
    assert "fresh" in world.volumes and journal(sid)[0]["inverse"] == {"kind": "remove-volume", "name": "fresh"}
    out = do(dk, "session.rollback")
    assert "fresh" not in world.volumes
    assert out["failed"] == []                                        # removed by its inverse, not twice
    assert [s["step"] for s in out["steps"]] == ["remove volume fresh (it didn't exist before)"]


def test_rollback_continues_past_a_failing_step_and_retries_nothing_done(world, dk):
    world.add_container("a")
    world.add_container("b")
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.stop", ref="a")
    do(dk, "containers.stop", ref="b")
    world.fail[("POST", "/containers/b/start")] = Reply(500, json={"message": "boom"})
    out = do(dk, "session.rollback")
    assert [(s["step"], s["status"]) for s in out["steps"]] == [("start b", "failed"), ("start a", "done")]
    assert "boom" in out["failed"][0]["error"]
    assert world.containers["a"]["running"] and not world.containers["b"]["running"]
    assert all(e["done"] for e in journal(sid))                      # documented: each inverse is tried once
    assert do(dk, "session.rollback")["steps"] == []


def test_rollback_recreate_is_skipped_when_container_already_back(world, dk):
    world.add_container("web")
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="web", force=True)
    world.add_container("web")                                        # someone recreated it by hand
    mark = len(world.d.seen)
    out = do(dk, "session.rollback")
    assert out["steps"] == [{"step": "recreate container web", "status": "done"}]
    assert world.mutations(mark) == []


def test_rollback_recreate_of_stopped_container_is_not_started(world, dk):
    world.add_container("job", running=False)
    do(dk, "session.begin")
    do(dk, "containers.rm", ref="job")
    do(dk, "session.rollback")
    assert world.containers["job"]["running"] is False
    assert not any(p.endswith("/start") for _, p in world.mutations())


def _stack_world(world: World) -> None:
    for svc in ("db", "api"):
        world.add_container(f"st-{svc}", labels={"aisb.stack": "st", "aisb.service": svc},
                            networks={"st_default": [svc]}, binds=["st_data:/data"] if svc == "db" else None)
        world.containers[f"st-{svc}"]["mode"] = "st_default"
    world.networks["st_default"] = {"Id": "s" * 64, "labels": {"aisb.stack": "st"}}
    world.volumes["st_data"] = {"files": {"f": b"1"}, "labels": {"aisb.stack": "st"}}


def test_stack_down_is_journaled_as_group_and_rolled_back(world, dk):
    _stack_world(world)
    before = world.snapshot_keys()
    sid = do(dk, "session.begin")["session"]
    do(dk, "stack.down", stack="st")
    assert world.containers == {} and world.networks == {} and "st_data" in world.volumes  # volumes kept
    inv = journal(sid)[0]["inverse"]
    assert inv["kind"] == "group"
    assert [s["kind"] for s in inv["steps"]] == ["recreate-network", "recreate-container", "recreate-container"]
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and world.snapshot_keys() == before
    assert out["steps"][0]["step"] == "recreate network st_default"         # the network comes back first
    assert world.networks["st_default"]["labels"] == {"aisb.stack": "st"}
    assert world.containers["st-api"]["networks"] == {"st_default": ["api"]} and world.containers["st-db"]["running"]


def test_stack_down_volumes_is_backed_up_and_restored(world, dk):
    _stack_world(world)
    sid = do(dk, "session.begin")["session"]
    do(dk, "stack.down", stack="st", volumes=True)
    assert "st_data" not in world.volumes
    steps = journal(sid)[0]["inverse"]["steps"]
    backup = next(s for s in steps if s["kind"] == "restore-volume")
    assert backup["name"] == "st_data" and Path(backup["backup"]).exists()
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and world.volumes["st_data"]["files"] == {"f": b"1"}
    assert set(world.containers) == {"st-db", "st-api"}


def test_stack_down_single_service_leaves_network_and_rolls_back(world, dk):
    _stack_world(world)
    sid = do(dk, "session.begin")["session"]
    do(dk, "stack.down", stack="st", service=["api"])
    assert set(world.containers) == {"st-db"} and "st_default" in world.networks
    assert [s["kind"] for s in journal(sid)[0]["inverse"]["steps"]] == ["recreate-container"] * 2
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and set(world.containers) == {"st-db", "st-api"}


def test_networks_rm_is_journaled_and_rolled_back(world, dk):
    world.networks["appnet"] = {"Id": "a" * 64, "labels": {"team": "x"}}
    sid = do(dk, "session.begin")["session"]
    do(dk, "networks.rm", ref="appnet")
    assert journal(sid)[0]["inverse"] == {"kind": "recreate-network", "name": "appnet", "driver": "bridge",
                                          "internal": False, "labels": {"team": "x"}}
    out = do(dk, "session.rollback")
    assert out["steps"] == [{"step": "recreate network appnet", "status": "done"}]
    assert world.networks["appnet"]["labels"] == {"team": "x"}
    assert do(dk, "session.rollback")["steps"] == []


def test_network_back_already_is_left_alone(world, dk):
    world.networks["appnet"] = {"Id": "a" * 64, "labels": {}}
    do(dk, "session.begin")
    do(dk, "networks.rm", ref="appnet")
    world.networks["appnet"] = {"Id": "b" * 64, "labels": {}}
    mark = len(world.d.seen)
    assert do(dk, "session.rollback")["failed"] == [] and world.mutations(mark) == []


def test_capture_failure_is_reported_not_undoable(world, dk):
    do(dk, "session.begin")
    with pytest.raises(NotFound):
        do(dk, "containers.rm", ref="ghost")                          # inspect 404s during capture, then rm 404s
    out = do(dk, "session.rollback")
    assert out["not_undoable"] == ["containers.rm"] and out["steps"] == []
    st = do(dk, "session.status")
    assert st["not_undoable"] == ["containers.rm"] and st["journal"][0]["undo"] == "capture-failed"


def test_images_rmi_and_prune_are_marked_not_undoable(world, dk):
    world.d.on("DELETE", r"/images/.+", json=[{"Untagged": "x:1"}])
    sid = do(dk, "session.begin")["session"]
    do(dk, "images.rmi", ref="x:1")
    (entry,) = journal(sid)
    assert entry["inverse"]["kind"] == "not-undoable" and "images.rmi" in entry["inverse"]["reason"]


def test_mutate_ops_without_inverse_are_journaled_with_none(world, dk):
    sid = do(dk, "session.begin")["session"]
    do(dk, "networks.create", name="n1")
    (entry,) = journal(sid)
    assert entry["inverse"] is None and entry["op"] == "networks.create"
    st = do(dk, "session.status")
    assert st["journal"] == [{"op": "networks.create", "undo": "none", "done": False}]
    assert st["summary"]["networks"]["added"] == 1
    out = do(dk, "session.rollback")
    assert [s["step"] for s in out["steps"]] == ["remove added network n1"] and "n1" not in world.networks


def test_secret_args_are_redacted_in_journal(world, dk):
    assert sess._redacted({"password": "p", "api_token": "t", "ref": "x"}) == {
        "password": "***", "api_token": "***", "ref": "x"}


def test_nothing_is_journaled_without_session_or_for_reads_and_previews(world, dk):
    world.add_container("web")
    do(dk, "containers.stop", ref="web")                              # no session: nothing to journal
    assert not (state.home("sessions") / "current").exists()
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.rm", ref="web", confirm=False)                 # preview only
    do(dk, "containers.stop", ref="web", dry_run=True)
    do(dk, "session.status")                                          # session ops are never journaled
    assert journal(sid) == [] and "web" in world.containers


# ================================================================================================
# session: lifecycle and edge cases
# ================================================================================================

def test_begin_twice_refuses_and_end_allows_a_new_one(world, dk):
    sid = do(dk, "session.begin", name="first", protect_data=True)["session"]
    with pytest.raises(ValueError, match="already active"):
        do(dk, "session.begin")
    assert do(dk, "session.end") == {"session": sid, "active": False}
    assert sess.current() is None
    meta = state.read_json(state.home("sessions", sid) / "session.json")
    assert meta["active"] is False and meta["protect_data"] is True and "ended" in meta
    sid2 = do(dk, "session.begin")["session"]
    assert sid2 != sid
    rows = do(dk, "session.list")
    assert {r["session"] for r in rows} == {sid, sid2} and [r["active"] for r in rows if r["session"] == sid] == [False]


def test_begin_after_stale_pointer_to_ended_session(world, dk):
    sid = do(dk, "session.begin")["session"]
    meta = state.read_json(state.home("sessions", sid) / "session.json")
    state.write_json(state.home("sessions", sid) / "session.json", {**meta, "active": False})
    assert do(dk, "session.begin")["session"] != sid                  # pointer exists but session inactive


@pytest.mark.parametrize("opname", ["session.status", "session.end", "session.rollback"])
def test_no_active_session(world, dk, opname):
    with pytest.raises(ValueError, match="no (active )?session"):
        do(dk, opname)


@pytest.mark.parametrize("argv", [("session", "status"), ("session", "rollback", "--yes")])
def test_no_session_cli_is_usage_error(world, cli, argv):
    code, _, err = cli(*argv)
    assert code == EXIT_USAGE and "session" in err


def test_empty_session_rollback_is_noop_and_status_by_id(world, dk):
    world.add_container("web")
    sid = do(dk, "session.begin")["session"]
    do(dk, "session.end")
    mark = len(world.d.seen)
    out = do(dk, "session.rollback", session=sid)                     # explicit id after end
    assert out == {"session": sid, "hosts": ["local"], "steps": [], "failed": [], "not_undoable": []}
    assert world.mutations(mark) == []
    st = do(dk, "session.status", session=sid)
    assert st["active"] is False and st["journal"] == []
    assert st["summary"]["containers"] == {"added": 0, "removed": 0, "changed": 0}


def test_session_list_skips_foreign_dirs(world, dk):
    (state.home("sessions") / "junk").mkdir()
    sid = do(dk, "session.begin")["session"]
    world.add_container("web")
    do(dk, "containers.stop", ref="web")
    (row,) = do(dk, "session.list")
    assert row["session"] == sid and row["changes"] == 1 and isinstance(row["began"], int)


def test_restore_db_capture_failure_and_protect_data(world, dk):
    world.add_container("app", image="myapp:1")
    world.d.on("POST", "/containers/app/exec", status=500, json={"message": "no exec"})
    sid = do(dk, "session.begin", protect_data=True)["session"]
    with pytest.raises((ValueError, APIError)):
        do(dk, "db.exec", ref="app", sql="delete from t")
    (entry,) = journal(sid)
    assert entry["inverse"]["kind"] == "capture-failed" and "app" in entry["inverse"]["error"]


def test_rollback_restore_db_step_replays_dump(world, dk, tmp_path):
    """A journaled restore-db inverse feeds the saved dump back into the database container."""
    world.add_container("pg", image="postgres:16")
    sid = do(dk, "session.begin")["session"]
    dump = tmp_path / "d.sql"
    dump.write_bytes(b"select 1;")
    state.append_jsonl(state.home("sessions", sid) / "journal.jsonl", {
        "id": "x", "op": "db.restore", "host": None, "done": False,
        "inverse": {"kind": "restore-db", "container": "pg", "database": None, "dump": str(dump)}})
    world.d.on("POST", "/containers/pg/exec", status=500, json={"message": "exec refused"})
    out = do(dk, "session.rollback")
    (s,) = out["steps"]
    assert s["step"] == "restore database in pg" and s["status"] == "failed" and "exec refused" in s["error"]


# ================================================================================================
# session: fleet hosts (per-host baseline files)
# ================================================================================================

@pytest.fixture
def remote(tmp_path_factory):
    import shutil
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="aisb-u-", dir="/tmp"))
    fake = FakeDaemon(d / "r.sock")
    fake.start()
    yield fake
    fake.stop()
    shutil.rmtree(d, ignore_errors=True)


def test_rollback_across_fleet_host_uses_its_own_baseline(world, dk, remote):
    rw = World(remote)
    rw.add_container("web")
    world.add_container("web")
    sid = do(dk, "session.begin")["session"]
    h = Host("r1", docker=f"unix://{remote.sock}")
    rdk = Docker(h.docker, timeout=5)
    with context.use(host=h):
        do(rdk, "containers.stop", ref="web")
        do(rdk, "containers.stop", ref="web")                         # baseline is captured only once
    rw.add_container("extra")
    base = state.read_json(state.home("sessions", sid) / "baseline-r1.json")
    assert base["host"]["name"] == "r1" and "web" in base["baseline"]["containers"]
    assert [e["host"] for e in journal(sid)] == ["r1", "r1"]
    assert sum(1 for s in remote.seen if s.path == "/containers/json") == 1

    plan = do(dk, "session.rollback", confirm=False)
    # newest first: the second stop's inverse (stop) then the first's (start): web ends up running
    assert [p["step"] for p in plan["planned"] if "step" in p] == [
        "[r1] remove added container extra", "[r1] stop web", "[r1] start web"]
    assert not rw.mutations(0)[2:]                                    # only the two stops so far
    out = do(dk, "session.rollback")
    assert out["hosts"] == ["local", "r1"] and out["failed"] == []
    assert rw.containers["web"]["running"] and "extra" not in rw.containers
    assert world.containers["web"]["running"]                         # local untouched
    assert world.mutations() == []


def test_rollback_reports_unreachable_host_and_missing_baseline(world, dk, remote):
    RemoteWorld = World(remote)
    RemoteWorld.add_container("web")
    sid = do(dk, "session.begin")["session"]
    h = Host("r1", docker=f"unix://{remote.sock}")
    with context.use(host=h):
        do(Docker(h.docker, timeout=5), "containers.stop", ref="web")
    # a second host whose baseline could not be captured
    remote.on("GET", "/containers/json", status=500, json={"message": "daemon sick"})
    h2 = Host("r2", docker=f"unix://{remote.sock}")
    with context.use(host=h2):
        do(Docker(h2.docker, timeout=5), "containers.stop", ref="web")
    b2 = state.read_json(state.home("sessions", sid) / "baseline-r2.json")
    assert b2["baseline"] is None and "daemon sick" in b2["error"]
    # r1 disappears before rollback
    rec = state.read_json(state.home("sessions", sid) / "baseline-r1.json")
    rec["host"]["docker"] = f"unix://{remote.sock}.gone"
    state.write_json(state.home("sessions", sid) / "baseline-r1.json", rec)
    out = do(dk, "session.rollback")
    failed = {f["step"]: f["error"] for f in out["failed"]}
    assert set(failed) == {"[r1] connect", "[r2] baseline"} and "daemon sick" in failed["[r2] baseline"]
    assert out["hosts"] == ["local", "r1", "r2"]


# ================================================================================================
# destroy ops need --yes; volumes only on request
# ================================================================================================

@pytest.mark.parametrize("argv", [
    ("containers", "rm", "web"),
    ("containers", "rm", "web", "--volumes"),
    ("volumes", "rm", "pg"),
    ("networks", "rm", "appnet"),
    ("images", "rmi", "nginx:1"),
    ("stack", "down", "st", "--volumes"),
])
def test_destroy_without_yes_sends_no_delete(world, cli, argv):
    world.add_container("web", anon={"/d": "a1"})
    world.add_container("st-a", labels={"aisb.stack": "st", "aisb.service": "a"})
    world.volumes["pg"] = {"files": {}, "labels": {}}
    world.volumes["st_v"] = {"files": {}, "labels": {"aisb.stack": "st"}}
    world.networks["appnet"] = {"Id": "a" * 64, "labels": {}}
    before = world.snapshot_keys()
    code, out, _ = cli(*argv)
    assert code == EXIT_CONFIRM and out["status"] == "confirmation_required"
    assert any(p["method"] == "DELETE" for p in out["planned"])
    assert world.d.calls("DELETE") == []
    assert world.snapshot_keys() == before


def test_containers_rm_volumes_flag_is_passed_only_when_asked(world, cli):
    world.add_container("a", anon={"/d": "va"})
    world.add_container("b", anon={"/d": "vb"})
    assert cli("containers", "rm", "a", "--force", "--yes")[0] == EXIT_OK
    assert cli("containers", "rm", "b", "--force", "--volumes", "--yes")[0] == EXIT_OK
    q = [s.query for s in world.d.seen if s.method == "DELETE"]
    assert [x["v"] for x in q] in (["0", "1"], ["false", "true"], ["False", "True"])
    assert "va" in world.volumes and "vb" not in world.volumes


@pytest.mark.parametrize(("status", "exc"), [(404, NotFound), (409, Conflict)])
def test_volume_and_network_rm_errors_propagate(world, dk, status, exc):
    world.volumes["v"] = {"files": {}, "labels": {}}
    world.networks["n"] = {"Id": "n" * 64, "labels": {}}
    world.fail[("DELETE", "/volumes/v")] = Reply(status, json={"message": "nope"})
    world.fail[("DELETE", "/networks/n")] = Reply(status, json={"message": "nope"})
    with pytest.raises(exc):
        dk.volumes.rm("v")
    with pytest.raises(exc):
        dk.networks.rm("n")
    assert "v" in world.volumes and "n" in world.networks


def test_cli_404_on_rm_is_docker_error_exit(world, cli):
    code, _, err = cli("volumes", "rm", "ghost", "--yes")
    assert code == EXIT_DOCKER and "no such volume" in err


# ================================================================================================
# volumes / networks / images APIs
# ================================================================================================

def test_volumes_list_filters_and_inspect(world, dk):
    world.volumes["a"] = {"files": {}, "labels": {"aisb.managed": "true"}}
    world.volumes["b"] = {"files": {}, "labels": {}}
    assert {v.name for v in dk.volumes.ls()} == {"a", "b"}
    assert [v.name for v in dk.volumes.ls(managed=True)] == ["a"]
    dk.volumes.ls(dangling=True, managed=True)
    assert world.d.seen[-1].filters() == {"dangling": ["true"], "label": ["aisb.managed=true"]}
    dk.volumes.ls(dangling=True)
    assert world.d.seen[-1].filters() == {"dangling": ["true"]}
    assert dk.volumes.inspect("a", fields="Name") == {"Name": "a"}
    v = dk.volumes.create("c", label={"team": "x"})
    assert v.name == "c" and world.volumes["c"]["labels"] == {"team": "x", "aisb.managed": "true"}


def test_volume_backup_roundtrip_plain_tar_and_missing(world, dk, tmp_path):
    world.volumes["v"] = {"files": {"k": b"val"}, "labels": {}}
    out = dk.volumes.backup("v", str(tmp_path / "v.tar"))
    assert out["written"].endswith("v.tar") and out["tar_bytes"] == out["file_bytes"] > 0
    assert _tar_files((tmp_path / "v.tar").read_bytes(), "v/") == {"k": b"val"}
    with pytest.raises(NotFound):
        dk.volumes.backup("missing", str(tmp_path / "m.tar"))
    assert not (tmp_path / "m.tar").exists()
    assert not any(c["labels"].get("aisb.helper") for c in world.containers.values())


def test_volume_backup_dry_run_writes_nothing(world, dk, tmp_path):
    world.volumes["v"] = {"files": {"k": b"val"}, "labels": {}}
    out = do(dk, "volumes.backup", ref="v", out=str(tmp_path / "v.tgz"), dry_run=True)
    assert out["status"] == "dry-run" and not (tmp_path / "v.tgz").exists()
    assert world.mutations() == []


def test_volume_backup_stream_failure_removes_partial_file(world, dk, tmp_path):
    world.volumes["v"] = {"files": {}, "labels": {}}
    world.d.on("GET", r"/containers/[^/]+/archive",  # a chunked body cut off before its last chunk
               Reply(body=b"5\r\nhello\r\n", content_type="application/x-tar",
                     headers={"Transfer-Encoding": "chunked"}))
    target = tmp_path / "v.tar"
    with pytest.raises(Exception):  # noqa: B017 - a truncated stream (http.client.IncompleteRead)
        dk.volumes.backup("v", str(target))
    assert not target.exists()
    assert not any(c["labels"].get("aisb.helper") for c in world.containers.values())  # helper still removed


def test_volume_restore_unrooted_tar_and_clear_failure_cleans_helper(world, dk, tmp_path):
    f = tmp_path / "flat.tar"
    f.write_bytes(tar_of({"a": b"1", "sub/b": b"2"}))
    out = dk.volumes.restore("v", str(f))
    assert out == {"volume": "v", "restored_entries": 2, "cleared": False}
    assert world.volumes["v"]["files"] == {"a": b"1", "sub/b": b"2"}
    put = next(s for s in world.d.seen if s.method == "PUT")
    assert put.query["path"] == "/v"
    world.d.on("POST", r"/containers/[^/]+/wait", status=500, json={"message": "wait broke"})
    with pytest.raises(APIError):
        dk.volumes.restore("v", str(f), clear=True)
    assert not any(c["labels"].get("aisb.helper") for c in world.containers.values())


def test_networks_api(world, dk):
    world.networks["bridge"] = {"Id": "b" * 64, "labels": {}}
    out = dk.networks.create("app", internal=True, label={"x": "y"})
    assert out["name"] == "app" and len(out["id"]) == 12
    body = next(s for s in world.d.seen if s.path == "/networks/create").body
    assert body["Internal"] is True and body["Labels"] == {"x": "y", "aisb.managed": "true"}
    assert {n.name for n in dk.networks.ls()} == {"bridge", "app"}
    world.add_container("web")
    dk.networks.connect("app", "web", alias=["w"])
    assert world.containers["web"]["networks"]["app"] == ["w"]
    assert dk.networks.inspect("app", fields="Name") == {"Name": "app"}
    world.d.on("POST", r"/networks/[^/]+/disconnect", status=200)
    assert dk.networks.disconnect("app", "web", force=True)["connected"] is False
    assert world.d.seen[-1].body == {"Container": "web", "Force": True}
    nid = world.networks["app"]["Id"]
    assert dk.networks.rm(nid) == {"removed": nid}                    # by id as well as by name
    assert "app" not in world.networks


@pytest.mark.parametrize(("ref", "expected"), [
    ("app", ("app", "latest")), ("app:1.2", ("app", "1.2")), ("host:5000/app", ("host:5000/app", "latest")),
    ("host:5000/app:v1", ("host:5000/app", "v1")), ("app@sha256:abc", ("app", "sha256:abc")),
])
def test_split_tag(ref, expected):
    assert split_tag(ref) == expected


def test_images_list_inspect_history_tag_rmi(daemon, dk):
    daemon.on("GET", "/images/json", json=[{"Id": "sha256:" + "a" * 64, "RepoTags": ["x:1"], "Size": 5, "Created": 1}])
    daemon.on("GET", "/images/x:1/json", json={"Id": "sha256:1", "Size": 9, "Config": {"Env": ["A=1"]}})
    daemon.on("GET", "/images/x:1/history", json=[{"CreatedBy": "RUN a", "Size": 3, "Created": 7}, {}])
    daemon.on("POST", "/images/x:1/tag", status=201)
    daemon.on("DELETE", "/images/x:1", json=[{"Untagged": "x:1"}])
    assert [i.id for i in dk.images.ls(all=True, dangling=True)]
    assert daemon.seen[-1].filters() == {"dangling": ["true"]} and daemon.seen[-1].query["all"] in ("1", "true", "True")
    dk.images.ls()
    assert "filters" not in daemon.seen[-1].query
    assert dk.images.inspect("x:1", fields="Size") == {"Size": 9}
    assert dk.images.history("x:1") == [{"created_by": "RUN a", "size": 3, "created": 7},
                                        {"created_by": "", "size": 0, "created": 0}]
    assert dk.images.tag("x:1", "reg:5000/y") == {"source": "x:1", "target": "reg:5000/y:latest"}
    assert daemon.seen[-1].query == {"repo": "reg:5000/y", "tag": "latest"}
    assert dk.images.rmi("x:1", force=True) == [{"Untagged": "x:1"}]
    assert daemon.seen[-1].query["force"] in ("1", "true", "True")


@pytest.mark.parametrize("status", [404, 409])
def test_images_rmi_errors(daemon, dk, status):
    daemon.on("DELETE", "/images/x:1", status=status, json={"message": "conflict: image is being used"})
    with pytest.raises((NotFound, Conflict)):
        dk.images.rmi("x:1")


def test_images_secrets_and_slim(daemon, dk):
    daemon.on("GET", "/images/x/json", json={"Size": 1000, "Config": {"Env": ["AWS_SECRET_ACCESS_KEY=abcdEFGH1234abcdEFGH1234abcdEFGH1234abcd"]}})
    daemon.on("GET", "/images/x/history", json=[{"CreatedBy": "RUN apt-get update", "Size": 900}])
    sec = dk.images.secrets("x")
    assert sec["count"] >= 1 and sec["note"]
    daemon.on("GET", "/images/y/json", json={"Config": {}})
    daemon.on("GET", "/images/y/history", json=[])
    assert dk.images.secrets("y") == {"image": "y", "count": 0, "findings": [], "note": None}
    assert dk.images.slim("x")["image"] == "x"


@pytest.mark.parametrize(("ref", "query", "shown"), [
    ("alpine", {"fromImage": "alpine", "tag": "latest"}, "alpine:latest"),
    ("alpine@sha256:ff", {"fromImage": "alpine", "tag": "sha256:ff"}, "alpine@sha256:ff"),
])
def test_images_pull(daemon, dk, ref, query, shown):
    daemon.on("POST", "/images/create", Reply(chunks=[
        b'{"status":"Pulling from library/alpine","id":"latest"}\n', b'{"status":"Digest: sha256:ff"}\n',
        b'{"status":"Downloaded newer image"}\n']))
    out = dk.images.pull(ref)
    assert out == {"image": shown, "messages": ["Digest: sha256:ff", "Downloaded newer image"]}
    assert daemon.seen[-1].query == query


def test_images_pull_error_in_stream(daemon, dk):
    daemon.on("POST", "/images/create", Reply(chunks=[b'{"error":"manifest unknown"}\n']))
    with pytest.raises(APIError, match="manifest unknown"):
        dk.images.pull("nope:1")


def test_images_build_ok_and_failure_keeps_log_tail(daemon, dk, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    daemon.on("POST", "/build", Reply(chunks=[b'{"stream":"Step 1/1 : FROM scratch\\n"}\n',
                                               b'{"aux":{"ID":"sha256:beef"}}\n']))
    out = dk.images.build(str(tmp_path), tag="t:1", build_arg={"A": "1"}, no_cache=True)
    assert out["id"] == "sha256:beef" and "Step 1/1" in out["output"]
    seen = daemon.seen[-1]
    assert seen.query["t"] == "t:1" and json.loads(seen.query["buildargs"]) == {"A": "1"}
    assert json.loads(seen.query["labels"]) == {"aisb.managed": "true"}
    names = tarfile.open(fileobj=io.BytesIO(seen.body)).getnames()
    assert "Dockerfile" in names
    daemon.on("POST", "/build", Reply(chunks=[b'{"stream":"Step 1/2 : RUN false\\n"}\n',
                                               b'{"error":"The command returned a non-zero code: 1"}\n']))
    with pytest.raises(APIError, match=r"(?s)non-zero code.*build log tail.*RUN false"):
        dk.images.build(str(tmp_path))


def test_build_is_mutate_and_dry_run_sends_nothing(daemon, dk, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    out = do(dk, "images.build", path=str(tmp_path), dry_run=True)
    assert out["status"] == "dry-run" and [p["method"] for p in out["planned"]] == ["POST"]
    assert daemon.calls("POST") == []


def test_images_envcheck(daemon, dk, tmp_path):
    daemon.on("GET", "/images/app/json", json={"Config": {"Env": ["PATH=/bin"], "Entrypoint": None, "Cmd": ["run"]}})
    daemon.on("POST", "/containers/create", status=201, json={"Id": "h" * 64})
    daemon.on("DELETE", "/containers/h+", status=204)
    daemon.on("GET", "/containers/h+/archive", Reply(body=tar_of({}), content_type="application/x-tar"))
    env = tmp_path / ".env"
    env.write_text("# comment\nexport DB_URL=x\nNOEQUALS\n")
    out = dk.images.envcheck("app", env=["MODE=dev"], env_file=str(env))
    assert out["image"] == "app" and "files_scanned" in out
    assert ("DELETE", f"/containers/{'h' * 64}") in daemon.calls()
    assert dk.images.envcheck("app")["image"] == "app"


# ================================================================================================
# state
# ================================================================================================

def test_state_home_permissions_and_atomic_write(tmp_path):
    p = state.home("a", "b")
    assert p.is_dir() and (p.stat().st_mode & 0o777) == 0o700
    f = state.write_json(p / "x.json", {"k": [1], "when": Path("/")})
    assert (f.stat().st_mode & 0o777) == 0o600 and state.read_json(f) == {"k": [1], "when": "/"}
    assert state.read_json(p / "missing.json", default={"d": 1}) == {"d": 1}
    assert list(p.iterdir()) == [f]


def test_state_write_json_failure_leaves_no_temp_file_and_keeps_old(tmp_path):
    p = state.home("w")
    good = state.write_json(p / "s.json", {"v": 1})

    class Boom:
        def __repr__(self) -> str:
            raise RuntimeError("unserializable")

    with pytest.raises(RuntimeError):
        state.write_json(good, {"v": Boom()})
    assert state.read_json(good) == {"v": 1} and [x.name for x in p.iterdir()] == ["s.json"]


def test_state_jsonl_roundtrip_skips_blank_lines():
    p = state.home("j") / "log.jsonl"
    assert list(state.read_jsonl(p)) == []
    state.append_jsonl(p, {"a": 1})
    with open(p, "a") as fh:
        fh.write("\n   \n")
    state.append_jsonl(p, {"b": Path("/x")})
    assert list(state.read_jsonl(p)) == [{"a": 1}, {"b": "/x"}]
    assert (p.stat().st_mode & 0o777) == 0o600


def test_state_home_default_is_user_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("AISB_HOME")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert state.home() == tmp_path / ".aisb"


def test_protect_data_dumps_db_before_exec_and_rollback_replays_it(world, dk):
    world.add_container("pg", image="postgres:16")
    execs = world.d.execs("pg", [(b"-- dump of app\n", b"", 0), (b"DELETE 3\n", b"", 0)] + [(b"", b"", 0)] * 4)
    sid = do(dk, "session.begin", protect_data=True)["session"]
    do(dk, "db.exec", ref="pg", sql="delete from t")
    (entry,) = journal(sid)
    inv = entry["inverse"]
    assert inv["kind"] == "restore-db" and inv["container"] == "pg"
    assert Path(inv["dump"]).read_bytes() == b"-- dump of app\n"
    assert execs[0].body["Cmd"][0] == "pg_dump" and "--clean" in execs[0].body["Cmd"]
    out = do(dk, "session.rollback")
    assert out["steps"] == [{"step": "restore database in pg", "status": "done"}]
    assert [e.body["Cmd"][0] for e in execs[2:]] == ["psql", "rm"]      # the dump fed back, then cleaned up
    assert world.containers["pg"]["uploads"]


def test_session_created_then_removed_container_is_not_resurrected(world, dk):
    world.add_container("keep")
    do(dk, "session.begin")
    world.add_container("tmp")                                        # created during the session...
    do(dk, "containers.rm", ref="tmp", force=True)                    # ...and removed again
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and set(world.containers) == {"keep"}  # the baseline never had it


def test_session_created_removed_and_recreated_container_is_removed(world, dk):
    do(dk, "session.begin")
    world.add_container("tmp")
    do(dk, "containers.rm", ref="tmp", force=True)
    world.add_container("tmp")                                        # and created once more
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and world.containers == {}


def test_session_created_then_removed_volume_is_not_resurrected(world, dk):
    do(dk, "session.begin")
    world.volumes["scratch"] = {"files": {"x": b"1"}, "labels": {}}
    do(dk, "volumes.rm", ref="scratch")
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and world.volumes == {}


def test_rollback_recreates_removed_volumes_with_their_labels_and_options(world, dk):
    world.volumes["pg"] = {"files": {"base/1": b"page"}, "labels": {"com.docker.compose.project": "shop"},
                           "options": {"type": "tmpfs"}}
    world.add_container("db", anon={"/data": "anon1"})
    world.volumes["anon1"]["labels"] = {"tier": "db"}
    do(dk, "session.begin")
    do(dk, "volumes.rm", ref="pg")
    do(dk, "containers.rm", ref="db", force=True, volumes=True)
    out = do(dk, "session.rollback")
    assert out["failed"] == []
    assert world.volumes["pg"]["labels"] == {"com.docker.compose.project": "shop"}   # not a bare auto-created one
    assert world.volumes["anon1"]["labels"] == {"tier": "db"}
    created = [s.body for s in world.d.seen if s.path == "/volumes/create"]
    assert {"Name": "pg", "Driver": "local", "DriverOpts": {"type": "tmpfs"},
            "Labels": {"com.docker.compose.project": "shop"}} in created
    assert world.volumes["pg"]["files"] == {"base/1": b"page"}


def test_rollback_skips_start_stop_of_containers_created_in_the_session(world, dk):
    world.add_container("keep", running=True)
    sid = do(dk, "session.begin")["session"]
    world.add_container("tmp", running=True)                          # created during the session
    do(dk, "containers.stop", ref="tmp")
    do(dk, "containers.stop", ref="keep")
    assert [e["inverse"]["container"] for e in journal(sid)] == ["tmp", "keep"]
    out = do(dk, "session.rollback")
    assert out["failed"] == []                                        # no spurious 404 for the removed "tmp"
    steps = [s["step"] for s in out["steps"]]
    assert "start keep" in steps and "start tmp" not in steps and "remove added container tmp" in steps
    assert "tmp" not in world.containers and world.containers["keep"]["running"] is True


def test_old_journals_without_container_names_still_roll_back(world, dk):
    world.add_container("keep", running=True)
    sid = do(dk, "session.begin")["session"]
    do(dk, "containers.stop", ref="keep")
    path = state.home("sessions", sid) / "journal.jsonl"
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    for e in entries:
        e["inverse"].pop("container")                                 # the shape older versions wrote
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))
    out = do(dk, "session.rollback")
    assert out["failed"] == [] and world.containers["keep"]["running"] is True

