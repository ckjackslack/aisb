"""Undo for Docker: a session journals how to reverse each destructive change before it happens."""

import json
import time
import uuid
from pathlib import Path
from typing import Annotated, Any

from .. import state
from ..errors import DockerError, NotFound
from ..insights import snapshot as snap
from ..models import RunSpec
from ..ops import HOOKS, HasResources, Op, Resource, Tier, op
from ..transport import SECRET_KEY
from ..util import q
from .containers import Containers, runspec_of

SKIP = {"session", "capsule"}  # resources whose ops are never journaled


def _dir(sid: str) -> Path:
    return state.home("sessions", sid)


def current() -> str | None:
    pointer = state.home("sessions") / "current"
    return pointer.read_text().strip() if pointer.exists() else None


def _redacted(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {k: ("***" if SECRET_KEY.search(k) else v) for k, v in kwargs.items()}


def _backup_volume(client: HasResources, name: str, into: Path) -> str:
    out = into / f"volume-{name}-{uuid.uuid4().hex[:6]}.tar.gz"
    client.resource("volumes").backup(name, str(out))  # type: ignore[attr-defined]
    return str(out)


def _container_state(client: HasResources, ref: str, artifacts: Path, *, volumes: bool) -> dict[str, Any]:
    info = client.transport.json("GET", f"/containers/{q(ref)}/json")
    inv: dict[str, Any] = {"kind": "recreate-container", "name": (info.get("Name") or ref).lstrip("/"),
                           "spec": runspec_of(info), "image_id": info.get("Image"),
                           "running": bool((info.get("State") or {}).get("Running")),
                           "networks": {n: ep.get("Aliases") or [] for n, ep in
                                        ((info.get("NetworkSettings") or {}).get("Networks") or {}).items()}}
    if volumes:  # `rm --volumes` deletes anonymous volumes: keep their contents
        inv["volumes"] = [{"name": m["Name"], "destination": m["Destination"],
                           "backup": _backup_volume(client, m["Name"], artifacts)}
                          for m in info.get("Mounts") or [] if m.get("Type") == "volume" and m.get("Name")]
    return inv


def capture(client: HasResources, o: Op, kwargs: Any) -> None:
    """ops.HOOKS entry: before a real mutate/destroy op, record how to undo it in the active session."""
    sid = current()
    if not sid or o.resource in SKIP:
        return
    d = _dir(sid)
    session = state.read_json(d / "session.json") or {}
    artifacts = state.home("sessions", sid, "artifacts")
    entry: dict[str, Any] = {"id": uuid.uuid4().hex[:8], "at": time.time(), "op": o.qualname,
                             "tier": str(o.tier), "args": _redacted(dict(kwargs)), "inverse": None, "done": False}
    try:
        if o.qualname == "containers.rm":
            entry["inverse"] = _container_state(client, kwargs["ref"], artifacts, volumes=bool(kwargs.get("volumes")))
        elif o.qualname in ("volumes.rm", "volumes.restore"):
            try:
                client.transport.json("GET", f"/volumes/{q(kwargs['ref'])}")
                entry["inverse"] = {"kind": "restore-volume", "name": kwargs["ref"],
                                    "backup": _backup_volume(client, kwargs["ref"], artifacts)}
            except NotFound:
                entry["inverse"] = {"kind": "remove-volume", "name": kwargs["ref"]}
        elif o.qualname == "db.restore" or (o.qualname == "db.exec" and session.get("protect_data")):
            from .services import SQL, adapter
            db = adapter(client.resource("db"), kwargs["ref"], SQL)
            out = artifacts / f"db-{kwargs['ref']}-{entry['id']}.sql"
            buf = bytearray()
            db.dump(buf.extend, database=kwargs.get("database"), clean=True)
            out.write_bytes(bytes(buf))
            entry["inverse"] = {"kind": "restore-db", "container": kwargs["ref"], "database": kwargs.get("database"),
                                "dump": str(out)}
        elif o.qualname == "stack.down":
            rows = client.resource("stack")._containers(client.resource("stack")._name(kwargs["stack"])[0])  # type: ignore[attr-defined]
            entry["inverse"] = {"kind": "group", "steps": [
                _container_state(client, r["Id"], artifacts, volumes=False) for r in rows]}
        elif o.qualname in ("containers.stop", "containers.start", "containers.restart"):
            info = client.transport.json("GET", f"/containers/{q(kwargs['ref'])}/json")
            entry["inverse"] = {"kind": "set-running", "name": kwargs["ref"],
                                "running": bool((info.get("State") or {}).get("Running"))}
        elif o.qualname in ("system.prune", "images.rmi"):
            entry["inverse"] = {"kind": "not-undoable", "reason": f"{o.qualname} cannot be reversed "
                                "(images can be pulled again; pruned objects are gone)"}
    except (DockerError, ValueError, KeyError, OSError) as e:
        entry["inverse"] = {"kind": "capture-failed", "error": str(e)}
    state.append_jsonl(d / "journal.jsonl", entry)


HOOKS.append(capture)


class Session(Resource, name="session"):
    @op(Tier.READ)
    def begin(self, *, name: Annotated[str | None, "label"] = None,
              protect_data: Annotated[bool, "also dump the DB before every `db exec` (slower, safer)"] = False,
              ) -> dict[str, Any]:
        """Start an undoable session: baseline snapshot now; every destructive change after this is journaled with
        its inverse (container specs, volume and DB backups) so `session rollback` can restore the baseline."""
        if (sid := current()) and (state.read_json(_dir(sid) / "session.json") or {}).get("active"):
            raise ValueError(f"session {sid} is already active (session end, or session rollback)")
        from .system import System
        sid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
        state.write_json(_dir(sid) / "session.json", {"id": sid, "name": name, "began": time.time(), "active": True,
                                                      "protect_data": protect_data,
                                                      "baseline": System(self.t).snapshot()})
        (state.home("sessions") / "current").write_text(sid)
        return {"session": sid, "active": True, "protect_data": protect_data,
                "note": "destroy ops still need --yes; the session only makes them undoable"}

    @op(Tier.READ)
    def status(self, *, session: Annotated[str | None, "session id (default: current)"] = None) -> dict[str, Any]:
        """What changed since the session began, and which changes can be undone."""
        from .system import System
        sid = session or current()
        if not sid:
            raise ValueError("no session (session begin)")
        meta = state.read_json(_dir(sid) / "session.json")
        journal = list(state.read_jsonl(_dir(sid) / "journal.jsonl"))
        diff = snap.compare(meta["baseline"], System(self.t).snapshot())
        return {"session": sid, "active": meta.get("active"), "summary": diff["summary"],
                "journal": [{"op": e["op"], "undo": (e.get("inverse") or {}).get("kind", "none"), "done": e["done"]}
                            for e in journal],
                "not_undoable": [e["op"] for e in journal if (e.get("inverse") or {}).get("kind") in
                                 ("not-undoable", "capture-failed")]}

    @op(Tier.READ, name="list")
    def ls(self) -> list[dict[str, Any]]:
        """Sessions on this machine, newest first."""
        out = []
        for d in sorted(state.home("sessions").iterdir(), reverse=True):
            if (meta := state.read_json(d / "session.json")) is not None:
                out.append({"session": meta["id"], "name": meta.get("name"), "active": meta.get("active"),
                            "began": int(meta["began"]), "changes": sum(1 for _ in state.read_jsonl(d / "journal.jsonl"))})
        return out

    @op(Tier.READ)
    def end(self) -> dict[str, Any]:
        """Stop journaling (artifacts are kept until you delete $AISB_HOME/sessions/ID)."""
        sid = current()
        if not sid:
            raise ValueError("no active session")
        meta = state.read_json(_dir(sid) / "session.json")
        state.write_json(_dir(sid) / "session.json", {**meta, "active": False, "ended": time.time()})
        (state.home("sessions") / "current").unlink(missing_ok=True)
        return {"session": sid, "active": False}

    @op(Tier.DESTROY)
    def rollback(self, *, session: Annotated[str | None, "session id (default: current)"] = None) -> dict[str, Any]:
        """Return to the session baseline: remove what was added, then replay journaled inverses newest-first
        (recreate removed containers, restore volumes and databases, restore run states). Idempotent."""
        from .system import System
        sid = session or current()
        if not sid:
            raise ValueError("no session to roll back")
        d = _dir(sid)
        meta = state.read_json(d / "session.json")
        journal = list(state.read_jsonl(d / "journal.jsonl"))
        diff = snap.compare(meta["baseline"], System(self.t).snapshot())
        steps: list[dict[str, Any]] = []

        def step(desc: str, fn: Any) -> None:
            if self.t.planning:
                self.t.note(step=desc)
                steps.append({"step": desc, "status": "planned"})
                return
            try:
                fn()
                steps.append({"step": desc, "status": "done"})
            except (DockerError, ValueError, OSError) as e:
                steps.append({"step": desc, "status": "failed", "error": str(e)})

        recreated = {s["name"] for e in journal if not e["done"] and e.get("inverse")
                     for s in ([e["inverse"]] + e["inverse"].get("steps", [])) if s.get("kind") == "recreate-container"}
        for name in diff["containers"]["added"]:
            if name not in recreated:
                step(f"remove added container {name}",
                     lambda n=name: self.t.json("DELETE", f"/containers/{q(n)}", query={"force": True, "v": True}))
        ctr = Containers(self.t)
        for e in reversed(journal):
            if e["done"] or not e.get("inverse"):
                continue
            for inv in [e["inverse"]] + e["inverse"].get("steps", []):
                self._undo(inv, ctr, step)
            if not self.t.planning:
                e["done"] = True
        for name in diff["volumes"]["added"]:
            step(f"remove added volume {name}", lambda n=name: self.t.json("DELETE", f"/volumes/{q(n)}"))
        for name in diff["networks"]["added"]:
            step(f"remove added network {name}", lambda n=name: self.t.json("DELETE", f"/networks/{q(n)}"))
        if not self.t.planning:
            (d / "journal.jsonl").write_text("".join(json.dumps(e) + "\n" for e in journal))
        return {"session": sid, "steps": steps, "failed": [s for s in steps if s["status"] == "failed"],
                "not_undoable": [e["op"] for e in journal if (e.get("inverse") or {}).get("kind") in
                                 ("not-undoable", "capture-failed")]}

    def _undo(self, inv: dict[str, Any], ctr: Containers, step: Any) -> None:
        kind = inv.get("kind")
        if kind == "recreate-container":
            def recreate() -> None:
                try:
                    self.t.json("GET", f"/containers/{q(inv['name'])}/json")
                    return  # already back
                except NotFound:
                    pass
                spec = RunSpec.from_dict({**inv["spec"], "image": inv["image_id"] or inv["spec"]["image"]})
                nets = list(inv.get("networks") or {})
                primary = next((n for n in nets if n not in ("bridge", "host", "none")), None)
                spec = spec.merge(network=primary, aliases=tuple(a for a in inv["networks"].get(primary, [])
                                                                   if len(a) != 12)) if primary else spec
                for v in inv.get("volumes") or []:
                    self.resource_volumes().restore(v["name"], v["backup"])
                cid = ctr.create_from(spec, pull=False)
                for n in nets:
                    if n not in (primary, "bridge", "host", "none"):
                        self.t.json("POST", f"/networks/{q(n)}/connect", body={"Container": cid})
                if inv.get("running"):
                    self.t.json("POST", f"/containers/{cid}/start")
            step(f"recreate container {inv['name']}", recreate)
        elif kind == "restore-volume":
            step(f"restore volume {inv['name']}", lambda: self.resource_volumes().restore(inv["name"], inv["backup"],
                                                                                        clear=True))
        elif kind == "remove-volume":
            step(f"remove volume {inv['name']} (it didn't exist before)",
                 lambda: self.t.json("DELETE", f"/volumes/{q(inv['name'])}"))
        elif kind == "restore-db":
            def restore_db() -> None:
                from .services import SQL, adapter
                adapter(self, inv["container"], SQL).script(Path(inv["dump"]).read_bytes(), database=inv.get("database"))
            step(f"restore database in {inv['container']}", restore_db)
        elif kind == "set-running":
            step(f"{'start' if inv['running'] else 'stop'} {inv['name']}",
                 lambda: self.t.json("POST", f"/containers/{q(inv['name'])}/{'start' if inv['running'] else 'stop'}"))

    def resource_volumes(self) -> Any:
        from .volumes import Volumes
        return Volumes(self.t)
