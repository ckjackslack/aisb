"""Bring a stack of services up in dependency order, gated on real readiness; tear it down by label."""

from pathlib import Path
from typing import Annotated, Any

from .. import stack as stk
from ..errors import NotFound
from ..ops import Resource, Tier, op
from ..util import q
from .containers import Containers

StackRef = Annotated[str, "stack JSON file (or, for down/ps, a stack name)"]


class StackOps(Resource, name="stack"):
    def _name(self, ref: str) -> tuple[str, stk.Stack | None]:
        if Path(ref).expanduser().is_file():
            s = stk.load(ref)
            return s.name, s
        return ref, None

    def _containers(self, name: str) -> list[dict[str, Any]]:
        rows = self.t.json("GET", "/containers/json", query={"all": True, "filters": {"label": [f"{stk.STACK_KEY}={name}"]}})
        return rows or []

    def _exists(self, path: str) -> dict[str, Any] | None:
        try:
            return self.t.json("GET", path)
        except NotFound:
            return None

    def _ready(self, svc: stk.Service, within: float) -> dict[str, Any]:
        from .services import Svc
        ctr, name, rule = Containers(self.t), svc.container, svc.ready
        if rule == "probe":
            try:
                return {"via": "probe", **Svc(self.t).ready(name, within=within, stable=1.0)}
            except ValueError:  # no adapter probe for this image (a custom app): running is the best signal
                rule = "running"
        if isinstance(rule, dict):
            return ctr.wait_for(name, log=rule.get("log"), port=rule.get("port"), within=within, interval=0.5)
        return ctr.wait_for(name, running=rule == "running", healthy=rule == "healthy", within=within, interval=0.5)

    @op(Tier.MUTATE)
    def up(self, file: Annotated[str, "stack JSON file"], *,
           within: Annotated[float, "readiness timeout per service (seconds)"] = 120.0,
           no_wait: Annotated[bool, "don't gate on readiness"] = False) -> dict[str, Any]:
        """Create network and volumes, then start services in dependency order, each gated on real readiness."""
        s = stk.load(file)
        ctr = Containers(self.t)
        labels = {stk.STACK_KEY: s.name, "aisb.managed": "true"}
        if not self._exists(f"/networks/{q(s.network)}"):
            self.t.json("POST", "/networks/create", body={"Name": s.network, "Driver": "bridge", "Labels": labels})
        for vol in s.volumes:
            if not self._exists(f"/volumes/{q(vol)}"):
                self.t.json("POST", "/volumes/create", body={"Name": vol, "Labels": labels})
        results = []
        for name in s.order:
            svc = s.services[name]
            info = self._exists(f"/containers/{q(svc.container)}/json")
            entry: dict[str, Any] = {"service": name, "container": svc.container}
            if info is None:
                ctr.create_from(svc.spec)
                self.t.json("POST", f"/containers/{q(svc.container)}/start")
                entry["action"] = "created"
            elif (info.get("Config", {}).get("Labels") or {}).get(stk.HASH_KEY) != svc.digest:
                entry["action"] = "drift"
                entry["hint"] = (f"config changed since it was created; recreate with "
                                 f"`aisb stack down {file} --service {name} --dry-run`, then `stack up`")
            elif not (info.get("State") or {}).get("Running"):
                ctr.start(svc.container)
                entry["action"] = "started"
            else:
                entry["action"] = "unchanged"
            if not no_wait and not self.t.planning and entry["action"] != "drift":
                entry["ready"] = r = self._ready(svc, within)
                if not r.get("ok"):
                    results.append(entry)
                    return {"ok": False, "stack": s.name, "reason": f"{name} did not become ready",
                            "services": results, "not_started": list(s.order[s.order.index(name) + 1:]),
                            "next": [f"aisb containers doctor {svc.container}"]}
            results.append(entry)
        return {"ok": True, "stack": s.name, "network": s.network, "services": results}

    @op(Tier.DESTROY)
    def down(self, stack: StackRef, *, service: Annotated[list[str] | None, "only these services"] = None,
             volumes: Annotated[bool, "also delete the stack's declared volumes (data loss)"] = False) -> dict[str, Any]:
        """Remove the stack's containers (and network; declared volumes only with --volumes)."""
        name, s = self._name(stack)
        rows = [r for r in self._containers(name)
                if not service or (r.get("Labels") or {}).get(stk.SERVICE_KEY) in service]
        removed = []
        for r in rows:
            self.t.json("DELETE", f"/containers/{r['Id']}", query={"force": True})
            removed.append((r.get("Names") or ["?"])[0].lstrip("/"))
        out: dict[str, Any] = {"stack": name, "removed_containers": removed}
        if not service:
            nets = self.t.json("GET", "/networks", query={"filters": {"label": [f"{stk.STACK_KEY}={name}"]}}) or []
            ours = {r["Id"] for r in rows}
            out["removed_networks"], out["kept_networks"] = [], []
            for n in nets:
                attached = (self.t.json("GET", f"/networks/{n['Id']}") or {}).get("Containers") or {}
                if foreign := sorted(c.get("Name", cid[:12]) for cid, c in attached.items() if cid not in ours):
                    out["kept_networks"].append({"network": n["Name"], "reason": "containers outside the stack are "
                                                 f"attached: {', '.join(foreign)} (disconnect them, then run down again)"})
                    continue
                self.t.json("DELETE", f"/networks/{n['Id']}")
                out["removed_networks"].append(n["Name"])
            if volumes:
                vols = (self.t.json("GET", "/volumes", query={"filters": {"label": [f"{stk.STACK_KEY}={name}"]}})
                        or {}).get("Volumes") or []
                for v in vols:
                    self.t.json("DELETE", f"/volumes/{q(v['Name'])}")
                out["removed_volumes"] = [v["Name"] for v in vols]
        return out

    @op(Tier.READ)
    def ps(self, stack: StackRef) -> dict[str, Any]:
        """Services of a stack: state, health, ports, and drift against the file (when a file is given)."""
        name, s = self._name(stack)
        rows = {(r.get("Labels") or {}).get(stk.SERVICE_KEY): r for r in self._containers(name)}
        services = []
        for svc in (s.order if s else sorted(k for k in rows if k)):
            r = rows.get(svc)
            entry: dict[str, Any] = {"service": svc, "state": r.get("State") if r else "missing",
                                     "status": r.get("Status") if r else None}
            if r:
                entry["ports"] = sorted({f"{p['PublicPort']}->{p['PrivatePort']}" for p in r.get("Ports") or []
                                         if p.get("PublicPort")})
            if s and r:
                entry["drift"] = (r.get("Labels") or {}).get(stk.HASH_KEY) != s.services[svc].digest
            services.append(entry)
        return {"stack": name, "services": services,
                "healthy": all(e["state"] == "running" and not e.get("drift") for e in services)}

