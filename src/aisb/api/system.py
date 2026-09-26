import time
from typing import Annotated, Any, Literal

from ..errors import NotFound

from .. import insights
from ..insights import snapshot as snap
from ..ops import Resource, Tier, op
from ..streams import iter_jsonl
from ..util import MANAGED, filters, project, q, to_unix

_EVENT_ATTRS = ("name", "image", "exitCode", "signal", "container")


def summarize_df(d: dict[str, Any]) -> dict[str, Any]:
    images = d.get("Images") or []
    containers = d.get("Containers") or []
    volumes = d.get("Volumes") or []
    cache = d.get("BuildCache") or []
    vsize = lambda v: max((v.get("UsageData") or {}).get("Size", 0), 0)  # noqa: E731
    return {
        "images": {"count": len(images), "active": sum(i.get("Containers", 0) > 0 for i in images),
                   "size": d.get("LayersSize", 0),
                   "reclaimable": sum(i.get("Size", 0) for i in images if i.get("Containers", 0) <= 0)},
        "containers": {"count": len(containers), "running": sum(c.get("State") == "running" for c in containers),
                       "size": sum(c.get("SizeRw", 0) for c in containers),
                       "reclaimable": sum(c.get("SizeRw", 0) for c in containers if c.get("State") != "running")},
        "volumes": {"count": len(volumes),
                    "active": sum((v.get("UsageData") or {}).get("RefCount", 0) > 0 for v in volumes),
                    "size": sum(vsize(v) for v in volumes),
                    "reclaimable": sum(vsize(v) for v in volumes if not (v.get("UsageData") or {}).get("RefCount"))},
        "build_cache": {"count": len(cache), "size": sum(c.get("Size", 0) for c in cache),
                        "reclaimable": sum(c.get("Size", 0) for c in cache if not c.get("InUse"))},
    }


def compact_event(e: dict[str, Any]) -> dict[str, Any]:
    actor = e.get("Actor") or {}
    attrs = actor.get("Attributes") or {}
    return {
        "time": e.get("time"), "type": e.get("Type"), "action": e.get("Action"),
        "id": (actor.get("ID") or "")[:12],
        **{k: attrs[k] for k in _EVENT_ATTRS if k in attrs},
    }


def _reclaimed(r: Any, key: str) -> dict[str, Any]:
    r = r or {}
    return {"deleted": len(r.get(key) or []), "space_reclaimed": r.get("SpaceReclaimed", 0)}


class System(Resource, name="system"):
    @op(Tier.READ)
    def ping(self) -> dict[str, Any]:
        """Check the daemon is reachable and report the negotiated API version."""
        return {"ok": True, "endpoint": self.t.endpoint.url, "api_version": self.t.version}

    @op(Tier.READ)
    def version(self) -> Any:
        """Daemon and API versions."""
        return self.t.json("GET", "/version")

    @op(Tier.READ)
    def info(self, *, fields: Annotated[str | None, "comma-separated dotted paths"] = None) -> Any:
        """System-wide information; narrow with --fields."""
        return project(self.t.json("GET", "/info"), fields)

    @op(Tier.READ)
    def df(self) -> dict[str, Any]:
        """Disk usage summary with reclaimable bytes per object type."""
        return summarize_df(self.t.json("GET", "/system/df", timeout=None))

    @op(Tier.READ)
    def events(self, *, since: Annotated[str, "unix ts, ISO time, or relative like 10m"] = "10m",
               until: Annotated[str, "end of window (bounded, never streams forever)"] = "now",
               filter: Annotated[list[str] | None, "KEY=VALUE, e.g. type=container, container=web, event=die"] = None,
               limit: Annotated[int, "max events returned"] = 200) -> list[dict[str, Any]]:
        """Daemon events in a bounded time window."""
        query = {"since": to_unix(since), "until": to_unix(until), "filters": filters(filter)}
        out: list[dict[str, Any]] = []
        for e in iter_jsonl(self.t.stream("GET", "/events", query=query)):
            out.append(compact_event(e))
            if len(out) >= limit:
                break
        return out

    @op(Tier.READ)
    def doctor(self, *, managed: Annotated[bool, "only containers created by aisb"] = False,
               tail: Annotated[int, "log lines scanned per container; 0 = skip logs (faster)"] = 200) -> dict[str, Any]:
        """Fleet triage across every container, worst first: state, config, image, and recent log signatures."""
        from .containers import Containers
        ctr = Containers(self.t)
        rows = self.t.json("GET", "/containers/json", query={"all": True, "filters": {"label": [MANAGED]} if managed else None})
        tags = {t: i["Id"] for i in self.t.json("GET", "/images/json") for t in i.get("RepoTags") or []}
        peers = ctr.names() if managed else frozenset(n.lstrip("/") for r in rows for n in r.get("Names") or [])
        reports = []
        for row in rows:
            info = self.t.json("GET", f"/containers/{row['Id']}/json")
            cfg = info.get("Config") or {}
            name = (info.get("Name") or row["Id"][:12]).lstrip("/")
            logs = tuple(ctr._text(row["Id"], tail=tail, tty=bool(cfg.get("Tty"))).splitlines()) if tail else ()
            reports.append(insights.diagnose(insights.Facts(name, info, logs=logs, image_id=tags.get(cfg.get("Image", "")),
                                                            peers=peers)))
        order = {"failing": 0, "degraded": 1, "healthy": 2}
        reports.sort(key=lambda r: (order[r["verdict"]], r["container"]))
        problems = [{"container": r["container"], "verdict": r["verdict"], "state": r["state"]["status"],
                     "likely_cause": r["likely_cause"],
                     "findings": [f"{f['severity']}:{f['code']}: {f['summary']}" for f in r["findings"]
                                  if f["severity"] != "info"]}
                    for r in reports if r["verdict"] != "healthy"]
        return {
            "scope": f"state, config, image{f', last {tail} log lines' if tail else ''}; no live stats",
            "summary": {v: sum(r["verdict"] == v for r in reports) for v in order},
            "problems": problems,
            "healthy": [r["container"] for r in reports if r["verdict"] == "healthy"],
            "next": [f"aisb containers doctor {p['container']}" for p in problems],
        }

    @op(Tier.READ)
    def audit(self, *, managed: Annotated[bool, "only containers created by aisb"] = False,
              container: Annotated[list[str] | None, "only these containers"] = None,
              min_severity: Annotated[Literal["info", "warning", "critical"], "hide findings below this"] = "warning",
              ) -> dict[str, Any]:
        """Security/config audit of containers: privileges, socket and host mounts, root user, exposed datastores,
        secrets in env, missing limits/healthchecks, unpinned images. Ranked with a 0-100 score per container."""
        from ..insights.audit import audit
        ids = container or [r["Id"] for r in self.t.json("GET", "/containers/json", query={
            "all": True, "filters": {"label": [MANAGED]} if managed else None}) or []]
        images: dict[str, Any] = {}
        order = ["info", "warning", "critical"]
        reports = []
        for cid in ids:
            info = self.t.json("GET", f"/containers/{q(cid)}/json")
            img = info.get("Image", "")
            if img not in images:
                try:
                    images[img] = self.t.json("GET", f"/images/{q(img)}/json")
                except NotFound:
                    images[img] = {}
            rep = audit(info, images[img])
            rep["findings"] = [f for f in rep["findings"] if order.index(f["severity"]) >= order.index(min_severity)]
            reports.append(rep)
        reports.sort(key=lambda r: (r["score"], r["container"]))
        codes: dict[str, int] = {}
        for r in reports:
            for f in r["findings"]:
                codes[f["code"]] = codes.get(f["code"], 0) + 1
        return {"containers": len(reports), "average_score": round(sum(r["score"] for r in reports) / len(reports))
                if reports else None, "most_common": dict(sorted(codes.items(), key=lambda kv: -kv[1])[:8]),
                "reports": reports}

    @op(Tier.READ)
    def watch(self, *, interval: Annotated[float, "seconds between checks"] = 30.0,
              duration: Annotated[float, "stop after N seconds"] = 300.0,
              until_change: Annotated[bool, "return as soon as anything changes"] = False,
              managed: Annotated[bool, "only containers created by aisb"] = False,
              tail: Annotated[int, "log lines scanned per container"] = 100) -> dict[str, Any]:
        """Re-run fleet triage and report only what changed: new problems, recoveries, verdict changes, arrivals."""
        def state() -> dict[str, tuple[str, tuple[str, ...], str]]:
            rep = self.doctor(managed=managed, tail=tail)
            rows = self.t.json("GET", "/containers/json", query={
                "all": True, "filters": {"label": [MANAGED]} if managed else None}) or []
            states = {(r.get("Names") or ["?"])[0].lstrip("/"): r.get("State", "") for r in rows}
            out = {c: ("healthy", (), states.get(c, "")) for c in rep["healthy"]}
            for p in rep["problems"]:
                out[p["container"]] = (p["verdict"], tuple(sorted(f.split(":")[1] for f in p["findings"])),
                                       states.get(p["container"], ""))
            return out
        begin = time.monotonic()
        prev, events, polls = state(), [], 1
        rank = {"healthy": 0, "degraded": 1, "failing": 2}
        while time.monotonic() - begin + interval <= duration:
            time.sleep(interval)
            cur, polls = state(), polls + 1
            now = int(time.time())
            for name in sorted(prev.keys() | cur.keys()):
                old, new = prev.get(name), cur.get(name)
                if old == new:
                    continue
                if old is None or new is None:
                    kind = "appeared" if old is None else "gone"
                else:
                    kind = "worse" if rank[new[0]] > rank[old[0]] else "better" if rank[new[0]] < rank[old[0]] \
                        else f"{old[2]} -> {new[2]}" if old[2] != new[2] else "findings-changed"
                events.append({"at": now, "container": name, "change": kind,
                               "from": old[0] if old else None, "to": new[0] if new else None,
                               "state": new[2] if new else None,
                               "new_findings": sorted(set(new[1]) - set(old[1] if old else ())) if new else [],
                               "resolved": sorted(set(old[1]) - set(new[1] if new else ())) if old else []})
            prev = cur
            if until_change and events:
                break
        worst = [n for n, (v, *_) in prev.items() if v == "failing"]
        return {"polls": polls, "seconds": round(time.monotonic() - begin, 1), "changes": events,
                "failing_now": worst, "next": [f"aisb containers doctor {n}" for n in worst]}

    @op(Tier.READ)
    def snapshot(self) -> dict[str, Any]:
        """Inventory of containers, images, volumes and networks; save it and diff later with `system changes`."""
        return snap.take(
            self.t.json("GET", "/containers/json", query={"all": True}),
            self.t.json("GET", "/images/json"),
            (self.t.json("GET", "/volumes") or {}).get("Volumes") or [],
            self.t.json("GET", "/networks"),
        )

    @op(Tier.READ)
    def changes(self, before: Annotated[str, "snapshot JSON file (from `system snapshot`)"],
                after: Annotated[str | None, "second snapshot file; default: live state now"] = None) -> dict[str, Any]:
        """What was added, removed, recreated or changed between two snapshots, with dry-run cleanup commands."""
        return snap.compare(snap.load(before), snap.load(after) if after else self.snapshot())

    @op(Tier.DESTROY)
    def prune(self, *, containers: Annotated[bool, "stopped containers"] = True,
              images: Annotated[bool, "dangling images"] = True,
              networks: Annotated[bool, "unused networks"] = True,
              volumes: Annotated[bool, "unused anonymous volumes (data loss!)"] = False,
              all_images: Annotated[bool, "all unused images, not just dangling"] = False,
              managed: Annotated[bool, "only objects labelled aisb.managed=true"] = False) -> dict[str, Any]:
        """Remove unused objects. Volumes are opt-in."""
        label = {"label": [MANAGED]} if managed else {}
        out: dict[str, Any] = {}
        if containers:
            out["containers"] = _reclaimed(self.t.json("POST", "/containers/prune", query={"filters": label or None}),
                                           "ContainersDeleted")
        if images:
            f = {"dangling": ["false" if all_images else "true"], **label}
            out["images"] = _reclaimed(self.t.json("POST", "/images/prune", query={"filters": f}, timeout=None),
                                       "ImagesDeleted")
        if networks:
            out["networks"] = _reclaimed(self.t.json("POST", "/networks/prune", query={"filters": label or None}),
                                         "NetworksDeleted")
        if volumes:
            # API >= 1.42 prunes only anonymous volumes unless all=true; aisb-managed named volumes count too.
            f = {**label, "all": ["true"]} if managed else None
            out["volumes"] = _reclaimed(self.t.json("POST", "/volumes/prune", query={"filters": f}),
                                        "VolumesDeleted")
        return out
