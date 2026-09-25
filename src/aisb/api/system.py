from typing import Annotated, Any

from ..ops import Resource, Tier, op
from ..streams import iter_jsonl
from ..util import MANAGED, filters, project, to_unix

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
