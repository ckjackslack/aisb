"""Point-in-time inventory of Docker objects and a structural diff between two of them."""

import json
import time
from pathlib import Path
from typing import Any

from ..util import MANAGED_KEY

VERSION = 1
KINDS = ("containers", "images", "volumes", "networks")


def take(containers: list[dict[str, Any]], images: list[dict[str, Any]],
         volumes: list[dict[str, Any]], networks: list[dict[str, Any]], *, now: float | None = None) -> dict[str, Any]:
    """Build a snapshot from raw list endpoints. Keyed by stable identity: container name, image id, volume and network name."""
    return {
        "aisb_snapshot": VERSION,
        "taken": int(time.time() if now is None else now),
        "containers": {
            (c.get("Names") or ["/" + c["Id"][:12]])[0].lstrip("/"): {
                "id": c["Id"][:12], "image": c.get("Image"), "image_id": (c.get("ImageID") or "")[7:19],
                "state": c.get("State"), "managed": (c.get("Labels") or {}).get(MANAGED_KEY) == "true",
            } for c in containers
        },
        "images": {i["Id"][7:19]: {"tags": sorted(t for t in i.get("RepoTags") or [] if t != "<none>:<none>"),
                                   "size": i.get("Size", 0)} for i in images},
        "volumes": {v["Name"]: {"driver": v.get("Driver"),
                                "managed": (v.get("Labels") or {}).get(MANAGED_KEY) == "true"} for v in volumes},
        "networks": {n["Name"]: {"id": n["Id"][:12], "driver": n.get("Driver")} for n in networks},
    }


def load(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).expanduser().read_text())
    if data.get("aisb_snapshot") != VERSION:
        raise ValueError(f"{path} is not an aisb snapshot (expected aisb_snapshot={VERSION})")
    return data


_CLEANUP = {
    "containers": "aisb containers rm {key} --force --dry-run",
    "images": "aisb images rmi {key} --dry-run",
    "volumes": "aisb volumes rm {key} --dry-run",
    "networks": "aisb networks rm {key} --dry-run",
}


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Added, removed and changed objects per kind, with dry-run cleanup commands for what was added."""
    out: dict[str, Any] = {"window": {"from": before.get("taken"), "to": after.get("taken")}}
    cleanup: list[str] = []
    for kind in KINDS:
        b, a = before.get(kind) or {}, after.get(kind) or {}
        added, removed = sorted(a.keys() - b.keys()), sorted(b.keys() - a.keys())
        changed = []
        for key in sorted(a.keys() & b.keys()):
            delta = {f: [b[key].get(f), a[key].get(f)] for f in a[key].keys() | b[key].keys()
                     if b[key].get(f) != a[key].get(f)}
            if delta:
                changed.append({"name": key, "recreated": "id" in delta and kind == "containers",
                                "changes": dict(sorted(delta.items()))})
        out[kind] = {"added": added, "removed": removed, "changed": changed}
        if kind == "images":
            out[kind]["tags"] = {k: (a.get(k) or b.get(k) or {}).get("tags", []) for k in added + removed}
        cleanup += [_CLEANUP[kind].format(key=k) for k in added]
    out["summary"] = {k: {x: len(out[k][x]) for x in ("added", "removed", "changed")} for k in KINDS}
    out["cleanup"] = cleanup
    return out
