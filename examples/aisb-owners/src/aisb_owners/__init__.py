"""aisb-owners: who owns each container, read from a label.

An example aisb plugin. Importing this module registers:
- the `owners` resource: `owners list` (read) and `owners stop-unowned` (mutate). Both get the CLI, `--help`,
  MCP tools, the portal, `aisb docs`, man pages, shell completion, policy rules and the audit log from aisb;
- a doctor rule, so `aisb containers doctor` and `aisb system doctor` report containers nobody owns.
"""

from collections.abc import Iterable, Mapping
from typing import Annotated, Any

from aisb.insights.triage import Facts, Finding, rule
from aisb.ops import Resource, Tier, op

LABEL = "com.example.owner"
Label = Annotated[str, "label that names the owning team"]


def _name(row: Mapping[str, Any]) -> str:
    return (row.get("Names") or ["/" + str(row.get("Id", ""))[:12]])[0].lstrip("/")


def by_owner(rows: Iterable[Mapping[str, Any]], label: str = LABEL) -> dict[str, Any]:
    """Pure: container rows (GET /containers/json) grouped by owner, plus the ones without an owner."""
    owners: dict[str, list[str]] = {}
    unowned: list[str] = []
    for row in rows:
        owner = (row.get("Labels") or {}).get(label, "").strip()
        (owners.setdefault(owner, []) if owner else unowned).append(_name(row))
    return {"label": label, "owners": {k: sorted(v) for k, v in sorted(owners.items())}, "unowned": sorted(unowned)}


class Owners(Resource, name="owners"):
    @op(Tier.READ, name="list")
    def ls(self, *, label: Label = LABEL, all: Annotated[bool, "include stopped containers"] = False) -> dict[str, Any]:
        """Containers grouped by the team in their owner label, and the ones nobody owns."""
        return by_owner(self.t.json("GET", "/containers/json", query={"all": all}), label)

    # MUTATE, not DESTROY: a stopped container starts again with its data intact. Use Tier.DESTROY for anything
    # that loses data; aisb then previews it and exits 3 until the user approves with --yes.
    @op(Tier.MUTATE, name="stop-unowned")
    def stop_unowned(self, *, label: Label = LABEL,
                     keep: Annotated[list[str] | None, "container names never to stop"] = None,
                     grace: Annotated[int, "seconds before SIGKILL"] = 10) -> dict[str, Any]:
        """Stop every running container without an owner label. Try it with --dry-run first."""
        rows = self.t.json("GET", "/containers/json")  # reads run even under --dry-run; the POSTs are only planned
        targets = [r for r in rows if not (r.get("Labels") or {}).get(label, "").strip()
                   and _name(r) not in set(keep or ())]
        for r in targets:
            self.t.json("POST", f"/containers/{r['Id']}/stop", query={"t": grace}, timeout=grace + 30)
        return {"stopped": sorted(map(_name, targets)), "kept": sorted(set(keep or ()))}


@rule
def unowned(f: Facts) -> Iterable[Finding]:
    """Doctor rule: a container nobody owns is one nobody gets paged for."""
    if not (f.config.get("Labels") or {}).get(LABEL, "").strip():
        yield Finding("info", "no-owner", f"no {LABEL} label: nobody owns this container",
                      (f"Config.Labels has no {LABEL}",), ("aisb owners list",))
