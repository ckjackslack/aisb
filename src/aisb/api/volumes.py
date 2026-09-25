from typing import Annotated, Any

from ..models import Volume
from ..ops import Resource, Tier, op
from ..util import MANAGED, MANAGED_KEY, kv, project, q

Ref = Annotated[str, "volume name"]


class Volumes(Resource, name="volumes"):
    @op(Tier.READ, name="list")
    def ls(self, *, dangling: Annotated[bool, "only volumes not used by any container"] = False,
           managed: Annotated[bool, "only volumes created by aisb"] = False) -> list[Volume]:
        """List volumes."""
        f = {"dangling": ["true"]} if dangling else {}
        if managed:
            f["label"] = [MANAGED]
        r = self.t.json("GET", "/volumes", query={"filters": f or None})
        return [Volume.from_api(v) for v in r.get("Volumes") or []]

    @op(Tier.READ)
    def inspect(self, ref: Ref, *, fields: Annotated[str | None, "comma-separated dotted paths"] = None) -> Any:
        """Volume details."""
        return project(self.t.json("GET", f"/volumes/{q(ref)}"), fields)

    @op(Tier.MUTATE)
    def create(self, name: str, *, driver: str = "local",
               label: Annotated[dict[str, str] | None, "KEY=VALUE"] = None) -> Volume:
        """Create a named volume."""
        return Volume.from_api(self.t.json("POST", "/volumes/create", body={
            "Name": name, "Driver": driver, "Labels": {**kv(label), MANAGED_KEY: "true"},
        }) | {"Name": name})

    @op(Tier.DESTROY)
    def rm(self, ref: Ref, *, force: bool = False) -> dict[str, Any]:
        """Remove a volume (its data is lost)."""
        self.t.json("DELETE", f"/volumes/{q(ref)}", query={"force": force})
        return {"removed": ref}
