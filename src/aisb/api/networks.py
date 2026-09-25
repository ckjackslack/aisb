from typing import Annotated, Any

from ..models import Network
from ..ops import Resource, Tier, op
from ..util import MANAGED_KEY, kv, project, q

Ref = Annotated[str, "network name or id"]


class Networks(Resource, name="networks"):
    @op(Tier.READ, name="list")
    def ls(self) -> list[Network]:
        """List networks."""
        return [Network.from_api(n) for n in self.t.json("GET", "/networks")]

    @op(Tier.READ)
    def inspect(self, ref: Ref, *, fields: Annotated[str | None, "comma-separated dotted paths"] = None) -> Any:
        """Network details including attached containers."""
        return project(self.t.json("GET", f"/networks/{q(ref)}"), fields)

    @op(Tier.MUTATE)
    def create(self, name: str, *, driver: str = "bridge", internal: bool = False,
               label: Annotated[dict[str, str] | None, "KEY=VALUE"] = None) -> dict[str, Any]:
        """Create a network."""
        r = self.t.json("POST", "/networks/create", body={
            "Name": name, "Driver": driver, "Internal": internal, "Labels": {**kv(label), MANAGED_KEY: "true"},
        })
        return {"id": r["Id"][:12], "name": name}

    @op(Tier.MUTATE)
    def connect(self, ref: Ref, container: Annotated[str, "container name or id"], *,
                alias: Annotated[list[str] | None, "DNS alias on this network"] = None) -> dict[str, Any]:
        """Attach a container to a network."""
        self.t.json("POST", f"/networks/{q(ref)}/connect",
                    body={"Container": container, "EndpointConfig": {"Aliases": alias or []}})
        return {"network": ref, "container": container, "connected": True}

    @op(Tier.MUTATE)
    def disconnect(self, ref: Ref, container: str, *, force: bool = False) -> dict[str, Any]:
        """Detach a container from a network."""
        self.t.json("POST", f"/networks/{q(ref)}/disconnect", body={"Container": container, "Force": force})
        return {"network": ref, "container": container, "connected": False}

    @op(Tier.DESTROY)
    def rm(self, ref: Ref) -> dict[str, Any]:
        """Remove a network."""
        self.t.json("DELETE", f"/networks/{q(ref)}")
        return {"removed": ref}
