from typing import Annotated, Any

from ..errors import APIError
from ..models import Image
from ..ops import Resource, Tier, op
from ..streams import iter_jsonl, tar_context
from ..util import MANAGED_KEY, clip, kv, project, q

Ref = Annotated[str, "image reference (name[:tag] or id)"]
Fields = Annotated[str | None, "comma-separated dotted paths to keep"]


def split_tag(ref: str) -> tuple[str, str]:
    """'host:5000/app' -> ('host:5000/app', 'latest'); 'app:1.2' -> ('app', '1.2')."""
    if "@" in ref:
        return tuple(ref.split("@", 1))  # type: ignore[return-value]
    repo, sep, tag = ref.rpartition(":")
    if not sep or "/" in tag:
        return ref, "latest"
    return repo, tag


class Images(Resource, name="images"):
    @op(Tier.READ, name="list")
    def ls(self, *, all: Annotated[bool, "include intermediate layers"] = False,
           dangling: Annotated[bool, "only untagged images"] = False) -> list[Image]:
        """List local images."""
        query = {"all": all, "filters": {"dangling": ["true"]} if dangling else None}
        return [Image.from_api(r) for r in self.t.json("GET", "/images/json", query=query)]

    @op(Tier.READ)
    def inspect(self, ref: Ref, *, fields: Fields = None) -> Any:
        """Low-level image details; narrow with --fields."""
        return project(self.t.json("GET", f"/images/{q(ref)}/json"), fields)

    @op(Tier.READ)
    def history(self, ref: Ref) -> list[dict[str, Any]]:
        """Layer history of an image."""
        return [{"created_by": h.get("CreatedBy", ""), "size": h.get("Size", 0), "created": h.get("Created", 0)}
                for h in self.t.json("GET", f"/images/{q(ref)}/history")]

    @op(Tier.MUTATE)
    def pull(self, ref: Ref) -> dict[str, Any]:
        """Pull an image (defaults to :latest)."""
        repo, tag = split_tag(ref)
        query = {"fromImage": repo, "tag": tag}
        events = list(iter_jsonl(self.t.stream("POST", "/images/create", query=query, timeout=None)))
        summary = [e["status"] for e in events if "status" in e and "id" not in e]
        return {"image": f"{repo}{'@' if tag.startswith('sha256:') else ':'}{tag}", "messages": summary}

    @op(Tier.MUTATE)
    def build(self, path: Annotated[str, "build context directory"] = ".", *,
              tag: Annotated[str | None, "name:tag for the result"] = None,
              dockerfile: str = "Dockerfile",
              build_arg: Annotated[dict[str, str] | None, "KEY=VALUE"] = None,
              no_cache: bool = False, pull: Annotated[bool, "always pull base images"] = False,
              max_bytes: Annotated[int, "cap build log size (keeps the tail)"] = 16 * 1024) -> dict[str, Any]:
        """Build an image from a local context (classic builder API)."""
        query = {
            "t": tag, "dockerfile": dockerfile, "buildargs": kv(build_arg) or None,
            "nocache": no_cache, "pull": pull, "rm": True, "forcerm": True, "labels": {MANAGED_KEY: "true"},
        }
        log: list[str] = []
        image_id = None
        try:
            for e in iter_jsonl(self.t.stream("POST", "/build", query=query, data=tar_context(path, dockerfile),
                                              content_type="application/x-tar", timeout=None)):
                log.append(e.get("stream", ""))
                image_id = (e.get("aux") or {}).get("ID", image_id)
        except APIError as err:
            tail = clip("".join(log), max_bytes)["output"]
            raise APIError(f"{err}\n--- build log tail ---\n{tail}") from None
        return {"id": image_id, "tag": tag, **clip("".join(log), max_bytes)}

    @op(Tier.MUTATE)
    def tag(self, ref: Ref, target: Annotated[str, "new name[:tag]"]) -> dict[str, Any]:
        """Add a tag to an image."""
        repo, tag = split_tag(target)
        self.t.json("POST", f"/images/{q(ref)}/tag", query={"repo": repo, "tag": tag})
        return {"source": ref, "target": f"{repo}:{tag}"}

    @op(Tier.DESTROY)
    def rmi(self, ref: Ref, *, force: bool = False) -> Any:
        """Remove an image."""
        return self.t.json("DELETE", f"/images/{q(ref)}", query={"force": force})
