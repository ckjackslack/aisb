from typing import Annotated, Any, Literal

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

    @op(Tier.READ)
    def secrets(self, ref: Ref) -> dict[str, Any]:
        """Credentials baked into an image: ENV/ARG values and build args in layer history, known token formats."""
        from ..insights.audit import dedupe, scan_env, scan_history
        info = self.t.json("GET", f"/images/{q(ref)}/json") or {}
        hits = dedupe(scan_history(self.history(ref)) + scan_env((info.get("Config") or {}).get("Env") or [], "image env"))
        return {"image": ref, "count": len(hits), "findings": hits,
                "note": "anything found here is readable by everyone who can pull the image: rotate it" if hits else None}

    @op(Tier.READ)
    def slim(self, ref: Ref) -> dict[str, Any]:
        """Where an image's bytes are, and which Dockerfile habits put them there (with the fix for each)."""
        from ..insights.audit import slim
        info = self.t.json("GET", f"/images/{q(ref)}/json") or {}
        return {"image": ref, **slim(self.history(ref), int(info.get("Size") or 0))}

    def inventory(self, ref: str, *, hash_files: bool) -> Any:
        """Stream the image's rootfs once (via a transient helper) into a package + file inventory."""
        from ..insights.packages import HASH_LIMIT, Inventory, wants
        from ..rootfs import walk
        from .containers import Containers
        inv = Inventory()
        with Containers(self.t).transient(ref, pull=False) as cid:
            for m, rel, data in walk(self.t, cid, "/", budget_mib=8192,
                                     want=lambda r, mm: wants(r, mm.size) or (hash_files and mm.size <= HASH_LIMIT)):
                if rel:
                    inv.add(rel, m, data)
        return inv

    @op(Tier.READ)
    def sbom(self, ref: Ref, *, format: Annotated[Literal["json", "cyclonedx"], "output format"] = "json",
             ecosystem: Annotated[str | None, "only this ecosystem (apk, dpkg, rpm, pypi, npm, gem)"] = None,
             ) -> dict[str, Any]:
        """Software bill of materials read straight from the image's package databases (no scanner needed)."""
        from ..insights.packages import cyclonedx, dedupe
        inv = self.inventory(ref, hash_files=False)
        inv.packages = [p for p in dedupe(inv.packages) if not ecosystem or p.ecosystem == ecosystem]
        if format == "cyclonedx":
            return cyclonedx(ref, inv)
        return {"image": ref, **inv.summary(),
                "components": [{"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "purl": p.purl}
                               for p in sorted(inv.packages, key=lambda p: (p.ecosystem, p.name.lower()))]}

    @op(Tier.READ)
    def diff(self, ref: Ref, other: Annotated[str, "second image"], *,
             top: Annotated[int, "largest file changes listed"] = 20) -> dict[str, Any]:
        """What changed between two images: files (by content), packages (up/downgrades), and config."""
        from ..insights.packages import config_diff, dedupe
        from ..insights.packages import diff as inv_diff
        a, b = self.inventory(ref, hash_files=True), self.inventory(other, hash_files=True)
        a.packages, b.packages = dedupe(a.packages), dedupe(b.packages)
        ca = (self.t.json("GET", f"/images/{q(ref)}/json") or {}).get("Config") or {}
        cb = (self.t.json("GET", f"/images/{q(other)}/json") or {}).get("Config") or {}
        return {"a": ref, "b": other, **inv_diff(a, b, top=top), "config": config_diff(ca, cb)}

    @op(Tier.READ)
    def envcheck(self, ref: Ref, *, env: Annotated[list[str] | None, "KEY=VALUE you plan to pass"] = None,
                 env_file: Annotated[str | None, "host .env file you plan to pass"] = None,
                 path: Annotated[list[str] | None, "extra directories to scan"] = None) -> dict[str, Any]:
        """Preflight an image's env contract before running it: missing required vars and likely typos."""
        from pathlib import Path

        from ..insights import envcontract as ec
        from .containers import Containers
        cfg = (self.t.json("GET", f"/images/{q(ref)}/json") or {}).get("Config") or {}
        provided = dict(e.partition("=")[::2] for e in cfg.get("Env") or [])
        if env_file:
            for line in Path(env_file).expanduser().read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, _, v = line.partition("=")
                    provided[k.strip().removeprefix("export ").strip()] = v
        provided |= kv(env)
        ctr = Containers(self.t)
        with ctr.transient(ref, pull=False) as cid:
            uses, scanned = ctr.env_uses(cid, cfg, path)
        return {"image": ref, "files_scanned": len(scanned), **ec.check(uses, provided)}

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
