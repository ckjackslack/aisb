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
    def vulns(self, ref: Ref, *,
              min_severity: Annotated[Literal["low", "medium", "high", "critical"], "hide findings below this"] = "low",
              limit: Annotated[int, "findings listed (counts cover all)"] = 50,
              details: Annotated[bool, "fetch advisories for severity and fixed versions (one request each, cached)"] = True,
              ) -> dict[str, Any]:
        """Known vulnerabilities in an image's packages: its SBOM matched against OSV.dev ($AISB_OSV_URL), with
        severity (CVSS v3 or the advisory's label), fixed versions and CVE aliases. Alpine, Debian, Ubuntu, PyPI, npm,
        RubyGems are queried; other ecosystems are listed as not covered."""
        from .. import supply
        from ..insights import vulns as vl
        from ..insights.packages import dedupe
        inv = self.inventory(ref, hash_files=False)
        comps = [{"ecosystem": p.ecosystem, "name": p.name, "version": p.version} for p in dedupe(inv.packages)]
        queries, owners, skipped = vl.queries(comps, inv.os)
        try:
            ids = supply.osv_ids(queries) if queries else []
            advisories = {vid: supply.osv_vuln(vid) for vid in sorted({i for group in ids for i in group})} \
                if details else {}
        except supply.SupplyError as e:
            raise APIError(f"vulnerability lookup failed: {e} (set $AISB_OSV_URL to a reachable OSV mirror)") from None
        rep = vl.report(owners, ids, advisories, queries, min_severity=min_severity)
        return {"image": ref, "os": inv.os, "packages": len(comps), "queried": len(queries),
                **({"not_covered": skipped} if skipped else {}), **rep, "findings": rep["findings"][:limit]}

    @op(Tier.READ)
    def updates(self, *refs: Annotated[str, "images to check (default: those used by running containers)"],
                all: Annotated[bool, "check every tagged local image"] = False) -> list[dict[str, Any]]:
        """Is a newer image published under the same tag? Compares local repo digests with the registry's current
        manifest digest (anonymous tokens, or ~/.docker/config.json credentials). Nothing is pulled."""
        from .. import supply
        if not refs:
            if all:
                refs = tuple(t for i in self.t.json("GET", "/images/json") or [] for t in i.get("RepoTags") or []
                             if t != "<none>:<none>")
            else:
                refs = tuple(sorted({c.get("Image", "") for c in self.t.json("GET", "/containers/json") or []
                                     if c.get("Image") and not c["Image"].startswith("sha256:")}))
        out = []
        for ref in dict.fromkeys(refs):
            try:
                local = self.t.json("GET", f"/images/{q(ref)}/json") or {}
            except APIError as e:
                out.append({"image": ref, "status": "error", "error": str(e)})
                continue
            except Exception as e:  # noqa: BLE001 - NotFound etc.: report per image
                out.append({"image": ref, "status": "missing", "error": str(e)})
                continue
            mine = {d.split("@", 1)[1] for d in local.get("RepoDigests") or [] if "@" in d}
            if not mine and str(local.get("Id", "")).startswith("sha256:") and local.get("Descriptor"):
                mine.add(local["Descriptor"].get("digest", ""))
            try:
                remote = supply.remote_digest(ref)
            except supply.SupplyError as e:
                out.append({"image": ref, "status": "unknown", "error": str(e)})
                continue
            status = "current" if remote in mine else "local-only" if not mine else "outdated"
            out.append({"image": ref, "status": status, "local": sorted(mine)[:1], "remote": remote,
                        **({"next": f"aisb images pull {ref}"} if status == "outdated" else {})})
        return out

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
