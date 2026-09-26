import gzip
import io
import tarfile
from pathlib import Path
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

    def _helper(self, vol: str, image: str, *, readonly: bool, cmd: tuple[str, ...] = ("true",)) -> str:
        from ..models import RunSpec
        from .containers import Containers
        spec = RunSpec(image=image, cmd=cmd, volumes=(f"{vol}:/v{':ro' if readonly else ''}",),
                       labels={"aisb.helper": f"volume:{vol}"})
        return Containers(self.t).create_from(spec)

    @op(Tier.MUTATE)
    def backup(self, ref: Ref, out: Annotated[str, "host file (.tar or .tar.gz)"], *,
               image: Annotated[str, "any local image for the helper (it is created, never started)"] = "busybox:1.36",
               ) -> dict[str, Any]:
        """Stream a volume's contents to a host tarball via a never-started helper container (read-only mount)."""
        from ..services.sql import gzip_sink
        path = Path(out).expanduser()
        self.t.json("GET", f"/volumes/{q(ref)}")  # 404 early for a missing volume
        hid = self._helper(ref, image, readonly=True)
        try:
            chunks = self.t.stream("GET", f"/containers/{hid}/archive", query={"path": "/v"}, timeout=None)
            if self.t.planning:
                return {"volume": ref, "out": str(path)}
            write, close = gzip_sink(path)  # gzips when the name ends in .gz
            try:
                for chunk in chunks:
                    write(chunk)
            except BaseException:
                close()
                path.unlink(missing_ok=True)
                raise
            raw = close()
        finally:
            self.t.json("DELETE", f"/containers/{hid}", query={"force": True})
        return {"volume": ref, "written": str(path), "tar_bytes": raw, "file_bytes": path.stat().st_size}

    @op(Tier.DESTROY)
    def restore(self, ref: Ref, file: Annotated[str, "tarball from `volumes backup` (or any tar)"], *,
                clear: Annotated[bool, "empty the volume first (needs a shell in --image)"] = False,
                image: Annotated[str, "helper image (needs sh for --clear)"] = "busybox:1.36") -> dict[str, Any]:
        """Write a tarball into a volume (created if missing). Existing files are overwritten; --clear wipes first."""
        raw = Path(file).expanduser().read_bytes()
        data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            names = tar.getnames()
        rooted = bool(names) and all(n == "v" or n.startswith("v/") for n in names)
        if clear:
            cid = self._helper(ref, image, readonly=False, cmd=("sh", "-c", "rm -rf /v/..?* /v/.[!.]* /v/*"))
            try:
                self.t.json("POST", f"/containers/{cid}/start")
                self.t.json("POST", f"/containers/{cid}/wait", timeout=None)
            finally:
                self.t.json("DELETE", f"/containers/{cid}", query={"force": True})
        hid = self._helper(ref, image, readonly=False)
        try:
            self.t.json("PUT", f"/containers/{hid}/archive", query={"path": "/" if rooted else "/v"},
                        data=data, content_type="application/x-tar", timeout=None)
        finally:
            self.t.json("DELETE", f"/containers/{hid}", query={"force": True})
        return {"volume": ref, "restored_entries": len(names), "cleared": clear}

    @op(Tier.DESTROY)
    def rm(self, ref: Ref, *, force: bool = False) -> dict[str, Any]:
        """Remove a volume (its data is lost)."""
        self.t.json("DELETE", f"/volumes/{q(ref)}", query={"force": force})
        return {"removed": ref}
