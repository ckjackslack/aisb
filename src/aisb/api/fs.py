"""Read container filesystems through the archive API: works on distroless images with no shell or coreutils."""

import base64
import fnmatch
import hashlib
import io
import json
import tarfile
from collections.abc import Iterator
from typing import Annotated, Any, Literal

from ..ops import Resource, Tier, op
from ..rootfs import ChunkReader, relative
from ..util import clip, q

Ref = Annotated[str, "container name or id (running or stopped)"]
Budget = Annotated[int, "abort after streaming this many MiB of archive"]

_TYPES = {tarfile.DIRTYPE: "dir", tarfile.SYMTYPE: "link", tarfile.LNKTYPE: "hardlink",
          tarfile.CHRTYPE: "char", tarfile.BLKTYPE: "block", tarfile.FIFOTYPE: "fifo"}


def _entry(m: tarfile.TarInfo, rel: str) -> dict[str, Any]:
    out = {"path": rel, "type": "file" if m.isfile() else _TYPES.get(m.type, "other"), "size": m.size,
           "mode": oct(m.mode & 0o7777), "mtime": int(m.mtime), "owner": f"{m.uid}:{m.gid}"}
    if m.issym() or m.islnk():
        out["target"] = m.linkname
    return out


def _decode_mode(mode: int) -> str:
    return "dir" if mode & (1 << 31) else "link" if mode & (1 << 27) else "file"


class Fs(Resource, name="fs"):
    def _members(self, ref: str, path: str, budget_mib: int) -> Iterator[tuple[tarfile.TarInfo, str, tarfile.TarFile]]:
        """Stream tar headers of `path`, yielding (member, path relative to `path`, tar)."""
        chunks = self.t.stream("GET", f"/containers/{q(ref)}/archive", query={"path": path}, timeout=None)
        reader = io.BufferedReader(ChunkReader(chunks, budget_mib << 20), 1 << 16)
        root = path.rstrip("/").rsplit("/", 1)[-1]
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            for m in tar:
                yield m, relative(m.name, root), tar

    @op(Tier.READ)
    def stat(self, ref: Ref, path: str) -> dict[str, Any]:
        """Type, size, mode and mtime of a path (a single HEAD request)."""
        hdr = self.t.head(f"/containers/{q(ref)}/archive", query={"path": path})
        st = json.loads(base64.b64decode(hdr.get("x-docker-container-path-stat", "e30=")))
        mode = st.get("mode", 0)
        return {"path": path, "name": st.get("name"), "type": _decode_mode(mode), "size": st.get("size"),
                "mode": oct(mode & 0o7777), "mtime": st.get("mtime"), "target": st.get("linkTarget") or None}

    @op(Tier.READ)
    def ls(self, ref: Ref, path: Annotated[str, "directory"] = "/", *,
           limit: Annotated[int, "max entries"] = 500, max_mb: Budget = 256) -> dict[str, Any]:
        """List a directory (one level) with type, size, mode, mtime and link targets."""
        entries = []
        for m, rel, _ in self._members(ref, path, max_mb):
            if rel and "/" not in rel.rstrip("/"):
                entries.append(_entry(m, rel.rstrip("/")))
                if len(entries) >= limit:
                    break
        entries.sort(key=lambda e: (e["type"] != "dir", e["path"]))
        return {"path": path, "count": len(entries), "entries": entries}

    @op(Tier.READ)
    def find(self, ref: Ref, path: Annotated[str, "directory to search"] = "/", *,
             name: Annotated[str | None, "glob on the file name, e.g. '*.conf'"] = None,
             type: Annotated[Literal["file", "dir", "link"] | None, "entry type"] = None,
             min_size: Annotated[int, "only entries at least this many bytes"] = 0,
             limit: Annotated[int, "max results"] = 200, max_mb: Budget = 512) -> dict[str, Any]:
        """Recursive search by name glob, type and size, like `find`, without needing find in the image."""
        hits = []
        truncated = False
        for m, rel, _ in self._members(ref, path, max_mb):
            if not rel:
                continue
            e = _entry(m, rel.rstrip("/"))
            if name and not fnmatch.fnmatch(e["path"].rsplit("/", 1)[-1], name):
                continue
            if (type and e["type"] != type) or e["size"] < min_size:
                continue
            if len(hits) >= limit:
                truncated = True
                break
            hits.append(e)
        return {"path": path, "count": len(hits), "truncated": truncated, "entries": hits}

    @op(Tier.READ)
    def cat(self, ref: Ref, path: Annotated[str, "file"], *, max_bytes: Annotated[int, "text shown"] = 64 * 1024,
            tail: Annotated[bool, "keep the end instead of the start when clipping"] = False) -> dict[str, Any]:
        """Print a file (text), or its size and sha256 when it is binary."""
        for m, _, tar in self._members(ref, path, 1024):
            if m.isdir():
                raise ValueError(f"{path} is a directory; use `fs ls`")
            if m.issym():
                return {"path": path, "type": "link", "target": m.linkname}
            data = tar.extractfile(m).read() if m.isfile() else b""  # type: ignore[union-attr]
            if b"\0" in data[:8192]:
                return {"path": path, "binary": True, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            text = data.decode(errors="replace")
            if tail:
                return {"path": path, "size": len(data), **clip(text, max_bytes)}
            head = data[:max_bytes].decode(errors="ignore")
            cut = len(data) > max_bytes
            return {"path": path, "size": len(data), "truncated": cut,
                    "output": head + (f"\n[... {len(data) - max_bytes} more bytes ...]" if cut else "")}
        raise ValueError(f"empty archive for {path}")
