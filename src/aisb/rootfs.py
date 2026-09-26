"""Stream a container's (or, through a transient helper, an image's) filesystem via the archive API.

Headers are read in stream mode, so a whole rootfs can be indexed without holding it in memory;
file contents are read only when the caller asks for them.
"""

import io
import tarfile
from collections.abc import Callable, Iterator
from typing import Any

from .errors import APIError
from .transport import Transport
from .util import q


class ChunkReader(io.RawIOBase):
    """File-like view of a byte-chunk iterator, with a hard byte budget."""

    def __init__(self, chunks: Iterator[bytes], budget: int) -> None:
        self._chunks, self._buf, self.read_total, self._budget = chunks, b"", 0, budget

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        while not self._buf:
            try:
                self._buf = next(self._chunks)
            except StopIteration:
                return 0
            self.read_total += len(self._buf)
            if self.read_total > self._budget:
                raise APIError(f"archive exceeded {self._budget >> 20} MiB; narrow the path or raise the budget")
        n = min(len(b), len(self._buf))
        b[:n], self._buf = self._buf[:n], self._buf[n:]
        return n


def relative(name: str, root: str) -> str:
    """Archive member name -> path relative to the requested directory ('' for the directory itself)."""
    name = name.removeprefix("./").lstrip("/")
    if not root:
        return name
    if name == root:
        return ""
    return name[len(root) + 1:] if name.startswith(root + "/") else name


def walk(t: Transport, ref: str, path: str = "/", *, budget_mib: int = 2048,
         want: Callable[[str, tarfile.TarInfo], bool] | None = None,
         ) -> Iterator[tuple[tarfile.TarInfo, str, bytes | None]]:
    """Yield (member, relative path, content if `want(rel, member)` else None) for everything under `path`."""
    chunks = t.stream("GET", f"/containers/{q(ref)}/archive", query={"path": path}, timeout=None)
    reader = io.BufferedReader(ChunkReader(chunks, budget_mib << 20), 1 << 16)
    root = path.rstrip("/").rsplit("/", 1)[-1]
    with tarfile.open(fileobj=reader, mode="r|") as tar:
        for m in tar:
            rel = relative(m.name, root)
            data = None
            if want is not None and m.isfile() and want(rel, m):
                data = tar.extractfile(m).read()  # type: ignore[union-attr]
            yield m, rel, data


def read_file(t: Transport, ref: str, path: str) -> bytes | None:
    """One file's content, or None if it doesn't exist or isn't a regular file."""
    from .errors import NotFound
    try:
        for m, _, data in walk(t, ref, path, budget_mib=256, want=lambda _r, _m: True):
            return data if m.isfile() else None
    except NotFound:
        return None
    return None
