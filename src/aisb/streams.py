"""Decoders for Docker's streaming formats and tar helpers for build/copy."""

import codecs
import fnmatch
import io
import json
import os
import struct
import tarfile
from collections.abc import Iterable, Iterator
from enum import IntEnum
from pathlib import Path
from typing import Any

from .errors import APIError

_HEADER = struct.Struct(">BxxxL")


class Stream(IntEnum):
    STDIN = 0
    STDOUT = 1
    STDERR = 2


def demux(chunks: Iterable[bytes]) -> Iterator[tuple[Stream, bytes]]:
    """Split Docker's multiplexed stdout/stderr frames (non-TTY logs, attach, exec)."""
    buf = bytearray()
    for chunk in chunks:
        buf += chunk
        while len(buf) >= _HEADER.size:
            kind, size = _HEADER.unpack_from(buf)
            end = _HEADER.size + size
            if len(buf) < end:
                break
            yield Stream(kind), bytes(buf[_HEADER.size:end])
            del buf[:end]
    if buf:
        raise ValueError(f"truncated multiplexed frame ({len(buf)} bytes left)")


def decode_output(raw: bytes, tty: bool) -> str:
    """Combine a log/exec payload into text; TTY output is raw, otherwise multiplexed."""
    payload = raw if tty else b"".join(data for _, data in demux([raw]))
    return payload.decode(errors="replace")


def iter_jsonl(chunks: Iterable[bytes]) -> Iterator[dict[str, Any]]:
    """Decode a stream of JSON objects (pull, build, events), raising embedded errors."""
    text = codecs.getincrementaldecoder("utf-8")(errors="replace")
    decoder = json.JSONDecoder()
    buf = ""
    for chunk in chunks:
        buf += text.decode(chunk)
        while buf := buf.lstrip():
            try:
                obj, end = decoder.raw_decode(buf)
            except json.JSONDecodeError:
                break
            buf = buf[end:]
            if isinstance(obj, dict) and obj.get("error"):
                raise APIError(str(obj.get("errorDetail", {}).get("message") or obj["error"]).strip())
            yield obj
    if (buf + text.decode(b"", final=True)).strip():
        raise ValueError(f"incomplete JSON at end of stream: {buf[:80]!r}")


def _ignore_rules(root: Path) -> list[tuple[bool, str]]:
    path = root / ".dockerignore"
    if not path.is_file():
        return []
    rules = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        rules.append((negate, os.path.normpath(line.lstrip("!").strip("/"))))
    return rules


def _ignored(rel: str, rules: list[tuple[bool, str]]) -> bool:
    """Last matching rule wins; a pattern also matches everything below a matched directory."""
    ignored = False
    for negate, pattern in rules:
        parts = rel.split("/")
        if any(fnmatch.fnmatch("/".join(parts[:i]), pattern) for i in range(1, len(parts) + 1)):
            ignored = not negate
    return ignored


def tar_context(path: str | Path, dockerfile: str = "Dockerfile") -> bytes:
    """In-memory build context honoring .dockerignore (Dockerfile and .dockerignore always kept)."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError(f"build context is not a directory: {root}")
    rules, keep = _ignore_rules(root), {dockerfile, ".dockerignore"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                full = Path(dirpath, name)
                rel = full.relative_to(root).as_posix()
                if rel in keep or not _ignored(rel, rules):
                    tar.add(full, arcname=rel, recursive=False)
    return buf.getvalue()


def tar_path(path: str | Path) -> bytes:
    """Tar a single file or directory under its basename (for PUT /archive)."""
    src = Path(path).expanduser().resolve()
    if not src.exists():
        raise ValueError(f"no such local path: {src}")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(src, arcname=src.name)
    return buf.getvalue()


def untar(data: bytes, dest: str | Path) -> list[str]:
    """Safely extract an archive from GET /archive; returns member names."""
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(Path(dest).expanduser(), filter="data")
        return tar.getnames()
