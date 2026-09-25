"""Small pure helpers shared by resources and the CLI."""

import re
import time
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

MANAGED_KEY = "aisb.managed"
MANAGED = f"{MANAGED_KEY}=true"

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def q(ref: str) -> str:
    """Quote a path segment; image refs keep their '/', ':' and '@'."""
    return quote(ref, safe="/:@")


def compact(d: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def dig(data: Any, path: str) -> Any:
    for key in path.split("."):
        if isinstance(data, Mapping):
            data = data.get(key)
        elif isinstance(data, list) and key.isdigit() and int(key) < len(data):
            data = data[int(key)]
        else:
            return None
    return data


def prune(value: Any) -> Any:
    """Recursively drop None/''/[]/{} values: Docker pads nested objects with empty keys."""
    if isinstance(value, Mapping):
        return {k: v for k, v in ((k, prune(v)) for k, v in value.items()) if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [prune(v) for v in value]
    return value


def project(data: Any, fields: str | None) -> Any:
    """Keep only comma-separated dotted paths, e.g. 'State.Status,Config.Image'; nested empties are pruned."""
    if not fields:
        return data
    return {f: prune(dig(data, f)) for f in (s.strip() for s in fields.split(",")) if f}


def clip(text: str, max_bytes: int) -> dict[str, Any]:
    """Keep the tail of long output (the end of a log is what matters)."""
    raw = text.encode()
    if max_bytes <= 0 or len(raw) <= max_bytes:
        return {"output": text, "truncated": False}
    kept = raw[-max_bytes:].decode(errors="ignore")
    return {"output": f"[... {len(raw) - max_bytes} bytes truncated ...]\n{kept}", "truncated": True}


def to_unix(value: str | int | float, *, now: float | None = None) -> int:
    """Accept unix seconds, 'now', relative '10m'/'2h'/'1d', or ISO-8601."""
    if isinstance(value, (int, float)):
        return int(value)
    v = value.strip().lower()
    now = time.time() if now is None else now
    if v == "now":
        return int(now)
    if m := re.fullmatch(r"(\d+)([smhd])", v):
        return int(now - int(m[1]) * _UNITS[m[2]])
    if v.isdigit():
        return int(v)
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())


def docker_time(value: str | None) -> float | None:
    """Docker's RFC 3339 nanosecond timestamps -> unix seconds; None for the zero time."""
    if not value or value.startswith("0001-"):
        return None
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    return datetime.fromisoformat(trimmed).timestamp()


def kv(items: Iterable[str] | Mapping[str, str] | None) -> dict[str, str]:
    if items is None:
        return {}
    if isinstance(items, Mapping):
        return {str(k): str(v) for k, v in items.items()}
    out = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"expected KEY=VALUE, got {item!r}")
        out[key] = value
    return out


def filters(items: Iterable[str] | None, **extra: list[str]) -> dict[str, list[str]] | None:
    """'type=container' pairs -> Docker filter map {'type': ['container']}."""
    out: dict[str, list[str]] = {}
    for key, value in _pairs(items):
        out.setdefault(key, []).append(value)
    for key, values in extra.items():
        if values:
            out.setdefault(key, []).extend(values)
    return out or None


def _pairs(items: Iterable[str] | None) -> Iterable[tuple[str, str]]:
    for item in items or ():
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"expected KEY=VALUE filter, got {item!r}")
        yield key, value


def split_cp(arg: str) -> tuple[str | None, str]:
    """'web:/etc/nginx' -> ('web', '/etc/nginx'); local paths -> (None, path)."""
    if ":" in arg and not arg.startswith(("/", ".", "~")):
        ref, _, path = arg.partition(":")
        return ref, path or "/"
    return None, arg
