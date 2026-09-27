"""Append-only, hash-chained audit log of changes made through aisb (JSONL, optional syslog mirror).

Each record carries `prev` (the previous record's hash) and `hash` = sha256(prev + canonical record), so
`verify()` detects edited, reordered or deleted lines. Writes are serialized across threads and processes.
"""

import fcntl
import hashlib
import json
import logging
import logging.handlers
import os
import threading
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from . import config, state
from .context import Ctx
from .transport import SECRET_KEY, redact_env

GENESIS = "0" * 64
_LOCK = threading.Lock()
_SYSLOG: dict[str, logging.Logger] = {}


def path() -> Path:
    cfg = config.load().audit
    p = os.environ.get("AISB_AUDIT") or cfg.get("path")
    return Path(p).expanduser() if p else state.home() / "audit.jsonl"


def enabled(tier: str) -> bool:
    cfg = config.load().audit
    if cfg.get("enabled") is False or os.environ.get("AISB_AUDIT") == "off":
        return False
    return tier != "read" or bool(cfg.get("reads"))


def redact(value: Any, key: str = "") -> Any:
    if key and SECRET_KEY.search(key):
        return "***"
    if isinstance(value, Mapping):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = list(value)
        if key in ("env", "Env") and all(isinstance(x, str) for x in items):
            return redact_env(items)
        return [redact(v) for v in items]
    return value


def _digest(prev: str, rec: Mapping[str, Any]) -> str:
    body = json.dumps({k: v for k, v in rec.items() if k not in ("hash",)}, sort_keys=True, default=str)
    return hashlib.sha256((prev + body).encode()).hexdigest()


def _last_hash(fh: Any) -> str:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    window = 65536
    while True:  # widen the tail window until it holds the whole last record (records can exceed 64 KiB)
        start = max(0, size - window)
        fh.seek(start)
        lines = [line for line in fh.read().splitlines() if line.strip()]
        if start == 0 or len(lines) > 1:
            break
        window *= 4
    if not lines:
        return GENESIS
    try:
        return json.loads(lines[-1]).get("hash") or GENESIS
    except ValueError:
        return GENESIS


def record(*, op: str, tier: str, args: Mapping[str, Any], ctx: Ctx, endpoint: str | None, ok: bool,
           error: str | None, ms: int, extra: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    if not enabled(tier):
        return None
    rec: dict[str, Any] = {"ts": round(time.time(), 3), **ctx.fields(), "endpoint": endpoint, "op": op, "tier": tier,
                           "args": redact(dict(args)), "ok": ok, "error": error, "ms": ms, **(extra or {})}
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _LOCK, open(p, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            rec["prev"] = _last_hash(fh)
            rec["hash"] = _digest(rec["prev"], rec)
            fh.seek(0, os.SEEK_END)
            fh.write(json.dumps(rec, default=str) + "\n")
            fh.flush()
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
    os.chmod(p, 0o600)
    _mirror(rec)
    return rec


def _mirror(rec: Mapping[str, Any]) -> None:
    target = config.load().audit.get("syslog")
    if not target:
        return
    logger = _SYSLOG.get(target)
    if logger is None:
        try:  # connecting can fail (tcp refused, unresolvable host): never after the change has already happened
            if target.startswith(("udp://", "tcp://")):
                import socket
                host, sep, port = target.split("://", 1)[1].rpartition(":")
                if not sep:  # "udp://logs.internal": no port given
                    host, port = port, ""
                handler = logging.handlers.SysLogHandler(
                    (host, int(port or 514)),
                    socktype=socket.SOCK_STREAM if target.startswith("tcp") else socket.SOCK_DGRAM)
            else:
                handler = logging.handlers.SysLogHandler(target)
        except (OSError, ValueError):
            return
        # named by target, and emptied first: loggers are process-global, so a counter-based name could hand
        # a reloaded config the previous target's handler too
        logger = logging.getLogger(f"aisb.audit.syslog.{target}")
        for old in list(logger.handlers):
            logger.removeHandler(old)
            old.close()
        logger.propagate, logger.level = False, logging.INFO
        logger.addHandler(handler)
        _SYSLOG[target] = logger
    try:
        logger.info("aisb: %s", json.dumps({k: v for k, v in rec.items() if k not in ("prev", "hash")}, default=str))
    except OSError:
        pass  # the local log is authoritative; the mirror is best-effort


def read(p: Path | None = None) -> Iterator[dict[str, Any]]:
    yield from state.read_jsonl(p or path())


def verify(p: Path | None = None) -> dict[str, Any]:
    prev, n = GENESIS, 0
    for n, rec in enumerate(read(p), 1):
        if rec.get("prev") != prev:
            return {"ok": False, "records": n, "broken_at": n, "reason": "chain broken: a record was removed or reordered"}
        if _digest(prev, rec) != rec.get("hash"):
            return {"ok": False, "records": n, "broken_at": n, "reason": "record content was modified"}
        prev = rec["hash"]
    return {"ok": True, "records": n, "head": prev}
