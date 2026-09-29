"""Append-only, hash-chained audit log of changes made through aisb (JSONL, optional syslog mirror).

Each record carries `prev` (the previous record's hash) and `hash` = sha256(prev + canonical record), so
`verify()` detects edited, reordered or deleted lines. Writes are serialized across threads and processes.

The plain chain can be recomputed by anyone who can write the file, and dropping the newest records leaves a valid
chain. Two optional layers close that:
- a signing key (`[audit] key`, `$AISB_AUDIT_KEY`): each record gets `kid` and `mac` = HMAC-SHA256(key, hash), so
  rewriting needs the key, not just write access to the log;
- anchors (`audit anchor`): a signed `{records, head}` checkpoint kept elsewhere; `verify(anchors=...)` then
  proves the log still holds that exact prefix, so truncation and wholesale rewrites before it are caught.
"""

import fcntl
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import threading
import time
from collections.abc import Iterable, Iterator, Mapping
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


def key_path() -> Path | None:
    p = os.environ.get("AISB_AUDIT_KEY") or config.load().audit.get("key")
    return Path(p).expanduser() if p else None


def load_key() -> bytes | None:
    """The configured signing key, or None when signing is off. A missing, empty or group/world-readable key
    file is an error: a key anyone can read signs nothing."""
    p = key_path()
    if p is None:
        return None
    try:
        if p.stat().st_mode & 0o077:
            raise ValueError(f"audit key {p} is readable by others; chmod 600 it")
        key = p.read_bytes().strip()
    except FileNotFoundError:
        raise ValueError(f"audit key {p} not found (create one with `aisb audit keygen {p}`)") from None
    if len(key) < 32:
        raise ValueError(f"audit key {p} is too short (need at least 32 bytes; `aisb audit keygen` makes one)")
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"aisb-audit-kid:" + key).hexdigest()[:12]


def _mac(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


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
    body = json.dumps({k: v for k, v in rec.items() if k not in ("hash", "mac")}, sort_keys=True, default=str)
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
    try:
        key = load_key()
    except (OSError, ValueError) as e:  # the change already happened: keep the record, and let verify flag it
        key, rec["unsigned"] = None, str(e)
    if key is not None:
        rec["kid"] = key_id(key)
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _LOCK, open(p, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            rec["prev"] = _last_hash(fh)
            rec["hash"] = _digest(rec["prev"], rec)
            if key is not None:
                rec["mac"] = _mac(key, rec["hash"])
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
        # named by target, and emptied first: loggers are process-global, so a fresh cache (a reset in tests,
        # a re-imported module) must not inherit an earlier handler
        logger = logging.getLogger(f"aisb.audit.syslog.{target}")
        for old in list(logger.handlers):
            logger.removeHandler(old)
            old.close()
        logger.propagate, logger.level = False, logging.INFO
        logger.addHandler(handler)
        _SYSLOG[target] = logger
    try:
        logger.info("aisb: %s", json.dumps({k: v for k, v in rec.items() if k not in ("prev", "hash", "mac")},
                                          default=str))
    except OSError:
        pass  # the local log is authoritative; the mirror is best-effort


def read(p: Path | None = None) -> Iterator[dict[str, Any]]:
    yield from state.read_jsonl(p or path())


def verify(p: Path | None = None, *, anchors: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Walk the chain; with a key, check every signature; with anchors, check the log still holds each one.

    Unsigned records are accepted only before the first signed one (a log that predates the key); after it, an
    unsigned record means signing was stripped or failed, and says why when it failed."""
    key = load_key()
    kid = key_id(key) if key else None
    want: dict[int, list[Mapping[str, Any]]] = {}
    for a in anchors:
        want.setdefault(int(a["records"]), []).append(a)
    prev, n, signed = GENESIS, 0, 0

    def fail(reason: str) -> dict[str, Any]:
        return {"ok": False, "records": n, "broken_at": n, "reason": reason}
    for n, rec in enumerate(read(p), 1):
        if rec.get("prev") != prev:
            return fail("chain broken: a record was removed or reordered")
        if _digest(prev, rec) != rec.get("hash"):
            return fail("record content was modified")
        if rec.get("unsigned"):
            return fail(f"record was not signed: {rec['unsigned']}")
        if (mac := rec.get("mac")) is None:
            if signed:
                return fail("unsigned record after signing began: signatures were stripped")
        else:
            signed += 1
            if key is not None and rec.get("kid") != kid:
                return fail(f"signed with another key (kid {rec.get('kid')}, configured {kid})")
            if key is not None and not hmac.compare_digest(str(mac), _mac(key, rec["hash"])):
                return fail("signature does not match: the record was forged or re-chained")
        prev = rec["hash"]
        if bad := _anchors_mismatch(want.get(n, ()), prev, key):
            return fail(bad)
    if bad := _anchors_mismatch(want.get(0, ()), GENESIS, key):
        return {"ok": False, "records": n, "broken_at": 0, "reason": bad}
    if beyond := [r for r in want if r > n]:
        return {"ok": False, "records": n, "broken_at": n + 1,
                "reason": f"the log has {n} records but an anchor holds {max(beyond)}: newer records were removed"}
    out: dict[str, Any] = {"ok": True, "records": n, "head": prev}
    if key is not None or signed:
        out["signed"] = signed
        out["unsigned"] = n - signed
        out["signatures"] = f"checked with key {kid}" if key else "not checked: no key configured"
    if want:
        out["anchors"] = sum(map(len, want.values()))
    return out


def _anchors_mismatch(anchors: Iterable[Mapping[str, Any]], head: str, key: bytes | None) -> str | None:
    for a in anchors:
        if a.get("head") != head:
            return f"record {a['records']} differs from its anchor: the log was rewritten"
        if key is None or a.get("mac") is None:
            continue
        if a.get("kid") != key_id(key):
            return f"anchor for record {a['records']} was signed with another key (kid {a.get('kid')})"
        if not hmac.compare_digest(str(a["mac"]), _mac(key, _anchor_msg(a))):
            return f"anchor for record {a['records']} has a bad signature: the anchor itself was altered"
    return None


def _anchor_msg(a: Mapping[str, Any]) -> str:
    return f"aisb-audit-anchor:{int(a['records'])}:{a['head']}:{a.get('ts')}"


def anchor(p: Path | None = None) -> dict[str, Any]:
    """A checkpoint of the current log ({records, head}, signed when a key is configured) to store elsewhere.
    Returns the verify failure instead when the chain is already broken: anchoring a tampered log proves nothing."""
    v = verify(p)
    if not v["ok"]:
        return v
    a: dict[str, Any] = {"records": v["records"], "head": v["head"], "ts": round(time.time(), 3)}
    if key := load_key():
        a["kid"], a["mac"] = key_id(key), _mac(key, _anchor_msg(a))
    return a


def read_anchors(p: Path) -> list[dict[str, Any]]:
    """Anchors appended to a file (`aisb audit anchor >> anchors.jsonl`): JSON objects, or lists of them, in a row."""
    text, items, i, dec = p.expanduser().read_text(), [], 0, json.JSONDecoder()
    while (i := len(text) - len(text[i:].lstrip())) < len(text):
        value, i = dec.raw_decode(text, i)
        items += value if isinstance(value, list) else [value]
    for a in items:
        if not isinstance(a, dict) or not isinstance(a.get("records"), int) or not isinstance(a.get("head"), str):
            raise ValueError(f"{p}: not an audit anchor (want {{\"records\": N, \"head\": \"...\"}}): {a!r}"[:300])
    return items


def keygen(out: Path) -> dict[str, Any]:
    """Write a new random key, owner-only, never over an existing file."""
    out = out.expanduser()
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import secrets
    key = secrets.token_hex(32).encode()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key + b"\n")
    return {"key": str(out), "kid": key_id(key)}
