"""Invocation context: who is acting, from where, on which host. Consumed by policy, audit and session capture.

A `contextvars` value, so it flows through calls without threading it through every signature. Fleet worker
threads get a copy (see `aisb.fleet.runner.fan_out`), each with its own `host`.
"""

import getpass
import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .fleet.inventory import Host


def _user() -> str:
    try:
        return os.environ.get("AISB_USER") or getpass.getuser()
    except (KeyError, OSError):
        return "unknown"


@dataclass(frozen=True, slots=True)
class Ctx:
    user: str
    source: str = "api"            # cli | mcp | portal | runbook | fleet | api
    host: "Host | None" = None     # fleet host an inner op runs on; None = the local endpoint
    ticket: str | None = None
    run_id: str | None = None

    def fields(self) -> dict[str, Any]:
        return {"user": self.user, "source": self.source, "host": self.host.name if self.host else None,
                "ticket": self.ticket, "run_id": self.run_id}


_CTX: ContextVar[Ctx | None] = ContextVar("aisb_ctx", default=None)


def current() -> Ctx:
    return _CTX.get() or Ctx(_user(), ticket=os.environ.get("AISB_TICKET") or None)


@contextmanager
def use(**changes: Any) -> Iterator[Ctx]:
    """Temporarily refine the context: `with context.use(source="mcp"): ...`."""
    ctx = replace(current(), **{k: v for k, v in changes.items() if v is not None or k == "host"})
    token = _CTX.set(ctx)
    try:
        yield ctx
    finally:
        _CTX.reset(token)
