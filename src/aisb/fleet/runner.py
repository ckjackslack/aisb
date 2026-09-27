"""Connect to a host's Docker (SSH tunnel, direct endpoint, or local) and fan work out over many hosts."""

import contextvars
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..errors import DockerError, DockerUnavailable
from .inventory import Host
from .ssh import Forwarder, Ssh, Tunnel, Unreachable, local_run

if TYPE_CHECKING:
    from ..client import Docker


class Pool:
    """One Docker tunnel (+ lazy port forwards) per SSH host, shared by every call inside `pooled()`.

    Fan-outs and `fleet watch` open a pool, so a host costs one SSH handshake per command instead of one per
    request or per poll. Dead tunnels are reopened transparently.
    """

    def __init__(self) -> None:
        self._conns: dict[tuple[Any, ...], tuple[Tunnel, Forwarder]] = {}
        self._locks: dict[tuple[Any, ...], threading.Lock] = {}
        self._guard = threading.Lock()

    @staticmethod
    def key(host: Host) -> tuple[Any, ...]:
        return host.name, host.ssh, host.port, host.key, host.socket, host.ssh_options

    def get(self, host: Host) -> tuple[str, Forwarder]:
        k = self.key(host)
        with self._guard:
            lock = self._locks.setdefault(k, threading.Lock())
        with lock:
            hit = self._conns.get(k)
            if hit and hit[0].alive:
                return hit[0].path, hit[1]
            if hit:
                hit[0].close()
                hit[1].close()
            ssh = Ssh.of(host)
            conn = (Tunnel.open(ssh, host.socket), Forwarder(ssh))
            self._conns[k] = conn
            return conn[0].path, conn[1]

    def close(self) -> None:
        with self._guard:
            for tunnel, fwd in self._conns.values():
                fwd.close()
                tunnel.close()
            self._conns.clear()


_POOL: contextvars.ContextVar[Pool | None] = contextvars.ContextVar("aisb_fleet_pool", default=None)


@contextmanager
def pooled() -> Iterator[Pool]:
    """Reuse connections for the duration of the block (nested calls share the outermost pool)."""
    if (existing := _POOL.get()) is not None:
        yield existing
        return
    pool = Pool()
    token = _POOL.set(pool)
    try:
        yield pool
    finally:
        _POOL.reset(token)
        pool.close()


@contextmanager
def docker(host: Host, *, timeout: float = 60.0) -> Iterator["Docker"]:
    from ..client import Docker  # late: aisb.client imports the api package, which imports this module
    if not host.ssh:
        yield Docker(host.docker, timeout=timeout)
        return
    with pooled() as pool:
        sock, fwd = pool.get(host)
        d = Docker(f"unix://{sock}", timeout=timeout)
        d.transport.dialer = fwd  # http/wait/brokers dial containers through SSH, from the host's viewpoint
        yield d


def shell(host: Host, command: str, *, stdin: bytes | None = None, timeout: float = 60.0) -> tuple[int, str, str]:
    """Run a command on the machine itself; tcp-only hosts have no shell."""
    if host.transport == "tcp":
        raise Unreachable(f"{host.name} is reached over {host.docker} only (no ssh): no shell access")
    proc = Ssh.of(host).run(command, stdin=stdin, timeout=timeout) if host.ssh else \
        local_run(command, stdin=stdin, timeout=timeout)
    return proc.returncode, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")


@dataclass(slots=True)
class HostResult:
    host: str
    ok: bool
    ms: int
    result: Any = None
    error: str | None = None
    transient: bool = False     # connection-level failure: safe to retry when nothing ran yet
    attempts: int = 1

    def row(self) -> dict[str, Any]:
        out: dict[str, Any] = {"host": self.host, "ok": self.ok, "ms": self.ms}
        out.update({"result": self.result} if self.ok else {"error": self.error})
        if self.attempts > 1:
            out["attempts"] = self.attempts
        return out


def _one(host: Host, fn: Callable[[Host], Any]) -> HostResult:
    from .. import context
    from ..policy import PolicyDenied
    t0 = time.monotonic()
    try:
        with context.use(host=host):
            res = fn(host)
        ok = not (isinstance(res, dict) and res.get("ok") is False)
        return HostResult(host.name, ok, int((time.monotonic() - t0) * 1000), res,
                          None if ok else str(res.get("reason") or res.get("error") or "condition not met"))
    except Unreachable as e:  # raised before anything ran on the host (SSH / tunnel setup)
        return HostResult(host.name, False, int((time.monotonic() - t0) * 1000), error=str(e), transient=True)
    except (DockerError, ValueError, OSError, PolicyDenied) as e:
        msg = e.as_dict()["message"] if isinstance(e, DockerError) else str(e)
        if isinstance(e, (DockerUnavailable, ConnectionError)) and host.ssh:
            msg += f" (is Docker running on {host.name}, and may {host.ssh} open {host.socket}? docker group)"
        return HostResult(host.name, False, int((time.monotonic() - t0) * 1000), error=msg)


def _attempt(host: Host, fn: Callable[[Host], Any], retries: int, host_timeout: float | None) -> HostResult:
    """Run one host with retries (transient failures only) under an optional wall-clock deadline."""
    deadline = time.monotonic() + host_timeout if host_timeout else None
    for n in range(1, retries + 2):
        if host_timeout:
            box: list[HostResult] = []
            ctx = contextvars.copy_context()
            worker = threading.Thread(target=lambda: box.append(ctx.run(_one, host, fn)), daemon=True)
            worker.start()
            worker.join(max(0.0, deadline - time.monotonic()) if deadline else None)
            res = box[0] if box else HostResult(host.name, False, int(host_timeout * 1000),
                                                error=f"timed out after {host_timeout:g}s")
        else:
            res = _one(host, fn)
        res.attempts = n
        if res.ok or not res.transient or n > retries or (deadline and time.monotonic() >= deadline):
            return res
        time.sleep(min(2 ** (n - 1), 10))
    return res


def fan_out(hosts: Sequence[Host], fn: Callable[[Host], Any], *, parallel: int = 8, batch: int | None = None,
            fail_fast: bool = False, retries: int = 0,
            host_timeout: float | None = None) -> tuple[list[HostResult], list[str]]:
    """Run fn per host over pooled connections.

    batch=N: rolling, N hosts at a time; fail_fast: don't start batches after a failure; retries: re-run a host
    whose connection could not be set up (nothing ran there yet); host_timeout: per-host wall-clock limit.
    Returns (results in host order, hosts skipped)."""
    size = batch or len(hosts) or 1
    results: list[HostResult] = []
    skipped: list[str] = []
    with pooled(), ThreadPoolExecutor(max_workers=max(1, min(parallel, size))) as pool:
        for i in range(0, len(hosts), size):
            chunk = hosts[i:i + size]
            if fail_fast and any(not r.ok for r in results):
                skipped += [h.name for h in chunk]
                continue
            # each worker runs in a copy of the caller's context (user, ticket, run id, pool); _one adds the host
            ctxs = [contextvars.copy_context() for _ in chunk]
            results += list(pool.map(lambda pair: pair[0].run(_attempt, pair[1], fn, retries, host_timeout),
                                     zip(ctxs, chunk)))
    return results, skipped


def summary(results: Sequence[HostResult], skipped: Sequence[str] = ()) -> dict[str, Any]:
    return {"hosts": len(results) + len(skipped), "ok": sum(r.ok for r in results),
            "failed": [r.host for r in results if not r.ok], **({"skipped": list(skipped)} if skipped else {})}
