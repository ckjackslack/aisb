"""Connect to a host's Docker (SSH tunnel, direct endpoint, or local) and fan work out over many hosts."""

import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..errors import DockerError, DockerUnavailable
from .inventory import Host
from .ssh import Forwarder, Ssh, Unreachable, local_run

if TYPE_CHECKING:
    from ..client import Docker


@contextmanager
def docker(host: Host, *, timeout: float = 60.0) -> Iterator["Docker"]:
    from ..client import Docker  # late: aisb.client imports the api package, which imports this module
    if host.ssh:
        ssh = Ssh.of(host)
        fwd = Forwarder(ssh)
        try:
            with ssh.tunnel(host.socket) as sock:
                d = Docker(f"unix://{sock}", timeout=timeout)
                d.transport.dialer = fwd  # http/wait/brokers dial containers through SSH, from the host's viewpoint
                yield d
        finally:
            fwd.close()
    else:
        yield Docker(host.docker, timeout=timeout)


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

    def row(self) -> dict[str, Any]:
        out: dict[str, Any] = {"host": self.host, "ok": self.ok, "ms": self.ms}
        out.update({"result": self.result} if self.ok else {"error": self.error})
        return out


def _one(host: Host, fn: Callable[[Host], Any]) -> HostResult:
    t0 = time.monotonic()
    try:
        res = fn(host)
        ok = not (isinstance(res, dict) and res.get("ok") is False)
        return HostResult(host.name, ok, int((time.monotonic() - t0) * 1000), res,
                          None if ok else str(res.get("reason") or res.get("error") or "condition not met"))
    except (DockerError, Unreachable, ValueError, OSError) as e:
        msg = e.as_dict()["message"] if isinstance(e, DockerError) else str(e)
        if isinstance(e, (DockerUnavailable, ConnectionError)) and host.ssh:
            msg += f" (is Docker running on {host.name}, and may {host.ssh} open {host.socket}? docker group)"
        return HostResult(host.name, False, int((time.monotonic() - t0) * 1000), error=msg)


def fan_out(hosts: Sequence[Host], fn: Callable[[Host], Any], *, parallel: int = 8, batch: int | None = None,
            fail_fast: bool = False) -> tuple[list[HostResult], list[str]]:
    """Run fn per host. batch=N: rolling, N hosts at a time; fail_fast: don't start batches after a failure.
    Returns (results in host order, hosts skipped)."""
    size = batch or len(hosts) or 1
    results: list[HostResult] = []
    skipped: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, min(parallel, size))) as pool:
        for i in range(0, len(hosts), size):
            chunk = hosts[i:i + size]
            if fail_fast and any(not r.ok for r in results):
                skipped += [h.name for h in chunk]
                continue
            results += list(pool.map(lambda h: _one(h, fn), chunk))
    return results, skipped


def summary(results: Sequence[HostResult], skipped: Sequence[str] = ()) -> dict[str, Any]:
    return {"hosts": len(results) + len(skipped), "ok": sum(r.ok for r in results),
            "failed": [r.host for r in results if not r.ok], **({"skipped": list(skipped)} if skipped else {})}
