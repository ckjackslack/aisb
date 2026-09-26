"""pyinfra operations backed by aisb on the target host. State-checked ops only emit commands when needed.

    from aisb.contrib.pyinfra import operations as aisb

    aisb.install()                                            # upload the bundle (re-uploaded only on change)
    aisb.stack(src="stacks/shop.json", recreate_drifted=True) # up, gated on readiness; noop when converged
    aisb.limits(container="shop-api", memory="256m", cpus=0.5)
    aisb.ready(container="shop-db", within=120)               # fail the deploy unless the service really works
    aisb.call("session", "begin")                             # anything else; destroy needs confirm=True
"""

import io
from typing import Any

from pyinfra import host, logger
from pyinfra.api import OperationError, operation
from pyinfra.operations import files

from ... import bundle
from ... import stack as stk
from ...models import parse_size
from . import PYTHON, PYZ
from .command import argv, shell
from .facts import AisbContainer, AisbStack

_BUNDLE: bytes | None = None


def _bundle() -> bytes:
    global _BUNDLE
    if _BUNDLE is None:
        _BUNDLE = bundle.build()
    return _BUNDLE


@operation()
def install(path: str = PYZ):
    """Upload aisb as a single .pyz (needs python3 >= 3.11 on the host, nothing else).

    The bundle is deterministic, so pyinfra's checksum comparison skips the upload until aisb changes.
    """
    yield from files.put._inner(src=io.BytesIO(_bundle()), dest=path, mode="755")


def _plan(s: stk.Stack, rows: list[dict[str, Any]] | None) -> dict[str, list[str]]:
    by_service = {(r.get("labels") or {}).get(stk.SERVICE_KEY): r for r in rows or []}
    plan: dict[str, list[str]] = {"missing": [], "stopped": [], "drift": [], "ok": []}
    for name in s.order:
        r = by_service.get(name)
        if r is None:
            plan["missing"].append(name)
        elif (r.get("labels") or {}).get(stk.HASH_KEY) != s.services[name].digest:
            plan["drift"].append(name)
        elif r.get("state") != "running":
            plan["stopped"].append(name)
        else:
            plan["ok"].append(name)
    return plan


@operation()
def stack(src: str, present: bool = True, recreate_drifted: bool = False, volumes: bool = False,
          within: float = 120.0, remote_dir: str = "/etc/aisb/stacks", pyz: str = PYZ, python: str = PYTHON):
    """Converge an aisb stack file on the host.

    + src: local stack JSON (validated here, before anything touches the host)
    + present: False removes the stack's containers and network
    + recreate_drifted: recreate services whose config changed (otherwise drift is reported and left alone);
      passing it is the approval for removing those containers (volumes are kept)
    + volumes: with present=False, also delete the stack's declared volumes (data loss)
    + within: readiness timeout per service; the deploy fails if a service never becomes ready
    """
    s = stk.load(src)
    rows = host.get_fact(AisbStack, s.name, pyz=pyz, python=python)
    run = lambda *parts, **kw: shell(argv(*parts, **kw), pyz=pyz, python=python)  # noqa: E731
    if not present:
        if rows:
            yield run("stack", "down", [s.name], {"volumes": volumes}, confirm=True)
        else:
            host.noop(f"stack {s.name} is not present")
        return
    plan = _plan(s, rows)
    remote = f"{remote_dir.rstrip('/')}/{s.name}.json"
    yield from files.put._inner(src=src, dest=remote)
    if plan["drift"] and not recreate_drifted:
        logger.warning(f"{host.name}: stack {s.name}: config drift in {', '.join(plan['drift'])} "
                       "(left running; pass recreate_drifted=True to recreate)")
    if plan["drift"] and recreate_drifted:
        yield run("stack", "down", [s.name], {"service": plan["drift"]}, confirm=True)
    if plan["missing"] or plan["stopped"] or (plan["drift"] and recreate_drifted):
        # `stack up` exits 4 when a service never becomes ready, which fails this operation
        yield run("stack", "up", [remote], {"within": within})
    else:
        host.noop(f"stack {s.name} is up to date ({len(plan['ok'])} services)")


@operation()
def limits(container: str, memory: str | None = None, cpus: float | None = None, pids: int | None = None,
           pyz: str = PYZ, python: str = PYTHON):
    """Set resource limits in place (no recreate); only emits a change when the live limits differ."""
    info = host.get_fact(AisbContainer, container, fields="HostConfig", pyz=pyz, python=python)
    hc = (info or {}).get("HostConfig") or {}
    unlimited = lambda v: v in (None, 0, -1)  # noqa: E731
    want: dict[str, Any] = {}
    if memory is not None and (parse_size(memory) or 0) != (hc.get("Memory") or 0):
        want["memory"] = memory
    if cpus is not None and int(cpus * 1e9) != (hc.get("NanoCpus") or 0):
        want["cpus"] = cpus
    if pids is not None and not (pids == hc.get("PidsLimit") or unlimited(pids) and unlimited(hc.get("PidsLimit"))):
        want["pids"] = pids
    if want:
        yield shell(argv("containers", "limit", [container], want), pyz=pyz, python=python)
    else:
        host.noop(f"{container} limits already match")


@operation(is_idempotent=False)
def ready(container: str, within: float = 120.0, pyz: str = PYZ, python: str = PYTHON):
    """Deploy gate: succeed only once the service inside really answers (`svc ready`: query, PING, TCP)."""
    yield shell(argv("svc", "ready", [container], {"within": within}), pyz=pyz, python=python)


@operation(is_idempotent=False)
def call(resource: str, op: str, *args: Any, cmd: list[str] | None = None, confirm: bool = False,
         dry_run: bool = False, pyz: str = PYZ, python: str = PYTHON, **options: Any):
    """Run any aisb op: `call("db", "exec", "pg", file="/srv/m.sql")`, `call("containers", "exec", "web",
    cmd=["nginx", "-s", "reload"])`. Destroy-tier ops refuse to run without confirm=True, exactly like `--yes`."""
    from ...ops import Tier
    from .command import resolve
    o = resolve(resource, op)
    if o.tier is Tier.DESTROY and not confirm and not dry_run:
        raise OperationError(f"{o.qualname} is destroy tier: pass confirm=True once the change is approved "
                             f"(or dry_run=True to print the plan)")
    if dry_run and o.tier is Tier.READ:
        raise OperationError(f"{o.qualname} is read tier; there is nothing to dry-run")
    parts = argv(resource, op, args, {**options, "dry_run": dry_run or None}, cmd=cmd or (),
                 confirm=confirm and o.tier is Tier.DESTROY)
    yield shell(parts, pyz=pyz, python=python)


__all__ = ["call", "install", "limits", "ready", "stack"]
