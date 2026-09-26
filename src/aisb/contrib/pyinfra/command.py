"""Build `python3 aisb.pyz RESOURCE OP ...` shell commands from Python arguments, validated against the registry."""

import shlex
from collections.abc import Iterable, Mapping
from typing import Any

from ...ops import Op, Tier, get_op
from . import PYTHON, PYZ


def flags(options: Mapping[str, Any]) -> list[str]:
    """{"within": 60, "no_wait": True, "env": ["A=1"]} -> --within 60 --no-wait --env A=1."""
    out: list[str] = []
    for key, value in options.items():
        flag = "--" + key.replace("_", "-")
        if value is None or value is False:
            continue
        if value is True:
            out.append(flag)
        elif isinstance(value, (list, tuple)):
            for item in value:
                out += [flag, str(item)]
        elif isinstance(value, Mapping):
            for k, v in value.items():
                out += [flag, f"{k}={v}"]
        else:
            out += [flag, str(value)]
    return out


def resolve(resource: str, op: str) -> Op:
    try:
        return get_op(f"{resource}.{op}")
    except (KeyError, ValueError) as e:
        raise ValueError(f"unknown aisb op {resource}.{op}") from e


def argv(resource: str, op: str, args: Iterable[Any] = (), options: Mapping[str, Any] | None = None, *,
         cmd: Iterable[str] = (), confirm: bool = False) -> list[str]:
    o = resolve(resource, op)
    tail = [str(a) for a in args] + flags(options or {})
    if confirm:
        if o.tier is not Tier.DESTROY:
            raise ValueError(f"{o.qualname} is {o.tier} tier; confirm only applies to destroy ops")
        tail.append("--yes")
    cmd = list(cmd)
    return [resource, op, *tail, "--json", *(["--", *cmd] if cmd else [])]


def shell(parts: list[str], *, pyz: str = PYZ, python: str = PYTHON, tolerate_missing: bool = False) -> str:
    """The shell line. Exit 4 (condition not met, `"ok": false` on stdout) is left to the caller.

    With tolerate_missing, a host without the bundle yet prints `null` instead of failing: facts gathered
    before `install` has run then read as "nothing there", and the deploy plans the full change.
    """
    run = shlex.join([python, pyz, *parts])
    if tolerate_missing:
        return f"if [ -f {shlex.quote(pyz)} ]; then {run}; else echo null; fi"
    return run
