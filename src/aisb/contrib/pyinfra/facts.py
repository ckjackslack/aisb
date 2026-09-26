"""aisb read ops as pyinfra facts. Only read-tier ops are accepted: gathering a fact can never change a host.

    from aisb.contrib.pyinfra.facts import Aisb, AisbDoctor
    host.get_fact(AisbDoctor)["summary"]
    host.get_fact(Aisb, "db", "query", args=["pg", "select count(*) from orders"])

Each fact is `None` on a host where the bundle isn't installed yet (see `operations.install`).
"""

import json
from typing import Any

from pyinfra.api import FactBase

from ...ops import Tier
from ...stack import STACK_KEY
from . import PYTHON, PYZ
from .command import argv, resolve, shell


class AisbFactBase(FactBase):
    """pyinfra binds fact arguments by the `command` signature, so each fact spells its parameters out."""
    abstract = True

    def requires_command(self, *args: Any, python: str = PYTHON, **kwargs: Any) -> str:
        return python

    @staticmethod
    def _run(parts: list[str], pyz: str, python: str) -> str:
        # exit 4 = "condition not met": the JSON on stdout says why, so it's a fact, not a failure
        return shell(parts, pyz=pyz, python=python, tolerate_missing=True) + " || [ $? -eq 4 ]"

    def process(self, output: list[str]) -> Any:
        text = "\n".join(output).strip()
        return json.loads(text) if text else None


class Aisb(AisbFactBase):
    """Any read-tier op: `host.get_fact(Aisb, "db", "query", args=["pg", "select 1"], options={"limit": 5})`."""

    def command(self, resource: str, op: str, args: list[Any] | None = None, options: dict[str, Any] | None = None,
                pyz: str = PYZ, python: str = PYTHON) -> str:
        if (o := resolve(resource, op)).tier is not Tier.READ:
            raise ValueError(f"{o.qualname} is {o.tier} tier; facts are read-only (use operations.call)")
        return self._run(argv(resource, op, args or (), options), pyz, python)


class AisbDoctor(AisbFactBase):
    """Fleet triage (`system doctor`): summary, problems worst first, healthy containers."""

    def command(self, tail: int = 200, pyz: str = PYZ, python: str = PYTHON) -> str:
        return self._run(argv("system", "doctor", (), {"tail": tail}), pyz, python)


class AisbServices(AisbFactBase):
    """Services detected inside containers (`svc list`), connection URLs with secrets masked."""

    def command(self, pyz: str = PYZ, python: str = PYTHON) -> str:
        return self._run(argv("svc", "list"), pyz, python)


class AisbContainer(AisbFactBase):
    """`containers inspect REF`; `fields="HostConfig,State"` keeps it small. None when it doesn't exist."""

    def command(self, ref: str, fields: str | None = None, pyz: str = PYZ, python: str = PYTHON) -> str:
        line = shell(argv("containers", "inspect", [ref], {"fields": fields}), pyz=pyz, python=python,
                     tolerate_missing=True)
        return f"{line} 2>/dev/null || echo null"


class AisbStack(AisbFactBase):
    """Every container of an aisb stack, with labels (service name, config hash) and state."""

    def command(self, stack: str, pyz: str = PYZ, python: str = PYTHON) -> str:
        return self._run(argv("containers", "list", (), {"all": True, "label": [f"{STACK_KEY}={stack}"]}), pyz, python)
