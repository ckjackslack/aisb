"""Policy guardrails: organisation rules evaluated in `invoke()` before any op runs (and shown in previews).

    [[policy.rules]]
    name = "prod destroy needs a ticket"
    match = { tier = "destroy", hosts = "@prod" }
    require = { ticket = true }

A rule applies when every `match` field holds; its effect is `deny`, `require`, `window` or `deny_if`.
`mode = "warn"` reports without blocking. Pure evaluation: `check(rules, op, kwargs, ctx, now)`.
"""

import datetime as dt
import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from .context import Ctx

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


@dataclass(frozen=True, slots=True)
class Violation:
    rule: str
    reason: str
    mode: str = "deny"   # deny | warn

    def row(self) -> dict[str, str]:
        return asdict(self)


class PolicyDenied(Exception):
    def __init__(self, op: str, violations: Sequence[Violation]) -> None:
        self.op, self.violations = op, list(violations)
        super().__init__(f"{op} denied by policy: " + "; ".join(f"[{v.rule}] {v.reason}" for v in violations))

    def as_dict(self) -> dict[str, Any]:
        return {"error": "PolicyDenied", "message": str(self), "op": self.op,
                "violations": [v.row() for v in self.violations]}


def _many(v: Any) -> list[str]:
    return [] if v is None else [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]


_LOCAL = ("local", "all", "*")


def _local_matches(expr: str) -> bool:
    """A selector evaluated for the local endpoint, which has no groups or labels: it is selected by `local`,
    `all` or `*` (or by exclusions alone), and removed by `!local`/`!all` or by any `&` intersection."""
    from .fleet.inventory import _TERM
    terms = [(op, atom.strip()) for op, atom in _TERM.findall(expr) if atom.strip()]
    plain = [atom for op, atom in terms if op not in ("&", "!", "&!")]
    chosen = any(a in _LOCAL for a in plain) if plain else True
    for op, atom in terms:
        if op == "&" and atom not in _LOCAL or op in ("!", "&!") and atom in _LOCAL:
            chosen = False
    return chosen


def _host_matches(expr: str, ctx: Ctx) -> bool:
    if ctx.host is None:
        return _local_matches(expr)
    from .fleet.inventory import Inventory
    try:
        inv = Inventory.load()
        if ctx.host.name not in inv.hosts:
            inv = Inventory({ctx.host.name: ctx.host}, {g: m for g, m in inv.groups.items()})
        return ctx.host.name in {h.name for h in inv.select(expr)}
    except ValueError:
        return False


def matches(match: Mapping[str, Any], op: str, tier: str, ctx: Ctx) -> bool:
    if (ops := _many(match.get("op"))) and not any(fnmatch.fnmatchcase(op, p) for p in ops):
        return False
    if (tiers := _many(match.get("tier"))) and tier not in tiers:
        return False
    if (sources := _many(match.get("source"))) and ctx.source not in sources:
        return False
    if (users := _many(match.get("user"))) and not any(fnmatch.fnmatchcase(ctx.user, u) for u in users):
        return False
    if (hosts := ",".join(_many(match.get("hosts")))) and not _host_matches(hosts, ctx):  # a list is a union
        return False
    return True


def image_of(kwargs: Mapping[str, Any]) -> str | None:
    for key in ("image", "ref"):
        v = kwargs.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def tag_of(image: str) -> str:
    if "@" in image:
        return "digest"
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else "latest"


def _conditions(cond: Mapping[str, Any], kwargs: Mapping[str, Any], op: str) -> list[str]:
    hits = []
    image = image_of(kwargs) if op.startswith(("containers.run", "images.pull", "fleet.ship", "images.tag")) else None
    vols = [str(v) for v in kwargs.get("volume") or kwargs.get("volumes") or [] if isinstance(v, str)] \
        if not isinstance(kwargs.get("volumes"), bool) else []
    if cond.get("privileged") and kwargs.get("privileged") is True:
        hits.append("privileged containers are not allowed")
    if (tags := _many(cond.get("image_tag"))) and image and tag_of(image) in tags:
        hits.append(f"image tag {tag_of(image)!r} is not allowed ({image})")
    if (globs := _many(cond.get("image"))) and image and any(fnmatch.fnmatchcase(image, g) for g in globs):
        hits.append(f"image {image} is not allowed")
    if cond.get("host_network") and kwargs.get("network") == "host":
        hits.append("host networking is not allowed")
    if cond.get("docker_socket") and any("docker.sock" in v for v in vols):
        hits.append("mounting the Docker socket is not allowed")
    if cond.get("volumes") and kwargs.get("volumes") is True:
        hits.append("deleting volume data (--volumes) is not allowed")
    if cond.get("force") and kwargs.get("force") is True:
        hits.append("--force is not allowed")
    return hits


def in_window(window: Mapping[str, Any], now: dt.datetime) -> bool:
    tz = window.get("tz")
    if tz:
        try:
            from zoneinfo import ZoneInfo
            now = now.astimezone(ZoneInfo(tz))
        except Exception:  # noqa: BLE001 - no tzdata: fall back to the given clock
            pass
    if (days := [d.lower()[:3] for d in _many(window.get("days"))]) and DAYS[now.weekday()] not in days:
        return False
    if hours := window.get("hours"):
        start, _, end = str(hours).partition("-")
        h = now.hour + now.minute / 60
        lo, hi = float(start), float(end or 24)
        if not (lo <= h < hi if lo <= hi else h >= lo or h < hi):  # windows may wrap midnight: "22-06"
            return False
    return True


# How you find out why something is denied: a broad rule (e.g. "every op needs a ticket") must not lock these
# away. A rule that names one of them in `match.op` still applies (e.g. hiding the audit log from agents).
GOVERNANCE_READS = frozenset({"policy.rules", "policy.check", "audit.log", "audit.verify", "config.show"})


def check(rules: Iterable[Mapping[str, Any]], op: str, tier: str, kwargs: Mapping[str, Any], ctx: Ctx,
          now: dt.datetime | None = None) -> list[Violation]:
    now = now or dt.datetime.now(dt.UTC)
    out: list[Violation] = []
    for i, rule in enumerate(rules):
        name, mode = str(rule.get("name") or f"rule-{i + 1}"), str(rule.get("mode") or "deny")
        match = rule.get("match") or {}
        if op in GOVERNANCE_READS and "op" not in match:
            continue
        if not matches(match, op, tier, ctx):
            continue
        reasons: list[str] = []
        if rule.get("deny"):
            reasons.append(str(rule.get("message") or f"{op} is not allowed here"))
        req = rule.get("require") or {}
        if req.get("ticket") and not ctx.ticket:
            reasons.append("a change ticket is required (--ticket or $AISB_TICKET)")
        if (pattern := req.get("ticket_pattern")) and ctx.ticket and not re.fullmatch(pattern, ctx.ticket):
            reasons.append(f"ticket {ctx.ticket!r} does not match {pattern}")
        if (window := rule.get("window")) and not in_window(window, now):
            reasons.append(f"outside the change window {dict(window)}")
        reasons += _conditions(rule.get("deny_if") or {}, kwargs, op)
        out += [Violation(name, r, mode) for r in reasons]
    return out


def enforce(op: str, tier: str, kwargs: Mapping[str, Any], ctx: Ctx) -> list[Violation]:
    """Evaluate the configured rules; raise PolicyDenied on blocking violations, return warnings."""
    from . import config
    found = check(config.load().policy, op, tier, kwargs, ctx)
    if denied := [v for v in found if v.mode != "warn"]:
        raise PolicyDenied(op, denied)
    return found
