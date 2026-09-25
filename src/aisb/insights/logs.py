"""Log fingerprinting: collapse thousands of lines into a few ranked templates."""

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

Level = Literal["error", "warn", "info", "debug", "other"]
SEVERITY: dict[str, int] = {"error": 4, "warn": 3, "info": 2, "debug": 1, "other": 0}

_MASKS = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<time>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b(?=[0-9a-f]*\d)[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"(?<![\w<])[-+]?\d+(?:\.\d+)?(?:ms|us|ns|s|m|h|[kmg]i?b|b|%)?(?![\w>])", re.I), "<n>"),
)
_LEVELS = (
    ("error", re.compile(r"\b(?:fatal|critical|crit|panic|error|err|exception|failed|failure)\b|^Traceback|^\s+at \S+\(", re.I)),
    ("warn", re.compile(r"\b(?:warn|warning|deprecated)\b", re.I)),
    ("info", re.compile(r"\b(?:info|notice)\b", re.I)),
    ("debug", re.compile(r"\b(?:debug|trace)\b", re.I)),
)
_SPACE = re.compile(r"\s+")


def _masked(line: str) -> tuple[str, dict[str, list[str]]]:
    """Template plus the raw values each mask token replaced, in order."""
    captured: dict[str, list[str]] = {}
    for rx, token in _MASKS:
        def keep(m: re.Match[str], token: str = token) -> str:
            captured.setdefault(token, []).append(m.group(0))
            return token
        line = rx.sub(keep, line)
    return _SPACE.sub(" ", line).strip(), captured


def template(line: str) -> str:
    """Mask the variable parts of a log line so that repeated events share one key."""
    return _masked(line)[0]


def level_of(line: str) -> Level:
    return next((name for name, rx in _LEVELS if rx.search(line)), "other")  # type: ignore[return-value]


_NUM = re.compile(r"[-+]?\d+(?:\.\d+)?")
_ID_TOKENS = ("<uuid>", "<hex>", "<ip>")


@dataclass(slots=True)
class Slot:
    """Running stats for one numeric position in a template."""
    unit: str
    first: float
    last: float
    lo: float
    hi: float

    def add(self, v: float) -> None:
        self.last, self.lo, self.hi = v, min(self.lo, v), max(self.hi, v)

    def as_dict(self, i: int) -> dict[str, Any]:
        trend = "up" if self.first == self.lo and self.last == self.hi else \
                "down" if self.first == self.hi and self.last == self.lo else None
        return {"slot": i, "unit": self.unit, "first": self.first, "last": self.last,
                "min": self.lo, "max": self.hi, **({"trend": trend} if trend else {})}


@dataclass(slots=True)
class Pattern:
    template: str
    level: Level
    count: int
    first_line: int
    last_line: int
    sample: str
    slots: list[Slot] = field(default_factory=list)
    ids: dict[str, set[str]] = field(default_factory=dict)

    def observe(self, values: dict[str, list[str]]) -> None:
        for i, raw in enumerate(values.get("<n>", ())):
            v = float(m.group(0)) if (m := _NUM.match(raw)) else 0.0
            if i < len(self.slots):
                self.slots[i].add(v)
            elif i == len(self.slots):
                self.slots.append(Slot(raw[m.end():] if m else "", v, v, v, v))
        for token in _ID_TOKENS:
            if token in values and len(seen := self.ids.setdefault(token, set())) < 50:
                seen.update(values[token])

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"template": self.template, "level": self.level, "count": self.count,
                               "first_line": self.first_line, "last_line": self.last_line, "sample": self.sample}
        if self.count >= 3 and (varying := [s.as_dict(i) for i, s in enumerate(self.slots) if s.lo != s.hi]):
            out["numbers"] = varying
        if self.count >= 2 and (same := {t[1:-1]: next(iter(v)) for t, v in self.ids.items() if len(v) == 1}):
            out["repeated_ids"] = same  # the same id recurring: retries, a stuck job, or one hot key
        return out


def fingerprint(lines: Sequence[str], *, top: int = 20, min_level: Level = "other",
                emerging_tail: float = 0.1) -> dict[str, Any]:
    """Group lines by template; rank by severity, then frequency.

    'emerging' lists templates first seen in the last `emerging_tail` fraction of the log:
    the new behaviour right before the end, which is usually where a crash is.
    Numeric slots that vary report first/last/min/max and a monotonic trend; ids that never change are flagged.
    """
    groups: dict[str, Pattern] = {}
    for i, raw in enumerate(lines, 1):
        if not (line := raw.rstrip()):
            continue
        key, values = _masked(line)
        if p := groups.get(key):
            p.count, p.last_line = p.count + 1, i
        else:
            p = groups[key] = Pattern(key, level_of(line), 1, i, i, line[:300])
        p.observe(values)
    floor = SEVERITY[min_level]
    kept = [p for p in groups.values() if SEVERITY[p.level] >= floor]
    ranked = sorted(kept, key=lambda p: (-SEVERITY[p.level], -p.count, p.first_line))
    cutoff = len(lines) * (1 - emerging_tail)
    emerging = [p for p in kept if p.first_line > cutoff and len(lines) >= 20]
    levels: Counter[str] = Counter()
    for p in groups.values():
        levels[p.level] += p.count
    return {
        "lines": len(lines),
        "patterns": len(groups),
        "levels": dict(levels),
        "top": [p.as_dict() for p in ranked[:top]],
        "emerging": [p.template for p in sorted(emerging, key=lambda p: p.first_line)][:top],
    }


def grep(lines: Sequence[str], pattern: str, context: int = 0) -> str:
    """grep -n -C: numbered matches with context; non-adjacent blocks separated by '--'."""
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"invalid regex {pattern!r}: {e}") from None
    keep: set[int] = set()
    for i, line in enumerate(lines):
        if rx.search(line):
            keep.update(range(max(0, i - context), min(len(lines), i + context + 1)))
    out: list[str] = []
    prev = None
    for i in sorted(keep):
        if prev is not None and i != prev + 1:
            out.append("--")
        out.append(f"{i + 1}:{lines[i]}")
        prev = i
    return "\n".join(out) + ("\n" if out else "")
