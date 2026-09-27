"""Host vitals (one POSIX script, parsed here), health assessment, and change detection. Pure except PROBE."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Verdict = Literal["healthy", "degraded", "failing", "down"]
RANK: dict[str, int] = {"healthy": 0, "degraded": 1, "failing": 2, "down": 3}

PROBE = r"""
echo '@@load'; cat /proc/loadavg 2>/dev/null
echo '@@cpus'; nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null
echo '@@mem'; cat /proc/meminfo 2>/dev/null
echo '@@disk'; df -Pk / 2>/dev/null | tail -n 1
echo '@@uptime'; cat /proc/uptime 2>/dev/null
echo '@@os'; cat /etc/os-release 2>/dev/null
echo '@@kernel'; uname -r 2>/dev/null
"""


@dataclass(slots=True)
class Vitals:
    load1: float | None = None
    cpus: int | None = None
    mem_total: int | None = None      # bytes
    mem_available: int | None = None
    disk_used_pct: float | None = None
    disk_free: int | None = None
    uptime_s: int | None = None
    os: str | None = None
    kernel: str | None = None

    @property
    def mem_available_pct(self) -> float | None:
        return round(self.mem_available / self.mem_total * 100, 1) if self.mem_total and self.mem_available is not None else None

    def row(self) -> dict[str, Any]:
        return {**asdict(self), "mem_available_pct": self.mem_available_pct}


def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = out.setdefault(line[2:].strip(), [])
        elif cur is not None and line.strip():
            cur.append(line)
    return out


def parse(text: str) -> Vitals:
    s, v = _sections(text), Vitals()
    if s.get("load"):
        v.load1 = float(s["load"][0].split()[0])
    if s.get("cpus") and s["cpus"][0].strip().isdigit():
        v.cpus = int(s["cpus"][0])
    mem = {k.strip(): int(rest.split()[0]) * 1024 for k, _, rest in (line.partition(":") for line in s.get("mem", []))
           if rest.split() and rest.split()[0].isdigit()}
    v.mem_total = mem.get("MemTotal")
    v.mem_available = mem.get("MemAvailable", (mem.get("MemFree", 0) + mem.get("Cached", 0)) if mem else None)
    if s.get("disk"):
        parts = s["disk"][0].split()
        if len(parts) >= 5 and parts[4].rstrip("%").isdigit():
            v.disk_used_pct, v.disk_free = float(parts[4].rstrip("%")), int(parts[3]) * 1024
    if s.get("uptime"):
        v.uptime_s = int(float(s["uptime"][0].split()[0]))
    osr = dict(line.split("=", 1) for line in s.get("os", []) if "=" in line)
    v.os = (osr.get("PRETTY_NAME") or osr.get("NAME") or "").strip('"') or None
    v.kernel = s["kernel"][0].strip() if s.get("kernel") else None
    return v


@dataclass(slots=True)
class Assessment:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)


def assess(vitals: Vitals | None, doctor: Mapping[str, Any] | None, *, error: str | None = None) -> Assessment:
    """Host verdict from vitals and `system doctor` output. `error` = unreachable."""
    if error:
        return Assessment("down", [error[:200]])
    failing: list[str] = []
    degraded: list[str] = []
    for p in (doctor or {}).get("problems", []):
        why = p.get("likely_cause") or (p.get("findings") or ["?"])[0].split(": ", 1)[-1]
        (failing if p["verdict"] == "failing" else degraded).append(f"container {p['container']} {p['verdict']}: {why}")
    if v := vitals:
        if v.disk_used_pct is not None:
            (failing if v.disk_used_pct >= 90 else degraded if v.disk_used_pct >= 80 else []).append(
                f"disk / {v.disk_used_pct:g}%")
        if (pct := v.mem_available_pct) is not None:
            (failing if pct < 5 else degraded if pct < 10 else []).append(f"memory available {pct:g}%")
        if v.load1 is not None and v.cpus and v.load1 / v.cpus >= 2:
            degraded.append(f"load {v.load1:g} on {v.cpus} cpus")
    verdict: Verdict = "failing" if failing else "degraded" if degraded else "healthy"
    return Assessment(verdict, failing + degraded)


def changes(prev: Mapping[str, Mapping[str, Any]], cur: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Diff two {host: {"verdict", "reasons"}} snapshots into events (worse/better/new reasons/resolved)."""
    events: list[dict[str, Any]] = []
    for host in sorted(prev.keys() | cur.keys()):
        a, b = prev.get(host), cur.get(host)
        if a == b:
            continue
        if a is None or b is None:
            events.append({"host": host, "change": "added" if a is None else "removed"})
            continue
        new, gone = sorted(set(b["reasons"]) - set(a["reasons"])), sorted(set(a["reasons"]) - set(b["reasons"]))
        if a["verdict"] == b["verdict"] and not new and not gone:
            continue
        kind = ("recovered" if a["verdict"] == "down" else "better") if RANK[b["verdict"]] < RANK[a["verdict"]] else \
            ("went down" if b["verdict"] == "down" else "worse") if RANK[b["verdict"]] > RANK[a["verdict"]] else "changed"
        events.append({"host": host, "change": kind, "from": a["verdict"], "to": b["verdict"],
                       "new": new, "resolved": gone})
    return events
