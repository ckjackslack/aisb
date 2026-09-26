"""Resource right-sizing: turn raw stats samples into usage percentiles, limit recommendations and flags."""

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

MIB = 1 << 20
MIN_MEMORY = 32 * MIB


@dataclass(frozen=True, slots=True)
class Sample:
    t: float
    cpu_total: int      # container CPU time, ns
    system_total: int   # host CPU time, ns
    ncpu: int
    memory: int         # usage minus page cache
    mem_limit: int
    pids: int
    net: int            # rx + tx bytes, cumulative
    block: int          # read + write bytes, cumulative

    @classmethod
    def from_api(cls, s: dict[str, Any], t: float) -> "Sample":
        cpu, mem = s.get("cpu_stats") or {}, s.get("memory_stats") or {}
        ms = mem.get("stats") or {}
        cache = ms.get("inactive_file", ms.get("cache", 0))
        blk = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
        return cls(
            t=t, cpu_total=(cpu.get("cpu_usage") or {}).get("total_usage", 0),
            system_total=cpu.get("system_cpu_usage", 0),
            ncpu=cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1,
            memory=max(mem.get("usage", 0) - cache, 0), mem_limit=mem.get("limit", 0),
            pids=(s.get("pids_stats") or {}).get("current") or 0,
            net=sum(n.get("rx_bytes", 0) + n.get("tx_bytes", 0) for n in (s.get("networks") or {}).values()),
            block=sum(b.get("value", 0) for b in blk if b.get("op", "").lower() in ("read", "write")))


@dataclass(frozen=True, slots=True)
class Limits:
    memory: int = 0      # bytes, 0 = unlimited
    nano_cpus: int = 0   # 1e9 = one CPU, 0 = unlimited
    pids: int = 0

    @classmethod
    def from_host_config(cls, hc: dict[str, Any]) -> "Limits":
        cpus = hc.get("NanoCpus") or 0
        if not cpus and (hc.get("CpuQuota") or 0) > 0:
            cpus = int(hc["CpuQuota"] / (hc.get("CpuPeriod") or 100_000) * 1e9)
        return cls(hc.get("Memory") or 0, cpus, max(hc.get("PidsLimit") or 0, 0))


@dataclass(slots=True)
class Report:
    name: str
    samples: int
    memory: dict[str, int]
    cpu_percent: dict[str, float]
    pids_max: int
    net_bps: float
    block_bps: float
    limits: dict[str, Any]
    recommend: dict[str, Any]
    flags: list[str] = field(default_factory=list)
    command: str | None = None


def percentile(values: Sequence[float], p: float) -> float:
    """Nearest-rank percentile; 0 for no data."""
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(math.ceil(p / 100 * len(ordered)) - 1, 0)]


def ceil_to(value: float, step: float) -> float:
    return math.ceil(value / step - 1e-9) * step


def cpu_series(samples: Sequence[Sample]) -> list[float]:
    """CPU % (100 = one full core) between successive samples."""
    out = []
    for a, b in zip(samples, samples[1:]):
        sys_delta = b.system_total - a.system_total
        if sys_delta > 0:
            out.append(max(b.cpu_total - a.cpu_total, 0) / sys_delta * b.ncpu * 100)
    return out


def human(n: int) -> str:
    return f"{n // (1 << 30)}g" if n % (1 << 30) == 0 else f"{math.ceil(n / MIB)}m"


def recommend(name: str, samples: Sequence[Sample], limits: Limits, *, headroom: float = 0.3) -> Report:
    mem = [s.memory for s in samples]
    cpu = cpu_series(samples)
    span = (samples[-1].t - samples[0].t) if len(samples) > 1 else 0
    rate = (lambda attr: (getattr(samples[-1], attr) - getattr(samples[0], attr)) / span if span else 0.0)
    peak, p95cpu = max(mem, default=0), percentile(cpu, 95)
    rec_mem = max(int(ceil_to(peak * (1 + headroom), 16 * MIB)), MIN_MEMORY)
    rec_cpus = max(ceil_to(p95cpu / 100 * (1 + headroom), 0.25), 0.25)
    rec_pids = max(int(ceil_to(max((s.pids for s in samples), default=0) * 2, 64)), 64)
    net_bps, blk_bps = rate("net"), rate("block")
    avg_cpu = sum(cpu) / len(cpu) if cpu else 0.0

    flags = []
    if limits.memory and peak > 0.8 * limits.memory:
        flags.append("at-risk")
    if (limits.memory and limits.memory > 3 * rec_mem) or (limits.nano_cpus and limits.nano_cpus > 3 * rec_cpus * 1e9):
        flags.append("over-provisioned")
    if not limits.memory or not limits.nano_cpus:
        flags.append("unlimited")
    if len(cpu) and avg_cpu < 0.5 and net_bps == 0:
        flags.append("idle")

    report = Report(
        name=name, samples=len(samples),
        memory={"avg": int(sum(mem) / len(mem)) if mem else 0, "p95": int(percentile(mem, 95)), "peak": peak},
        cpu_percent={"avg": round(avg_cpu, 2), "p95": round(p95cpu, 2), "max": round(max(cpu, default=0.0), 2)},
        pids_max=max((s.pids for s in samples), default=0), net_bps=round(net_bps, 1), block_bps=round(blk_bps, 1),
        limits={"memory": limits.memory or None, "cpus": limits.nano_cpus / 1e9 or None, "pids": limits.pids or None},
        recommend={"memory": human(rec_mem), "memory_bytes": rec_mem, "cpus": rec_cpus, "pids": rec_pids},
        flags=flags)
    if {"at-risk", "over-provisioned", "unlimited"} & set(flags):
        report.command = f"aisb containers limit {name} --memory {human(rec_mem)} --cpus {rec_cpus:g} --pids {rec_pids}"
    return report
