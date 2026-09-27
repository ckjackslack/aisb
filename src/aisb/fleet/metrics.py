"""Fleet metrics history in sqlite3: record status samples, then trends, forecasts and uptime/SLO reports."""

import fnmatch
import json
import os
import sqlite3
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

from .. import state

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts REAL NOT NULL, host TEXT NOT NULL, verdict TEXT NOT NULL, load REAL, cpus INTEGER, mem_free_pct REAL,
    disk_pct REAL, running INTEGER, total INTEGER, reasons TEXT
);
CREATE INDEX IF NOT EXISTS samples_host_ts ON samples (host, ts);
"""
DAY = 86400.0


def path() -> Path:
    return Path(os.environ["AISB_METRICS"]).expanduser() if os.environ.get("AISB_METRICS") else state.home() / "metrics.db"


def connect(p: Path | None = None) -> sqlite3.Connection:
    db = sqlite3.connect(p or path(), timeout=30)
    db.executescript(SCHEMA)
    return db


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def record(rows: Iterable[Mapping[str, Any]], *, ts: float | None = None, retention_days: float = 30,
           p: Path | None = None) -> int:
    """Store one `fleet status` row per host; prune samples older than the retention."""
    ts = ts or time.time()
    data = []
    for r in rows:
        running, _, total = str(r.get("containers") or "").partition("/")
        data.append((ts, r["host"], r["verdict"], r.get("load"), r.get("cpus"), r.get("mem_free_pct"),
                     r.get("disk_pct"), _int(running), _int(total), json.dumps(r.get("reasons") or [])))
    with closing(connect(p)) as db, db:
        db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?)", data)
        db.execute("DELETE FROM samples WHERE ts < ?", (ts - retention_days * DAY,))
    return len(data)


def samples(*, since: float, hosts: Sequence[str] | None = None, p: Path | None = None) -> dict[str, list[dict[str, Any]]]:
    with closing(connect(p)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM samples WHERE ts >= ? ORDER BY host, ts", (since,)).fetchall()
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if hosts is None or any(fnmatch.fnmatchcase(r["host"], h) for h in hosts):
            out.setdefault(r["host"], []).append({**dict(r), "reasons": json.loads(r["reasons"] or "[]")})
    return out


def linear_fit(xs: Sequence[float], ys: Sequence[float]) -> tuple[float, float] | None:
    """Least squares y = a + b*x; None when x doesn't vary."""
    n = len(xs)
    if n < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return my - b * mx, b


def forecast_full(points: Sequence[tuple[float, float]], *, limit: float = 100.0,
                  min_span: float = 3600.0) -> dict[str, Any] | None:
    """When does a growing percentage reach `limit`? Needs >= 3 points over >= min_span seconds."""
    pts = sorted((t, v) for t, v in points if v is not None)
    if len(pts) < 3 or pts[-1][0] - pts[0][0] < min_span:
        return None
    fit = linear_fit([t for t, _ in pts], [v for _, v in pts])
    if fit is None:
        return None
    a, b = fit
    per_day = b * DAY
    now, last = pts[-1][0], pts[-1][1]
    if b <= 0:
        return {"per_day": round(per_day, 3), "days_left": None, "trend": "flat or shrinking"}
    days = (limit - (a + b * now)) / per_day
    return {"per_day": round(per_day, 3), "days_left": round(max(days, 0.0), 1), "trend": "growing",
            "at": time.strftime("%Y-%m-%d", time.localtime(now + max(days, 0) * DAY)), "last": last}


def summarize(host: str, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    verdicts = [r["verdict"] for r in rows]
    n = len(rows)
    share = lambda v: round(100 * verdicts.count(v) / n, 2) if n else None  # noqa: E731
    vals = lambda k: [r[k] for r in rows if r[k] is not None]  # noqa: E731
    avg = lambda xs: round(sum(xs) / len(xs), 2) if xs else None  # noqa: E731
    loads, mem, disk = vals("load"), vals("mem_free_pct"), vals("disk_pct")
    reasons: dict[str, int] = {}
    for r in rows:
        for reason in r["reasons"]:
            key = reason.split(":")[0] if reason.startswith("container ") else reason.split(" ")[0]
            reasons[key] = reasons.get(key, 0) + 1
    return {
        "host": host, "samples": n, "from": rows[0]["ts"] if rows else None, "to": rows[-1]["ts"] if rows else None,
        "uptime_pct": round(100 - (share("down") or 0), 2) if n else None,
        "healthy_pct": share("healthy"), "degraded_pct": share("degraded"), "failing_pct": share("failing"),
        "load": {"avg": avg(loads), "max": max(loads) if loads else None},
        "mem_free_pct": {"avg": avg(mem), "min": min(mem) if mem else None},
        "disk_pct": {"last": disk[-1] if disk else None,
                     "forecast": forecast_full([(r["ts"], r["disk_pct"]) for r in rows])},
        "top_reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])[:5]),
        "last_verdict": verdicts[-1] if verdicts else None,
    }
