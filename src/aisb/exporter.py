"""`aisb exporter`: Prometheus metrics for a fleet (or the local daemon), refreshed in the background.

    aisb exporter --port 9323 --target @prod --interval 30      # scrape http://HOST:9323/metrics
    aisb exporter --local                                        # containers of the local daemon only

Plugs aisb's triage into existing monitoring (Prometheus, VictoriaMetrics, Grafana Agent...) without an agent on
any host. Metrics are served from the last refresh, so scrapes are instant and never pile up SSH sessions.
"""

import argparse
import json
import re
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

VERDICTS = ("healthy", "degraded", "failing", "down")


def _esc(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_:]", "_", s)


class Exposition:
    """Collects samples and renders the Prometheus text format (HELP/TYPE once per family)."""

    def __init__(self) -> None:
        self.families: dict[str, tuple[str, str, list[str]]] = {}

    def add(self, name: str, value: float | int | None, labels: Mapping[str, Any] | None = None, *,
            help_: str = "", kind: str = "gauge") -> None:
        if value is None:
            return
        name = _name(name)
        fam = self.families.setdefault(name, (help_, kind, []))
        lab = ",".join(f'{_name(k)}="{_esc(v)}"' for k, v in (labels or {}).items())
        fam[2].append(f"{name}{{{lab}}} {float(value):g}" if lab else f"{name} {float(value):g}")

    def render(self) -> str:
        out = []
        for name, (help_, kind, lines) in self.families.items():
            out += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}", *lines]
        return "\n".join(out) + "\n"


def fleet_metrics(rows: Iterable[Mapping[str, Any]], *, duration: float | None = None) -> str:
    e = Exposition()
    for r in rows:
        h = {"host": r["host"]}
        e.add("aisb_host_up", 0 if r["verdict"] == "down" else 1, h, help_="1 if SSH and Docker answered")
        for v in VERDICTS:
            e.add("aisb_host_verdict", 1 if r["verdict"] == v else 0, {**h, "verdict": v},
                  help_="current verdict (one-hot)")
        e.add("aisb_host_load1", r.get("load"), h, help_="1-minute load average")
        e.add("aisb_host_cpus", r.get("cpus"), h, help_="online CPUs")
        if r.get("mem_free_pct") is not None:
            e.add("aisb_host_memory_available_ratio", r["mem_free_pct"] / 100, h, help_="MemAvailable / MemTotal")
        if r.get("disk_pct") is not None:
            e.add("aisb_host_disk_used_ratio", r["disk_pct"] / 100, h, help_="root filesystem usage")
        running, _, total = str(r.get("containers") or "").partition("/")
        if running.isdigit() and total.isdigit():
            e.add("aisb_host_containers", int(running), {**h, "state": "running"}, help_="containers by state")
            e.add("aisb_host_containers", int(total), {**h, "state": "all"})
        e.add("aisb_host_reasons", len(r.get("reasons") or []), h, help_="number of reasons behind the verdict")
    e.add("aisb_scrape_duration_seconds", duration, help_="time the last refresh took")
    e.add("aisb_last_refresh_timestamp_seconds", time.time(), help_="unix time of the last refresh")
    return e.render()


def local_metrics(report: Mapping[str, Any], *, duration: float | None = None) -> str:
    e = Exposition()
    for v in ("failing", "degraded", "healthy"):
        e.add("aisb_containers_by_verdict", report["summary"].get(v, 0), {"verdict": v}, help_="containers per verdict")
    for p in report.get("problems", []):
        e.add("aisb_container_problem", 1, {"container": p["container"], "verdict": p["verdict"],
                                            "cause": p.get("likely_cause") or ""}, help_="a container needing attention")
    e.add("aisb_scrape_duration_seconds", duration, help_="time the last refresh took")
    return e.render()


class Collector:
    def __init__(self, refresh: Callable[[], str], interval: float) -> None:
        self.refresh, self.interval = refresh, interval
        self.text = "# aisb exporter: first refresh pending\n"
        self.error: str | None = None
        self._stop = threading.Event()

    def loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.text, self.error = self.refresh(), None
            except Exception as e:  # noqa: BLE001 - keep serving the last good data
                self.error = f"{type(e).__name__}: {e}"
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()


def serve(collector: Collector, bind: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_GET(self) -> None:
            if self.path.split("?")[0] == "/metrics":
                body = collector.text.encode()
                if collector.error:
                    body += f"# last refresh failed: {collector.error}\n".encode()
                ctype = "text/plain; version=0.0.4; charset=utf-8"
            elif self.path == "/healthz":
                body, ctype = json.dumps({"ok": collector.error is None, "error": collector.error}).encode(), \
                    "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    return srv


def main(argv: list[str] | None = None) -> int:
    from .client import Docker
    p = argparse.ArgumentParser(prog="aisb exporter", description="Prometheus metrics for a fleet or the local daemon")
    p.add_argument("--port", type=int, default=9323)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--interval", type=float, default=30.0, help="seconds between refreshes")
    p.add_argument("--target", default="all", help="fleet selector")
    p.add_argument("--inventory", help="inventory file (default: $AISB_FLEET or ~/.aisb/fleet.json)")
    p.add_argument("--local", action="store_true", help="export the local daemon's containers instead of a fleet")
    p.add_argument("--tail", type=int, default=0, help="log lines scanned per container by the triage")
    p.add_argument("--record", action="store_true", help="also store each refresh in the metrics history")
    args = p.parse_args(argv)
    d = Docker(timeout=120)

    def refresh() -> str:
        t0 = time.monotonic()
        if args.local:
            rep = d.system.doctor(tail=args.tail)
            return local_metrics(rep, duration=time.monotonic() - t0)
        from .fleet import metrics
        from .fleet.inventory import Inventory
        rows = d.fleet._status(Inventory.load(args.inventory).select(args.target), doctor=True, tail=args.tail,
                               parallel=16)
        if args.record:
            metrics.record(rows)
        return fleet_metrics(rows, duration=time.monotonic() - t0)

    collector = Collector(refresh, args.interval)
    threading.Thread(target=collector.loop, daemon=True).start()
    srv = serve(collector, args.bind, args.port)
    print(json.dumps({"url": f"http://{args.bind}:{srv.server_address[1]}/metrics", "interval": args.interval,
                      "mode": "local" if args.local else f"fleet {args.target}"}), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
