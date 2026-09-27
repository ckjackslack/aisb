"""Monitoring: metrics history + forecasts, SLO reports, alert sinks, Prometheus exporter."""

import json
import os
import re
import shutil
import tempfile
import textwrap
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aisb import config, notify
from aisb.cli import EXIT_OK, main
from aisb.exporter import Collector, Exposition, fleet_metrics, serve
from aisb.fleet import metrics
from conftest import FakeDaemon, Reply

DAY = 86400


def row(host: str, verdict: str = "healthy", disk: float | None = 50.0, **kw) -> dict:
    return {"host": host, "verdict": verdict, "load": 0.5, "cpus": 4, "mem_free_pct": 60.0, "disk_pct": disk,
            "containers": "3/4", "reasons": kw.get("reasons", []), **kw}


# --- metrics math -------------------------------------------------------------------------------

def test_linear_fit_and_forecast():
    assert metrics.linear_fit([0, 1, 2], [1, 3, 5]) == (1.0, 2.0)
    assert metrics.linear_fit([1, 1], [1, 2]) is None
    now = time.time()
    growing = [(now - 3 * DAY + i * DAY, 70 + 5 * i) for i in range(4)]   # +5%/day, 85% now -> 3 days left
    f = metrics.forecast_full(growing)
    assert f["trend"] == "growing" and f["per_day"] == pytest.approx(5, abs=0.01) and f["days_left"] == pytest.approx(3, abs=0.1)
    flat = [(now - i * DAY, 40.0) for i in range(4)]
    assert metrics.forecast_full(flat)["days_left"] is None
    assert metrics.forecast_full(growing[:2]) is None                     # too few points
    assert metrics.forecast_full([(now + i, 1.0 + i) for i in range(5)]) is None   # span too short


def test_record_samples_retention_and_summary(tmp_path):
    db = tmp_path / "m.db"
    now = time.time()
    metrics.record([row("a", disk=80)], ts=now - 40 * DAY, p=db)
    for i, v in enumerate(["healthy", "healthy", "down", "degraded"]):
        metrics.record([row("a", v, disk=80 + i, reasons=["disk / 8x%"] if v == "degraded" else []), row("b")],
                       ts=now - (3 - i) * DAY, p=db)
    data = metrics.samples(since=now - 100 * DAY, p=db)
    assert len(data["a"]) == 4                                               # the 40-day-old sample was pruned
    s = metrics.summarize("a", data["a"])
    assert (s["uptime_pct"], s["healthy_pct"], s["degraded_pct"]) == (75.0, 50.0, 25.0)
    assert s["disk_pct"]["forecast"]["days_left"] == pytest.approx(17, abs=0.5)  # 83% now, +1%/day
    assert metrics.samples(since=now - 100 * DAY, hosts=["b*"], p=db).keys() == {"b"}


# --- fleet ops over fake daemons ---------------------------------------------------------------------

@pytest.fixture
def fleet(tmp_path, monkeypatch, capsys):
    d = Path(tempfile.mkdtemp(prefix="aisb-m-", dir="/tmp"))
    a = FakeDaemon(d / "a.sock")
    a.start()
    a.on("GET", "/info", json={"ContainersRunning": 1, "Containers": 2})
    a.on("GET", "/containers/json", json=[])
    a.on("GET", "/images/json", json=[])
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"a": {"docker": f"unix://{a.sock}"},
                                         "gone": {"docker": f"unix://{d}/missing.sock"}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        code = main([*argv, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    yield run
    a.stop()
    shutil.rmtree(d, ignore_errors=True)


def test_status_record_then_trends_and_report(fleet):
    assert fleet("fleet", "status", "--record")[1]["recorded"] == 2
    now = time.time()
    metrics.record([row("a", disk=50 + i) for i in range(1)], ts=now - 2 * DAY)
    code, tr, _ = fleet("fleet", "trends", "--since", "7d")
    assert code == EXIT_OK and {h["host"] for h in tr["hosts"]} == {"a", "gone"}
    code, rep, _ = fleet("fleet", "report", "--since", "30d", "--slo", "99")
    assert rep["below_slo"] == ["gone"] and rep["fleet_uptime_pct"] is not None


# --- sinks against a real local HTTP server ------------------------------------------------------------

@pytest.fixture
def hook():
    got: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append({"path": self.path, "headers": dict(self.headers), "body": body})
            self.send_response(200)
            self.end_headers()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    yield f"http://127.0.0.1:{srv.server_address[1]}", got
    srv.shutdown()


def sinks(url: str) -> None:
    Path(os.environ["AISB_CONFIG"]).write_text(textwrap.dedent(f"""
        [notify.hook]
        type = "webhook"
        url = "{url}/hook"
        [notify.slack]
        type = "slack"
        url_env = "TEST_SLACK_URL"
        [notify.phone]
        type = "ntfy"
        url = "{url}/topic"
        min_level = "failing"
        [notify.mail]
        type = "email"
        smtp = "mail.test:587"
        from = "aisb@test"
        to = ["ops@test"]
        user = "aisb"
        password_env = "TEST_SMTP_PW"
    """))
    config.reset()


def test_webhook_slack_ntfy(hook, monkeypatch):
    url, got = hook
    sinks(url)
    monkeypatch.setenv("TEST_SLACK_URL", f"{url}/slack")
    msg = notify.Message("disk full soon", "web1: 91%", "failing", {"host": "web1"})
    assert notify.send("hook", msg)["sent"] and notify.send("slack", msg)["sent"] and notify.send("phone", msg)["sent"]
    by = {g["path"]: g for g in got}
    assert json.loads(by["/hook"]["body"])["data"] == {"host": "web1"}
    assert "*disk full soon*" in json.loads(by["/slack"]["body"])["text"]
    assert by["/topic"]["headers"]["Priority"] == "high" and by["/topic"]["body"] == b"web1: 91%"
    assert notify.send("phone", notify.Message("fyi", "x", "info"))["sent"] is False     # below min_level


def test_email_via_smtp_boundary(monkeypatch):
    sinks("http://unused")
    monkeypatch.setenv("TEST_SMTP_PW", "s3cret")
    sent: dict = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["addr"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context):
            sent["tls"] = True

        def login(self, user, pw):
            sent["login"] = (user, pw)

        def send_message(self, m):
            sent["msg"] = m
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    notify.send("mail", notify.Message("db1 down", "unreachable", "down"))
    assert sent["addr"] == ("mail.test", 587) and sent["tls"] and sent["login"] == ("aisb", "s3cret")
    assert sent["msg"]["Subject"] == "[aisb:down] db1 down" and sent["msg"]["To"] == "ops@test"


def test_fan_isolates_failures(hook, monkeypatch):
    url, got = hook
    sinks(url)
    monkeypatch.delenv("TEST_SLACK_URL", raising=False)
    out = notify.fan(["slack", "hook", "nope"], notify.Message("t", "x", "failing"))
    assert [o["sent"] for o in out] == [False, True, False]
    assert "TEST_SLACK_URL is not set" in out[0]["error"] and "unknown notify sink" in out[2]["error"]


def test_status_notify_only_when_unhealthy(fleet, hook):
    url, got = hook
    sinks(url)
    code, out, _ = fleet("fleet", "status", "a", "--notify", "hook")
    assert "notified" not in out and not got                        # all healthy: silence
    code, out, _ = fleet("fleet", "status", "--notify", "hook", "--fail-on", "down")
    assert out["notified"][0]["sent"] and "gone: down" in json.loads(got[0]["body"])["text"]


def test_notify_send_dry_run_hides_secrets(fleet, monkeypatch):
    sinks("http://hooks.example.com")
    monkeypatch.setenv("TEST_SLACK_URL", "https://hooks.slack.com/services/T0/B0/SECRET")
    code, out, _ = fleet("notify", "send", "slack", "--title", "deploy done", "--dry-run")
    assert code == EXIT_OK and out["planned"] == [{"notify": "slack", "to": "hooks.slack.com", "title": "deploy done",
                                                   "level": "info"}]
    assert "SECRET" not in json.dumps(out)


# --- exporter ----------------------------------------------------------------------------------------

_SAMPLE = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*",?)*\})? -?[0-9.e+-]+$')


def test_exposition_format():
    text = fleet_metrics([row("web1"), {**row("db\"1"), "verdict": "down", "reasons": ["x"]}], duration=1.5)
    for line in text.splitlines():
        assert line.startswith("# ") or _SAMPLE.match(line), line
    assert text.count("# TYPE aisb_host_up gauge") == 1
    assert 'aisb_host_up{host="db\\"1"} 0' in text and 'aisb_host_verdict{host="web1",verdict="healthy"} 1' in text
    e = Exposition()
    e.add("x", None)
    assert e.render() == "\n"


def test_exporter_serves_last_refresh():
    calls = {"n": 0}

    def refresh() -> str:
        calls["n"] += 1
        return fleet_metrics([row("a")])
    c = Collector(refresh, interval=60)
    threading.Thread(target=c.loop, daemon=True).start()
    srv = serve(c, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        deadline = time.time() + 5
        while calls["n"] == 0 and time.time() < deadline:
            time.sleep(0.02)
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/metrics", timeout=5) as r:
            body = r.read().decode()
            assert r.headers["Content-Type"].startswith("text/plain; version=0.0.4")
        assert 'aisb_host_up{host="a"} 1' in body
    finally:
        c.stop()
        srv.shutdown()
