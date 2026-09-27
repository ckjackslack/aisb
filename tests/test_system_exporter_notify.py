"""Prometheus exporter (text exposition, HTTP endpoints, CLI entry) and alert sinks (notify + `notify` ops)."""

import json
import os
import re
import socket
import textwrap
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aisb import config, exporter, notify
from aisb.cli import EXIT_OK, EXIT_USAGE, main
from aisb.exporter import Collector, Exposition, fleet_metrics, local_metrics, serve

# One sample line of the text exposition format 0.0.4.
_SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\\n]|\\[\\"n])*",?)*\})? '
                     r'(-?[0-9.]+(e[+-]?[0-9]+)?|[+-]Inf|NaN)$')


def assert_valid_exposition(text: str) -> dict[str, str]:
    """Every line is HELP/TYPE/sample; each family declared once, before its samples; returns family -> type."""
    assert text.endswith("\n")
    types: dict[str, str] = {}
    helped: set[str] = set()
    current = None
    for line in text.splitlines():
        if line.startswith("# HELP "):
            name = line.split()[2]
            assert name not in helped, f"HELP twice for {name}"
            helped.add(name)
            current = name
        elif line.startswith("# TYPE "):
            _, _, name, kind = line.split()
            assert name == current and name not in types and kind in ("gauge", "counter", "untyped")
            types[name] = kind
        else:
            m = _SAMPLE.match(line)
            assert m, line
            assert m.group(1) == current, f"sample {m.group(1)} outside its family block"
    return types


# --- Exposition -------------------------------------------------------------------------------------

def test_exposition_escapes_labels_and_sanitizes_names():
    e = Exposition()
    e.add("my-metric.total", 3, {"path": 'C:\\tmp\\"x"', "multi line": "a\nb"}, help_="demo", kind="counter")
    e.add("my-metric.total", 1.5e-7, {"path": "/"})
    e.add("skipped", None, {"a": "b"}, help_="never rendered")
    e.add("plain", 0)
    text = e.render()
    assert assert_valid_exposition(text) == {"my_metric_total": "counter", "plain": "gauge"}
    assert 'my_metric_total{path="C:\\\\tmp\\\\\\"x\\"",multi_line="a\\nb"} 3' in text
    assert 'my_metric_total{path="/"} 1.5e-07' in text
    assert "plain 0" in text.splitlines() and "skipped" not in text
    assert "# HELP plain \n" in text                     # empty help still yields a HELP line


@pytest.mark.parametrize(("value", "rendered"), [
    (0, "0"), (3.0, "3"), (-2, "-2"), (0.25, "0.25"), (1.5e-7, "1.5e-07"),
    (1790526405.0045033, "1790526405.0045033"),     # was "1.79053e+09" with :g -> timestamp off by ~1h
    (123456789012, "123456789012"),                  # bytes: all digits kept
    (float("inf"), "+Inf"), (float("-inf"), "-Inf"), (float("nan"), "NaN"), (True, "1"),
])
def test_exposition_values_are_exact(value, rendered):
    e = Exposition()
    e.add("v", value)
    assert e.render().splitlines()[-1] == f"v {rendered}"
    assert_valid_exposition(e.render())
    if rendered not in ("+Inf", "-Inf", "NaN"):
        assert float(rendered) == float(value)


def test_exposition_empty():
    assert Exposition().render() == "\n"


def test_fleet_metrics_all_fields():
    rows = [
        {"host": "web1", "verdict": "degraded", "load": 1.25, "cpus": 4, "mem_free_pct": 25.0, "disk_pct": 80.0,
         "containers": "3/5", "reasons": ["disk", "load"]},
        {"host": "db\\1", "verdict": "down", "containers": "?/?", "reasons": None},     # unreachable: sparse row
        {"host": "x", "verdict": "healthy", "containers": None, "mem_free_pct": 0.0},
    ]
    text = fleet_metrics(rows, duration=0.25)
    types = assert_valid_exposition(text)
    assert set(types) >= {"aisb_host_up", "aisb_host_verdict", "aisb_host_containers", "aisb_scrape_duration_seconds",
                          "aisb_last_refresh_timestamp_seconds"}
    lines = set(text.splitlines())
    assert {'aisb_host_up{host="web1"} 1', 'aisb_host_up{host="db\\\\1"} 0',
            'aisb_host_verdict{host="web1",verdict="degraded"} 1', 'aisb_host_verdict{host="web1",verdict="healthy"} 0',
            'aisb_host_memory_available_ratio{host="web1"} 0.25', 'aisb_host_disk_used_ratio{host="web1"} 0.8',
            'aisb_host_containers{host="web1",state="running"} 3', 'aisb_host_containers{host="web1",state="all"} 5',
            'aisb_host_reasons{host="web1"} 2', 'aisb_host_reasons{host="db\\\\1"} 0',
            'aisb_host_memory_available_ratio{host="x"} 0', 'aisb_scrape_duration_seconds 0.25'} <= lines
    assert not any(line.startswith(('aisb_host_load1{host="db', 'aisb_host_containers{host="db',
                                    'aisb_host_containers{host="x"')) for line in lines)
    assert sum(line.startswith('aisb_host_verdict{host="x"') for line in lines) == 4      # one-hot over VERDICTS
    ts = float(next(line for line in lines if line.startswith("aisb_last_refresh")).split()[1])
    assert abs(ts - time.time()) < 60


def test_fleet_metrics_without_duration_has_no_duration_sample():
    assert "aisb_scrape_duration_seconds" not in fleet_metrics([])


def test_local_metrics():
    rep = {"summary": {"failing": 1, "healthy": 3},
           "problems": [{"container": "api", "verdict": "failing", "likely_cause": "oom-killed"},
                        {"container": 'we"ird', "verdict": "degraded", "likely_cause": None}]}
    text = local_metrics(rep, duration=1)
    assert_valid_exposition(text)
    lines = set(text.splitlines())
    assert {'aisb_containers_by_verdict{verdict="failing"} 1', 'aisb_containers_by_verdict{verdict="degraded"} 0',
            'aisb_containers_by_verdict{verdict="healthy"} 3',
            'aisb_container_problem{container="api",verdict="failing",cause="oom-killed"} 1',
            'aisb_container_problem{container="we\\"ird",verdict="degraded",cause=""} 1',
            "aisb_scrape_duration_seconds 1"} <= lines
    assert "aisb_container_problem" not in local_metrics({"summary": {}})


# --- Collector + HTTP -------------------------------------------------------------------------------

def _get(url: str) -> tuple[int, str, str]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.headers["Content-Type"], r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers["Content-Type"], ""


@pytest.fixture
def no_proxy(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def test_collector_keeps_last_good_data_on_error():
    results = iter(["good 1\n"])

    def refresh() -> str:
        try:
            return next(results)
        except StopIteration:
            raise RuntimeError("ssh timed out") from None
    c = Collector(refresh, interval=0)
    c._stop.wait = lambda _t: c.stop() if c.error else None  # two iterations, no real waiting
    c.loop()
    assert (c.text, c.error) == ("good 1\n", "RuntimeError: ssh timed out")


def test_http_endpoints(no_proxy):
    c = Collector(lambda: "x 1\n", interval=60)
    srv = serve(c, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        code, ctype, body = _get(base + "/metrics")
        assert (code, body) == (200, "# aisb exporter: first refresh pending\n")
        assert ctype == "text/plain; version=0.0.4; charset=utf-8"
        assert json.loads(_get(base + "/healthz")[2]) == {"ok": True, "error": None}
        c.text, c.error = "x 1\n", "OSError: boom"
        code, _, body = _get(base + "/metrics?name[]=x")                 # query string ignored
        assert code == 200 and body == "x 1\n# last refresh failed: OSError: boom\n"
        code, ctype, body = _get(base + "/healthz")
        assert ctype == "application/json" and json.loads(body) == {"ok": False, "error": "OSError: boom"}
        assert _get(base + "/")[0] == 404 and _get(base + "/metricsx")[0] == 404
    finally:
        srv.shutdown()
        srv.server_close()


def _drive_main(monkeypatch, capsys, argv: list[str], want: str) -> tuple[str, dict]:
    """Run exporter.main; the (patched) serve loop answers real HTTP requests until `want` shows up, then ^C."""
    got: dict[str, str] = {}

    def serve_forever(self, poll_interval=0.5):
        done = threading.Event()

        def client():
            port = self.server_address[1]
            deadline = time.time() + 10
            while time.time() < deadline:
                got["body"] = _get(f"http://127.0.0.1:{port}/metrics")[2]
                if want in got["body"]:
                    break
                time.sleep(0.02)
            done.set()
            socket.create_connection(("127.0.0.1", port)).close()   # wake the last handle_request
        threading.Thread(target=client, daemon=True).start()
        self.timeout = 0.5
        while not done.is_set():
            self.handle_request()
        raise KeyboardInterrupt
    monkeypatch.setattr(exporter.ThreadingHTTPServer, "serve_forever", serve_forever)
    assert exporter.main(argv) == 0
    return got["body"], json.loads(capsys.readouterr().out.splitlines()[0])


def test_main_local_mode(daemon, host, monkeypatch, capsys, no_proxy):
    monkeypatch.setenv("DOCKER_HOST", host)
    daemon.on("GET", "/containers/json", json=[{"Id": "api", "Names": ["/api"]}])
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", "/containers/api/json", json={
        "Name": "/api", "Config": {"Image": "api:1"}, "HostConfig": {},
        "State": {"Status": "exited", "Running": False, "ExitCode": 137, "OOMKilled": True}})
    body, banner = _drive_main(monkeypatch, capsys, ["--local", "--port", "0", "--interval", "60"],
                               "aisb_container_problem")
    assert banner["mode"] == "local" and banner["url"].endswith("/metrics") and banner["interval"] == 60
    assert_valid_exposition(body)
    assert 'aisb_container_problem{container="api",verdict="failing",cause="oom-killed"} 1' in body
    assert not any(s.path.endswith("/logs") for s in daemon.seen)                   # --tail 0 default


def test_main_fleet_mode_records(daemon, host, monkeypatch, capsys, tmp_path, no_proxy):
    daemon.on("GET", "/info", json={"ContainersRunning": 1, "Containers": 2})
    daemon.on("GET", "/containers/json", json=[])
    daemon.on("GET", "/images/json", json=[])
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"a": {"docker": host, "groups": ["prod"]}}}))
    monkeypatch.setenv("DOCKER_HOST", host)
    body, banner = _drive_main(monkeypatch, capsys, ["--inventory", str(inv), "--target", "@prod", "--record",
                                                     "--port", "0"], "aisb_host_up")
    assert banner["mode"] == "fleet @prod"
    assert_valid_exposition(body)
    assert 'aisb_host_up{host="a"} 1' in body
    from aisb.fleet import metrics
    assert "a" in metrics.samples(since=0)                                          # --record stored it


# --- notify ---------------------------------------------------------------------------------------------

@pytest.fixture
def hook(no_proxy):
    got: list[dict] = []
    status = {"code": 200}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            got.append({"path": self.path, "headers": dict(self.headers),
                        "body": self.rfile.read(int(self.headers["Content-Length"]))})
            self.send_response(status["code"])
            self.send_header("Content-Length", "0")
            self.end_headers()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", got, status
    srv.shutdown()
    srv.server_close()


def configure(toml: str) -> None:
    Path(os.environ["AISB_CONFIG"]).write_text(textwrap.dedent(toml))
    config.reset()


@pytest.mark.parametrize(("level", "icon", "prio"), [
    ("info", ":information_source:", "default"), ("warning", ":warning:", "default"),
    ("degraded", ":warning:", "default"), ("critical", ":rotating_light:", "high"),
    ("down", ":red_circle:", "urgent"), ("bogus", ":information_source:", "default"),
])
def test_payload_levels(level, icon, prio):
    msg = notify.Message("t", "body", level)
    url, body, headers = notify.payload({"type": "slack", "url": "https://h/s"}, msg)
    assert json.loads(body)["text"] == f"{icon} *t*\nbody" and headers == {"Content-Type": "application/json"}
    url, body, headers = notify.payload({"type": "ntfy", "url": "https://n/topic"}, msg)
    assert (url, body, headers) == ("https://n/topic", b"body", {"Title": "t", "Priority": prio, "Tags": level})


def test_webhook_payload_custom_headers_and_data():
    msg = notify.Message("t", "x", "failing", {"at": object.__name__, "n": 1})
    url, body, headers = notify.payload({"type": "webhook", "url": "https://w", "headers": {"X-Key": "k"}}, msg)
    assert headers == {"Content-Type": "application/json", "X-Key": "k"}
    assert json.loads(body) == {"title": "t", "text": "x", "level": "failing", "data": {"at": "object", "n": 1}}


def test_email_payload_defaults_and_data():
    em = notify.payload({"type": "email"}, notify.Message("t", "hello", "info", {"k": 1}))
    assert em["From"] == "aisb@localhost" and em["To"] == "" and em["Subject"] == "[aisb:info] t"
    assert em.get_content().startswith("hello\n\n{") and '"k": 1' in em.get_content()
    em = notify.payload({"type": "email", "to": ["a@x", "b@x"]}, notify.Message("t", "plain"))
    assert em["To"] == "a@x, b@x" and em.get_content() == "plain\n"


@pytest.mark.parametrize(("toml", "name", "error"), [
    ("", "ops", "configured: none"),
    ('[notify.a]\ntype = "pager"\n', "a", "type must be webhook | slack | ntfy | email"),
    ('[notify.a]\ntype = "slack"\n', "a", "slack sink needs url or url_env"),
    ('[notify.a]\ntype = "webhook"\nurl_env = "AISB_TEST_MISSING_URL"\n', "a", "$AISB_TEST_MISSING_URL is not set"),
])
def test_sink_configuration_errors(toml, name, error, monkeypatch):
    monkeypatch.delenv("AISB_TEST_MISSING_URL", raising=False)
    configure(toml)
    with pytest.raises(notify.NotifyError, match=re.escape(error)):
        notify.send(name, notify.Message("t", "x", "down"))


def test_webhook_send_and_http_failure(hook):
    url, got, status = hook
    configure(f'[notify.w]\ntype = "webhook"\nurl = "{url}/w?token=SECRET"\n')
    assert notify.send("w", notify.Message("t", "x")) == {"sink": "w", "sent": True, "type": "webhook", "status": 200}
    assert got[0]["path"] == "/w?token=SECRET"
    status["code"] = 500
    with pytest.raises(notify.NotifyError) as info:
        notify.send("w", notify.Message("t", "x"))
    assert "failed" in str(info.value) and "SECRET" not in str(info.value)    # query (tokens) stripped


def test_unreachable_sink_is_isolated_by_fan(no_proxy):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                                               # nothing listens there now
    configure(f'[notify.dead]\ntype = "ntfy"\nurl = "http://127.0.0.1:{port}/t"\n')
    out = notify.fan(["dead"], notify.Message("t", "x"))
    assert out[0]["sent"] is False and out[0]["error"].startswith(f"POST http://127.0.0.1:{port}/t failed")
    assert notify.fan(None, notify.Message("t", "x")) == []


def test_min_level_filters(hook):
    url, got, _ = hook
    configure(f'[notify.p]\ntype = "ntfy"\nurl = "{url}/p"\nmin_level = "down"\n')
    assert notify.send("p", notify.Message("t", "x", "critical")) == {
        "sink": "p", "sent": False, "reason": "below min_level down"}
    assert notify.send("p", notify.Message("t", "x", "down"))["sent"] and len(got) == 1


class FakeSMTP:
    """smtplib.SMTP at the network boundary."""
    log: list = []
    fail: Exception | None = None

    def __init__(self, host, port, timeout):
        if FakeSMTP.fail:
            raise FakeSMTP.fail
        self.log.append(("connect", host, port))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context):
        self.log.append(("starttls",))

    def login(self, user, pw):
        self.log.append(("login", user, pw))

    def send_message(self, m):
        self.log.append(("send", m["To"]))


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.log, FakeSMTP.fail = [], None
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


@pytest.mark.parametrize(("extra", "log"), [
    ('smtp = "mx:25"\n', [("connect", "mx", 25), ("send", "o@x")]),                       # port 25: no TLS
    ("", [("connect", "localhost", 25), ("send", "o@x")]),                                 # default relay
    ('smtp = "mx:25"\nstarttls = true\nuser = "u"\npassword = "p"\n',
     [("connect", "mx", 25), ("starttls",), ("login", "u", "p"), ("send", "o@x")]),
    ('smtp = "mx:587"\nstarttls = false\nuser = "u"\n', [("connect", "mx", 587), ("login", "u", ""), ("send", "o@x")]),
])
def test_email_transport_options(smtp, extra, log):
    configure('[notify.m]\ntype = "email"\nto = ["o@x"]\n' + extra)
    assert notify.send("m", notify.Message("t", "x")) == {"sink": "m", "sent": True, "type": "email", "to": ["o@x"]}
    assert smtp.log == log


def test_email_failure_wrapped(smtp):
    import smtplib
    configure('[notify.m]\ntype = "email"\nsmtp = "mx:587"\nto = ["o@x"]\n')
    smtp.fail = smtplib.SMTPConnectError(421, b"busy")
    with pytest.raises(notify.NotifyError, match="email via mx:587 failed"):
        notify.send("m", notify.Message("t", "x"))
    smtp.fail = ConnectionRefusedError("refused")
    assert "refused" in notify.fan(["m"], notify.Message("t", "x"))[0]["error"]


# --- `aisb notify` ops ----------------------------------------------------------------------------------

@pytest.fixture
def cli(capsys):
    def run(*argv: str):
        code = main([*argv, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def test_notify_list_never_shows_secrets(cli):
    configure("""
        [notify.hook]
        type = "webhook"
        url = "https://hooks.example.com/abc?token=SECRET"
        [notify.slack]
        type = "slack"
        url_env = "SLACK_URL"
        min_level = "failing"
        [notify.mail]
        type = "email"
        to = ["ops@x"]
        password = "SECRET"
    """)
    code, out, _ = cli("notify", "list")
    assert code == EXIT_OK and "SECRET" not in json.dumps(out)
    assert out == [{"sink": "hook", "type": "webhook", "min_level": "info", "target": "hooks.example.com"},
                   {"sink": "slack", "type": "slack", "min_level": "failing", "target": "$SLACK_URL"},
                   {"sink": "mail", "type": "email", "min_level": "info", "target": ["ops@x"]}]


def test_notify_send_and_test(cli, hook):
    url, got, _ = hook
    configure(f'[notify.w]\ntype = "webhook"\nurl = "{url}/w"\n')
    code, out, _ = cli("notify", "send", "w", "--title", "deployed", "--text", "v2", "--level", "warning")
    assert code == EXIT_OK and out["sent"] and json.loads(got[0]["body"])["level"] == "warning"
    code, out, _ = cli("notify", "test", "w")
    assert code == EXIT_OK and json.loads(got[1]["body"])["title"] == "aisb test message"


def test_notify_dry_run_email_and_webhook_send_nothing(cli, hook, smtp):
    url, got, _ = hook
    configure(f'[notify.w]\ntype = "webhook"\nurl = "{url}/w"\n'
              '[notify.m]\ntype = "email"\nto = ["a@x", "b@x"]\n')
    code, out, _ = cli("notify", "send", "m", "--title", "t", "--dry-run")
    assert code == EXIT_OK and out["planned"] == [{"notify": "m", "to": "a@x, b@x", "title": "t", "level": "info"}]
    code, out, _ = cli("notify", "test", "w", "--dry-run")
    assert out["planned"][0]["to"] == url.removeprefix("http://")
    assert got == [] and smtp.log == []


def test_notify_unknown_sink_is_usage_error(cli):
    code, _, err = cli("notify", "send", "nope", "--title", "t")
    assert code == EXIT_USAGE and "unknown notify sink" in err

