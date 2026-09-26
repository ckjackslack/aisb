"""Killer-feature ops wired through the fake daemon (the process boundary), plus the portal over real HTTP."""

import http.client
import json
import threading
from collections.abc import Iterator

import pytest

from aisb.cli import EXIT_CONFIRM, EXIT_OK, main
from aisb.client import Docker
from aisb.ops import Tier
from aisb.portal import Portal
from conftest import FakeDaemon, Reply


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


@pytest.fixture(autouse=True)
def aisb_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AISB_HOME", str(tmp_path / "home"))


# --- containers limit / system rightsize ---------------------------------------------------------

def test_limit_updates_in_place(cli, daemon):
    daemon.on("GET", "/containers/api/json", json={"HostConfig": {"Memory": 0, "NanoCpus": 0}})
    daemon.on("POST", "/containers/api/update", json={"Warnings": []})
    code, out, _ = cli("containers", "limit", "api", "--memory", "256m", "--cpus", "0.5", "--pids", "0")
    assert code == EXIT_OK
    body = next(s for s in daemon.seen if s.path.endswith("/update")).body
    assert body == {"Memory": 256 << 20, "MemorySwap": 512 << 20, "NanoCpus": 500_000_000, "PidsLimit": -1}
    assert not any(s.path.endswith(("/create", "/start")) for s in daemon.seen)


def test_limit_needs_something(cli, daemon):
    code, _, err = cli("containers", "limit", "api")
    assert code != EXIT_OK and "at least one" in err


def test_rightsize_samples_and_recommends(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "a" * 64, "Names": ["/api"]}])
    tick = iter(range(100))

    def stats(_):
        i = next(tick)
        return Reply(json={"cpu_stats": {"cpu_usage": {"total_usage": i * 5 * 10**8}, "system_cpu_usage": i * 10**9,
                                         "online_cpus": 1},
                           "memory_stats": {"usage": (100 + i) << 20, "limit": 1 << 34, "stats": {"inactive_file": 0}},
                           "pids_stats": {"current": 12}, "networks": {"eth0": {"rx_bytes": i, "tx_bytes": i}}})
    daemon.on("GET", f"/containers/{'a' * 64}/stats", stats)
    daemon.on("GET", f"/containers/{'a' * 64}/json", json={"HostConfig": {"Memory": 0, "NanoCpus": 0}})
    code, out, _ = cli("system", "rightsize", "--seconds", "0.2", "--interval", "0.1")
    assert code == EXIT_OK
    (c,) = out["containers"]
    assert c["samples"] == 3 and c["cpu_percent"]["avg"] == 50.0 and c["flags"] == ["unlimited"]
    assert out["commands"] == ["aisb containers limit api --memory 144m --cpus 0.75 --pids 64"]
    stats_q = next(s for s in daemon.seen if s.path.endswith("/stats")).query
    assert stats_q == {"stream": "0", "one-shot": "1"} or stats_q == {"stream": "false", "one-shot": "true"}


def test_rightsize_rejects_unknown_container(cli, daemon):
    daemon.on("GET", "/containers/json", json=[])
    code, _, err = cli("system", "rightsize", "--container", "ghost", "--seconds", "0")
    assert code != EXIT_OK and "ghost" in err


# --- session: journal + rollback -----------------------------------------------------------------

def _inventory(daemon: FakeDaemon, containers: list[dict]) -> None:
    daemon.on("GET", "/containers/json", lambda _: Reply(json=containers))
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", "/volumes", json={"Volumes": []})
    daemon.on("GET", "/networks", json=[])


def test_session_journals_stop_and_rollback_restarts(cli, daemon):
    rows = [{"Id": "c" * 64, "Names": ["/web"], "Image": "nginx", "ImageID": "sha256:1", "State": "running", "Labels": {}}]
    _inventory(daemon, rows)
    daemon.on("GET", "/containers/web/json", json={"State": {"Running": True}})
    daemon.on("POST", "/containers/web/stop", status=204)
    daemon.on("POST", "/containers/web/start", status=204)
    assert cli("session", "begin")[0] == EXIT_OK
    assert cli("containers", "stop", "web")[0] == EXIT_OK
    code, plan, _ = cli("session", "rollback")
    assert code == EXIT_CONFIRM and not any(s.path == "/containers/web/start" for s in daemon.seen)
    code, out, _ = cli("session", "rollback", "--yes")
    assert code == EXIT_OK and out["steps"] == [{"step": "start web", "status": "done"}]
    assert daemon.calls("POST")[-1] == ("POST", "/containers/web/start")
    _, again, _ = cli("session", "rollback", "--yes")
    assert again["steps"] == []  # idempotent


def test_session_marks_prune_not_undoable(cli, daemon):
    _inventory(daemon, [])
    daemon.on("POST", "/containers/prune", json={})
    daemon.on("POST", "/images/prune", json={})
    daemon.on("POST", "/networks/prune", json={})
    cli("session", "begin")
    cli("system", "prune", "--yes")
    _, out, _ = cli("session", "rollback", "--yes")
    assert out["not_undoable"] == ["system.prune"]


# --- portal -----------------------------------------------------------------------------------------

@pytest.fixture
def portal(host, daemon) -> Iterator[tuple[Portal, int]]:
    daemon.on("GET", "/containers/json", json=[{"Id": "d" * 64, "Names": ["/web"], "Image": "nginx", "State": "running",
                                               "Status": "Up", "Ports": [], "Labels": {}}])
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", f"/containers/{'d' * 64}/json", json={"Name": "/web", "Config": {"Image": "nginx"},
                                                           "State": {"Status": "running", "Running": True}})
    daemon.on("GET", "/containers/web/json", json={"Name": "/web", "Config": {"Image": "nginx"},
                                                   "State": {"Status": "running", "Running": True}})
    daemon.on("GET", f"/containers/{'d' * 64}/logs", Reply(body=b""))
    daemon.on("POST", "/containers/web/restart", status=204)
    p = Portal(lambda: Docker(host, timeout=5), allow=Tier.MUTATE, token="tok")
    srv = p.server("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield p, srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _req(port: int, method: str, path: str, *, token: str | None = "tok", host: str | None = None,
         body: dict | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}", "Content-Type": "application/json"}
    if token:
        headers["X-AISB-Token"] = token
    conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
    r = conn.getresponse()
    data = r.read()
    return r.status, (json.loads(data) if r.getheader("Content-Type", "").startswith("application/json") else
                      {"html": data.decode()})


@pytest.mark.parametrize(("token", "host", "status"), [
    ("tok", None, 200), (None, None, 401), ("nope", None, 401), ("tok", "evil.example:80", 421),
])
def test_portal_guards(portal, token, host, status):
    _, port = portal
    assert _req(port, "GET", "/api/ops", token=token, host=host)[0] == status


def test_portal_page_embeds_token_and_overview(portal):
    _, port = portal
    code, page = _req(port, "GET", "/", token=None)
    assert code == 200 and 'const TOKEN="tok"' in page["html"]
    code, ov = _req(port, "GET", "/api/overview")
    assert code == 200, ov
    assert ov["containers"][0]["name"] == "web" and ov["containers"][0]["verdict"] == "healthy"


@pytest.mark.parametrize(("path", "body", "status"), [
    ("/api/op/containers/restart", {"ref": "web"}, 200),
    ("/api/op/containers/rm", {"ref": "web"}, 403),                 # destroy: never
    ("/api/op/db/exec", {"ref": "web", "file": "/etc/passwd"}, 403),  # host-file argument
    ("/api/op/capsule/create", {"ref": "web", "out": "/tmp/x"}, 403),  # writes host files
    ("/api/op/containers/restart", {"nope": 1}, 400),
])
def test_portal_op_policy(portal, daemon, path, body, status):
    _, port = portal
    assert _req(port, "POST", path, body=body)[0] == status


def test_portal_read_only_refuses_mutate(host, daemon):
    p = Portal(lambda: Docker(host, timeout=5), allow=Tier.READ)
    assert p.call("containers.restart", {"ref": "web"})[0] == 403
    assert "containers.inspect" in p.ops and "containers.restart" not in p.ops
