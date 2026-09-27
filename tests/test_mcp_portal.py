"""MCP resources/prompts and the portal's fleet + approvals endpoints."""

import http.client
import json
import textwrap
import threading

import pytest

from aisb import Docker
from aisb.mcp import Server
from aisb.ops import Tier
from aisb.portal import Portal


def rpc(srv: Server, method: str, **params):
    return srv.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


@pytest.fixture
def library(tmp_path, monkeypatch):
    lib = tmp_path / "runbooks"
    lib.mkdir()
    (lib / "restart-web.toml").write_text(textwrap.dedent("""
        name = "restart-web"
        description = "rolling restart of the web tier"
        [[steps]]
        name = "go"
        approve = "restart web?"
        [[steps]]
        name = "restart"
        run = "containers restart web"
    """))
    monkeypatch.setenv("AISB_RUNBOOKS", str(lib))
    return lib


def test_mcp_advertises_resources_and_prompts(host, library):
    srv = Server(lambda: Docker(host, timeout=5))
    caps = rpc(srv, "initialize")["result"]["capabilities"]
    assert {"tools", "resources", "prompts"} <= caps.keys()
    uris = [r["uri"] for r in rpc(srv, "resources/list")["result"]["resources"]]
    assert {"aisb://fleet/status", "aisb://runbooks/pending", "aisb://audit/recent", "aisb://policy/rules"} <= set(uris)
    names = [p["name"] for p in rpc(srv, "prompts/list")["result"]["prompts"]]
    assert {"investigate-incident", "rollout", "daily-check", "runbook-restart-web"} <= set(names)


def test_mcp_reads_resources(host, daemon, library):
    daemon.on("GET", "/containers/json", json=[])
    daemon.on("GET", "/images/json", json=[])
    srv = Server(lambda: Docker(host, timeout=5))
    doc = json.loads(rpc(srv, "resources/read", uri="aisb://local/doctor")["result"]["contents"][0]["text"])
    assert doc["summary"] == {"failing": 0, "degraded": 0, "healthy": 0}
    src = rpc(srv, "resources/read", uri="aisb://runbooks/restart-web")["result"]["contents"][0]
    assert src["mimeType"] == "text/plain" and "rolling restart" in src["text"]
    assert rpc(srv, "resources/read", uri="aisb://nope")["error"]["code"] == -32002


def test_mcp_prompts_render_and_validate(library):
    srv = Server(lambda: None)
    msg = rpc(srv, "prompts/get", name="runbook-restart-web", arguments={"vars": "a=1"})["result"]["messages"][0]
    assert "runbook_plan" in msg["content"]["text"] and "confirm=true" in msg["content"]["text"]
    assert rpc(srv, "prompts/get", name="rollout", arguments={"stack": "s.json"})["error"]["code"] == -32602
    assert "fleet_status" in rpc(srv, "prompts/get", name="investigate-incident")["result"]["messages"][0]["content"]["text"]


# --- portal ----------------------------------------------------------------------------------------------

def _get(port: int, path: str, *, body: dict | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST" if body is not None else "GET", path, body=json.dumps(body).encode() if body is not None else None,
                 headers={"Host": f"127.0.0.1:{port}", "X-AISB-Token": "t", "Content-Type": "application/json"})
    r = conn.getresponse()
    return r.status, json.loads(r.read())


@pytest.fixture
def portal(host, daemon):
    def start(allow: Tier):
        p = Portal(lambda: Docker(host, timeout=5), allow=allow, token="t")
        srv = p.server("127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return srv.server_address[1]
    started: list = []
    yield start
    for s in started:
        s.shutdown()
        s.server_close()


def test_portal_fleet_tab_without_inventory(portal, tmp_path, monkeypatch):
    monkeypatch.setenv("AISB_FLEET", str(tmp_path / "none.json"))
    code, out = _get(portal(Tier.READ), "/api/fleet")
    assert code == 200 and out["enabled"] is False


def test_portal_fleet_tab_with_inventory(portal, daemon, host, tmp_path, monkeypatch):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"x": {"docker": host}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))
    daemon.on("GET", "/info", json={"ContainersRunning": 0, "Containers": 0})
    daemon.on("GET", "/containers/json", json=[])
    daemon.on("GET", "/images/json", json=[])
    code, out = _get(portal(Tier.READ), "/api/fleet")
    assert code == 200 and out["enabled"] and out["hosts"][0]["host"] == "x"


def test_portal_approvals_flow(portal, daemon, library, host, capsys):
    from aisb.cli import main
    daemon.on("POST", "/containers/web/restart", status=204)
    main(["runbook", "run", "restart-web", "--yes", "--host", host, "--json"])
    run_id = json.loads(capsys.readouterr().out)["run"]
    ro = portal(Tier.READ)
    code, pending = _get(ro, "/api/op/runbook/pending", body={})
    assert code == 200 and pending[0]["run"] == run_id and pending[0]["prompt"] == "restart web?"
    assert _get(ro, "/api/op/runbook/approve", body={"run": run_id})[0] == 403      # read-only portal
    rw = portal(Tier.MUTATE)
    code, out = _get(rw, "/api/op/runbook/approve", body={"run": run_id, "resume": True, "note": "lgtm"})
    assert code == 200 and out["source"] == "portal" and out["resumed"]["status"] == "done"
    assert ("POST", "/containers/web/restart") in daemon.calls()
