"""More platform coverage: runbook engine edge cases, portal security (token, Host allowlist, tiers, JSON errors),
the MCP server's protocol surface, and the bundle builder."""

import http.client
import io
import json
import os
import textwrap
import threading
import zipfile
from pathlib import Path

import pytest

from aisb import Docker, bundle, config, runbooks
from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_UNMET, main
from aisb.mcp import Server, describe, get_prompt
from aisb.ops import Tier, registry
from aisb.portal import HOST_EFFECTS, Portal, exposed_ops

from conftest import Reply


def write_config(text: str) -> None:
    Path(os.environ["AISB_CONFIG"]).write_text(textwrap.dedent(text))
    config.reset()


# --- runbooks ------------------------------------------------------------------------------------------

@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def book(path: Path, body: str) -> str:
    path.write_text(textwrap.dedent(body))
    return str(path)


def test_list_reports_broken_runbooks(tmp_path, monkeypatch, cli):
    lib = tmp_path / "lib"
    lib.mkdir()
    book(lib / "good.toml", 'name = "good"\ndescription = "d"\n[[steps]]\nname = "s"\nsleep = 0\n')
    (lib / "bad.json").write_text('{"steps": []}')
    (lib / "notes.txt").write_text("ignored")
    monkeypatch.setenv("AISB_RUNBOOKS", f"{lib}{os.pathsep}{tmp_path / 'missing'}")
    code, out, _ = cli("runbook", "list")
    by = {r["name"]: r for r in out}
    assert by["good"] == {"name": "good", "file": str(lib / "good.toml"), "steps": 1, "description": "d"}
    assert "non-empty" in by["bad"]["error"] and len(out) == 2


def test_plan_covers_sleep_read_mutate_and_plan_errors(tmp_path, cli, daemon):
    f = book(tmp_path / "p.toml", """
        [[steps]]
        name = "nap"
        sleep = 1
        [[steps]]
        name = "look"
        run = "containers list"
        [[steps]]
        name = "bounce"
        run = "containers restart web"
        [[steps]]
        name = "deploy"
        run = "stack up /nonexistent/stack.json"
    """)
    code, out, _ = cli("runbook", "plan", f)
    steps = {s["step"]: s for s in out["steps"]}
    assert code == EXIT_OK and steps["nap"] == {"step": "nap", "kind": "sleep", "when": "success", "sleep": 1.0}
    assert steps["look"]["note"].startswith("read step") and steps["look"]["tier"] == "read"
    assert steps["bounce"]["planned"][0]["path"] == "/containers/web/restart"
    assert "plan_error" in steps["deploy"] and "nonexistent" in steps["deploy"]["plan_error"]
    assert daemon.calls("POST") == []


def test_invalid_step_command_is_a_usage_error(tmp_path, cli):
    f = book(tmp_path / "bad.toml", '[[steps]]\nname = "x"\nrun = "containers restart --no-such-flag"\n')
    code, _, err = cli("runbook", "plan", f)
    assert code != EXIT_OK and "invalid command: containers restart --no-such-flag" in err


def test_execution_sleep_continue_on_error_and_unmet_read_step(tmp_path, cli, daemon):
    daemon.on("GET", "/containers/web/json", json={"State": {"Running": False, "Status": "exited", "ExitCode": 2},
                                                   "Config": {"Tty": True}})
    daemon.on("GET", "/containers/web/logs", body=b"bye\n", content_type="text/plain")
    daemon.on("POST", "/containers/web/start", status=204)
    f = book(tmp_path / "e.toml", """
        [[steps]]
        name = "nap"
        sleep = 0
        [[steps]]
        name = "optional"
        run = "containers restart ghost"
        continue_on_error = true
        [[steps]]
        name = "check"
        run = "containers wait web --running --within 1"
        [[steps]]
        name = "fix"
        when = "check.failed"
        run = "containers start web"
    """)
    code, out, _ = cli("runbook", "run", f, "--yes")
    status = {s["step"]: s for s in out["steps"]}
    assert [s["status"] for s in out["steps"]] == ["done", "failed", "failed", "done"]
    assert "container stopped (exit code 2)" in status["check"]["error"]
    assert code == EXIT_UNMET and out["status"] == "failed" and "ghost" in status["optional"]["error"]
    assert ("POST", "/containers/web/start") in daemon.calls()
    code, runs, _ = cli("runbook", "runs", "--limit", "5")
    assert runs[0]["run"] == out["run"] and runs[0]["done"] == 2 and runs[0]["steps"] == 4
    code, pend, _ = cli("runbook", "pending")
    assert pend == []                                          # a failed run isn't waiting for anyone


APPROVE = """
    [[steps]]
    name = "go"
    approve = "ok?"
    [[steps]]
    name = "bounce"
    run = "containers restart web"
"""


def test_resume_of_a_finished_run_and_dry_run_resume(tmp_path, cli, daemon):
    daemon.on("POST", "/containers/web/restart", status=204)
    f = book(tmp_path / "a.toml", APPROVE)
    code, out, _ = cli("runbook", "run", f, "--yes")
    run_id = out["run"]
    code, plan, _ = cli("runbook", "resume", run_id)
    assert code == EXIT_CONFIRM and [p["step"] for p in plan["planned"]] == ["go", "bounce"]
    assert daemon.calls("POST") == []
    code, plan, _ = cli("runbook", "approve", run_id, "--dry-run")
    assert code == EXIT_OK and plan["planned"][0]["step"] == "go" and plan["planned"][0]["decision"] == "approve"
    assert runbooks.load_run(run_id)["approvals"] == {}           # a dry-run approval records nothing
    cli("runbook", "approve", run_id, "--resume")
    code, again, _ = cli("runbook", "resume", run_id, "--yes")
    assert code == EXIT_OK and again == {"run": run_id, "status": "done", "note": "nothing to resume"}
    code, _, err = cli("runbook", "approve", run_id)
    assert code != EXIT_OK and "is not waiting for an approval (status done)" in err


def test_approve_resume_refuses_a_run_not_started_with_yes(tmp_path, cli, daemon):
    rb = runbooks.load(book(tmp_path / "a.toml", APPROVE))
    st = runbooks.new_run(rb, {}, confirmed=False)
    st["steps"]["go"]["status"], st["status"] = "waiting", "waiting"
    runbooks.save(st)
    code, _, err = cli("runbook", "approve", st["run"], "--resume")
    assert code != EXIT_OK and "not started with --yes" in err
    assert runbooks.load_run(st["run"])["approvals"]["go"]["decision"] == "approve"   # the answer itself is kept
    assert daemon.calls("POST") == []


# --- portal -------------------------------------------------------------------------------------------

def request(port: int, path: str, *, method: str = "GET", body: bytes | None = None, token: str | None = "t",
            host: str | None = None, headers: dict | None = None) -> tuple[int, dict | str, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}", **({"X-AISB-Token": token} if token is not None else {}),
         "Content-Type": "application/json", **(headers or {})}
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    raw = r.read()
    try:
        data: dict | str = json.loads(raw)
    except ValueError:
        data = raw.decode()
    return r.status, data, dict(r.getheaders())


@pytest.fixture
def portal(host):
    started: list = []

    def start(allow: Tier = Tier.READ, factory=None, hosts: frozenset[str] = frozenset()):
        p = Portal(factory or (lambda: Docker(host, timeout=5)), allow=allow, token="t", hosts=hosts)
        srv = p.server("127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        started.append(srv)
        return srv.server_address[1], p
    yield start
    for s in started:
        s.shutdown()
        s.server_close()


@pytest.mark.parametrize("allow", [Tier.READ, Tier.MUTATE])
def test_portal_never_exposes_destroy_or_host_file_ops(allow):
    ops = exposed_ops(allow)
    assert ops and all(o.tier is not Tier.DESTROY for o in ops.values())
    assert not (HOST_EFFECTS & ops.keys())
    assert all(o.tier is Tier.READ for o in ops.values()) if allow is Tier.READ else \
        any(o.tier is Tier.MUTATE for o in ops.values())


DESTROY_OPS = sorted(f"{o.resource}/{o.name}" for ops in registry().values() for o in ops.values()
                     if o.tier is Tier.DESTROY)


@pytest.mark.parametrize("qualname", DESTROY_OPS)
def test_portal_refuses_every_destroy_op_even_with_mutate(portal, daemon, qualname):
    port, _ = portal(Tier.MUTATE)
    code, out, _ = request(port, f"/api/op/{qualname}", method="POST",
                           body=json.dumps({"ref": "x", "confirm": True, "dry_run": False}).encode())
    assert code == 403 and "not available in the portal" in out["error"]
    assert daemon.seen == []


@pytest.mark.parametrize(("path", "method", "token", "host", "status", "error"), [
    ("/api/ops", "GET", None, None, 401, "X-AISB-Token"),
    ("/api/ops", "GET", "wrong", None, 401, "X-AISB-Token"),
    ("/api/ops", "GET", "t", "evil.example:80", 421, "unexpected Host"),
    ("/", "GET", None, "evil.example", 421, "unexpected Host"),          # DNS rebinding: the page isn't served
    ("/api/op/containers/list", "POST", None, None, 401, "X-AISB-Token"),
    ("/api/op/containers/list", "POST", "t", "attacker:1", 421, "unexpected Host"),
])
def test_portal_rejects_bad_token_and_host(portal, daemon, path, method, token, host, status, error):
    port, _ = portal(Tier.MUTATE)
    code, out, headers = request(port, path, method=method, token=token, host=host, body=b"{}" if method == "POST" else None)
    assert code == status and error in out["error"]
    assert headers["Cache-Control"] == "no-store" and headers["X-Content-Type-Options"] == "nosniff"
    assert daemon.seen == []


def test_portal_page_embeds_token_and_allow(portal):
    port, _ = portal(Tier.MUTATE)
    code, page, headers = request(port, "/?x=1", token=None)
    assert code == 200 and 'const TOKEN="t", ALLOW="mutate"' in page
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_portal_custom_host_allowlist(portal):
    port, _ = portal(hosts=frozenset({"ops.internal:8765"}))
    assert request(port, "/api/ops", host="ops.internal:8765")[0] == 200
    assert request(port, "/api/ops")[0] == 421                      # the default loopback names aren't added


@pytest.mark.parametrize(("path", "body", "status", "error"), [
    ("/api/op/containers", b"{}", 404, "use POST /api/op/<resource>/<op>"),
    ("/api/nope/containers/list", b"{}", 404, "use POST"),
    ("/api/op/containers/list", b"[1, 2]", 400, "JSON object"),
    ("/api/op/containers/list", b"{bad json", 400, "JSON object"),
    ("/api/op/containers/restart", b'{"ref": "web"}', 403, "not available"),   # mutate on a read-only portal
    ("/api/op/containers/list", b'{"file": "/etc/passwd"}', 403, "host-file arguments"),
    ("/api/op/containers/list", b'{"inventory": "/root/fleet.json", "out": "/tmp/x"}', 403, "inventory, out"),
    ("/api/op/containers/list", b'{"no_such_arg": 1}', 400, "UsageError"),
])
def test_portal_json_errors(portal, daemon, path, body, status, error):
    port, _ = portal()
    code, out, _ = request(port, path, method="POST", body=body)
    assert code == status and error in json.dumps(out)
    assert daemon.calls("POST") == []


def test_portal_oversized_body_is_refused(portal, daemon):
    port, _ = portal()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest("POST", "/api/op/containers/list", skip_host=True)
    for k, v in {"Host": f"127.0.0.1:{port}", "X-AISB-Token": "t", "Content-Length": str((1 << 20) + 1)}.items():
        conn.putheader(k, v)
    conn.endheaders()
    r = conn.getresponse()
    assert r.status == 400 and "max 1 MiB" in json.loads(r.read())["error"]


def test_portal_get_unknown_path_is_404(portal):
    port, _ = portal()
    assert request(port, "/api/whatever")[:2] == (404, {"error": "not found"})


def test_portal_docker_errors_are_502_and_crashes_500(portal, daemon, host):
    port, _ = portal()
    code, out, _ = request(port, "/api/op/containers/inspect", method="POST", body=b'{"ref": "ghost"}')
    assert code == 502 and out["error"] == "NotFound"
    daemon.on("GET", "/containers/json", status=500, json={"message": "daemon on fire"})
    code, out, _ = request(port, "/api/overview")
    assert code == 502 and "daemon on fire" in json.dumps(out)

    def broken():
        raise RuntimeError("factory exploded")
    port2, _ = portal(factory=broken)
    code, out, _ = request(port2, "/api/overview")
    assert (code, out) == (500, {"error": "RuntimeError", "message": "factory exploded"})
    code, out, _ = request(port2, "/api/op/containers/list", method="POST", body=b"{}")
    assert (code, out["error"]) == (500, "RuntimeError")


def test_portal_policy_denial_is_403(portal, daemon):
    write_config("""
        [[policy.rules]]
        name = "no clicking restarts"
        match = { source = "portal", tier = "mutate" }
        deny = true
    """)
    daemon.on("POST", "/containers/web/restart", status=204)
    port, _ = portal(Tier.MUTATE)
    code, out, _ = request(port, "/api/op/containers/restart", method="POST", body=b'{"ref": "web"}')
    assert code == 403 and out["error"] == "PolicyDenied" and "no clicking restarts" in json.dumps(out)
    assert daemon.calls("POST") == []


def test_portal_mutate_dry_run_and_cache_invalidation(portal, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "w" * 12, "Names": ["/web"], "Image": "nginx",
                                                "State": "exited", "Status": "Exited (0)", "Labels": {}}])
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", "/containers/(w+|web)/json", json={"Name": "/web", "Config": {"Tty": True, "Image": "nginx"},
                                                        "State": {"Running": False, "Status": "exited", "ExitCode": 0}})
    daemon.on("GET", "/containers/(w+|web)/logs", body=b"", content_type="text/plain")
    daemon.on("POST", "/containers/web/restart", status=204)
    port, p = portal(Tier.MUTATE)
    code, ov, _ = request(port, "/api/overview")
    assert code == 200 and ov["containers"][0]["name"] == "web" and ov["containers"][0]["verdict"] != "healthy"
    n = len(daemon.seen)
    assert request(port, "/api/overview")[1] == ov and len(daemon.seen) == n       # cached
    code, plan, _ = request(port, "/api/op/containers/restart", method="POST", body=b'{"ref": "web", "dry_run": true}')
    assert code == 200 and plan["status"] == "dry-run" and daemon.calls("POST") == []
    code, _, _ = request(port, "/api/op/containers/restart", method="POST", body=b'{"ref": "web"}')
    assert code == 200 and daemon.calls("POST") == [("POST", "/containers/web/restart")]
    assert p._cache is None                                                         # the next overview is fresh


def test_portal_catalog_and_fleet_cache(portal, daemon, host, tmp_path, monkeypatch):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"x": {"docker": host}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))
    daemon.on("GET", "/info", json={"ContainersRunning": 0, "Containers": 0})
    port, _ = portal()
    code, cat, _ = request(port, "/api/ops")
    assert code == 200 and all(c["tier"] == "read" for c in cat) and {"op", "tier", "summary", "params"} <= cat[0].keys()
    code, first, _ = request(port, "/api/fleet")
    n = len(daemon.seen)
    assert request(port, "/api/fleet")[1] == first and len(daemon.seen) == n       # cached for FLEET_CACHE_S
    inv.write_text("{not json")
    port2, _ = portal()
    code, out, _ = request(port2, "/api/fleet")
    assert code == 502 and out["error"] == "JSONDecodeError"


def test_portal_overview_survives_service_detection_errors(portal, daemon):
    rows = [{"Id": "d" * 12, "Names": ["/db"], "Image": "postgres:16", "State": "running", "Status": "Up", "Labels": {}}]
    # the triage lists all containers and works; service detection (running only) hits a daemon error
    daemon.on("GET", "/containers/json", lambda seen: Reply(json=rows) if "all" in seen.query
              else Reply(500, json={"message": "list failed"}))
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", "/containers/(d+|db)/json", json={"Name": "/db", "Config": {"Tty": True, "Image": "postgres:16"},
                                                       "State": {"Running": True, "Status": "running"}})
    daemon.on("GET", "/containers/(d+|db)/logs", body=b"ready\n", content_type="text/plain")
    port, _ = portal()
    code, out, _ = request(port, "/api/overview")
    assert code == 200 and out["containers"][0]["name"] == "db" and out["containers"][0]["service"] is None


# --- MCP ---------------------------------------------------------------------------------------------------

def rpc(srv: Server, method: str, mid: int | None = 1, **params):
    return srv.handle({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})


def text_of(res: dict) -> dict:
    return json.loads(res["result"]["content"][0]["text"])


def test_mcp_tiers_and_tool_schemas():
    ro = Server(lambda: None, max_tier=Tier.READ)
    assert ro.tools and all(o.tier is Tier.READ for o in ro.tools.values())
    mid = Server(lambda: None, max_tier=Tier.MUTATE)
    assert not any(o.tier is Tier.DESTROY for o in mid.tools.values())
    full = Server(lambda: None)
    rm = describe(full.tools["containers_rm"])
    assert {"dry_run", "confirm", "ticket"} <= rm["inputSchema"]["properties"].keys()
    assert rm["annotations"]["destructiveHint"] and not rm["annotations"]["readOnlyHint"]
    ls = describe(full.tools["containers_list"])
    assert not {"dry_run", "confirm", "ticket"} & ls["inputSchema"]["properties"].keys()
    assert ls["annotations"]["readOnlyHint"] and ls["description"].startswith("[read]")


def test_mcp_protocol_basics():
    srv = Server(lambda: None)
    assert rpc(srv, "ping")["result"] == {}
    assert rpc(srv, "notifications/initialized", mid=None) is None
    assert rpc(srv, "initialize", protocolVersion="2024-11-05")["result"]["protocolVersion"] == "2024-11-05"
    assert rpc(srv, "nope")["error"] == {"code": -32601, "message": "method not found: nope"}
    tpl = rpc(srv, "resources/templates/list")["result"]["resourceTemplates"]
    assert tpl[0]["uriTemplate"] == "aisb://runbooks/{name}"
    assert len(rpc(srv, "tools/list")["result"]["tools"]) == len(srv.tools)


def test_mcp_tool_call_errors_and_confirmation(host, daemon):
    srv = Server(lambda: Docker(host, timeout=5))
    res = rpc(srv, "tools/call", name="containers_nuke", arguments={})["result"]
    assert res["isError"] and "unknown tool" in text_of({"result": res})["error"]
    res = rpc(srv, "tools/call", name="containers_inspect", arguments={"ref": "ghost"})["result"]
    assert res["isError"] and text_of({"result": res})["error"] == "NotFound"
    res = rpc(srv, "tools/call", name="containers_list", arguments={"bogus": 1})["result"]
    assert res["isError"] and text_of({"result": res})["error"] == "UsageError"
    daemon.on("DELETE", "/containers/old", status=204)
    res = rpc(srv, "tools/call", name="containers_rm", arguments={"ref": "old"})["result"]
    out = text_of({"result": res})
    assert not res["isError"] and out["status"] == "confirmation_required" and out["planned"][0]["method"] == "DELETE"
    assert daemon.calls("DELETE") == []
    res = rpc(srv, "tools/call", name="containers_rm", arguments={"ref": "old", "confirm": True})["result"]
    assert not res["isError"] and daemon.calls("DELETE") == [("DELETE", "/containers/old")]


def test_mcp_applies_config_defaults_for_known_params_only(host, daemon):
    write_config("""
        [defaults."containers.list"]
        all = true
        not_a_param = 1
    """)
    daemon.on("GET", "/containers/json", json=[])
    srv = Server(lambda: Docker(host, timeout=5))
    res = rpc(srv, "tools/call", name="containers_list", arguments={})["result"]
    assert not res["isError"]
    assert daemon.seen[-1].query.get("all") in ("1", "true", "True")


def test_mcp_serve_loop():
    srv = Server(lambda: None)
    stdin = io.StringIO("\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}), "", "{not json",
        json.dumps([{"jsonrpc": "2.0", "id": 2, "method": "ping"}]),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"})]) + "\n")
    stdout = io.StringIO()
    srv.serve(stdin, stdout)
    replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [r.get("id") for r in replies] == [1, None, None, 3]
    assert replies[1]["error"]["code"] == -32700 and replies[2]["error"]["code"] == -32600


def test_mcp_prompts_skip_broken_runbooks_and_unknown_prompt(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "broken.toml").write_text("steps = 3\n")
    (lib / "ok.json").write_text(json.dumps({"name": "ok", "steps": [{"name": "s", "sleep": 0}]}))
    monkeypatch.setenv("AISB_RUNBOOKS", str(lib))
    srv = Server(lambda: None)
    names = [p["name"] for p in rpc(srv, "prompts/list")["result"]["prompts"]]
    assert "runbook-ok" in names and not any("broken" in n for n in names)
    assert rpc(srv, "prompts/get", name="nope")["error"]["code"] == -32602
    msg = get_prompt("rollout", {"stack": "s.json", "canary": "@canary", "rest": "@web,!@canary"})
    assert "batch=1, fail_fast=true" in msg["messages"][0]["content"]["text"]
    assert "run the ok runbook" in get_prompt("runbook-ok", {})["description"]


def test_mcp_resource_errors(host, daemon, tmp_path, monkeypatch):
    monkeypatch.setenv("AISB_RUNBOOKS", str(tmp_path))
    srv = Server(lambda: Docker(host, timeout=5))
    assert rpc(srv, "resources/read", uri="aisb://runbooks/missing")["error"]["code"] == -32002
    res = rpc(srv, "resources/read", uri="aisb://runbooks/pending")["result"]["contents"][0]
    assert res["mimeType"] == "application/json" and json.loads(res["text"]) == []


# --- bundle ---------------------------------------------------------------------------------------------------

@pytest.fixture
def pkg(tmp_path) -> Path:
    root = tmp_path / "src" / "aisb"
    (root / "contrib" / "x").mkdir(parents=True)
    (root / "__pycache__").mkdir()
    (root / "sub").mkdir()
    (root / "__init__.py").write_text("")
    (root / "sub" / "m.py").write_text("X = 1\n")
    (root / "contrib" / "x" / "y.py").write_text("import pyinfra\n")
    (root / "__pycache__" / "z.py").write_text("")
    return root


def test_sources_skip_contrib_and_caches(pkg):
    assert [n for n, _ in bundle.sources(pkg)] == ["aisb/__init__.py", "aisb/sub/m.py"]


def test_legal_files_come_from_the_checkout(pkg):
    root = pkg.parents[1]
    (root / "LICENSE").write_text("Apache")
    (root / "NOTICE").write_text("aisb")
    assert bundle.legal(pkg) == [("LICENSE", b"Apache"), ("NOTICE", b"aisb")]
    z = zipfile.ZipFile(io.BytesIO(bundle.build(pkg)[len(bundle.SHEBANG):]))
    assert sorted(z.namelist()) == ["LICENSE", "NOTICE", "__main__.py", "aisb/__init__.py", "aisb/sub/m.py"]
    assert {i.date_time for i in z.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_legal_falls_back_to_distribution_metadata(pkg, monkeypatch, tmp_path):
    from importlib import metadata
    root = pkg.parents[1]
    (root / "LICENSE").write_text("Apache")
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    (dist_dir / "NOTICE").write_text("from metadata")

    class Dist:                                          # the installed-package boundary
        files = [metadata.PackagePath("aisb-1.0.dist-info/licenses/NOTICE"),
                 metadata.PackagePath("aisb-1.0.dist-info/licenses/LICENSE")]

        def locate_file(self, f):
            return dist_dir / f.name
    monkeypatch.setattr(metadata, "distribution", lambda name: Dist())
    assert bundle.legal(pkg) == [("LICENSE", b"Apache"), ("NOTICE", b"from metadata")]


def test_legal_refuses_to_bundle_without_license_terms(pkg, monkeypatch):
    from importlib import metadata

    def missing(name):
        raise metadata.PackageNotFoundError(name)
    monkeypatch.setattr(metadata, "distribution", missing)
    with pytest.raises(FileNotFoundError, match="cannot bundle without LICENSE, NOTICE"):
        bundle.legal(pkg)
    with pytest.raises(FileNotFoundError):
        bundle.build(pkg)


def test_bundle_main_writes_an_executable(tmp_path, capsys):
    out = tmp_path / "a.pyz"
    assert bundle.main([str(out)]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["bundle"] == str(out) and info["bytes"] == out.stat().st_size and out.stat().st_mode & 0o111
    assert info["run"] == "python3 a.pyz system ping"



def test_portal_main_prints_url_and_warns_off_loopback(host, daemon, monkeypatch, capsys):
    """Ctrl-C at the server loop (the boundary) ends `aisb portal` cleanly after it printed how to connect."""
    import aisb.portal as portal_mod

    def interrupted(self, *a, **kw):
        raise KeyboardInterrupt
    monkeypatch.setattr(portal_mod.ThreadingHTTPServer, "serve_forever", interrupted)
    assert portal_mod.main(["--host", host, "--port", "0", "--bind", "127.0.0.2", "--token", "fixed"]) == 0
    out, err = capsys.readouterr()
    info = json.loads(out)
    assert info["url"].startswith("http://127.0.0.2:") and info["token"] == "fixed" and info["allow"] == "read"
    assert "warning: listening on 127.0.0.2" in err
    assert portal_mod.main(["--host", host, "--port", "0", "--allow", "mutate"]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out)["allow"] == "mutate" and err == ""
