"""Platform layer: config/profiles/aliases, policy, audit, plugins, output rendering, context propagation."""

import datetime as dt
import json
import sys
import textwrap
from pathlib import Path

import pytest

from aisb import audit, config, plugins
from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_POLICY, EXIT_USAGE, main
from aisb.context import Ctx
from aisb.fleet.inventory import Host
from aisb.policy import PolicyDenied, check, in_window, tag_of
from aisb.render import pick, render, yaml


def write_config(text: str) -> Path:
    import os
    p = Path(os.environ["AISB_CONFIG"])
    p.write_text(textwrap.dedent(text))
    config.reset()
    return p


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        head, tail = (list(argv[:argv.index("--")]), list(argv[argv.index("--"):])) if "--" in argv else (list(argv), [])
        code = main([*head, "--host", host, "--json", *tail] if head and head[0] not in ("--profile",) else [*argv])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


# --- config -----------------------------------------------------------------------------------

def test_config_profiles_defaults_and_unknown_sections():
    data = {"defaults": {"*": {"a": 1}, "containers.*": {"tail": 10}, "containers.logs": {"tail": 99}},
            "profiles": {"prod": {"defaults": {"containers.*": {"tail": 5}}, "env": {"AISB_FLEET": "/x.json"}}}}
    assert config.parse(data).defaults_for("containers.logs") == {"a": 1, "tail": 99}
    prod = config.parse(data, profile="prod")
    assert prod.defaults_for("containers.stats") == {"a": 1, "tail": 5} and prod.env == {"AISB_FLEET": "/x.json"}
    with pytest.raises(ValueError, match="unknown profile"):
        config.parse(data, profile="nope")
    with pytest.raises(ValueError, match="unknown sections"):
        config.parse({"defualts": {}})


def test_cli_applies_config_defaults_aliases_and_profiles(cli, daemon, monkeypatch):
    write_config("""
        [defaults]
        "containers.logs" = { tail = 7 }
        [aliases]
        web-logs = "containers logs web"
        [profiles.quiet.defaults]
        "containers.logs" = { tail = 1 }
    """)
    daemon.on("GET", "/containers/web/json", json={"Config": {"Tty": True}})
    daemon.on("GET", "/containers/web/logs", body=b"a\nb\n")
    assert cli("containers", "logs", "web")[0] == EXIT_OK
    assert daemon.seen[-1].query["tail"] == "7"
    assert cli("web-logs")[0] == EXIT_OK  # alias expands; --host/--json still appended
    monkeypatch.setenv("AISB_PROFILE", "quiet")
    config.reset()
    cli("containers", "logs", "web")
    assert daemon.seen[-1].query["tail"] == "1"
    monkeypatch.setenv("AISB_PROFILE", "missing")
    code, _, err = cli("containers", "logs", "web")
    assert code == EXIT_USAGE and "unknown profile" in err


# --- policy -----------------------------------------------------------------------------------

WEB1 = Host("web1", ssh="ops@w1", groups=("web", "prod"), labels={"region": "eu"})


def ctx(**kw) -> Ctx:
    return Ctx(**{"user": "alice", "source": "cli", **kw})


@pytest.mark.parametrize(("rule", "op", "tier", "kwargs", "c", "blocked"), [
    ({"match": {"tier": "destroy"}, "deny": True}, "containers.rm", "destroy", {}, ctx(), True),
    ({"match": {"tier": "destroy"}, "deny": True}, "containers.stop", "mutate", {}, ctx(), False),
    ({"match": {"op": "containers.*", "hosts": "@prod"}, "deny": True}, "containers.rm", "destroy", {}, ctx(host=WEB1), True),
    ({"match": {"hosts": "@prod"}, "deny": True}, "containers.rm", "destroy", {}, ctx(), False),          # local
    ({"match": {"hosts": "local"}, "deny": True}, "containers.rm", "destroy", {}, ctx(), True),
    ({"match": {"hosts": "region=us"}, "deny": True}, "x.y", "mutate", {}, ctx(host=WEB1), False),
    ({"match": {"source": "mcp"}, "deny": True}, "x.y", "mutate", {}, ctx(source="mcp"), True),
    ({"match": {"user": "bob*"}, "deny": True}, "x.y", "mutate", {}, ctx(), False),
    ({"require": {"ticket": True}}, "x.y", "mutate", {}, ctx(), True),
    ({"require": {"ticket": True}}, "x.y", "mutate", {}, ctx(ticket="CHG-1"), False),
    ({"require": {"ticket_pattern": r"CHG-\d+"}}, "x.y", "mutate", {}, ctx(ticket="oops"), True),
    ({"deny_if": {"privileged": True}}, "containers.run", "mutate", {"privileged": True}, ctx(), True),
    ({"deny_if": {"image_tag": ["latest"]}}, "containers.run", "mutate", {"image": "nginx"}, ctx(), True),
    ({"deny_if": {"image_tag": ["latest"]}}, "containers.run", "mutate", {"image": "nginx:1.27"}, ctx(), False),
    ({"deny_if": {"image": "docker.io/*"}}, "images.pull", "mutate", {"ref": "docker.io/x:1"}, ctx(), True),
    ({"deny_if": {"docker_socket": True}}, "containers.run", "mutate",
     {"volume": ["/var/run/docker.sock:/var/run/docker.sock"]}, ctx(), True),
    ({"deny_if": {"volumes": True}}, "containers.rm", "destroy", {"volumes": True}, ctx(), True),
    ({"deny_if": {"host_network": True}}, "containers.run", "mutate", {"network": "host"}, ctx(), True),
])
def test_policy_rules(rule, op, tier, kwargs, c, blocked):
    assert bool(check([{"name": "r", **rule}], op, tier, kwargs, c)) is blocked


@pytest.mark.parametrize(("window", "when", "inside"), [
    ({"days": ["mon", "tue"], "hours": "09-17"}, dt.datetime(2026, 9, 28, 10), True),     # Monday 10:00
    ({"days": ["mon", "tue"], "hours": "09-17"}, dt.datetime(2026, 9, 28, 18), False),
    ({"days": ["sat"]}, dt.datetime(2026, 9, 28, 10), False),
    ({"hours": "22-06"}, dt.datetime(2026, 9, 28, 23), True),                               # wraps midnight
    ({"hours": "22-06"}, dt.datetime(2026, 9, 28, 12), False),
])
def test_windows(window, when, inside):
    assert in_window(window, when.replace(tzinfo=dt.timezone.utc)) is inside


@pytest.mark.parametrize(("image", "tag"), [("nginx", "latest"), ("nginx:1.2", "1.2"), ("reg:5000/app", "latest"),
                                            ("reg:5000/app:v2", "v2"), ("app@sha256:ab", "digest")])
def test_tag_of(image, tag):
    assert tag_of(image) == tag


def test_policy_blocks_cli_with_exit_5_and_shows_in_previews(cli, daemon):
    write_config("""
        [[policy.rules]]
        name = "no destroy without ticket"
        match = { tier = "destroy" }
        require = { ticket = true }
        [[policy.rules]]
        name = "heads up"
        match = { op = "containers.restart" }
        deny = true
        mode = "warn"
    """)
    daemon.on("DELETE", "/containers/web", status=204)
    daemon.on("POST", "/containers/web/restart", status=204)
    code, plan, _ = cli("containers", "rm", "web")
    assert code == EXIT_CONFIRM and any("would be DENIED" in w for w in plan["warnings"])
    code, _, err = cli("containers", "rm", "web", "--yes")
    assert code == EXIT_POLICY and json.loads(err)["violations"][0]["rule"] == "no destroy without ticket"
    assert not any(s.method == "DELETE" for s in daemon.seen)
    assert cli("containers", "rm", "web", "--yes", "--ticket", "CHG-7")[0] == EXIT_OK
    code, _, err = cli("containers", "restart", "web")
    assert code == EXIT_OK and "warn only" in err  # warn-mode rules never block


def test_policy_check_op(cli):
    write_config("""
        [[policy.rules]]
        match = { op = "containers.rm" }
        deny_if = { volumes = true }
    """)
    code, out, _ = cli("policy", "check", "--", "containers", "rm", "db", "--volumes")
    assert code == EXIT_OK and out["allowed"] is False and "volume data" in out["violations"][0]["reason"]
    assert cli("policy", "check", "--", "containers", "rm", "db")[1]["allowed"] is True


def test_mcp_reports_policy_denial():
    from aisb.mcp import Server
    write_config("""
        [[policy.rules]]
        match = { source = "mcp", tier = ["mutate", "destroy"] }
        deny = true
        message = "agents are read-only here"
    """)
    from aisb import Docker
    srv = Server(lambda: Docker("unix:///nonexistent/aisb.sock", timeout=1))  # denial happens before any request
    res = srv.call("containers_restart", {"ref": "web"})
    assert res["isError"] and "agents are read-only here" in res["content"][0]["text"]


# --- audit ------------------------------------------------------------------------------------

def test_audit_records_changes_and_detects_tampering(cli, daemon):
    daemon.on("POST", "/containers/web/restart", status=204)
    daemon.on("POST", "/containers/nope/restart", status=404, json={"message": "no such container"})
    daemon.on("GET", "/containers/web/json", json={"State": {}})
    cli("containers", "restart", "web", "--ticket", "CHG-1")
    cli("containers", "restart", "nope")
    cli("containers", "inspect", "web")                                   # reads are not audited by default
    recs = list(audit.read())
    assert [(r["op"], r["ok"], r["ticket"]) for r in recs] == [("containers.restart", True, "CHG-1"),
                                                               ("containers.restart", False, None)]
    assert recs[0]["source"] == "cli" and recs[0]["run_id"] and recs[0]["user"]
    assert audit.verify()["ok"]
    code, rows, _ = cli("audit", "log", "--failed")
    assert [r["op"] for r in rows] == ["containers.restart"] and "no such container" in rows[0]["error"]
    lines = audit.path().read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["ok"] = False
    audit.path().write_text("\n".join([json.dumps(tampered), *lines[1:]]) + "\n")
    assert audit.verify() == {"ok": False, "records": 1, "broken_at": 1, "reason": "record content was modified"}
    audit.path().write_text(lines[1] + "\n")
    assert audit.verify()["reason"].startswith("chain broken")


def test_audit_redacts_secrets():
    rec = audit.redact({"env": ["DB_PASSWORD=hunter2", "MODE=x"], "api_token": "abc", "nested": {"secret": "s"}})
    assert rec == {"env": ["DB_PASSWORD=***", "MODE=x"], "api_token": "***", "nested": {"secret": "***"}}


# --- plugins ----------------------------------------------------------------------------------

def test_plugin_resource_gets_cli_mcp_docs(tmp_path, monkeypatch, cli, daemon):
    (tmp_path / "acme_plugin.py").write_text(textwrap.dedent('''
        from typing import Annotated
        from aisb.ops import Resource, Tier, op

        class Acme(Resource, name="acme"):
            @op(Tier.READ)
            def hello(self, who: Annotated[str, "name"] = "world") -> dict:
                """Say hello (plugin op)."""
                return {"hello": who, "api": self.t.json("GET", "/_ping_json")}
    '''))
    (tmp_path / "broken_plugin.py").write_text("raise RuntimeError('boom')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("AISB_PLUGINS", "acme_plugin,broken_plugin")
    plugins.reset()
    daemon.on("GET", "/_ping_json", json={"ok": 1})
    code, out, _ = cli("acme", "hello", "aisb")
    assert code == EXIT_OK and out == {"hello": "aisb", "api": {"ok": 1}}
    from aisb.mcp import Server
    from aisb.ops import render_markdown
    assert "acme_hello" in Server(lambda: None).tools and "## acme" in render_markdown()
    assert "RuntimeError: boom" in plugins.errors()["broken_plugin"]
    sys.modules.pop("acme_plugin", None)


# --- output ------------------------------------------------------------------------------------

ROWS = [{"name": "api", "state": "running", "ports": ["80/tcp"], "labels": {"a": "1"}},
        {"name": "db", "state": "exited", "ports": [], "labels": {}}]


def test_render_formats_and_pick():
    assert render(ROWS, "ndjson").splitlines()[1] == json.dumps(ROWS[1])
    assert render(ROWS, "csv").splitlines()[0] == "name,state,ports,labels"
    assert render(ROWS, "table").splitlines()[0].split() == ["NAME", "STATE", "PORTS"]
    assert pick({"summary": 1, "rows": ROWS}, "name,labels.a") == {"summary": 1, "rows": [
        {"name": "api", "labels.a": "1"}, {"name": "db", "labels.a": None}]}
    assert render({"output": "line\n", "x": 1}, "raw") == "line"


@pytest.mark.parametrize(("value", "text"), [
    ({"a": "yes", "b": "1.5", "c": "x: y", "d": None, "e": True, "f": []}, 'a: "yes"\nb: "1.5"\nc: "x: y"\nd: null\ne: true\nf: []'),
    ([{"k": [1, 2]}], "- k:\n    - 1\n    - 2"),
])
def test_yaml_quotes_ambiguous_scalars(value, text):
    assert yaml(value) == text


def test_cli_output_and_pick(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "a" * 64, "Names": ["/api"], "Image": "x", "State": "running",
                                                "Status": "Up", "Labels": {}}])
    code = main(["containers", "list", "--host", f"unix://{daemon.sock}", "-o", "csv", "--pick", "name,state"])
    assert code == EXIT_OK


# --- context ------------------------------------------------------------------------------------

def test_fleet_inner_ops_share_run_id_and_carry_host(two_daemons_fleet):
    run, (a, b) = two_daemons_fleet
    for d in (a, b):
        d.on("POST", "/containers/api/restart", status=204)
    code, out, _ = run("fleet", "apply", "all", "--", "containers", "restart", "api")
    assert code == EXIT_OK
    recs = list(audit.read())
    inner = [r for r in recs if r["op"] == "containers.restart"]
    outer = [r for r in recs if r["op"] == "fleet.apply"]
    assert sorted(r["host"] for r in inner) == ["a", "b"] and len(outer) == 1
    assert {r["run_id"] for r in inner} == {outer[0]["run_id"]}


def test_fleet_policy_is_evaluated_per_host(two_daemons_fleet):
    run, (a, b) = two_daemons_fleet
    write_config("""
        [[policy.rules]]
        name = "db hosts are frozen"
        match = { hosts = "@db", tier = "mutate" }
        deny = true
    """)
    for d in (a, b):
        d.on("POST", "/containers/api/restart", status=204)
    code, out, _ = run("fleet", "apply", "all", "--", "containers", "restart", "api")
    assert out["summary"]["failed"] == ["b"] and "frozen" in out["results"][1]["error"]
    assert ("POST", "/containers/api/restart") in a.calls() and ("POST", "/containers/api/restart") not in b.calls()


@pytest.fixture
def two_daemons_fleet(tmp_path, monkeypatch, capsys):
    import shutil
    import tempfile

    from conftest import FakeDaemon
    d = Path(tempfile.mkdtemp(prefix="aisb-p-", dir="/tmp"))
    a, b = FakeDaemon(d / "a.sock"), FakeDaemon(d / "b.sock")
    a.start()
    b.start()
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"a": {"docker": f"unix://{a.sock}", "groups": ["web"]},
                                         "b": {"docker": f"unix://{b.sock}", "groups": ["db"]}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        i = argv.index("--") if "--" in argv else len(argv)
        code = main([*argv[:i], "--json", *argv[i:]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    yield run, (a, b)
    a.stop()
    b.stop()
    shutil.rmtree(d, ignore_errors=True)


def test_policy_denied_payload():
    e = PolicyDenied("x.y", [])
    assert e.as_dict()["error"] == "PolicyDenied"
