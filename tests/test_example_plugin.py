"""examples/aisb-owners end to end against the fake daemon: the plugin's ops through the CLI, dry run, policy,
audit, MCP, docs, man pages and completion, plus its doctor rule. Keeps the example honest as aisb changes."""

import json
import sys
import tomllib
from pathlib import Path

import pytest

from aisb import audit, completion, config, manpages, plugins
from aisb.cli import EXIT_OK, EXIT_POLICY, main

EXAMPLE = Path(__file__).parents[1] / "examples" / "aisb-owners"
ROWS = [
    {"Id": "a" * 64, "Names": ["/web"], "Labels": {"com.example.owner": "payments"}},
    {"Id": "b" * 64, "Names": ["/tmp-debug"], "Labels": {}},
    {"Id": "c" * 64, "Names": ["/db"], "Labels": None},
]


@pytest.fixture
def owners(monkeypatch, daemon):
    from aisb.insights import triage
    rules = list(triage.RULES)
    monkeypatch.syspath_prepend(str(EXAMPLE / "src"))
    monkeypatch.setenv("AISB_PLUGINS", "aisb_owners")
    plugins.reset()
    daemon.on("GET", r"/containers/json", json=ROWS)
    daemon.on("POST", r"/containers/\w+/stop", status=204)
    yield daemon
    triage.RULES[:] = rules   # the plugin's doctor rule must not leak into other tests
    sys.modules.pop("aisb_owners", None)


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str) -> tuple[int, object]:
        code = main([*argv, "--host", host, "--json"])
        out = capsys.readouterr().out
        return code, json.loads(out) if out.strip() else None
    return run


def test_list_groups_containers_by_owner(owners, cli):
    code, out = cli("owners", "list", "--all")
    assert code == EXIT_OK
    assert out == {"label": "com.example.owner", "owners": {"payments": ["web"]}, "unowned": ["db", "tmp-debug"]}
    assert owners.seen[-1].query["all"] in ("1", "true", "True")


def test_stop_unowned_dry_run_plans_and_sends_nothing(owners, cli):
    code, out = cli("owners", "stop-unowned", "--keep", "db", "--dry-run")
    assert code == EXIT_OK and owners.calls("POST") == []
    assert out["status"] == "dry-run"
    assert [p["path"].split("/")[-2:] for p in out["planned"]] == [["b" * 64, "stop"]]


def test_stop_unowned_stops_and_is_audited(owners, cli):
    code, out = cli("owners", "stop-unowned", "--keep", "db", "--grace", "3")
    assert code == EXIT_OK and out == {"stopped": ["tmp-debug"], "kept": ["db"]}
    assert owners.calls("POST") == [("POST", f"/containers/{'b' * 64}/stop")]
    (rec,) = [r for r in audit.read() if r["op"] == "owners.stop-unowned"]
    assert rec["ok"] and rec["args"]["keep"] == ["db"] and rec["tier"] == "mutate"


def test_policy_rules_apply_to_plugin_ops(owners, cli, tmp_path):
    Path(config.default_path()).write_text('[[policy.rules]]\nname = "no janitor"\nmatch = { op = "owners.*" }\n'
                                           'deny = true\n')
    config.reset()
    assert cli("owners", "stop-unowned")[0] == EXIT_POLICY
    assert owners.calls("POST") == []


def test_the_plugin_reaches_every_generated_surface(owners):
    from aisb.mcp import Server
    from aisb.ops import render_markdown
    assert {"owners_list", "owners_stop-unowned"} <= set(Server(lambda: None).tools)
    assert "## owners" in render_markdown()
    assert "'owners') echo 'list stop-unowned'" in completion.script("bash")
    page = manpages.pages()["aisb-owners.1"]
    assert "stop\\-unowned (mutate)" in page and "\\-\\-keep" in page


def test_doctor_rule_reports_unowned_containers(owners):
    plugins.load()
    import aisb_owners  # type: ignore[import-not-found]
    from aisb.insights.triage import RULES, Facts
    assert aisb_owners.unowned in RULES
    facts = Facts("tmp-debug", {"Config": {"Labels": {}}, "State": {"Status": "running"}})
    assert [f.code for f in aisb_owners.unowned(facts)] == ["no-owner"]


def test_package_metadata_points_at_the_module():
    meta = tomllib.loads((EXAMPLE / "pyproject.toml").read_text())
    (module,) = meta["project"]["entry-points"]["aisb.plugins"].values()
    assert (EXAMPLE / "src" / module / "__init__.py").exists()
    assert any(d.startswith("aisb") for d in meta["project"]["dependencies"])
