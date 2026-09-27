"""Runbooks: parsing/validation, planning, approvals, retries, failure handling and resume."""

import json
import textwrap
from pathlib import Path

import pytest

from aisb import config, runbooks
from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_UNMET, main

from conftest import Reply


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def book(tmp_path: Path, body: str, name: str = "rb.toml") -> str:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    return str(p)


BASIC = """
    name = "basic"
    vars = { c = "web" }
    [[steps]]
    name = "restart"
    run = "containers restart {c}"
    [[steps]]
    name = "go"
    approve = "restart done on {c}; remove old?"
    [[steps]]
    name = "remove"
    run = "containers rm old --force"
    [[steps]]
    name = "cleanup"
    when = "on_failure"
    run = "containers start {c}"
"""


# --- parsing ------------------------------------------------------------------------------------

@pytest.mark.parametrize(("data", "error"), [
    ({"steps": []}, "non-empty"),
    ({"steps": [{"name": "a"}]}, "exactly one of"),
    ({"steps": [{"name": "a", "run": "x", "sleep": 1}]}, "exactly one of"),
    ({"steps": [{"name": "a", "run": "x"}, {"name": "a", "run": "y"}]}, "duplicate"),
    ({"steps": [{"name": "a b", "run": "x"}]}, "invalid name"),
    ({"steps": [{"name": "a", "run": "x", "retries": 3}]}, "unknown keys"),
    ({"steps": [{"name": "a", "run": "x", "when": "later.ok"}]}, "not an earlier step"),
    ({"steps": [{"name": "a", "run": "x", "when": "sometimes"}]}, "when must be"),
])
def test_parse_errors(data, error):
    with pytest.raises(ValueError, match=error):
        runbooks.parse(data)


def test_render_and_argv():
    step = runbooks.Step("s", run="aisb containers logs {c} --grep '{pat}'")
    assert runbooks.argv_of(step, {"c": "web", "pat": "a b"}) == ["containers", "logs", "web", "--grep", "a b"]
    with pytest.raises(ValueError, match=r"undefined variable\(s\) \['pat'\]"):
        runbooks.argv_of(step, {"c": "web"})


@pytest.mark.parametrize(("when", "states", "failed", "runs"), [
    ("success", {}, False, True), ("success", {}, True, False),
    ("always", {}, True, True), ("on_failure", {}, False, False), ("on_failure", {}, True, True),
    ("a.ok", {"a": {"status": "done"}}, True, True), ("a.failed", {"a": {"status": "done"}}, False, False),
])
def test_should_run(when, states, failed, runs):
    assert runbooks.should_run(runbooks.Step("x", run="y", when=when), states, failed) is runs


def test_find_by_name(tmp_path, monkeypatch):
    (tmp_path / "lib").mkdir()
    book(tmp_path / "lib", BASIC, "deploy.toml")
    monkeypatch.setenv("AISB_RUNBOOKS", str(tmp_path / "lib"))
    assert runbooks.load("deploy").name == "basic"
    with pytest.raises(ValueError, match="not found"):
        runbooks.load("nope")


# --- execution through the CLI + fake daemon ------------------------------------------------------

def routes(daemon, *, restart_status: int = 204):
    daemon.on("POST", "/containers/web/restart", status=restart_status,
              **({} if restart_status < 400 else {"json": {"message": "boom"}}))
    daemon.on("DELETE", "/containers/old", status=204)
    daemon.on("POST", "/containers/web/start", status=204)


def test_run_needs_yes_then_waits_for_approval_then_completes(cli, daemon, tmp_path):
    routes(daemon)
    f = book(tmp_path, BASIC)
    code, plan, _ = cli("runbook", "run", f)
    assert code == EXIT_CONFIRM and [p["step"] for p in plan["planned"]] == ["restart", "go", "remove", "cleanup"]
    assert not any(s.method in ("POST", "DELETE") for s in daemon.seen)
    code, out, _ = cli("runbook", "run", f, "--yes")
    assert code == EXIT_UNMET and out["status"] == "waiting" and "remove old?" in out["reason"]
    assert daemon.calls("POST") == [("POST", "/containers/web/restart")]
    code, pend, _ = cli("runbook", "pending")
    assert pend == [{**pend[0], "run": out["run"], "step": "go", "prompt": "restart done on web; remove old?"}]
    code, ap, _ = cli("runbook", "approve", out["run"], "--resume", "--note", "ok")
    assert code == EXIT_OK and ap["resumed"]["status"] == "done"
    assert [s["status"] for s in ap["resumed"]["steps"]] == ["done", "done", "done", "skipped"]
    assert daemon.calls("POST").count(("POST", "/containers/web/restart")) == 1   # completed steps never re-run
    shown = cli("runbook", "show", out["run"])[1]
    assert shown["approvals"]["go"]["note"] == "ok" and shown["steps"]["remove"]["command"] == "containers rm old --force"


def test_deny_runs_on_failure_steps(cli, daemon, tmp_path):
    routes(daemon)
    code, out, _ = cli("runbook", "run", book(tmp_path, BASIC), "--yes")
    cli("runbook", "approve", out["run"], "--deny", "--note", "not today")
    code, res, _ = cli("runbook", "resume", out["run"], "--yes")
    assert code == EXIT_UNMET and "denied by" in res["reason"]
    assert [s["status"] for s in res["steps"]] == ["done", "failed", "skipped", "done"]
    assert ("POST", "/containers/web/start") in daemon.calls() and ("DELETE", "/containers/old") not in daemon.calls()


def test_retry_then_resume_after_fix(cli, daemon, tmp_path):
    attempts = {"n": 0}

    def flaky(_):
        attempts["n"] += 1
        return Reply(status=204) if attempts["n"] >= 3 else Reply(500, json={"message": "not yet"})
    daemon.on("POST", "/containers/web/restart", flaky)
    daemon.on("POST", "/containers/db/restart", status=500, json={"message": "db down"})
    f = book(tmp_path, """
        [[steps]]
        name = "web"
        run = "containers restart web"
        retry = { times = 3, delay = 0 }
        [[steps]]
        name = "db"
        run = "containers restart db"
        [[steps]]
        name = "after"
        run = "containers restart web"
    """)
    code, out, _ = cli("runbook", "run", f, "--yes")
    assert code == EXIT_UNMET and [s["status"] for s in out["steps"]] == ["done", "failed", "skipped"]
    assert out["steps"][0]["attempts"] == 3 and "db down" in out["reason"]
    daemon.on("POST", "/containers/db/restart", status=204)          # operator fixes the problem
    code, res, _ = cli("runbook", "resume", out["run"], "--yes")
    assert code == EXIT_OK and res["status"] == "done" and attempts["n"] == 4   # web not re-run, `after` ran once


def test_resume_refuses_changed_runbook(cli, daemon, tmp_path):
    routes(daemon)
    f = book(tmp_path, BASIC)
    _, out, _ = cli("runbook", "run", f, "--yes")
    Path(f).write_text(Path(f).read_text().replace("remove old?", "remove it?"))
    code, _, err = cli("runbook", "resume", out["run"], "--yes")
    assert code != EXIT_OK and "changed since the run started" in err
    assert cli("runbook", "resume", out["run"], "--yes", "--allow-changed")[1]["status"] == "waiting"


def test_policy_denial_fails_the_step(cli, daemon, tmp_path, monkeypatch):
    import os
    Path(os.environ["AISB_CONFIG"]).write_text(textwrap.dedent("""
        [[policy.rules]]
        name = "runbooks may not delete"
        match = { source = "runbook", tier = "destroy" }
        deny = true
    """))
    config.reset()
    routes(daemon)
    f = book(tmp_path, """
        [[steps]]
        name = "rm"
        run = "containers rm old --force"
    """)
    code, plan, _ = cli("runbook", "run", f)
    assert "would be DENIED" in json.dumps(plan)
    code, out, _ = cli("runbook", "run", f, "--yes")
    assert code == EXIT_UNMET and "runbooks may not delete" in out["reason"]
    assert ("DELETE", "/containers/old") not in daemon.calls()


def test_steps_cannot_nest_runbooks(cli, tmp_path):
    f = book(tmp_path, """
        [[steps]]
        name = "loop"
        run = "runbook run other.toml"
    """)
    code, _, err = cli("runbook", "plan", f)
    assert code != EXIT_OK and "another runbook" in err
