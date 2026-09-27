"""Safety core: tier enforcement, dry-run, confirmation, policy, audit chain, CLI exit codes.

Only process boundaries are faked (the Docker daemon socket, the clock, syslog sockets); aisb internals run for real.
"""

import datetime as dt
import json
import os
import socket
import textwrap
from pathlib import Path
from typing import Annotated, Literal

import pytest

from aisb import audit, config, context, ops
from aisb.cli import EXIT_CONFIRM, EXIT_DOCKER, EXIT_OK, EXIT_POLICY, EXIT_UNMET, EXIT_USAGE, main, run
from aisb.client import Docker
from aisb.context import Ctx
from aisb.fleet.inventory import Host
from aisb.ops import Op, Resource, Tier, get_op, invoke, op
from aisb.policy import PolicyDenied, check, enforce, in_window, matches

MUTATING = ("POST", "PUT", "DELETE")


def write_config(text: str) -> Path:
    p = Path(os.environ["AISB_CONFIG"])
    p.write_text(textwrap.dedent(text))
    config.reset()
    return p


def mutating(daemon) -> list[tuple[str, str]]:
    return [c for c in daemon.calls() if c[0] in MUTATING]


def records() -> list[dict]:
    return list(audit.read())


@pytest.fixture
def cli(host, capsys):
    """main() with --host/--json injected before any trailing `--`; returns (code, parsed stdout, stderr)."""
    def go(*argv: str):
        head, tail = (list(argv[:argv.index("--")]), list(argv[argv.index("--"):])) if "--" in argv else (list(argv), [])
        code = main([*head, "--host", host, "--json", *tail])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return go


@pytest.fixture
def toy():
    """A throw-away resource (unregistered afterwards) to drive invoke() paths no built-in op reaches cleanly."""
    class Toy(Resource, name="safetytoy"):
        @op(Tier.READ)
        def peek(self, ref: str) -> dict:
            """Read a toy."""
            return self.t.json("GET", f"/toys/{ref}")

        @op(Tier.MUTATE)
        def poke(self, ref: str, *, env: list[str] | None = None, password: str | None = None,
                 labels: dict[str, str] | None = None) -> dict:
            """Change a toy."""
            self.t.json("POST", f"/toys/{ref}/poke", body={"env": env or [], "labels": labels or {}})
            return {"poked": ref, **({"warnings": ["toy warning"]} if self.t.planning else {})}

        @op(Tier.DESTROY)
        def smash(self, ref: str, *, force: bool = False) -> dict:
            """Delete a toy."""
            self.t.json("DELETE", f"/toys/{ref}", query={"force": force})
            return {"removed": ref}

        @op(Tier.MUTATE)
        def unmet(self) -> dict:
            """Condition not met."""
            return {"ok": False, "reason": "not ready yet"}

        @op(Tier.MUTATE)
        def boom(self, kind: Literal["runtime", "interrupt", "value"] = "runtime") -> None:
            """Fail."""
            raise {"runtime": RuntimeError("kaput"), "interrupt": KeyboardInterrupt(), "value": ValueError("bad arg")}[kind]

        @op(Tier.MUTATE)
        def nested(self, ref: str) -> dict:
            """Change two toys through the registry, as fleet/runbooks do."""
            inner = Docker.from_transport(self.t)
            invoke(inner, get_op("safetytoy.poke"), {"ref": ref})
            invoke(inner, get_op("safetytoy.poke"), {"ref": ref + "2"})
            return {"run_id": context.current().run_id}

    yield Toy
    ops._REGISTRY.pop("safetytoy", None)
    ops._RESOURCES.pop("safetytoy", None)


def toy_routes(daemon) -> None:
    daemon.on("GET", r"/toys/[^/]+", json={"toy": True})
    daemon.on("POST", r"/toys/[^/]+/poke", status=204)
    daemon.on("DELETE", r"/toys/[^/]+", status=204)


# === 1. safety invariants ======================================================================

DESTROYS = [
    (["containers", "rm", "web", "--force", "--volumes"], "DELETE", "/containers/web"),
    (["volumes", "rm", "data"], "DELETE", "/volumes/data"),
    (["images", "rmi", "nginx:1"], "DELETE", "/images/nginx:1"),
]


@pytest.mark.parametrize("argv,method,path", DESTROYS)
def test_destroy_without_yes_sends_nothing_and_exits_3(cli, daemon, argv, method, path):
    daemon.on(method, path, status=200, json=[])
    code, out, _ = cli(*argv)
    assert code == EXIT_CONFIRM
    assert mutating(daemon) == []
    assert out["status"] == "confirmation_required" and out["tier"] == "destroy"
    assert out["planned"][0]["method"] == method and out["planned"][0]["path"].endswith(path)
    assert "explicitly approve" in out["hint"]
    assert records() == []  # a preview is not a change


@pytest.mark.parametrize("argv,method,path", DESTROYS)
def test_destroy_with_yes_sends_request_and_is_audited(cli, daemon, argv, method, path):
    daemon.on(method, path, status=200, json=[])
    code, _, _ = cli(*argv, "--yes")
    assert code == EXIT_OK
    assert mutating(daemon) == [(method, path)]
    (rec,) = records()
    assert rec["ok"] is True and rec["tier"] == "destroy" and rec["source"] == "cli" and rec["run_id"]


@pytest.mark.parametrize("argv", [
    ["containers", "stop", "web"],
    ["containers", "restart", "web", "--grace", "1"],
    ["volumes", "create", "data", "--label", "a=b"],
    ["images", "tag", "nginx:1", "reg/nginx:2"],
    ["images", "pull", "alpine:3"],
    ["containers", "rm", "web", "--yes"],          # --dry-run wins over --yes
    ["volumes", "rm", "data", "--yes"],
])
def test_dry_run_never_sends_mutating_requests(cli, daemon, argv):
    code, out, _ = cli(*argv, "--dry-run")
    assert code == EXIT_OK
    assert mutating(daemon) == []
    assert out["status"] == "dry-run" and out["planned"] and all(p["method"] in MUTATING for p in out["planned"])
    assert records() == []


def test_policy_denial_exits_5_sends_nothing_and_is_audited(cli, daemon):
    write_config("""
        [[policy.rules]]
        name = "no-destroy"
        match = { tier = "destroy" }
        deny = true
        message = "destroy is frozen"
        [[policy.rules]]
        name = "no-stop"
        match = { op = "containers.stop" }
        deny = true
    """)
    code, _, err = cli("containers", "rm", "web", "--yes")
    assert code == EXIT_POLICY and daemon.calls() == []
    payload = json.loads(err)
    assert payload["error"] == "PolicyDenied" and payload["violations"] == [
        {"rule": "no-destroy", "reason": "destroy is frozen", "mode": "deny"}]
    code, _, err = cli("containers", "stop", "web")
    assert code == EXIT_POLICY and daemon.calls() == []
    assert "containers.stop is not allowed here" in err
    denied = records()
    assert [(r["op"], r["ok"], r["denied"], r["ms"]) for r in denied] == [
        ("containers.rm", False, True, 0), ("containers.stop", False, True, 0)]
    assert "denied by policy" in denied[0]["error"]
    code, rows, _ = cli("audit", "log", "--failed")
    assert code == EXIT_OK and [r["op"] for r in rows] == ["containers.stop", "containers.rm"]


def test_warn_mode_proceeds_and_reports_on_stderr(cli, daemon):
    write_config("""
        [[policy.rules]]
        name = "heads-up"
        mode = "warn"
        match = { op = "containers.*" }
        require = { ticket = true }
    """)
    daemon.on("POST", "/containers/web/stop", status=204)
    code, out, err = cli("containers", "stop", "web")
    assert code == EXIT_OK and out == {"ref": "web", "changed": True}
    assert mutating(daemon) == [("POST", "/containers/web/stop")]
    assert json.loads(err)["warnings"] == ["policy [heads-up] a change ticket is required (--ticket or $AISB_TICKET) (warn only)"]
    assert records()[0]["ok"] is True


def test_previews_show_would_be_denied_and_warn_only(cli, daemon):
    write_config("""
        [[policy.rules]]
        name = "hard"
        match = { tier = ["mutate", "destroy"] }
        deny_if = { force = true }
        [[policy.rules]]
        name = "soft"
        mode = "warn"
        match = { op = "containers.*" }
        deny = true
    """)
    code, out, _ = cli("containers", "rm", "web", "--force")
    assert code == EXIT_CONFIRM and daemon.calls() == []
    assert out["warnings"] == ["policy [hard] --force is not allowed (would be DENIED)",
                               "policy [soft] containers.rm is not allowed here (warn only)"]
    code, out, _ = cli("containers", "stop", "web", "--dry-run")
    assert code == EXIT_OK and out["warnings"] == ["policy [soft] containers.stop is not allowed here (warn only)"]
    assert records() == []


def test_ticket_flag_and_env_reach_policy_and_audit(cli, daemon, monkeypatch):
    write_config("""
        [[policy.rules]]
        match = { tier = "destroy" }
        require = { ticket = true, ticket_pattern = "^OPS-[0-9]+$" }
    """)
    daemon.on("DELETE", "/volumes/v", status=204)
    code, _, err = cli("volumes", "rm", "v", "--yes")
    assert code == EXIT_POLICY and "[rule-1] a change ticket is required" in err
    code, _, err = cli("volumes", "rm", "v", "--yes", "--ticket", "JIRA-1")
    assert code == EXIT_POLICY and "does not match" in err
    assert daemon.calls() == []
    assert cli("volumes", "rm", "v", "--yes", "--ticket", "OPS-42")[0] == EXIT_OK
    monkeypatch.setenv("AISB_TICKET", "OPS-7")
    assert cli("volumes", "rm", "v", "--yes")[0] == EXIT_OK
    assert [r["ticket"] for r in records()] == [None, "JIRA-1", "OPS-42", "OPS-7"]


def test_secrets_are_redacted_in_audit_args(toy, daemon, client):
    toy_routes(daemon)
    invoke(client, get_op("safetytoy.poke"), {"ref": "t", "env": ["API_TOKEN=tok123", "MODE=x", "BARE"],
                                             "password": "hunter2", "labels": {"db_secret": "s3", "team": "a"}})
    text = audit.path().read_text()
    assert "tok123" not in text and "hunter2" not in text and "s3" not in text
    (rec,) = records()
    assert rec["args"] == {"ref": "t", "env": ["API_TOKEN=***", "MODE=x", "BARE"], "password": "***",
                           "labels": {"db_secret": "***", "team": "a"}}
    assert daemon.seen[0].body["env"] == ["API_TOKEN=tok123", "MODE=x", "BARE"]  # redaction is for the log only


@pytest.mark.parametrize("value,expected", [
    ({"Env": ["PASSWORD=p"]}, {"Env": ["PASSWORD=***"]}),
    ({"env": ["A=1", 2]}, {"env": ["A=1", 2]}),                    # not all strings: left as is
    ({"cmd": ("a", {"private_key": "k"})}, {"cmd": ["a", {"private_key": "***"}]}),
    ({"auth": {"user": "u"}}, {"auth": "***"}),                     # a secret-looking key hides the whole value
    ({"ssh_key": "k", "keyboard": "q"}, {"ssh_key": "***", "keyboard": "q"}),
    ("plain", "plain"),
])
def test_redact(value, expected):
    assert audit.redact(value) == expected


def test_run_id_shared_by_nested_ops_and_fresh_per_change(toy, daemon, client):
    toy_routes(daemon)
    out = invoke(client, get_op("safetytoy.nested"), {"ref": "a"})
    recs = records()
    assert [r["op"] for r in recs] == ["safetytoy.poke", "safetytoy.poke", "safetytoy.nested"]
    assert len({r["run_id"] for r in recs}) == 1 and out.result["run_id"] == recs[0]["run_id"]
    invoke(client, get_op("safetytoy.poke"), {"ref": "b"})
    assert records()[-1]["run_id"] != recs[0]["run_id"]
    with context.use(run_id="given"):
        invoke(client, get_op("safetytoy.poke"), {"ref": "c"})
    assert records()[-1]["run_id"] == "given"
    assert context.current().run_id is None


def test_reads_are_not_audited_unless_configured_and_get_no_run_id(toy, daemon, client):
    toy_routes(daemon)
    assert invoke(client, get_op("safetytoy.peek"), {"ref": "a"}).result == {"toy": True}
    assert records() == []
    write_config("""
        [audit]
        reads = true
    """)
    invoke(client, get_op("safetytoy.peek"), {"ref": "a"})
    (rec,) = records()
    assert rec["tier"] == "read" and rec["run_id"] is None and rec["endpoint"].startswith("unix://")


def test_read_ops_ignore_dry_run_and_confirm(toy, daemon, client):
    toy_routes(daemon)
    assert invoke(client, get_op("safetytoy.peek"), {"ref": "a"}, dry_run=True).status == "ok"


def test_hooks_run_only_for_real_changes(toy, daemon, client, monkeypatch):
    toy_routes(daemon)
    seen = []
    monkeypatch.setattr(ops, "HOOKS", [lambda c, o, kw: seen.append((o.qualname, dict(kw), len(daemon.calls())))])
    invoke(client, get_op("safetytoy.peek"), {"ref": "a"})
    invoke(client, get_op("safetytoy.poke"), {"ref": "a"}, dry_run=True)
    invoke(client, get_op("safetytoy.smash"), {"ref": "a"})              # preview: not confirmed
    assert seen == []
    n = len(daemon.calls())
    invoke(client, get_op("safetytoy.smash"), {"ref": "a"}, confirm=True)
    assert seen == [("safetytoy.smash", {"ref": "a"}, n)]                 # before the DELETE went out


def test_hook_failure_aborts_the_change_and_is_audited(toy, daemon, client, monkeypatch):
    toy_routes(daemon)

    def refuse(c, o, kw):
        raise RuntimeError("cannot record undo")
    monkeypatch.setattr(ops, "HOOKS", [refuse])
    with pytest.raises(RuntimeError):
        invoke(client, get_op("safetytoy.poke"), {"ref": "a"})
    assert mutating(daemon) == []
    assert records()[0]["error"] == "RuntimeError: cannot record undo"


def test_invoke_denied_by_policy_never_runs_hooks(toy, daemon, client, monkeypatch):
    write_config("""
        [[policy.rules]]
        match = { op = "safetytoy.*", source = "api" }
        deny = true
    """)
    toy_routes(daemon)
    monkeypatch.setattr(ops, "HOOKS", [lambda *a: pytest.fail("hook ran")])
    with pytest.raises(PolicyDenied) as e:
        invoke(client, get_op("safetytoy.smash"), {"ref": "a"}, confirm=True)
    assert e.value.op == "safetytoy.smash" and daemon.calls() == []
    preview = invoke(client, get_op("safetytoy.poke"), {"ref": "a"}, dry_run=True)
    assert preview.payload() == {"status": "dry-run", "planned": [
        {"method": "POST", "path": "/toys/a/poke", "body": {"env": [], "labels": {}}}],
        "warnings": ["toy warning", "policy [rule-1] safetytoy.poke is not allowed here (would be DENIED)"]}


def test_outcomes_and_failures_are_audited(toy, daemon, client):
    toy_routes(daemon)
    out = invoke(client, get_op("safetytoy.unmet"), {})
    assert out.status == "ok" and out.payload() == {"ok": False, "reason": "not ready yet"} and out.warnings == []
    with pytest.raises(RuntimeError):
        invoke(client, get_op("safetytoy.boom"), {})
    with pytest.raises(KeyboardInterrupt):
        invoke(client, get_op("safetytoy.boom"), {"kind": "interrupt"})
    recs = records()
    assert [(r["ok"], r["error"]) for r in recs] == [
        (False, "not ready yet"), (False, "RuntimeError: kaput"), (False, "KeyboardInterrupt: ")]
    assert audit.verify() == {"ok": True, "records": 3, "head": recs[-1]["hash"]}


def test_outcome_payload_without_warnings():
    assert ops.Outcome("confirm", planned=[{"x": 1}]).payload() == {"status": "confirm", "planned": [{"x": 1}]}


# === audit chain =================================================================================

def _chain(n: int = 4) -> list[str]:
    for i in range(n):
        audit.record(op=f"t.op{i}", tier="mutate", args={"i": i}, ctx=Ctx("u"), endpoint=None, ok=True,
                     error=None, ms=i)
    return audit.path().read_text().splitlines()


def _write(lines: list[str]) -> None:
    audit.path().write_text("".join(line + "\n" for line in lines))


def _edit(lines, i, **changes):
    rec = json.loads(lines[i])
    rec.update(changes)
    return [*lines[:i], json.dumps(rec), *lines[i + 1:]]


@pytest.mark.parametrize("tamper,broken_at,reason", [
    (lambda ls: _edit(ls, 0, ok=False), 1, "modified"),
    (lambda ls: _edit(ls, 2, user="mallory"), 3, "modified"),
    (lambda ls: _edit(ls, 3, args={"i": 99}), 4, "modified"),                        # last record edited
    (lambda ls: _edit(ls, 1, hash="f" * 64), 2, "modified"),                         # forged hash
    (lambda ls: ls[1:], 1, "removed or reordered"),                                  # first removed
    (lambda ls: [ls[0], *ls[2:]], 2, "removed or reordered"),                        # middle removed
    (lambda ls: [ls[0], ls[2], ls[1], ls[3]], 2, "removed or reordered"),            # swapped
    (lambda ls: [*ls, ls[1]], 5, "removed or reordered"),                            # replayed
    (lambda ls: [*ls, json.dumps({"op": "fake", "prev": "0" * 64, "hash": "x"})], 5, "removed or reordered"),
])
def test_verify_detects_each_tampering_kind(tamper, broken_at, reason):
    lines = _chain()
    assert audit.verify()["ok"] is True
    _write(tamper(lines))
    res = audit.verify()
    assert res["ok"] is False and res["broken_at"] == broken_at and reason in res["reason"]


def test_verify_empty_and_explicit_path(tmp_path):
    assert audit.verify() == {"ok": True, "records": 0, "head": audit.GENESIS}
    lines = _chain(2)
    copy = tmp_path / "copy.jsonl"
    copy.write_text("\n".join(lines) + "\n")
    assert audit.verify(copy)["records"] == 2 and audit.verify(copy)["head"] == json.loads(lines[-1])["hash"]


def test_chain_continues_across_appends_and_permissions():
    lines = _chain(2)
    assert json.loads(lines[1])["prev"] == json.loads(lines[0])["hash"]
    assert json.loads(lines[0])["prev"] == audit.GENESIS
    assert oct(audit.path().stat().st_mode & 0o777) == "0o600"


def test_chain_survives_records_larger_than_the_tail_window():
    audit.record(op="big", tier="mutate", args={"blob": "x" * 200_000}, ctx=Ctx("u"), endpoint=None, ok=True,
                 error=None, ms=0)
    _chain(2)
    assert audit.verify()["ok"] is True and audit.verify()["records"] == 3


def test_writer_restarts_chain_after_garbage_tail():
    audit.path().parent.mkdir(parents=True, exist_ok=True)
    audit.path().write_text("not json\n")
    rec = audit.record(op="x", tier="mutate", args={}, ctx=Ctx("u"), endpoint=None, ok=True, error=None, ms=0)
    assert rec["prev"] == audit.GENESIS
    audit.path().write_text(json.dumps({"no": "hash"}) + "\n")
    rec = audit.record(op="x", tier="mutate", args={}, ctx=Ctx("u"), endpoint=None, ok=True, error=None, ms=0)
    assert rec["prev"] == audit.GENESIS


@pytest.mark.parametrize("cfg,env,tier,on", [
    ("", None, "mutate", True),
    ("", None, "read", False),
    ("[audit]\nreads = true", None, "read", True),
    ("[audit]\nenabled = false", None, "destroy", False),
    ("", "off", "destroy", False),
])
def test_audit_enabled(monkeypatch, cfg, env, tier, on):
    write_config(cfg)
    if env:
        monkeypatch.setenv("AISB_AUDIT", env)
    assert audit.enabled(tier) is on
    rec = audit.record(op="x", tier=tier, args={}, ctx=Ctx("u"), endpoint=None, ok=True, error=None, ms=0)
    assert (rec is not None) is on


def test_audit_path_sources(monkeypatch, tmp_path):
    assert audit.path() == Path(os.environ["AISB_HOME"]) / "audit.jsonl"
    write_config(f'[audit]\npath = "{tmp_path}/cfg.jsonl"')
    assert audit.path() == tmp_path / "cfg.jsonl"
    monkeypatch.setenv("AISB_AUDIT", str(tmp_path / "env.jsonl"))
    assert audit.path() == tmp_path / "env.jsonl"
    audit.record(op="x", tier="mutate", args={}, ctx=Ctx("u"), endpoint=None, ok=True, error=None, ms=0)
    assert (tmp_path / "env.jsonl").exists() and not (tmp_path / "cfg.jsonl").exists()


@pytest.fixture
def fresh_syslog(monkeypatch):
    loggers: dict = {}
    monkeypatch.setattr(audit, "_SYSLOG", loggers)
    yield
    for logger in loggers.values():
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()


def _rec() -> dict:
    return audit.record(op="t.x", tier="mutate", args={"password": "p"}, ctx=Ctx("u"), endpoint=None, ok=True,
                        error=None, ms=1)


def test_syslog_mirror_udp(fresh_syslog):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    write_config(f'[audit]\nsyslog = "udp://127.0.0.1:{srv.getsockname()[1]}"')
    try:
        _rec()
        _rec()  # the logger is cached per target
        msgs = [srv.recv(65536).decode(), srv.recv(65536).decode()]
    finally:
        srv.close()
    assert len(audit._SYSLOG) == 1
    body = json.loads(msgs[0].split("aisb: ", 1)[1].rstrip("\x00"))
    assert body["op"] == "t.x" and body["args"] == {"password": "***"} and "hash" not in body and "prev" not in body


def test_syslog_mirror_unix_socket(fresh_syslog, tmp_path):
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="aisb-log-", dir="/tmp"))
    sock_path = d / "log.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(str(sock_path))
    srv.settimeout(5)
    write_config(f'[audit]\nsyslog = "{sock_path}"')
    try:
        _rec()
        assert b'"op": "t.x"' in srv.recv(65536)
    finally:
        srv.close()
        sock_path.unlink()
        d.rmdir()


@pytest.mark.parametrize("target", ["tcp://127.0.0.1:{port}", "udp://localhost.invalid.", "/nonexistent/log.sock"])
def test_syslog_mirror_failures_never_break_the_change(fresh_syslog, target):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens on this port any more
    write_config(f'[audit]\nsyslog = "{target.format(port=port)}"')
    rec = _rec()
    assert rec is not None and records() == [rec] and audit.verify()["ok"]


def test_syslog_udp_without_port_uses_514(fresh_syslog, monkeypatch):
    import logging.handlers
    seen = []

    class Recorder(logging.handlers.SysLogHandler):
        def __init__(self, address, socktype=None):
            seen.append((address, socktype))
            logging.Handler.__init__(self)
            self.socket = None

        def emit(self, record):
            raise OSError("syslog went away")   # the mirror is best-effort: never fails the change
    monkeypatch.setattr(logging.handlers, "SysLogHandler", Recorder)
    write_config('[audit]\nsyslog = "udp://logs.internal"')
    _rec()
    assert seen == [(("logs.internal", 514), socket.SOCK_DGRAM)]


# === audit governance ops ========================================================================

def test_audit_log_filters(cli, daemon, monkeypatch):
    t0 = 1_700_000_000.0
    clock = iter([t0 - 7200, t0 - 10, t0 - 5, t0])
    ali, bob = Ctx("alice", source="cli", run_id="r1"), Ctx("bob", host=Host("web1"), run_id="r2")
    with monkeypatch.context() as m:
        m.setattr(audit.time, "time", lambda: next(clock))
        audit.record(op="containers.rm", tier="destroy", args={}, ctx=ali, endpoint=None, ok=True, error=None, ms=0)
        audit.record(op="images.pull", tier="mutate", args={}, ctx=ali, endpoint=None, ok=False, error="x", ms=0)
        audit.record(op="containers.stop", tier="mutate", args={}, ctx=bob, endpoint=None, ok=True, error=None, ms=0)
        audit.record(op="volumes.rm", tier="destroy", args={}, ctx=bob, endpoint=None, ok=True, error=None, ms=0)

    def ops_of(*flags):
        code, rows, _ = cli("audit", "log", *flags)
        assert code == EXIT_OK
        return [r["op"] for r in rows]
    assert ops_of() == ["volumes.rm", "containers.stop", "images.pull", "containers.rm"]
    assert ops_of("--action", "containers.*") == ["containers.stop", "containers.rm"]
    assert ops_of("--user", "b*") == ["volumes.rm", "containers.stop"]
    assert ops_of("--on", "local") == ["images.pull", "containers.rm"]
    assert ops_of("--on", "web*") == ["volumes.rm", "containers.stop"]
    assert ops_of("--failed") == ["images.pull"]
    assert ops_of("--run", "r1") == ["images.pull", "containers.rm"]
    assert ops_of("--limit", "1") == ["volumes.rm"]
    assert ops_of("--since", str(int(t0 - 60))) == ["volumes.rm", "containers.stop", "images.pull"]
    code, rows, _ = cli("audit", "log", "--limit", "1")
    assert rows[0]["host"] == "web1" and rows[0]["run_id"] == "r2" and len(rows[0]["at"]) == 19


def test_audit_verify_op(cli, daemon):
    _chain(2)
    code, out, _ = cli("audit", "verify")
    assert code == EXIT_OK and out["ok"] is True and out["records"] == 2 and out["path"] == str(audit.path())


# === 2. policy (pure evaluation) =================================================================

ME = Ctx("alice", source="cli")
MON_10_UTC = dt.datetime(2026, 9, 28, 10, 30, tzinfo=dt.UTC)   # a Monday


@pytest.mark.parametrize("match,op_,tier,ctx,hit", [
    ({}, "containers.rm", "destroy", ME, True),
    ({"op": "containers.*"}, "containers.rm", "destroy", ME, True),
    ({"op": ["images.*", "volumes.rm"]}, "containers.rm", "destroy", ME, False),
    ({"op": ["images.*", "volumes.rm"]}, "volumes.rm", "destroy", ME, True),
    ({"tier": "destroy"}, "x.y", "mutate", ME, False),
    ({"tier": ["mutate", "destroy"]}, "x.y", "mutate", ME, True),
    ({"source": "mcp"}, "x.y", "mutate", ME, False),
    ({"source": ["mcp", "cli"]}, "x.y", "mutate", ME, True),
    ({"user": "bob"}, "x.y", "mutate", ME, False),
    ({"user": ["b*", "al*"]}, "x.y", "mutate", ME, True),
    ({"hosts": "local"}, "x.y", "mutate", ME, True),
    ({"hosts": "all"}, "x.y", "mutate", ME, True),
    ({"hosts": "web1, *"}, "x.y", "mutate", ME, True),
    ({"hosts": "@prod"}, "x.y", "mutate", ME, False),
    ({"hosts": "!local"}, "x.y", "mutate", ME, False),
    ({"hosts": ["web1", "local"]}, "x.y", "mutate", ME, True),       # lists work like every other match field
    ({"op": "containers.*", "tier": "destroy", "source": "cli", "user": "alice"}, "containers.rm", "destroy", ME, True),
    ({"op": "containers.*", "tier": "destroy", "source": "mcp"}, "containers.rm", "destroy", ME, False),
])
def test_matches(match, op_, tier, ctx, hit):
    assert matches(match, op_, tier, ctx) is hit


@pytest.fixture
def inventory(monkeypatch, tmp_path):
    p = tmp_path / "fleet.json"
    p.write_text(json.dumps({"hosts": {"web1": {"groups": ["prod"], "labels": {"region": "eu"}},
                                       "web2": {"groups": ["staging"]}},
                             "groups": {"eu": ["region=eu"]}}))
    monkeypatch.setenv("AISB_FLEET", str(p))
    return p


@pytest.mark.parametrize("host,expr,hit", [
    ("web1", "@prod", True),
    ("web2", "@prod", False),
    ("web1", "@eu", True),
    ("web1", "web*,!web1", False),
    ("web2", "web*,!web1", True),
    ("web1", ["@staging", "@prod"], True),
    ("adhoc", "adhoc", True),              # a host not in the inventory (e.g. `--on` an ad-hoc endpoint)
    ("adhoc", "@prod", False),             # selects hosts, but not this one
    ("web2", "@nosuchgroup", False),       # a selector error never matches
    ("web1", "local", False),
])
def test_matches_fleet_hosts(inventory, host, expr, hit):
    h = Host(host, groups=("prod",) if host == "web1" else ())
    assert matches({"hosts": expr}, "containers.rm", "destroy", Ctx("u", host=h)) is hit


@pytest.mark.parametrize("window,when,inside", [
    ({}, MON_10_UTC, True),
    ({"days": ["mon", "tue"]}, MON_10_UTC, True),
    ({"days": ["Tuesday", "WED"]}, MON_10_UTC, False),
    ({"days": "monday"}, MON_10_UTC, True),
    ({"hours": "09-17"}, MON_10_UTC, True),
    ({"hours": "09-10"}, MON_10_UTC, False),                     # end is exclusive: 10:30 is out
    ({"hours": "10.5-11"}, MON_10_UTC, True),                    # fractional start: 10:30 is in
    ({"hours": "11-12"}, MON_10_UTC, False),
    ({"hours": "10"}, MON_10_UTC, True),                         # open end means until midnight
    ({"hours": "22-06"}, MON_10_UTC, False),                     # wraps midnight
    ({"hours": "22-06"}, MON_10_UTC.replace(hour=23), True),
    ({"hours": "22-06"}, MON_10_UTC.replace(hour=22, minute=0), True),
    ({"hours": "22-06"}, MON_10_UTC.replace(hour=5, minute=59), True),
    ({"hours": "22-06"}, MON_10_UTC.replace(hour=6, minute=0), False),
    ({"hours": "09-17", "tz": "Asia/Tokyo"}, MON_10_UTC, False),        # 19:30 in Tokyo
    ({"hours": "09-17", "tz": "America/New_York"}, MON_10_UTC, False),  # 06:30 EDT (UTC-4)
    ({"hours": "06-07", "tz": "America/New_York"}, MON_10_UTC, True),
    ({"days": ["sun"], "tz": "America/Los_Angeles"}, MON_10_UTC.replace(hour=3), True),  # still Sunday there
    ({"days": ["mon"], "tz": "America/Los_Angeles"}, MON_10_UTC.replace(hour=3), False),
    ({"hours": "09-17", "tz": "Not/AZone"}, MON_10_UTC, True),          # unknown tz: the given clock
    ({"days": ["mon"], "hours": "22-06"}, MON_10_UTC.replace(hour=23), True),
    ({"days": ["tue"], "hours": "22-06"}, MON_10_UTC.replace(hour=23), False),
])
def test_in_window(window, when, inside):
    assert in_window(window, when) is inside


@pytest.mark.parametrize("ticket,pattern,require,violations", [
    (None, None, True, ["a change ticket is required (--ticket or $AISB_TICKET)"]),
    ("", None, True, ["a change ticket is required (--ticket or $AISB_TICKET)"]),
    ("X-1", None, True, []),
    (None, r"^OPS-\d+$", False, []),                                   # pattern alone only checks given tickets
    ("OPS-12", r"OPS-\d+", True, []),
    ("OPS-12x", r"OPS-\d+", True, ["ticket 'OPS-12x' does not match OPS-\\d+"]),   # fullmatch, not search
    ("xOPS-12", r"OPS-\d+", False, ["ticket 'xOPS-12' does not match OPS-\\d+"]),
    ("INC-9", r"^(OPS|INC)-[0-9]+$", True, []),
])
def test_ticket_rules(ticket, pattern, require, violations):
    rule = {"require": {"ticket": require, **({"ticket_pattern": pattern} if pattern else {})}}
    got = check([rule], "containers.rm", "destroy", {}, Ctx("u", ticket=ticket), MON_10_UTC)
    assert [v.reason for v in got] == violations


@pytest.mark.parametrize("cond,op_,kwargs,reason", [
    ({"privileged": True}, "containers.run", {"privileged": True}, "privileged containers are not allowed"),
    ({"privileged": True}, "containers.run", {"privileged": False}, None),
    ({"privileged": False}, "containers.run", {"privileged": True}, None),
    ({"image_tag": "latest"}, "containers.run", {"image": "nginx"}, "image tag 'latest' is not allowed (nginx)"),
    ({"image_tag": ["latest", "dev"]}, "images.pull", {"ref": "reg:5000/app:dev"}, "image tag 'dev' is not allowed"),
    ({"image_tag": "latest"}, "images.pull", {"ref": "reg:5000/app"}, "image tag 'latest'"),
    ({"image_tag": "latest"}, "images.pull", {"ref": "reg:5000/app:1.2"}, None),
    ({"image_tag": "digest"}, "fleet.ship", {"image": "app@sha256:abc"}, "image tag 'digest'"),
    ({"image_tag": "latest"}, "images.tag", {"ref": "app"}, "image tag 'latest'"),
    ({"image_tag": "latest"}, "containers.rm", {"ref": "app"}, None),           # not an image op
    ({"image_tag": "latest"}, "containers.run", {"image": ""}, None),
    ({"image": "docker.io/*"}, "containers.run", {"image": "docker.io/evil:1"}, "image docker.io/evil:1 is not allowed"),
    ({"image": ["a/*", "b/*"]}, "containers.run", {"image": "c/x"}, None),
    ({"host_network": True}, "containers.run", {"network": "host"}, "host networking is not allowed"),
    ({"host_network": True}, "containers.run", {"network": "bridge"}, None),
    ({"docker_socket": True}, "containers.run", {"volume": ["/var/run/docker.sock:/s"]}, "mounting the Docker socket"),
    ({"docker_socket": True}, "stack.up", {"volumes": ["/run/docker.sock:/x", 3]}, "mounting the Docker socket"),
    ({"docker_socket": True}, "containers.run", {"volume": ["/data:/data"]}, None),
    ({"docker_socket": True}, "containers.rm", {"volumes": True}, None),
    ({"volumes": True}, "containers.rm", {"volumes": True}, "deleting volume data (--volumes) is not allowed"),
    ({"volumes": True}, "containers.rm", {"volumes": False}, None),
    ({"force": True}, "containers.rm", {"force": True}, "--force is not allowed"),
    ({"force": True}, "containers.rm", {"force": "yes"}, None),
])
def test_deny_if(cond, op_, kwargs, reason):
    got = check([{"name": "r", "deny_if": cond}], op_, "mutate", kwargs, ME, MON_10_UTC)
    if reason is None:
        assert got == []
    else:
        assert len(got) == 1 and reason in got[0].reason


def test_check_collects_every_reason_names_rules_and_modes():
    rules = [
        {"match": {"tier": "destroy"}, "deny": True, "require": {"ticket": True},
         "window": {"hours": "0-1"}, "deny_if": {"force": True}},
        {"name": "soft", "mode": "warn", "deny": True, "message": "careful"},
        {"name": "other-op", "match": {"op": "images.*"}, "deny": True},
    ]
    got = check(rules, "containers.rm", "destroy", {"force": True}, ME, MON_10_UTC)
    assert [(v.rule, v.mode) for v in got] == [("rule-1", "deny")] * 4 + [("soft", "warn")]
    assert got[0].reason == "containers.rm is not allowed here"
    assert got[2].reason == "outside the change window {'hours': '0-1'}"
    assert got[-1].row() == {"rule": "soft", "reason": "careful", "mode": "warn"}


def test_check_defaults_to_now(monkeypatch):
    rule = [{"window": {"hours": "0-24"}}]
    assert check(rule, "a.b", "mutate", {}, ME) == []


def test_enforce_raises_only_for_blocking(monkeypatch):
    write_config("""
        [[policy.rules]]
        name = "w"
        mode = "warn"
        deny = true
    """)
    assert [v.rule for v in enforce("a.b", "mutate", {}, ME)] == ["w"]
    write_config("""
        [[policy.rules]]
        name = "w"
        mode = "warn"
        deny = true
        [[policy.rules]]
        name = "d"
        deny_if = { force = true }
    """)
    assert enforce("a.b", "mutate", {"force": False}, ME)[0].rule == "w"
    with pytest.raises(PolicyDenied) as e:
        enforce("a.b", "mutate", {"force": True}, ME)
    assert [v.rule for v in e.value.violations] == ["d"]
    assert str(e.value) == "a.b denied by policy: [d] --force is not allowed"


def test_policy_window_blocks_cli_outside_hours(cli, daemon, monkeypatch):
    write_config("""
        [[policy.rules]]
        name = "business-hours"
        match = { tier = "destroy" }
        window = { days = ["mon", "tue", "wed", "thu", "fri"], hours = "09-17", tz = "UTC" }
    """)
    daemon.on("DELETE", "/volumes/v", status=204)

    class Clock(dt.datetime):
        now_value = dt.datetime(2026, 9, 27, 12, tzinfo=dt.UTC)   # a Sunday

        @classmethod
        def now(cls, tz=None):
            return cls.now_value
    monkeypatch.setattr("aisb.policy.dt.datetime", Clock)
    code, _, err = cli("volumes", "rm", "v", "--yes")
    assert code == EXIT_POLICY and "outside the change window" in err and daemon.calls() == []
    Clock.now_value = MON_10_UTC
    assert cli("volumes", "rm", "v", "--yes")[0] == EXIT_OK


# === policy governance ops =======================================================================

def test_policy_rules_op_lists_effective_rules(cli, daemon):
    write_config("""
        [[policy.rules]]
        match = { tier = "destroy" }
        require = { ticket = true }
        [[policy.rules]]
        name = "no-priv"
        mode = "warn"
        deny_if = { privileged = true }
        message = "m"
    """)
    code, out, _ = cli("policy", "rules")
    assert code == EXIT_OK and out == [
        {"name": "rule-1", "mode": "deny", "match": {"tier": "destroy"}, "require": {"ticket": True}},
        {"name": "no-priv", "mode": "warn", "match": {}, "deny_if": {"privileged": True}, "message": "m"}]


def test_policy_check_op(cli, daemon, inventory):
    write_config("""
        [[policy.rules]]
        name = "prod"
        match = { hosts = "@prod", source = "mcp" }
        deny = true
        [[policy.rules]]
        name = "bob"
        mode = "warn"
        match = { user = "bob" }
        deny = true
    """)
    code, out, _ = cli("policy", "check", "--on", "web1", "--source", "mcp", "--", "containers", "rm", "db")
    assert code == EXIT_OK and out["allowed"] is False and out["host"] == "web1" and out["tier"] == "destroy"
    assert cli("policy", "check", "--on", "web1", "--", "containers", "rm", "db")[1]["allowed"] is True
    code, out, _ = cli("policy", "check", "--user", "bob", "--", "containers", "rm", "db")
    assert out["allowed"] is True and out["violations"][0]["mode"] == "warn" and out["host"] == "local"
    code, _, err = cli("policy", "check", "--on", "nope", "--", "containers", "rm", "db")
    assert code == EXIT_USAGE and "unknown host 'nope'" in err
    code, _, err = cli("policy", "check", "--", "containers")
    assert code == EXIT_USAGE and "give the command after --" in err
    code, _, err = cli("policy", "check", "--", "containers", "frobnicate")
    assert code == EXIT_USAGE and "invalid command" in err
    assert daemon.calls() == []


def test_policy_check_uses_global_ticket(cli, daemon):
    write_config("""
        [[policy.rules]]
        match = { tier = "destroy" }
        require = { ticket = true }
    """)
    assert cli("policy", "check", "--", "volumes", "rm", "v")[1]["allowed"] is False
    assert cli("policy", "check", "--ticket", "T-1", "--", "volumes", "rm", "v")[1]["allowed"] is True


# === config ======================================================================================

DEFAULTS = {"*": {"a": 0, "b": 0, "c": 0, "d": 0}, "containers.*": {"b": 1, "c": 1, "d": 1},
            "*.logs": {"c": 2, "d": 2}, "containers.logs": {"d": 3}, "images.*": {"a": 9}}


@pytest.mark.parametrize("qualname,expected", [
    ("containers.logs", {"a": 0, "b": 1, "c": 2, "d": 3}),
    ("containers.stats", {"a": 0, "b": 1, "c": 1, "d": 1}),
    ("system.logs", {"a": 0, "b": 0, "c": 2, "d": 2}),
    ("images.ls", {"a": 9, "b": 0, "c": 0, "d": 0}),
    ("volumes.ls", {"a": 0, "b": 0, "c": 0, "d": 0}),
])
def test_defaults_glob_precedence(qualname, expected):
    assert config.parse({"defaults": DEFAULTS}).defaults_for(qualname) == expected
    reordered = dict(reversed(list(DEFAULTS.items())))  # precedence is by specificity, not file order
    assert config.parse({"defaults": reordered}).defaults_for(qualname) == expected


def test_parse_profiles_merge_and_errors():
    data = {"audit": {"reads": True, "syslog": "/dev/log"}, "policy": {"rules": [{"deny": True}]},
            "plugins": {"modules": ["p1"]}, "notify": {"ops": {"type": "slack", "url": "u"}},
            "aliases": {"x": 1}, "env": {"K": 2},
            "profiles": {"prod": {"audit": {"reads": False}, "policy": {"rules": []}}, "dev": {}}}
    base = config.parse(data)
    assert base.aliases == {"x": "1"} and base.env == {"K": "2"} and base.plugins == ["p1"]
    assert base.notify == {"ops": {"type": "slack", "url": "u"}} and base.profiles == ["dev", "prod"]
    prod = config.parse(data, profile="prod")
    assert prod.audit == {"reads": False, "syslog": "/dev/log"} and prod.policy == [] and prod.profile == "prod"
    with pytest.raises(ValueError, match="profiles: none"):
        config.parse({}, profile="x")
    with pytest.raises(ValueError, match=r"cfg.toml: unknown sections \['bogus'\]"):
        config.parse({"bogus": 1}, path=Path("cfg.toml"))
    with pytest.raises(ValueError, match="unknown sections"):
        config.parse({"profiles": {"p": {"bogus": 1}}}, profile="p")


def test_load_caches_reloads_and_applies_profile_env(monkeypatch, tmp_path):
    write_config("""
        [aliases]
        a = "containers ls"
        [profiles.ci.env]
        AISB_SAFETY_X = "~/fleet.json"
        AISB_SAFETY_Y = "from-config"
    """)
    monkeypatch.delenv("AISB_SAFETY_X", raising=False)
    monkeypatch.setenv("AISB_SAFETY_Y", "from-env")
    first = config.load()
    assert config.load() is first
    Path(os.environ["AISB_CONFIG"]).write_text('[aliases]\nb = "x"\n')
    assert config.load() is first and config.load(reload=True).aliases == {"b": "x"}
    other = tmp_path / "other.toml"
    other.write_text('[aliases]\nc = "y"\n')
    assert config.load(path=other).aliases == {"c": "y"}
    write_config("""
        [profiles.ci.env]
        AISB_SAFETY_X = "~/fleet.json"
        AISB_SAFETY_Y = "from-config"
    """)
    cfg = config.load(profile="ci")
    assert cfg.profile == "ci" and config.load(profile="ci") is cfg
    assert os.environ["AISB_SAFETY_X"] == os.path.expanduser("~/fleet.json")
    assert os.environ["AISB_SAFETY_Y"] == "from-env"      # an explicit env var beats the profile
    monkeypatch.delenv("AISB_SAFETY_X")


def test_load_missing_and_invalid(tmp_path):
    assert config.load(path=tmp_path / "missing.toml").defaults == {}
    bad = tmp_path / "bad.toml"
    bad.write_text("[defaults\n")
    with pytest.raises(ValueError, match="invalid TOML"):
        config.load(path=bad)


def test_default_path(monkeypatch):
    monkeypatch.delenv("AISB_CONFIG")
    assert config.default_path() == Path("~/.aisb/config.toml").expanduser()


# === context =====================================================================================

def test_context_user_ticket_and_nesting(monkeypatch):
    monkeypatch.setenv("AISB_USER", "carol")
    monkeypatch.setenv("AISB_TICKET", "T-1")
    base = context.current()
    assert (base.user, base.source, base.ticket, base.run_id, base.host) == ("carol", "api", "T-1", None, None)
    h = Host("web1")
    with context.use(source="cli", ticket=None, host=h) as c:        # None is ignored, except for host
        assert (c.source, c.ticket, c.host) == ("cli", "T-1", h)
        with context.use(host=None, run_id="r") as inner:
            assert inner.host is None and inner.run_id == "r" and inner.source == "cli"
        assert context.current().host is h
        assert c.fields() == {"user": "carol", "source": "cli", "host": "web1", "ticket": "T-1", "run_id": None}
    assert context.current().source == "api"


def test_context_user_fallbacks(monkeypatch):
    import getpass
    monkeypatch.delenv("AISB_USER", raising=False)
    monkeypatch.setattr(getpass, "getuser", lambda: "osuser")
    assert context._user() == "osuser"

    def no_user():
        raise KeyError("no passwd entry")
    monkeypatch.setattr(getpass, "getuser", no_user)
    assert context._user() == "unknown"


# === CLI =========================================================================================

def test_exit_codes(cli, daemon, toy):
    toy_routes(daemon)
    daemon.on("POST", "/containers/web/stop", status=500, json={"message": "daemon exploded"})
    code, _, err = cli("containers", "stop", "web")
    assert code == EXIT_DOCKER and "daemon exploded" in err
    assert records()[-1]["ok"] is False
    code, _, err = cli("containers", "limit", "web")
    assert code == EXIT_USAGE and json.loads(err)["error"] == "UsageError"
    assert cli("safetytoy", "unmet")[0:2] == (EXIT_UNMET, {"ok": False, "reason": "not ready yet"})
    assert cli("safetytoy", "boom", "interrupt")[0] == 130
    assert cli("safetytoy", "boom", "value")[0] == EXIT_USAGE
    with pytest.raises(RuntimeError):
        cli("safetytoy", "boom")
    code, out, _ = cli("safetytoy", "peek", "a")
    assert (code, out) == (EXIT_OK, {"toy": True})


def test_usage_errors_from_argparse(cli, capsys):
    with pytest.raises(SystemExit) as e:
        main(["containers", "rm"])
    assert e.value.code == EXIT_USAGE
    with pytest.raises(SystemExit) as e:
        main(["containers", "stop", "web", "--", "extra"])
    assert e.value.code == EXIT_USAGE and "takes no trailing command" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        main(["docs", "--", "x"])
    assert e.value.code == EXIT_USAGE


def test_version_and_profile_preamble(daemon, capsys, monkeypatch):
    from aisb import __version__
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == EXIT_OK and capsys.readouterr().out.startswith(f"aisb {__version__} ")
    write_config("""
        [profiles.prod.defaults]
        "containers.stop" = { grace = 3 }
        [profiles.dev.defaults]
        "containers.stop" = { grace = 4 }
    """)
    daemon.on("POST", "/containers/web/stop", status=204)
    for argv, grace in ((["--profile", "prod"], "3"), (["--profile=dev"], "4")):
        monkeypatch.delenv("AISB_PROFILE", raising=False)
        assert main([*argv, "containers", "stop", "web", "--host", f"unix://{daemon.sock}"]) == EXIT_OK
        assert daemon.seen[-1].query["t"] == grace
    capsys.readouterr()
    monkeypatch.delenv("AISB_PROFILE", raising=False)
    assert main(["--profile", "nope", "containers", "ls"]) == EXIT_USAGE
    assert "unknown profile 'nope'" in capsys.readouterr().err


def test_profile_flag_without_resource(capsys, monkeypatch):
    with pytest.raises(SystemExit) as e:
        main(["--profile"])
    assert e.value.code == EXIT_USAGE and os.environ["AISB_PROFILE"] == ""


def test_bad_config_is_a_usage_error(capsys):
    write_config("[defaults\n")
    assert main(["containers", "ls"]) == EXIT_USAGE
    assert json.loads(capsys.readouterr().err)["error"] == "ConfigError"


def test_aliases_expand_with_quoting(cli, daemon):
    write_config("""
        [aliases]
        nuke = "containers rm 'my web'"
        ls = "containers list --all"
    """)
    code, out, _ = cli("nuke")
    assert code == EXIT_CONFIRM and out["planned"][0]["path"].endswith("/containers/my%20web")
    daemon.on("GET", "/containers/json", json=[])
    assert cli("ls")[0] == EXIT_OK and daemon.seen[-1].query["all"] == "true"


def test_config_defaults_apply_only_to_own_params_and_flags_override(cli, daemon):
    write_config("""
        [defaults]
        "*" = { grace = 1, bogus-flag = 1 }
        "containers.*" = { max-bytes = 5 }
        "containers.stop" = { grace = 2 }
    """)
    daemon.on("POST", r"/containers/web/(stop|restart)", status=204)
    assert cli("containers", "stop", "web")[0] == EXIT_OK and daemon.seen[-1].query["t"] == "2"
    assert cli("containers", "restart", "web")[0] == EXIT_OK and daemon.seen[-1].query["t"] == "1"
    assert cli("containers", "stop", "web", "--grace", "9")[0] == EXIT_OK and daemon.seen[-1].query["t"] == "9"


def test_config_defaults_never_confirm_destroy(cli, daemon):
    write_config("""
        [defaults]
        "*" = { yes = true, dry_run = false, force = true }
    """)
    code, out, _ = cli("containers", "rm", "web")
    assert code == EXIT_CONFIRM and mutating(daemon) == []
    assert out["planned"][0]["query"] == {"force": True, "v": False}   # `force` is an op param: applied


@pytest.mark.parametrize("fmt,check_out", [
    ("yaml", lambda s: s.startswith("- name: api")),
    ("csv", lambda s: s.splitlines()[0] == "name,state"),
    ("ndjson", lambda s: json.loads(s.splitlines()[1]) == {"name": "db", "state": "exited"}),
    ("table", lambda s: s.splitlines()[0].split() == ["NAME", "STATE"]),
    ("json", lambda s: json.loads(s)[0]["name"] == "api"),
    ("raw", lambda s: json.loads(s)[1]["state"] == "exited"),
])
def test_output_formats(daemon, host, capsys, fmt, check_out):
    daemon.on("GET", "/containers/json", json=[{"Id": "a" * 64, "Names": ["/api"], "State": "running"},
                                              {"Id": "b" * 64, "Names": ["/db"], "State": "exited"}])
    assert main(["containers", "list", "--host", host, "-o", fmt, "--pick", "name,state"]) == EXIT_OK
    assert check_out(capsys.readouterr().out.rstrip("\n"))


def test_json_vs_table_selection(daemon, host, toy):
    import argparse
    import io
    toy_routes(daemon)

    class Tty(io.StringIO):
        def isatty(self):
            return True
    o = get_op("safetytoy.peek")
    base = {"host": host, "timeout": 5, "output": None, "pick": None, "ticket": None, "ref": "a"}
    for json_flag, out, is_json in ((None, io.StringIO(), True), (None, Tty(), False), (False, io.StringIO(), False),
                                    (True, Tty(), True)):
        err = io.StringIO()
        assert run(o, argparse.Namespace(json=json_flag, **base), out, err) == EXIT_OK
        text = out.getvalue()
        assert (text == '{"toy": true}\n') is is_json, (json_flag, text)


def test_dry_run_output_ignores_pick_and_confirm_is_always_json(daemon, host, capsys):
    assert main(["containers", "rm", "web", "--host", host, "-o", "yaml"]) == EXIT_CONFIRM
    assert json.loads(capsys.readouterr().out)["status"] == "confirmation_required"


def test_docs_and_site(capsys, tmp_path, toy):
    assert main(["docs"]) == EXIT_OK
    md = capsys.readouterr().out
    assert md.startswith("# aisb command reference") and "## safetytoy" in md
    assert "| smash | destroy | `aisb safetytoy smash REF [--force] [--dry-run] [--yes]` | Delete a toy. |" in md
    assert main(["docs", "--site", str(tmp_path / "site")]) == EXIT_OK
    res = json.loads(capsys.readouterr().out)
    pages = sorted(p.name for p in (tmp_path / "site").iterdir())
    assert res["pages"] == len(pages) and "index.md" in pages and "safetytoy.md" in pages
    page = (tmp_path / "site" / "safetytoy.md").read_text()
    assert "| `--env` | flag (repeatable) |  |" in page and "| `KIND` | positional | `'runtime'` |  (one of: runtime, interrupt, value) |" in page
    assert "| [safetytoy](safetytoy.md) | 6 | 1 | 4 | 1 |" in (tmp_path / "site" / "index.md").read_text()


def test_special_subcommands_dispatch(capsys):
    with pytest.raises(SystemExit) as e:
        main(["bundle", "--help"])
    assert e.value.code == 0 and "usage:" in capsys.readouterr().out


def test_python_dash_m(monkeypatch, capsys):
    import runpy
    import sys
    monkeypatch.setattr(sys, "argv", ["aisb", "--version"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("aisb", run_name="__main__")
    assert e.value.code == EXIT_OK and capsys.readouterr().out.startswith("aisb ")


# === ops registry ================================================================================

def test_param_introspection_and_schema(toy):
    poke, boom, smash = get_op("safetytoy.poke"), get_op("safetytoy.boom"), get_op("safetytoy.smash")
    assert poke.json_schema() == {
        "type": "object", "additionalProperties": False, "required": ["ref"],
        "properties": {"ref": {"type": "string"}, "env": {"type": "array", "items": {"type": "string"}},
                       "password": {"type": "string"},
                       "labels": {"type": "object", "additionalProperties": {"type": "string"}}}}
    assert boom.json_schema()["properties"]["kind"] == {"type": "string", "enum": ["runtime", "interrupt", "value"],
                                                         "default": "runtime"}
    assert smash.json_schema()["properties"]["force"] == {"type": "boolean", "default": False}
    assert poke.summary == "Change a toy." and poke.qualname == "safetytoy.poke"
    assert ops.usage(poke) == "aisb safetytoy poke REF [--env ENV]... [--password PASSWORD] [--labels LABELS]... [--dry-run]"


def test_param_of_edge_types():
    import inspect

    def f(self, a: Annotated[int | str, "multi"], *rest: str, b: tuple[int, ...] = (), c: bool = True,
          d: Annotated[float, 3, "not first"] = 0.5, e=None) -> None:
        pass
    o = Op.build("edge", f, Tier.MUTATE, "edge-op")
    by = {p.name: p for p in o.params}
    assert by["a"].type is str and by["a"].help == "multi" and by["a"].required
    assert by["rest"].variadic and not by["rest"].required and by["rest"].schema() == {
        "type": "array", "items": {"type": "string"}}
    assert by["b"].many and by["b"].type is int and by["b"].schema()["items"] == {"type": "integer"}
    assert by["c"].schema() == {"type": "boolean", "default": True}
    assert by["d"].help == "not first" and by["d"].schema() == {"type": "number", "description": "not first", "default": 0.5}
    assert by["e"].type is str and by["e"].kind is inspect.Parameter.KEYWORD_ONLY
    assert o.name == "edge-op" and o.summary == ""
    assert ops.usage(o) == "aisb edge edge-op A [-- REST...] [--b B]... [--no-c] [--d D] [--e E] [--dry-run]"


def test_op_call_argument_errors(toy, client):
    poke = get_op("safetytoy.poke")
    with pytest.raises(ValueError, match=r"unknown argument\(s\) for safetytoy.poke: \['nope'\]"):
        poke.call(client, {"ref": "a", "nope": 1})
    with pytest.raises(ValueError, match="missing argument for safetytoy.poke: ref"):
        poke.call(client, {})
    with pytest.raises(ValueError, match="unknown operation: safetytoy.nope"):
        get_op("safetytoy.nope")
    with pytest.raises(ValueError, match="unknown operation: nothing"):
        get_op("nothing")


def test_mapping_params_are_coerced(toy, daemon, client):
    toy_routes(daemon)
    invoke(client, get_op("safetytoy.poke"), {"ref": "a", "labels": ["k=v", "x=y=z"]})
    assert daemon.seen[-1].body["labels"] == {"k": "v", "x": "y=z"}


def test_jsonable():
    from dataclasses import dataclass

    @dataclass
    class D:
        x: int
    assert ops.jsonable(D(1)) == {"x": 1}
    assert ops.jsonable(b"\xffok") == "�ok"
    assert sorted(ops.jsonable({1, 2})) == [1, 2] and ops.jsonable((1,)) == [1]
    assert ops.jsonable(D) == str(D) and ops.jsonable(Path("/x")) == "/x"


# === client ======================================================================================

def test_client_resources(toy, host):
    d = Docker(host, timeout=1)
    assert d.resource("containers") is d.containers
    t = d.resource("safetytoy")
    assert isinstance(t, toy) and d.resource("safetytoy") is t and t.t is d.transport
    with pytest.raises(ValueError, match="unknown resource: nope"):
        d.resource("nope")
    with Docker.from_transport(d.transport) as again:
        assert again.transport is d.transport and again.volumes.t is d.transport


# === plugins =====================================================================================

def test_plugins_sources_setup_and_errors(tmp_path, monkeypatch):
    from aisb import plugins
    (tmp_path / "safety_plug_a.py").write_text("CALLS = []\ndef setup():\n    CALLS.append(1)\n")
    (tmp_path / "safety_plug_b.py").write_text("setup = 'not callable'\n")
    monkeypatch.syspath_prepend(str(tmp_path))

    class EP:
        value = "safety_plug_a:thing"
    monkeypatch.setattr(plugins, "entry_points", lambda group: [EP()] if group == "aisb.plugins" else [])
    monkeypatch.setenv("AISB_PLUGINS", " safety_plug_a , ,safety_plug_missing")
    write_config('[plugins]\nmodules = ["safety_plug_b", "safety_plug_a"]')
    assert plugins._sources() == ["safety_plug_a", "safety_plug_missing", "safety_plug_b"]
    loaded = plugins.load()
    assert loaded["safety_plug_a"] is None and loaded["safety_plug_b"] is None
    assert plugins.errors() == {"safety_plug_missing": "ModuleNotFoundError: No module named 'safety_plug_missing'"}
    import safety_plug_a
    assert safety_plug_a.CALLS == [1]
    assert plugins.load() is loaded and safety_plug_a.CALLS == [1]   # once per process
    import sys
    for m in ("safety_plug_a", "safety_plug_b"):
        sys.modules.pop(m, None)


def test_plugins_ignore_broken_config(monkeypatch):
    from aisb import plugins
    monkeypatch.setattr(plugins, "entry_points", lambda group: [])
    write_config("[defaults\n")
    assert plugins._sources() == []


# === config op ===================================================================================

def test_config_show(cli, daemon):
    write_config("""
        [defaults]
        "containers.*" = { tail = 5 }
        [audit]
        reads = false
        [notify.ops]
        type = "webhook"
        url = "http://x"
        [[policy.rules]]
        deny = true
        mode = "warn"
        [profiles.a]
    """)
    code, out, _ = cli("config", "show")
    assert code == EXIT_OK and out["exists"] and out["profile"] is None and out["profiles"] == ["a"]
    assert out["policy_rules"] == 1 and out["notify"] == {"ops": "webhook"} and out["audit_log"] == str(audit.path())
    assert out["defaults"] == {"containers.*": {"tail": 5}}


# === render ======================================================================================

@pytest.mark.parametrize("data,fmt,text", [
    ({"a": 1}, "json", '{"a": 1}'),
    ("héllo", "json", '"héllo"'),
    ({"n": None, "t": True, "f": False, "i": 3, "x": 1.5, "s": "007", "e": "", "c": "a:", "h": "a #b"}, "yaml",
     'n: null\nt: true\nf: false\ni: 3\nx: 1.5\ns: "007"\ne: ""\nc: "a:"\nh: "a #b"'),
    ({}, "yaml", "{}"),
    ([], "yaml", "[]"),
    ({"empty": {}, "none": [], "weird key": 1}, "yaml", 'empty: {}\nnone: []\n"weird key": 1'),
    ([[1, 2], [], {}, {"a": {"b": [1]}}, "x"], "yaml", "- - 1\n  - 2\n- []\n- {}\n- a:\n    b:\n      - 1\n- x"),
    ("plain", "yaml", "plain"),
    ({"a": 1}, "ndjson", '{"a": 1}'),
    ([1, "x"], "ndjson", '1\n"x"'),
    ({"rows": [{"a": 1}], "n": 1}, "ndjson", '{"a": 1}'),
    ({"a": 1, "b": [1, 2]}, "csv", "a,b\n1,1; 2"),
    ([1, 2], "csv", "value\n1\n2"),
    ("s", "csv", "value\ns"),
    ([{"a": None, "b": [{"x": 1}], "c": {"k": 1}}], "csv", 'a,b,c\n,"[{""x"": 1}]","{""k"": 1}"'),
    ("line\n", "raw", "line"),
    ({"output": "o\n", "exit_code": 0}, "raw", "o"),
    ({"a": 1}, "raw", '{\n  "a": 1\n}'),
    ({"output": "o\n", "exit_code": 0}, "table", 'o\n{"exit_code": 0}'),
    ({"rows": [{"a": 1, "nested": {"x": 1}, "deep": [[1]]}], "total": 1}, "table", 'A\n1\n{"total": 1}'),
    ([{"a": 1}, {"b": "x"}], "table", "A  B\n1\n   x"),
    ({"a": [1]}, "table", '{\n  "a": [\n    1\n  ]\n}'),
    ({"one": [{"a": 1}], "two": [{"b": 2}]}, "table", '{\n  "one": [\n    {\n      "a": 1\n    }\n  ],\n  "two": [\n    {\n      "b": 2\n    }\n  ]\n}'),
    ([b"by", Path("/p")], "json", '["by", "/p"]'),
])
def test_render(data, fmt, text):
    from aisb.render import render
    assert render(data, fmt) == text


def test_pick_shapes():
    from dataclasses import dataclass

    from aisb.render import pick

    @dataclass
    class Row:
        name: str
        state: dict
    rows = [Row("a", {"up": True}), Row("b", {"up": False})]
    assert pick(rows, "name, state.up,") == [{"name": "a", "state.up": True}, {"name": "b", "state.up": False}]
    assert pick({"name": "x", "other": 1}, "name") == {"name": "x"}
    assert pick("scalar", "name") == "scalar" and pick([], "name") == []
