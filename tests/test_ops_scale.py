"""Operations at scale: remediation rules, fleet-wide logs, canary go/no-go."""

import json
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from aisb.cli import EXIT_OK, EXIT_UNMET, main
from aisb.insights import remediate as rm
from conftest import FakeDaemon, Reply

MIB = 1 << 20


def report(name="api", status="exited", codes=(), exit_code=1):
    return {"container": name, "state": {"status": status, "exit_code": exit_code},
            "findings": [{"code": c} for c in codes]}


@pytest.mark.parametrize(("rep", "inspect", "rules", "actions", "suggested"), [
    (report(codes=("app-error",)), {}, rm.RULES, [("start-exited", "containers.start")], []),
    (report(status="running", codes=("unhealthy",)), {}, rm.RULES, [("restart-unhealthy", "containers.restart")], []),
    (report(codes=("missing-env", "crash-loop")), {}, rm.RULES, [], ["missing-env", "crash-loop"]),
    (report(codes=("oom-killed",)), {"HostConfig": {"Memory": 256 * MIB}}, rm.RULES,
     [("raise-memory", "containers.limit"), ("start-exited", "containers.start")], []),
    (report(codes=("oom-killed",)), {"HostConfig": {"Memory": 0}}, rm.RULES, [], ["raise-memory"]),
    (report(status="running", codes=("memory-pressure",)), {"HostConfig": {"Memory": 100 * MIB}}, rm.RULES,
     [("raise-memory", "containers.limit")], []),
    (report(codes=("app-error",)), {}, ("restart-unhealthy",), [], []),                # rule not enabled
    (report(codes=("dependency-unreachable",)), {}, rm.RULES, [], ["dependency-unreachable"]),
])
def test_remediation_plan(rep, inspect, rules, actions, suggested):
    p = rm.plan(rep, inspect, rules=rules)
    assert [(a.rule, a.op) for a in p.actions] == actions
    assert [s["rule"] for s in p.suggestions] == suggested


def test_raise_memory_rounds_to_16mib():
    p = rm.plan(report(codes=("oom-killed",)), {"HostConfig": {"Memory": 100 * MIB}})
    assert p.actions[0].kwargs == {"ref": "api", "memory": "128m"}      # 125m rounded up to a 16 MiB step


# --- fleet logs / canary over two fake daemons ------------------------------------------------------------

def ts(offset: float) -> str:
    t = time.time() - offset
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1e9):09d}Z"


@pytest.fixture
def pair(tmp_path, monkeypatch, capsys):
    d = Path(tempfile.mkdtemp(prefix="aisb-o-", dir="/tmp"))
    a, b = FakeDaemon(d / "a.sock"), FakeDaemon(d / "b.sock")
    a.start()
    b.start()
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"a": {"docker": f"unix://{a.sock}", "groups": ["canary"]},
                                         "b": {"docker": f"unix://{b.sock}", "groups": ["stable"]}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        code = main([*argv, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    yield run, a, b
    a.stop()
    b.stop()
    shutil.rmtree(d, ignore_errors=True)


def serve_container(d: FakeDaemon, log: str, *, restarts: int = 0, status: str = "running") -> None:
    d.on("GET", "/containers/api/json", json={"Name": "/api", "RestartCount": restarts,
                                              "Config": {"Tty": True, "Image": "api:1", "Env": []},
                                              "State": {"Status": status, "Running": status == "running"},
                                              "HostConfig": {"RestartPolicy": {"Name": "always"}}})
    d.on("GET", "/containers/api/logs", Reply(body=log.encode()))
    d.on("GET", "/images/json", json=[])
    d.on("GET", "/containers/json", json=[{"Id": "x", "Names": ["/api"], "State": status}])


def test_fleet_logs_merge_by_time_and_host(pair):
    run, a, b = pair
    serve_container(a, f"{ts(30)} a-first\n{ts(10)} a-third\n")
    serve_container(b, f"{ts(20)} b-second\n{ts(5)} b-ERROR boom\n")
    code, out, _ = run("fleet", "logs", "all", "api", "--since", "5m")
    lines = out["output"].splitlines()
    assert code == EXIT_OK and [ln.split("| ")[1] for ln in lines] == ["a-first", "b-second", "a-third", "b-ERROR boom"]
    assert lines[1].split()[1] == "b"
    code, out, _ = run("fleet", "logs", "all", "api", "--grep", "ERROR")
    assert out["lines"] == 1


def test_fleet_logs_follow_dedupes(pair, monkeypatch):
    run, a, b = pair
    serve_container(a, f"{ts(3)} same line\n")
    serve_container(b, f"{ts(2)} other\n")
    code, out, _ = run("fleet", "logs", "all", "api", "--follow", "--seconds", "2.5")
    assert code == EXIT_OK and out["lines"] == 2                        # repeated polls don't duplicate lines


def test_canary_no_go_on_errors_and_restarts(pair):
    run, a, b = pair
    errors = "".join(f"{ts(60 - i)} ERROR payment failed id={i}\n" for i in range(30))
    serve_container(a, errors, restarts=3)
    serve_container(b, f"{ts(30)} INFO ok\n")
    code, out, _ = run("fleet", "canary", "@canary", "@stable", "--container", "api", "--since", "5m")
    assert code == EXIT_UNMET and out["go"] is False
    assert any("errors" in r for r in out["reasons"]) and any("restarts 3 > baseline 0" in r for r in out["reasons"])


def test_canary_go_when_comparable(pair):
    run, a, b = pair
    for d in (a, b):
        serve_container(d, f"{ts(30)} INFO ok\n{ts(20)} ERROR one blip\n")
    code, out, _ = run("fleet", "canary", "@canary", "@stable", "--container", "api")
    assert code == EXIT_OK and out["go"] is True and out["reasons"] == []


def test_canary_rejects_overlap(pair):
    run, *_ = pair
    code, _, err = run("fleet", "canary", "all", "@stable", "--container", "api")
    assert code != EXIT_OK and "overlap" in err
