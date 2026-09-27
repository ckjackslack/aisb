"""Fleet robustness: connection pool, retries, per-host timeouts, --fail-on, and sessions spanning hosts."""

import json
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_UNMET, main
from aisb.fleet import runner
from aisb.fleet.inventory import Host
from aisb.fleet.ssh import Unreachable
from conftest import FakeDaemon, Reply


# --- retries / timeouts -------------------------------------------------------------------------

def test_retries_only_transient_failures(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    calls: dict[str, int] = {}

    def fn(h: Host):
        calls[h.name] = calls.get(h.name, 0) + 1
        if h.name == "flaky" and calls[h.name] < 3:
            raise Unreachable("ssh: connection timed out")
        if h.name == "broken":
            raise ValueError("bad input")  # not transient: never retried
        return "ok"
    results, _ = runner.fan_out([Host("flaky"), Host("broken"), Host("fine")], fn, retries=3)
    by = {r.host: r for r in results}
    assert (by["flaky"].ok, by["flaky"].attempts, calls["flaky"]) == (True, 3, 3)
    assert (by["broken"].ok, calls["broken"]) == (False, 1)
    assert by["flaky"].row()["attempts"] == 3 and "attempts" not in by["fine"].row()


def test_retries_give_up():
    results, _ = runner.fan_out([Host("down")], lambda h: (_ for _ in ()).throw(Unreachable("no route")), retries=0)
    assert results[0].error == "no route" and results[0].transient


def test_host_timeout():
    results, _ = runner.fan_out([Host("slow"), Host("quick")],
                                lambda h: time.sleep(5) if h.name == "slow" else "ok", host_timeout=0.3)
    by = {r.host: r for r in results}
    assert by["slow"].error == "timed out after 0.3s" and by["quick"].ok


# --- connection pool ------------------------------------------------------------------------------

class FakeTunnel:
    opened = 0

    def __init__(self, path: str) -> None:
        self.path, self.alive_flag = path, True
        FakeTunnel.opened += 1

    @property
    def alive(self) -> bool:
        return self.alive_flag

    def close(self) -> None:
        self.alive_flag = False


def test_pool_reuses_and_reopens_dead_tunnels(monkeypatch):
    FakeTunnel.opened = 0
    monkeypatch.setattr(runner.Tunnel, "open", classmethod(lambda cls, ssh, sock: FakeTunnel(f"/tmp/fake-{sock}")))
    h = Host("web1", ssh="ops@web1")
    with runner.pooled() as pool:
        with runner.docker(h) as a, runner.docker(h) as b:
            assert a.transport.endpoint.url == b.transport.endpoint.url
        with runner.pooled() as inner:        # nested pools share the outer one
            assert inner is pool
        assert FakeTunnel.opened == 1
        next(iter(pool._conns.values()))[0].alive_flag = False  # the ssh process died
        with runner.docker(h):
            pass
        assert FakeTunnel.opened == 2
    assert all(not t.alive for t, _ in pool._conns.values()) or not pool._conns


# --- --fail-on and fleet sessions against fake daemons ---------------------------------------------

def _snapshot_routes(d: FakeDaemon, containers: list[dict]) -> None:
    d.on("GET", "/containers/json", lambda _: Reply(json=containers))
    d.on("GET", "/images/json", json=[])
    d.on("GET", "/volumes", json={"Volumes": []})
    d.on("GET", "/networks", json=[])


@pytest.fixture
def fleet2(tmp_path, monkeypatch, capsys):
    d = Path(tempfile.mkdtemp(prefix="aisb-r-", dir="/tmp"))
    a, b = FakeDaemon(d / "a.sock"), FakeDaemon(d / "b.sock")
    a.start()
    b.start()
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"a": {"docker": f"unix://{a.sock}"}, "b": {"docker": f"unix://{b.sock}"},
                                         "gone": {"docker": f"unix://{d}/missing.sock"}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        i = argv.index("--") if "--" in argv else len(argv)
        code = main([*argv[:i], "--json", *argv[i:]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    yield run, a, b
    a.stop()
    b.stop()
    shutil.rmtree(d, ignore_errors=True)


def test_status_fail_on(fleet2):
    run, a, b = fleet2
    for d in (a, b):
        d.on("GET", "/info", json={"ContainersRunning": 0, "Containers": 0})
        _snapshot_routes(d, [])
    code, out, _ = run("fleet", "status", "a,b", "--no-doctor", "--fail-on", "down")
    assert code == EXIT_OK and out["ok"] is True
    code, out, _ = run("fleet", "status", "all", "--no-doctor", "--fail-on", "down")
    assert code == EXIT_UNMET and "gone" in out["reason"]
    code, out, _ = run("fleet", "status", "all", "--no-doctor")
    assert code == EXIT_OK and "ok" not in out           # no gate, no verdict on the exit code


def test_session_spans_fleet_hosts(fleet2):
    run, a, b = fleet2
    web = [{"Id": "w" * 64, "Names": ["/web"], "Image": "nginx", "ImageID": "sha256:1", "State": "running",
            "Labels": {}}]
    for d in (a, b):
        _snapshot_routes(d, web)
        d.on("GET", "/containers/web/json", json={"State": {"Running": True}})
        d.on("POST", "/containers/web/stop", status=204)
        d.on("POST", "/containers/web/start", status=204)
    assert run("session", "begin", "--host", f"unix://{a.sock}")[0] == EXIT_OK   # local endpoint for the baseline
    code, out, _ = run("fleet", "apply", "a,b", "--", "containers", "stop", "web")
    assert code == EXIT_OK and out["summary"]["ok"] == 2
    code, plan, _ = run("session", "rollback", "--host", f"unix://{a.sock}")
    assert code == EXIT_CONFIRM and {p["step"] for p in plan["planned"]} == {"[a] start web", "[b] start web"}
    assert not any(s.path.endswith("/start") for d in (a, b) for s in d.seen)
    code, out, _ = run("session", "rollback", "--host", f"unix://{a.sock}", "--yes")
    assert code == EXIT_OK and out["hosts"] == ["a", "b", "local"]
    assert sorted(s["step"] for s in out["steps"]) == ["[a] start web", "[b] start web"]
    assert all(("POST", "/containers/web/start") in d.calls() for d in (a, b))
    code, again, _ = run("session", "rollback", "--host", f"unix://{a.sock}", "--yes")
    assert again["steps"] == []  # idempotent across hosts too
