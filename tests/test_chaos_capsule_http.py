"""Chaos: every injected fault is reverted (success, failure and interrupt paths), dry-run sends nothing, and the
game-day report card grades detection, blast radius and recovery. Only the daemon and the clock are faked."""

import json
import re
import threading
from typing import Any

import pytest

from aisb import errors
from aisb.ops import Tier, get_op, invoke
from aisb.transport import DRY_ID

from conftest import Reply, Seen, frame

# --- helpers -----------------------------------------------------------------------------------


def info(name: str, *, running: bool = True, paused: bool = False, status: str = "running",
         image: str = "busybox", networks: dict[str, Any] | None = None, health: list[str] | None = None,
         cid: str | None = None) -> dict[str, Any]:
    return {"Id": cid or f"{name}id0123456789", "Name": f"/{name}",
            "State": {"Running": running, "Paused": paused, "Restarting": False, "Status": status},
            "Config": {"Image": image, "Env": [], **({"Healthcheck": {"Test": health}} if health else {})},
            "NetworkSettings": {"Networks": networks or {}}}


@pytest.fixture
def sleeps(monkeypatch):
    """No real waiting: record every time.sleep() and return immediately."""
    calls: list[float] = []
    monkeypatch.setattr("aisb.api.chaos.time.sleep", calls.append)
    return calls


def posts(daemon) -> list[str]:
    return [p for m, p in daemon.calls() if m in ("POST", "DELETE")]


# --- tiers & dry-run ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["pause", "disconnect", "latency", "kill", "run"])
def test_every_chaos_op_is_mutate_tier(name):
    assert get_op(f"chaos.{name}").tier is Tier.MUTATE


def test_dry_run_pause_sends_nothing_and_does_not_wait(client, daemon, sleeps):
    out = invoke(client, get_op("chaos.pause"), {"ref": "web", "seconds": 30}, dry_run=True)
    assert out.status == "dry-run"
    assert [(p["method"], p["path"]) for p in out.planned] == [
        ("POST", "/containers/web/pause"), ("POST", "/containers/web/unpause")]
    assert daemon.calls() == [] and sleeps == []  # a preview must not freeze the caller for the fault duration


def test_dry_run_kill_sends_nothing(client, daemon):
    out = invoke(client, get_op("chaos.kill"), {"ref": "web", "signal": "TERM"}, dry_run=True)
    assert [(p["method"], p["path"]) for p in out.planned] == [("POST", "/containers/web/kill")]
    assert daemon.calls() == []


# --- pause -------------------------------------------------------------------------------------


def test_pause_injects_holds_then_unpauses(client, daemon, sleeps):
    daemon.on("POST", "/containers/web/pause", status=204).on("POST", "/containers/web/unpause", status=204)
    r = client.chaos.pause("web", seconds=3)
    assert r == {"fault": "pause", "container": "web", "seconds": 3, "reverted": True}
    assert posts(daemon) == ["/containers/web/pause", "/containers/web/unpause"] and sleeps == [3]


@pytest.mark.parametrize("exc", [KeyboardInterrupt, RuntimeError])
def test_pause_is_reverted_when_the_hold_is_interrupted(client, daemon, monkeypatch, exc):
    daemon.on("POST", "/containers/web/pause", status=204).on("POST", "/containers/web/unpause", status=204)

    def boom(_s: float) -> None:
        raise exc()
    monkeypatch.setattr("aisb.api.chaos.time.sleep", boom)
    with pytest.raises(exc):
        client.chaos.pause("web", seconds=3)
    assert posts(daemon) == ["/containers/web/pause", "/containers/web/unpause"]


def test_pause_that_fails_to_inject_does_not_try_to_revert(client, daemon, sleeps):
    daemon.on("POST", "/containers/web/pause", status=409, json={"message": "already paused"})
    with pytest.raises(errors.Conflict):
        client.chaos.pause("web", seconds=3)
    assert posts(daemon) == ["/containers/web/pause"] and sleeps == []


def test_pause_revert_failure_is_not_reported_as_reverted(client, daemon, sleeps):
    daemon.on("POST", "/containers/web/pause", status=204)
    daemon.on("POST", "/containers/web/unpause", status=500, json={"message": "cgroup gone"})
    with pytest.raises(errors.APIError, match="cgroup gone"):
        client.chaos.pause("web", seconds=1)


def test_kill_sends_the_signal_and_nothing_else(client, daemon):
    daemon.on("POST", "/containers/web/kill", status=204)
    assert client.chaos.kill("web", signal="TERM") == {"fault": "kill", "container": "web", "signal": "TERM"}
    assert daemon.seen[-1].query == {"signal": "TERM"} and posts(daemon) == ["/containers/web/kill"]


# --- disconnect --------------------------------------------------------------------------------

CID = "db0123456789abcdef"
NETS = {"app": {"Aliases": ["db", "db0123456789", "www"]}, "back": {"Aliases": None},
        "host": {}, "none": {}}


def _net_daemon(daemon, *, fail: dict[str, int] | None = None) -> list[Seen]:
    fail = fail or {}
    daemon.on("GET", "/containers/web/json", json=info("web", networks=NETS, cid=CID))
    seen: list[Seen] = []

    def handler(s: Seen) -> Reply:
        seen.append(s)
        key = s.path.split("/")[2] + "/" + s.path.split("/")[3]
        if key in fail:
            return Reply(fail[key], json={"message": f"{key} failed"})
        return Reply(200, body=b"")
    daemon.on("POST", r"/networks/[^/]+/(dis)?connect", handler)
    return seen


def _ops(seen: list[Seen]) -> list[str]:
    return [s.path.split("/")[2] + "/" + s.path.split("/")[3] for s in seen]


def test_disconnect_all_user_networks_then_reconnects_with_aliases(client, daemon, sleeps):
    seen = _net_daemon(daemon)
    r = client.chaos.disconnect("web", seconds=2)
    assert r["networks"] == ["app", "back"] and r["reverted"] and sleeps == [2]
    assert _ops(seen) == ["app/disconnect", "back/disconnect", "app/connect", "back/connect"]
    assert seen[0].body == {"Container": CID, "Force": True}
    # the short-id alias Docker adds by itself is dropped; real DNS aliases are restored, even one like "db"
    # that happens to be a prefix of the (hex) container id
    assert seen[2].body == {"Container": CID, "EndpointConfig": {"Aliases": ["db", "www"]}}
    assert seen[3].body["EndpointConfig"] == {"Aliases": []}


def test_disconnect_single_network(client, daemon, sleeps):
    seen = _net_daemon(daemon)
    assert client.chaos.disconnect("web", network="back", seconds=1)["networks"] == ["back"]
    assert _ops(seen) == ["back/disconnect", "back/connect"]


@pytest.mark.parametrize("network", ["nope", None])
def test_disconnect_refuses_when_not_attached_and_changes_nothing(client, daemon, sleeps, network):
    daemon.on("GET", "/containers/web/json", json=info("web", networks={"host": {}} if network is None else NETS))
    with pytest.raises(ValueError, match="is not attached to"):
        client.chaos.disconnect("web", network=network)
    assert posts(daemon) == []


def test_disconnect_is_healed_when_interrupted(client, daemon, monkeypatch):
    seen = _net_daemon(daemon)

    def boom(_s: float) -> None:
        raise KeyboardInterrupt
    monkeypatch.setattr("aisb.api.chaos.time.sleep", boom)
    with pytest.raises(KeyboardInterrupt):
        client.chaos.disconnect("web")
    assert _ops(seen) == ["app/disconnect", "back/disconnect", "app/connect", "back/connect"]


def test_disconnect_partially_injected_is_healed(client, daemon, sleeps):
    """The second disconnect fails: the first network must be reconnected, not left partitioned."""
    seen = _net_daemon(daemon, fail={"back/disconnect": 500})
    with pytest.raises(errors.APIError, match="back/disconnect failed"):
        client.chaos.disconnect("web")
    assert _ops(seen) == ["app/disconnect", "back/disconnect", "app/connect"] and sleeps == []


def test_disconnect_heal_tries_every_network_even_if_one_fails(client, daemon, sleeps):
    seen = _net_daemon(daemon, fail={"app/connect": 500})
    with pytest.raises(errors.APIError, match="app/connect failed"):
        client.chaos.disconnect("web")
    assert _ops(seen)[-2:] == ["app/connect", "back/connect"]


# --- latency (tc netem sidecar) ----------------------------------------------------------------


def _latency_daemon(daemon, *, output: bytes = b"injected\nreverted\n", code: int = 0,
                    wait: Reply | None = None) -> list[Seen]:
    daemon.on("GET", "/containers/db/json", json=info("db", cid="dbfull"))
    created: list[Seen] = []

    def create(s: Seen) -> Reply:
        created.append(s)
        return Reply(201, json={"Id": f"side{len(created)}"})
    daemon.on("POST", "/containers/create", create)
    daemon.on("POST", r"/containers/side\d/start", status=204)
    daemon.on("POST", r"/containers/side\d/wait", wait or Reply(json={"StatusCode": code}))
    daemon.on("GET", r"/containers/side\d/json", json={"Config": {"Tty": False}})
    daemon.on("GET", r"/containers/side\d/logs", Reply(body=frame(1, output),
                                                       content_type="application/vnd.docker.multiplexed-stream"))
    daemon.on("DELETE", r"/containers/side\d", status=204)
    return created


def test_latency_runs_a_self_reverting_sidecar_and_removes_it(client, daemon):
    created = _latency_daemon(daemon)
    r = client.chaos.latency("db", ms=150, jitter=20, loss=1.5, seconds=4)
    assert r == {"fault": "latency", "container": "db", "netem": "delay 150ms 20ms loss 1.5%", "seconds": 4,
                 "injected": True, "reverted": True}
    body = created[0].body
    assert body["HostConfig"]["NetworkMode"] == "container:dbfull" and body["HostConfig"]["CapAdd"] == ["NET_ADMIN"]
    script = body["Cmd"][2]
    assert "tc qdisc add dev $i root netem delay 150ms 20ms loss 1.5%" in script and "tc qdisc del" in script
    assert len(created) == 1 and ("DELETE", "/containers/side1") in daemon.calls()


def test_latency_without_loss_omits_it(client, daemon):
    _latency_daemon(daemon)
    assert client.chaos.latency("db", seconds=1)["netem"] == "delay 200ms 0ms"


def test_latency_cleans_up_qdisc_when_sidecar_did_not_revert(client, daemon):
    created = _latency_daemon(daemon, output=b"injected\n", code=137)  # killed mid-sleep
    with pytest.raises(ValueError, match="tc failed in the sidecar: injected"):
        client.chaos.latency("db", seconds=1)
    assert len(created) == 2 and "tc qdisc del" in created[1].body["Cmd"][2]
    assert "add" not in created[1].body["Cmd"][2]
    assert {("DELETE", "/containers/side1"), ("DELETE", "/containers/side2"),
            ("POST", "/containers/side2/start")} <= set(daemon.calls())


def test_latency_missing_netem_module_gets_a_hint(client, daemon):
    _latency_daemon(daemon, output=b"Error: Specified qdisc kind is unknown.\n", code=3)
    with pytest.raises(ValueError, match="modprobe sch_netem"):
        client.chaos.latency("db", seconds=1)


def test_latency_is_reverted_when_waiting_fails(client, daemon):
    """The wait breaks (daemon error / Ctrl-C) after the sidecar injected: the sidecar is force-removed mid-sleep,
    so its own revert never runs; a cleanup sidecar must still delete the qdisc and the error must surface."""
    created = _latency_daemon(daemon, wait=Reply(500, json={"message": "wait broke"}))
    with pytest.raises(errors.APIError, match="wait broke"):
        client.chaos.latency("db", seconds=1)
    assert ("DELETE", "/containers/side1") in daemon.calls()
    assert len(created) == 2 and "tc qdisc del" in created[1].body["Cmd"][2]
    assert ("POST", "/containers/side2/start") in daemon.calls() and ("DELETE", "/containers/side2") in daemon.calls()


def test_latency_dry_run_sends_nothing(client, daemon):
    daemon.on("GET", "/containers/db/json", json=info("db", cid="dbfull"))
    out = invoke(client, get_op("chaos.latency"), {"ref": "db", "seconds": 1}, dry_run=True)
    assert [p["method"] for p in out.planned][:3] == ["POST", "POST", "POST"]
    assert all(m == "GET" for m, _ in daemon.calls())
    assert not any(DRY_ID in p for _, p in daemon.calls())


# --- healthy() ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("state", "want"), [
    ({"paused": True}, (False, "paused")),
    ({"running": False, "status": "exited"}, (False, "exited")),
    ({}, (True, "running")),
    ({"health": ["NONE"]}, (True, "running")),
])
def test_healthy_from_state(client, daemon, state, want):
    daemon.on("GET", "/containers/c/json", json=info("c", **state))
    assert client.chaos.healthy("c") == want


def test_healthy_missing_container(client, daemon):
    assert client.chaos.healthy("gone") == (False, "missing")


@pytest.mark.parametrize(("test", "code", "argv"), [
    (["CMD-SHELL", "curl -f localhost"], 0, ["sh", "-c", "curl -f localhost"]),
    (["CMD", "pg_isready", "-q"], 1, ["pg_isready", "-q"]),
])
def test_healthy_runs_the_containers_own_healthcheck(client, daemon, test, code, argv):
    daemon.on("GET", "/containers/c/json", json=info("c", health=test))
    created = daemon.execs("c", [(b"", b"", code)])
    assert client.chaos.healthy("c") == (code == 0, f"healthcheck exit {code}")
    assert created[0].body["Cmd"] == argv


@pytest.mark.parametrize(("out", "ok"), [(b"PONG\n", True), (b"LOADING\n", False)])
def test_healthy_uses_the_service_probe(client, daemon, out, ok):
    daemon.on("GET", "/containers/cache/json", json=info("cache", image="redis:7"))
    daemon.execs("cache", [(out, b"", 0)])
    healthy, detail = client.chaos.healthy("cache")
    assert healthy is ok and (detail == "PING" if ok else "PING" in detail)


# --- game day ----------------------------------------------------------------------------------


class Shop:
    """Two-service stack whose health reacts to the faults the fake daemon receives."""

    def __init__(self, daemon, tmp_path, *, web_depends: bool = True, never_recovers: str | None = None,
                 dies_on_unpause: str | None = None) -> None:
        self.paused: set[str] = set()
        self.dead: set[str] = set()
        self.cut: set[str] = set()
        self.log: list[str] = []
        self.file = tmp_path / "stack.json"
        self.file.write_text(json.dumps({"name": "shop", "services": {
            "db": {"image": "busybox"}, "web": {"image": "busybox", "depends_on": ["db"]}}}))

        def inspect(s: Seen) -> Reply:
            name = s.path.split("/")[2]
            down = name in self.paused or name == never_recovers or name in self.dead or (web_depends and name == "shop-web" and
                                                                     ("shop-db" in self.paused or "shop-db" in self.cut))
            return Reply(json={**info(name, paused=name in self.paused, running=not down or name in self.paused,
                                      status="exited" if down else "running",
                                      networks={"shop_default": {"Aliases": ["db"]}}), "Id": name})

        def act(s: Seen) -> Reply:
            parts = s.path.strip("/").split("/")
            self.log.append(f"{parts[-1]} {parts[1]}")
            if parts[-1] == "pause":
                self.paused.add(parts[1])
            elif parts[-1] == "unpause":
                self.paused.discard(parts[1])
                if parts[1] == dies_on_unpause:
                    self.dead.add(parts[1])
            elif parts[-1] == "disconnect":
                self.cut.add(s.body["Container"])
            elif parts[-1] == "connect":
                self.cut.discard(s.body["Container"])
            return Reply(204)
        daemon.on("GET", r"/containers/shop-\w+/json", inspect)
        daemon.on("POST", r"/containers/shop-\w+/(un)?pause", act)
        daemon.on("POST", r"/networks/[^/]+/(dis)?connect", act)


class Clock:
    """Each worker-thread hold blocks until the monitor has looked at the stack once while the fault is in place;
    the main thread never really sleeps; monotonic advances 1s per call so recovery windows elapse
    deterministically."""

    def __init__(self) -> None:
        self.holds: list[threading.Event] = []
        self.cond = threading.Condition()
        self.seen = 0
        self.now = 0.0
        self.expect_holds = True

    def sleep(self, s: float) -> None:
        if threading.current_thread() is not threading.main_thread():
            ev = threading.Event()
            with self.cond:
                self.holds.append(ev)
                self.cond.notify_all()
            assert ev.wait(5), "monitor never ran"
        elif s == 0.5:
            if self.holds:
                self.holds[-1].set()
        elif self.expect_holds:  # the monitor's first look waits until this round's fault is really in place
            with self.cond:
                assert self.cond.wait_for(lambda: len(self.holds) > self.seen, 5), "fault never injected"
                self.seen = len(self.holds)

    def monotonic(self) -> float:
        self.now += 1.0
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr("aisb.api.chaos.time.sleep", c.sleep)
    monkeypatch.setattr("aisb.api.chaos.time.monotonic", c.monotonic)
    return c


def test_game_day_grades_detection_blast_radius_and_recovery(client, daemon, tmp_path, clock):
    shop = Shop(daemon, tmp_path)
    r = client.chaos.run(str(shop.file), faults=["pause"], seconds=8)
    assert r["stack"] == "shop" and r["score"] == 100
    by = {c["service"]: c for c in r["report"]}
    assert by["db"] == {"service": "db", "fault": "pause", "detected": True, "blast_radius": ["web"],
                        "recovered": True, "recovery_seconds": 2.0}
    assert by["web"]["detected"] and by["web"]["blast_radius"] == []
    assert r["findings"] == ["pause of db took down web"]
    assert shop.log == ["pause shop-db", "unpause shop-db", "pause shop-web", "unpause shop-web"]
    assert shop.paused == set()


def test_game_day_disconnect_is_undetected_and_healed(client, daemon, tmp_path, clock):
    shop = Shop(daemon, tmp_path, web_depends=False)
    r = client.chaos.run(str(shop.file), faults=["disconnect"], service=["web"], seconds=8)
    assert [c["service"] for c in r["report"]] == ["web"]
    assert r["report"][0]["detected"] is False
    assert r["findings"] == ["disconnect of web went undetected by its own health signal"]
    assert shop.log == ["disconnect shop_default", "connect shop_default"] and shop.cut == set()


def test_game_day_reports_non_recovery(client, daemon, tmp_path, clock):
    shop = Shop(daemon, tmp_path, web_depends=False, dies_on_unpause="shop-web")
    r = client.chaos.run(str(shop.file), faults=["pause"], service=["web"], seconds=8, recover_within=3)
    card = r["report"][0]
    assert card["recovered"] is False and card["recovery_seconds"] is None and r["score"] == 0
    assert "web did not recover within 3s after pause" in r["findings"]


def test_game_day_skips_when_stack_is_unhealthy_before(client, daemon, tmp_path, clock):
    shop = Shop(daemon, tmp_path, never_recovers="shop-db")
    r = client.chaos.run(str(shop.file), faults=["pause", "disconnect"], seconds=8)
    assert r["score"] is None and r["findings"] == [] and len(r["report"]) == 4
    assert all(c["skipped"] == "stack not healthy before the fault" and c["unhealthy"] == ["db"] for c in r["report"])
    assert shop.log == []  # nothing injected into an already-broken stack


def test_game_day_rejects_unknown_faults(client, daemon, tmp_path):
    shop = Shop(daemon, tmp_path)
    with pytest.raises(ValueError, match=re.escape("unknown faults: ['cpu']")):
        client.chaos.run(str(shop.file), faults=["pause", "cpu"])
    assert daemon.calls() == []


def test_game_day_dry_run_plans_without_touching_anything(client, daemon, tmp_path):
    shop = Shop(daemon, tmp_path)
    out = invoke(client, get_op("chaos.run"), {"stack": str(shop.file), "seconds": 5}, dry_run=True)
    assert out.planned == [{"chaos": f, "service": s, "seconds": 5}
                           for s in ("db", "web") for f in ("pause", "disconnect")]
    assert daemon.calls() == [] and shop.log == []


def test_game_day_interrupted_while_watching_still_reverts(client, daemon, tmp_path, monkeypatch):
    """Ctrl-C in the monitor loop must not leave the target paused: the fault worker is a daemon thread that
    would die with the interpreter, so run() has to wait for it to revert before propagating."""
    shop = Shop(daemon, tmp_path)
    injected = threading.Event()

    def sleep(s: float) -> None:
        if threading.current_thread() is not threading.main_thread():
            injected.set()
            threading.Event().wait(0.2)  # the hold: a short real wait so the worker is alive when Ctrl-C lands
        else:
            assert injected.wait(5)
            raise KeyboardInterrupt
    monkeypatch.setattr("aisb.api.chaos.time.sleep", sleep)
    with pytest.raises(KeyboardInterrupt):
        client.chaos.run(str(shop.file), faults=["pause"], service=["db"], seconds=8)
    assert shop.log == ["pause shop-db", "unpause shop-db"] and shop.paused == set()


def test_game_day_fault_that_fails_to_inject_is_not_graded(client, daemon, tmp_path, clock):
    clock.expect_holds = False  # injection fails: nothing is ever held
    shop = Shop(daemon, tmp_path)
    daemon.on("POST", "/containers/shop-db/pause", status=500, json={"message": "cannot pause"})
    r = client.chaos.run(str(shop.file), faults=["pause"], service=["db"], seconds=8)
    card = r["report"][0]
    assert "cannot pause" in card["skipped"] and "detected" not in card
    assert r["score"] is None and r["findings"] == []


def test_game_day_latency_fault(client, daemon, tmp_path, clock):
    clock.expect_holds = False  # the sidecar holds the fault itself (no worker sleep)
    shop = Shop(daemon, tmp_path, web_depends=False)
    daemon.on("POST", "/containers/create", Reply(201, json={"Id": "side1"}))
    daemon.on("POST", "/containers/side1/start", status=204)
    daemon.on("POST", "/containers/side1/wait", json={"StatusCode": 0})
    daemon.on("GET", "/containers/side1/json", json={"Config": {"Tty": False}})
    daemon.on("GET", "/containers/side1/logs", Reply(body=frame(1, b"injected\nreverted\n"),
                                                     content_type="application/vnd.docker.multiplexed-stream"))
    daemon.on("DELETE", "/containers/side1", status=204)
    r = client.chaos.run(str(shop.file), faults=["latency"], service=["db"], seconds=8)
    card = r["report"][0]
    assert card["fault"] == "latency" and card["recovered"] and r["findings"] == []  # latency is never "undetected"
    create = next(s for s in daemon.seen if s.path == "/containers/create")
    assert "delay 300ms" in create.body["Cmd"][2]


def test_latency_cleanup_failure_surfaces_when_nothing_else_failed(client, daemon):
    created = _latency_daemon(daemon, output=b"injected\n", code=0)
    daemon.on("POST", r"/containers/side2/start", status=500, json={"message": "cleanup start failed"})
    with pytest.raises(errors.APIError, match="cleanup start failed"):
        client.chaos.latency("db", seconds=1)
    assert len(created) == 2 and ("DELETE", "/containers/side2") in daemon.calls()  # cleanup sidecar removed too


def test_latency_cleanup_failure_never_masks_the_original_error(client, daemon):
    _latency_daemon(daemon, wait=Reply(500, json={"message": "wait broke"}))
    daemon.on("POST", r"/containers/side2/start", status=500, json={"message": "cleanup start failed"})
    with pytest.raises(errors.APIError, match="wait broke"):
        client.chaos.latency("db", seconds=1)


def test_disconnect_partial_inject_with_failing_heal_keeps_the_original_error(client, daemon, sleeps):
    seen = _net_daemon(daemon, fail={"back/disconnect": 500, "app/connect": 500})
    with pytest.raises(errors.APIError, match="back/disconnect failed") as info:
        client.chaos.disconnect("web")
    assert _ops(seen) == ["app/disconnect", "back/disconnect", "app/connect"]
    assert any("revert also failed: app/connect failed" in n for n in info.value.__notes__)
