"""Chaos fidelity: the netem cleanup sidecar's exact shape and lifecycle, and instant-health edge cases.
Only the daemon is faked (routes, exec queue); adapters are the real registry (plus one probe-less plugin)."""

import re
import time
from typing import Any, ClassVar

import pytest

from aisb import errors
from aisb.client import Docker
from aisb.services import REGISTRY, Target
from aisb.services.base import Adapter
from test_chaos_capsule_http import _latency_daemon, info

from conftest import Reply, Seen

UNTC = "for i in $(ls /sys/class/net | grep -v '^lo$'); do tc qdisc del dev $i root; done"


def state_info(name: str, **st: Any) -> dict[str, Any]:
    d = info(name)
    d["State"] = {"Running": True, "Paused": False, "Restarting": False, "Status": "running", **st}
    return d


# --- _untc: the qdisc cleanup sidecar ------------------------------------------------------------


def test_cleanup_sidecar_spec_is_exact(client, daemon):
    created = _latency_daemon(daemon, output=b"injected\n", code=137)  # killed mid-sleep: its own revert never ran
    with pytest.raises(ValueError, match="tc failed in the sidecar"):
        client.chaos.latency("db", seconds=1, image="tools/tc:9")
    assert len(created) == 2
    fix = created[1].body
    assert fix["Image"] == "tools/tc:9" == created[0].body["Image"]
    assert fix["Cmd"] == ["sh", "-c", UNTC]
    assert fix["HostConfig"]["NetworkMode"] == "container:dbfull"
    assert fix["HostConfig"]["CapAdd"] == ["NET_ADMIN"]


def test_cleanup_sidecar_is_force_removed_even_while_running(client, daemon):
    created = _latency_daemon(daemon, output=b"injected\n", code=137)
    removed: list[Seen] = []

    def rm(s: Seen) -> Reply:  # like dockerd: a running container is only removed with force
        removed.append(s)
        if s.query.get("force") not in ("1", "true", "True"):
            return Reply(409, json={"message": "cannot remove a running container"})
        return Reply(204)
    daemon.on("DELETE", r"/containers/side\d", rm)
    with pytest.raises(ValueError, match="tc failed in the sidecar"):
        client.chaos.latency("db", seconds=1)
    assert len(created) == 2
    assert [s.path for s in removed] == ["/containers/side1", "/containers/side2"]
    assert all(s.query.get("force") in ("1", "true", "True") for s in removed)


def test_cleanup_sidecar_is_waited_for_without_a_client_timeout(host, daemon):
    """The cleanup must finish however long tc takes: its wait uses no client timeout."""
    created = _latency_daemon(daemon, output=b"injected\n", code=137)

    def slow_wait(s: Seen) -> Reply:
        time.sleep(0.6)
        return Reply(json={"StatusCode": 0})
    daemon.on("POST", "/containers/side2/wait", slow_wait)
    dk = Docker(host, timeout=0.2)
    with pytest.raises(ValueError, match="tc failed in the sidecar"):  # not a timeout from the cleanup
        dk.chaos.latency("db", seconds=1)
    assert len(created) == 2 and ("DELETE", "/containers/side2") in daemon.calls()


def test_cleanup_sidecar_is_removed_when_its_wait_fails(client, daemon):
    created = _latency_daemon(daemon, output=b"injected\n", code=137)
    daemon.on("POST", "/containers/side2/wait", status=500, json={"message": "wait broke"})
    with pytest.raises(errors.APIError, match="wait broke"):  # the qdisc may be left: the cleanup error surfaces
        client.chaos.latency("db", seconds=1)
    assert len(created) == 2 and ("DELETE", "/containers/side2") in daemon.calls()


# --- healthy() -----------------------------------------------------------------------------------


def test_restarting_container_is_unhealthy(client, daemon):
    daemon.on("GET", "/containers/c/json", json=state_info("c", Restarting=True, Status="restarting"))
    assert client.chaos.healthy("c") == (False, "restarting")


def test_adapter_without_probe_falls_back_to_healthcheck_then_running(client, daemon, monkeypatch):
    class Toy(Adapter):  # a plugin adapter that offers no probe
        kind = "toy"
        image_rx: ClassVar[re.Pattern[str]] = re.compile(r"^toyd$")
    monkeypatch.setitem(REGISTRY.adapters, "toy", Toy)
    d = state_info("t")
    d["Config"]["Image"] = "toyd:1"
    assert REGISTRY.detect(Target.from_inspect(d))[0] is Toy
    daemon.on("GET", "/containers/t/json", json=d)
    assert client.chaos.healthy("t") == (True, "running")


def test_probe_error_text_is_truncated_to_200_chars(client, daemon):
    daemon.on("GET", "/containers/cache/json", json=info("cache", image="redis:7"))
    daemon.execs("cache", [(b"E" * 500 + b"\n", b"", 0)])
    ok, detail = client.chaos.healthy("cache")
    assert ok is False
    assert len(detail) == 200 and detail.startswith("redis: PING -> 'EEE")


def test_probe_detail_is_returned_verbatim(client, daemon):
    daemon.on("GET", "/containers/cache/json", json=info("cache", image="redis:7"))
    daemon.execs("cache", [(b"PONG\n", b"", 0)])
    assert client.chaos.healthy("cache") == (True, "PING")

