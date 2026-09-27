"""Policy edge cases found by mutation testing (`mutmut run "aisb.policy*"`): the denial contract, every reason
text, window boundaries, rule ordering and the local endpoint in host selectors."""

import datetime as dt
import json
import os
import time

import pytest

from aisb import policy
from aisb.cli import EXIT_POLICY, main
from aisb.context import Ctx
from aisb.fleet.inventory import Host

LOCAL = Ctx("alice", source="cli")
MON_10 = dt.datetime(2026, 9, 28, 10, 0, tzinfo=dt.UTC)  # a Monday


def test_denial_error_contract(host, capsys):
    from pathlib import Path
    Path(os.environ["AISB_CONFIG"]).write_text(
        '[[policy.rules]]\nname = "a"\ndeny = true\n\n[[policy.rules]]\nname = "b"\nrequire = { ticket = true }\n')
    from aisb import config
    config.reset()
    assert main(["volumes", "rm", "v", "--yes", "--host", host, "--json"]) == EXIT_POLICY
    err = json.loads(capsys.readouterr().err)
    assert err == {"error": "PolicyDenied", "op": "volumes.rm",
                   "message": "volumes.rm denied by policy: [a] volumes.rm is not allowed here; "
                              "[b] a change ticket is required (--ticket or $AISB_TICKET)",
                   "violations": [{"rule": "a", "reason": "volumes.rm is not allowed here", "mode": "deny"},
                                  {"rule": "b", "reason": "a change ticket is required (--ticket or $AISB_TICKET)",
                                   "mode": "deny"}]}


@pytest.mark.parametrize(("cond", "kwargs", "reason"), [
    ({"privileged": True}, {"image": "nginx:1", "privileged": True}, "privileged containers are not allowed"),
    ({"host_network": True}, {"image": "nginx:1", "network": "host"}, "host networking is not allowed"),
    ({"docker_socket": True}, {"image": "nginx:1", "volume": ["/var/run/docker.sock:/s"]},
     "mounting the Docker socket is not allowed"),
    ({"volumes": True}, {"volumes": True}, "deleting volume data (--volumes) is not allowed"),
    ({"force": True}, {"force": True}, "--force is not allowed"),
    ({"image_tag": ["latest"]}, {"image": "nginx"}, "image tag 'latest' is not allowed (nginx)"),
    ({"image": "evil/*"}, {"image": "evil/x:1"}, "image evil/x:1 is not allowed"),
])
def test_every_condition_names_its_reason(cond, kwargs, reason):
    op = "containers.run" if "image" in kwargs else "containers.rm"
    (v,) = policy.check([{"name": "r", "deny_if": cond}], op, "mutate", kwargs, LOCAL, MON_10)
    assert v.reason == reason


@pytest.mark.parametrize(("hours", "at", "inside"), [
    ("09-17", (9, 0), True), ("09-17", (16, 59), True), ("09-17", (17, 0), False),   # the end is exclusive
    ("22-06", (22, 0), True), ("22-06", (5, 59), True), ("22-06", (6, 0), False),
    ("09-09", (9, 0), False),                                                        # an empty window, not a full day
    ("00-24", (23, 59), True), ("08", (23, 59), True),                               # open end = until midnight
])
def test_window_boundaries(hours, at, inside):
    now = dt.datetime(2026, 9, 28, *at, tzinfo=dt.UTC)
    assert policy.in_window({"hours": hours}, now) is inside


def test_window_defaults_to_utc_not_the_local_clock(monkeypatch):
    monkeypatch.setenv("TZ", "Asia/Tokyo")   # UTC+9: a local-clock bug would shift the window by nine hours
    time.tzset()
    try:
        hour = dt.datetime.now(dt.UTC).hour
        rule = {"name": "w", "window": {"hours": f"{hour:02d}-{hour + 1:02d}"}}
        assert policy.check([rule], "volumes.rm", "destroy", {}, LOCAL) == []
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()


def test_rules_after_an_exempted_governance_rule_still_apply():
    rules = [{"name": "blanket", "require": {"ticket": True}},
             {"name": "hide audit", "match": {"op": "audit.*"}, "deny": True}]
    assert [v.rule for v in policy.check(rules, "audit.log", "read", {}, LOCAL, MON_10)] == ["hide audit"]


@pytest.mark.parametrize(("hosts", "applies"), [
    ("local", True), ("all", True), ("*", True), ("!web1", True), ("web1,local", True),
    ("@prod", False), ("all,!local", False), ("all!local", False), ("!local", False), ("local,&region=eu", False),
    ("all&!local", False), ("all,&!@prod", True),
])
def test_host_selectors_on_the_local_endpoint(hosts, applies):
    got = policy.check([{"name": "r", "match": {"hosts": hosts}, "deny": True}], "volumes.rm", "destroy", {}, LOCAL,
                       MON_10)
    assert bool(got) is applies
    assert policy._local_matches(hosts) is applies   # a real bool, not merely falsy


def test_computed_groups_apply_to_hosts_outside_the_inventory_file(tmp_path, monkeypatch):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"web1": {"ssh": "web1", "groups": ["web"]}}, "groups": {"edge": ["web*"]}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))
    rule = {"name": "edge only", "match": {"hosts": "@edge"}, "deny": True}
    adhoc = Ctx("alice", host=Host("web9"))   # e.g. `--inventory other.json`: not in the default file
    assert policy.check([rule], "volumes.rm", "destroy", {}, adhoc, MON_10)
    assert not policy.check([rule], "volumes.rm", "destroy", {}, Ctx("alice", host=Host("db1")), MON_10)
