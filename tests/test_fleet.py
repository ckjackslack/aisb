"""Fleet: inventory, selectors, health, fan-out, and fleet ops across several (fake) Docker daemons."""

import json
import os
import shutil
import socket
import stat
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_UNMET, main
from aisb.fleet import health, runner
from aisb.fleet.inventory import Host, Inventory
from aisb.fleet.ssh import Ssh, Unreachable
from conftest import FakeDaemon, Reply


def inv_of(hosts: dict, groups: dict | None = None) -> Inventory:
    return Inventory({n: Host.from_dict(n, d) for n, d in hosts.items()}, groups or {})


FLEET = {"web1": {"ssh": "ops@10.0.0.1", "groups": ["web", "prod"], "labels": {"region": "eu"}},
         "web2": {"ssh": "ops@10.0.0.2", "groups": ["web", "prod"], "labels": {"region": "us"}},
         "db1": {"ssh": "db1", "port": 2222, "groups": ["db", "prod"], "labels": {"region": "eu"}},
         "build": {"docker": "tcp://build:2376", "groups": ["ci"]},
         "here": {}}


# --- selectors ---------------------------------------------------------------------------------------

@pytest.mark.parametrize(("expr", "names"), [
    ("all", ["build", "db1", "here", "web1", "web2"]),
    ("web1", ["web1"]),
    ("web*", ["web1", "web2"]),
    ("@prod", ["db1", "web1", "web2"]),
    ("region=eu", ["db1", "web1"]),
    ("@prod,&region=eu", ["db1", "web1"]),
    ("@web,!web2", ["web1"]),
    ("!@prod", ["build", "here"]),
    ("@edge", ["web1", "web2"]),                 # computed group: selectors, nesting a group
    ("@edge,&@canary", ["web1"]),
    ("region=u*", ["web2"]),
])
def test_select(expr, names):
    inv = inv_of(FLEET, {"edge": ["@web"], "canary": ["web1", "build"]})
    assert [h.name for h in inv.select(expr)] == names


@pytest.mark.parametrize(("expr", "error"), [
    ("wbe1", "unknown host 'wbe1'"), ("@nope", "unknown group @nope"), ("", "empty target"),
    ("web1,!web1", "selects no hosts"),
])
def test_select_errors(expr, error):
    with pytest.raises(ValueError, match=error):
        inv_of(FLEET).select(expr)


def test_group_cycles_and_clashes_are_rejected():
    with pytest.raises(ValueError, match="cycle"):
        inv_of(FLEET, {"a": ["@b"], "b": ["@a"]}).validate()
    with pytest.raises(ValueError, match="both computed and assigned"):
        inv_of(FLEET, {"web": ["web1"]}).validate()


def test_inventory_roundtrip_is_private(tmp_path):
    inv = inv_of(FLEET, {"edge": ["@web"]})
    inv.path = tmp_path / "fleet.json"
    inv.save()
    assert stat.S_IMODE(inv.path.stat().st_mode) == 0o600
    again = Inventory.load(inv.path)
    assert again.hosts == inv.hosts and again.groups == inv.groups
    assert json.loads(inv.path.read_text())["hosts"]["here"] == {}


def test_upsert_merges_and_host_validation():
    inv = inv_of(FLEET)
    h = inv.upsert(Host("web1", groups=("canary",), labels={"tier": "1"}))
    assert h.ssh == "ops@10.0.0.1" and h.groups == ("web", "prod", "canary") and h.labels == {"region": "eu", "tier": "1"}
    with pytest.raises(ValueError, match="unknown keys"):
        Host.from_dict("x", {"sshh": "a"})
    with pytest.raises(ValueError, match="invalid host name"):
        Host.from_dict("bad name", {})
    assert [Host.from_dict(n, FLEET[n]).transport for n in ("web1", "build", "here")] == ["ssh", "tcp", "local"]


# --- ssh command lines -------------------------------------------------------------------------------

def test_ssh_argv(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/ssh")
    s = Ssh("ops@db1", 2222, "~/.ssh/ops", ("ProxyJump=bastion",))
    argv = s.argv()
    assert argv[0] == "/usr/bin/ssh" and "BatchMode=yes" in argv and "ControlMaster=auto" in argv
    assert argv[argv.index("-p") + 1] == "2222" and argv[argv.index("-i") + 1] == os.path.expanduser("~/.ssh/ops")
    assert "ProxyJump=bastion" in argv
    assert "ControlPath=none" in s.argv(multiplex=False)  # tunnels never ride the shared master


def test_ssh_missing_client(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(Unreachable, match="not installed"):
        Ssh("x").argv()


# --- health ------------------------------------------------------------------------------------------

PROBE_OUT = """@@load
3.10 2.00 1.00 2/300 999
@@cpus
2
@@mem
MemTotal:        8000000 kB
MemFree:          100000 kB
MemAvailable:     600000 kB
@@disk
/dev/sda1  100000000  85000000  15000000  85% /
@@uptime
7200.5 100.0
@@os
NAME="Ubuntu"
PRETTY_NAME="Ubuntu 24.04 LTS"
@@kernel
6.8.0-45-generic
"""


def test_parse_vitals():
    v = health.parse(PROBE_OUT)
    assert (v.load1, v.cpus, v.disk_used_pct, v.uptime_s, v.os, v.kernel) == \
        (3.1, 2, 85.0, 7200, "Ubuntu 24.04 LTS", "6.8.0-45-generic")
    assert v.mem_available_pct == 7.5 and v.disk_free == 15000000 * 1024


def test_parse_tolerates_missing_sections():
    assert health.parse("@@load\n@@cpus\n") == health.Vitals()


@pytest.mark.parametrize(("vitals", "problems", "verdict", "reason"), [
    (health.Vitals(disk_used_pct=50), [], "healthy", None),
    (health.Vitals(disk_used_pct=85), [], "degraded", "disk / 85%"),
    (health.Vitals(disk_used_pct=95), [], "failing", "disk / 95%"),
    (health.Vitals(mem_total=100, mem_available=3), [], "failing", "memory available 3%"),
    (health.Vitals(load1=9, cpus=4), [], "degraded", "load 9 on 4 cpus"),
    (None, [{"container": "api", "verdict": "failing", "likely_cause": "oom-killed", "findings": []}],
     "failing", "container api failing: oom-killed"),
    (None, [{"container": "w", "verdict": "degraded", "likely_cause": None, "findings": ["warning:log-errors: 7 lines"]}],
     "degraded", "container w degraded: 7 lines"),
])
def test_assess(vitals, problems, verdict, reason):
    a = health.assess(vitals, {"problems": problems})
    assert a.verdict == verdict and (reason in a.reasons if reason else a.reasons == [])


def test_assess_down():
    assert health.assess(None, None, error="ssh: connect refused") == health.Assessment("down", ["ssh: connect refused"])


def test_changes():
    ok, disk = {"verdict": "healthy", "reasons": []}, {"verdict": "degraded", "reasons": ["disk / 85%"]}
    down = {"verdict": "down", "reasons": ["refused"]}
    events = health.changes({"a": ok, "b": down, "c": disk, "gone": ok}, {"a": disk, "b": ok, "c": disk, "new": ok})
    assert [(e["host"], e["change"]) for e in events] == [("a", "worse"), ("b", "recovered"), ("gone", "removed"),
                                                           ("new", "added")]
    assert events[0]["new"] == ["disk / 85%"]


# --- fan-out -----------------------------------------------------------------------------------------

def test_fan_out_batches_fail_fast_and_ok_false():
    hosts = [Host(f"h{i}") for i in range(5)]
    seen: list[str] = []

    def fn(h: Host):
        seen.append(h.name)
        if h.name == "h1":
            raise Unreachable("boom")
        return {"ok": False, "reason": "not ready"} if h.name == "h0" else "fine"
    results, skipped = runner.fan_out(hosts, fn, batch=2, fail_fast=True)
    assert [r.host for r in results] == ["h0", "h1"] and skipped == ["h2", "h3", "h4"]
    assert (results[0].ok, results[0].error, results[1].error) == (False, "not ready", "boom")
    assert runner.summary(results, skipped) == {"hosts": 5, "ok": 0, "failed": ["h0", "h1"], "skipped": ["h2", "h3", "h4"]}


# --- fleet ops across two fake daemons -----------------------------------------------------------------

@pytest.fixture
def two() -> Iterator[tuple[FakeDaemon, FakeDaemon]]:
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="aisb-f-", dir="/tmp"))
    daemons = (FakeDaemon(tmp / "a.sock"), FakeDaemon(tmp / "b.sock"))
    for d in daemons:
        d.start()
    yield daemons
    for d in daemons:
        d.stop()
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def fleet(two, tmp_path, monkeypatch, capsys):
    a, b = two
    path = tmp_path / "fleet.json"
    path.write_text(json.dumps({"hosts": {
        "a": {"docker": f"unix://{a.sock}", "groups": ["web"]},
        "b": {"docker": f"unix://{b.sock}", "groups": ["web", "db"]}}}))
    monkeypatch.setenv("AISB_FLEET", str(path))
    monkeypatch.setenv("AISB_HOME", str(tmp_path / "home"))

    def run(*argv: str):
        code = main([*argv, "--json"] if "--" not in argv else
                    [*argv[:argv.index("--")], "--json", *argv[argv.index("--"):]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def _containers(d: FakeDaemon, *names: str) -> None:
    d.on("GET", "/containers/json", json=[{"Id": n * 12, "Names": [f"/{n}"], "Image": "img", "State": "running",
                                           "Status": "Up", "Labels": {}} for n in names])


def test_query_fans_out_and_flattens(fleet, two):
    a, b = two
    _containers(a, "api")
    _containers(b, "api", "db")
    code, out, _ = fleet("fleet", "query", "@web", "--flat", "--", "containers", "list")
    assert code == EXIT_OK and out["op"] == "containers.list"
    assert [(r["host"], r["name"]) for r in out["rows"]] == [("a", "api"), ("b", "api"), ("b", "db")]


def test_query_rejects_wrong_tier(fleet):
    code, _, err = fleet("fleet", "query", "all", "--", "containers", "restart", "api")
    assert code != EXIT_OK and "fleet apply" in err


def test_apply_dry_run_plans_per_host_and_sends_nothing(fleet, two):
    code, out, _ = fleet("fleet", "apply", "@db", "--dry-run", "--", "containers", "restart", "api")
    assert code == EXIT_OK and out["status"] == "dry-run"
    assert out["planned"] == [{"host": "b", "op": "containers.restart",
                               "planned": [{"method": "POST", "path": "/containers/api/restart", "query": {"t": 10}}]}]
    assert not any(s.method == "POST" for d in two for s in d.seen)


def test_destroy_needs_yes_then_runs_everywhere(fleet, two):
    for d in two:
        d.on("DELETE", "/containers/old", status=204)
    code, out, _ = fleet("fleet", "destroy", "all", "--", "containers", "rm", "old")
    assert code == EXIT_CONFIRM and [p["host"] for p in out["planned"]] == ["a", "b"]
    assert not any(s.method == "DELETE" for d in two for s in d.seen)
    code, out, _ = fleet("fleet", "destroy", "all", "--yes", "--", "containers", "rm", "old")
    assert code == EXIT_OK and out["summary"]["ok"] == 2
    assert all(("DELETE", "/containers/old") in d.calls() for d in two)


def test_partial_failure_exits_unmet(fleet, two):
    a, _ = two
    a.on("POST", "/containers/api/restart", status=204)  # b has no such route -> 404
    code, out, _ = fleet("fleet", "apply", "all", "--", "containers", "restart", "api")
    assert code == EXIT_UNMET and out["summary"]["failed"] == ["b"] and "b" in out["reason"]


def test_ps_and_doctor_carry_host(fleet, two):
    a, b = two
    _containers(a, "api")
    _containers(b, "db")
    code, out, _ = fleet("fleet", "ps", "all")
    assert [(r["host"], r["name"]) for r in out["rows"]] == [("a", "api"), ("b", "db")]


def test_ship_skips_hosts_that_have_the_same_layers(fleet, two, host, daemon):
    a, b = two
    img = {"Id": "sha256:local", "RepoTags": ["app:1"], "RootFS": {"Layers": ["sha256:l1"]}, "Architecture": "amd64",
           "Os": "linux"}
    daemon.on("GET", "/images/app:1/json", json=img)
    daemon.on("GET", "/images/app:1/get", Reply(chunks=[b"tar-bytes"], content_type="application/x-tar"))
    a.on("GET", "/images/app:1/json", json={**img, "Id": "sha256:other-store-id"})  # same layers, other engine
    loaded: list[bytes] = []

    def load(seen):
        loaded.append(seen.body)
        b.on("GET", "/images/app:1/json", json=img)
        return Reply(chunks=[b'{"stream":"Loaded image: app:1\\n"}\n'])
    b.on("POST", "/images/load", load)
    code = main(["fleet", "ship", "app:1", "all", "--host", host, "--json"])
    assert code == EXIT_OK
    assert loaded == [b"tar-bytes"]
    assert not any(s.path == "/images/load" for s in a.seen)


def test_inventory_editing_and_dry_run(fleet, tmp_path):
    code, out, _ = fleet("fleet", "add", "c", "--ssh", "ops@c", "--group", "db", "--label", "region=eu", "--dry-run")
    assert code == EXIT_OK and "c" not in Inventory.load().hosts
    fleet("fleet", "add", "c", "--ssh", "ops@c", "--group", "db", "--label", "region=eu")
    code, out, _ = fleet("fleet", "group", "canary", "--add", "@db,&region=eu")
    assert out["added"] == ["c"]
    code, out, _ = fleet("fleet", "hosts", "@canary")
    assert [h["host"] for h in out] == ["c"] and out[0]["groups"] == ["canary", "db"]
    fleet("fleet", "remove", "c")
    assert "c" not in Inventory.load().hosts


def test_export_pyinfra_is_valid_python(fleet):
    fleet("fleet", "add", "w", "--ssh", "ops@10.1.1.1", "--port", "2200", "--group", "web")
    code, out, _ = fleet("fleet", "export", "all")
    ns: dict = {}
    exec(compile(out["output"], "inventory.py", "exec"), ns)
    # a and b are unix sockets on this machine: they collapse into one @local entry
    assert ns["web"] == [("@local", {}), ("w", {"ssh_hostname": "10.1.1.1", "ssh_user": "ops", "ssh_port": 2200})]
    assert ns["fleet"].count(("@local", {})) == 1


# --- live: a throwaway sshd in front of the real daemon -----------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def sshd(tmp_path) -> Iterator[dict]:
    sshd_bin, docker_sock = shutil.which("sshd") or "/usr/sbin/sshd", Path("/var/run/docker.sock")
    if not (Path(sshd_bin).exists() and shutil.which("ssh") and os.geteuid() == 0 and docker_sock.exists()):
        pytest.skip("needs sshd, ssh, root and a local Docker socket")
    key = tmp_path / "id"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    hostkey = tmp_path / "hostkey"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)], check=True)
    auth = tmp_path / "authorized_keys"
    auth.write_text((tmp_path / "id.pub").read_text())
    auth.chmod(0o600)
    port = _free_port()
    Path("/run/sshd").mkdir(exist_ok=True)
    proc = subprocess.Popen([sshd_bin, "-D", "-e", "-p", str(port), "-h", str(hostkey), "-o", f"AuthorizedKeysFile={auth}",
                             "-o", "PermitRootLogin=prohibit-password", "-o", "StrictModes=no",
                             "-o", "AllowStreamLocalForwarding=yes", "-o", "ListenAddress=127.0.0.1"],
                            stderr=subprocess.DEVNULL)
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)
    yield {"ssh": "root@127.0.0.1", "port": port, "key": str(key),
           "ssh_options": ["StrictHostKeyChecking=no", f"UserKnownHostsFile={tmp_path / 'known'}"]}
    proc.terminate()
    proc.wait(timeout=5)


@pytest.mark.docker
def test_live_ssh_tunnel_shell_and_status(sshd, tmp_path):
    host = Host.from_dict("live", sshd)
    code, out, _ = runner.shell(host, "echo hi; exit 3")
    assert (code, out) == (3, "hi\n")
    with runner.docker(host) as d:
        assert d.system.ping()["ok"]
    unreachable = Host.from_dict("gone", {**sshd, "port": _free_port()})
    with pytest.raises(Unreachable):
        runner.shell(unreachable, "true")
    from aisb import Docker
    inv = inv_of({"live": sshd, "gone": {**sshd, "port": _free_port()}})
    inv.path = tmp_path / "fleet.json"
    inv.save()
    local = Docker()
    local.containers.run("busybox:1.36", "sh", "-c", "mkdir -p /w && echo fleet-http > /w/index.html && httpd -f -p 8080 -h /w",
                         name="aisb-fleet-http", detach=True, port=[f"127.0.0.1:{_free_port()}:8080"])
    try:
        with runner.docker(host) as d:
            d.containers.wait_for("aisb-fleet-http", running=True, within=10, interval=0.2)
            res = d.http.get("aisb-fleet-http", "/", port=8080)
            assert res["ok"] and res["body"].strip() == "fleet-http"
            assert res["url"].startswith("http://127.0.0.1:")      # the address as the Docker host sees it
            assert d.transport.dialer._open                       # ...reached through an SSH port forward
    finally:
        local.containers.rm("aisb-fleet-http", force=True)
    st = Docker().fleet.status(inventory=str(inv.path), tail=0)
    assert {h["host"]: h["verdict"] for h in st["hosts"]}["gone"] == "down"
    assert st["hosts"][-1]["host"] == "live" and st["hosts"][-1]["cpus"]
