"""More fleet coverage: tier matching, per-host plans, destroy/--yes, batches and --fail-fast, policy per host,
ship, logs merge/follow, canary go/no-go, desired state failures, inventory import/export, status/watch gates."""

import calendar
import json
import shutil
import tempfile
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aisb import config
from aisb import stack as stk
from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_UNMET, main
from aisb.fleet import metrics
from aisb.fleet.inventory import Inventory

from conftest import FakeDaemon, Reply

# --- fixtures ----------------------------------------------------------------------------------------


@pytest.fixture
def fleet3(tmp_path, monkeypatch, capsys):
    """Three fake daemons (a, b: @web; c: @db; a also @canary) plus a host whose socket doesn't exist."""
    d = Path(tempfile.mkdtemp(prefix="aisb-m-", dir="/tmp"))
    daemons = {n: FakeDaemon(d / f"{n}.sock") for n in ("a", "b", "c")}
    for fake in daemons.values():
        fake.start()
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {
        "a": {"docker": f"unix://{daemons['a'].sock}", "groups": ["web", "canary"], "labels": {"region": "eu"}},
        "b": {"docker": f"unix://{daemons['b'].sock}", "groups": ["web"], "labels": {"region": "us"}},
        "c": {"docker": f"unix://{daemons['c'].sock}", "groups": ["db"]},
        "gone": {"docker": f"unix://{d}/missing.sock", "groups": ["dead"]}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        i = argv.index("--") if "--" in argv else len(argv)
        code = main([*argv[:i], "--json", *argv[i:]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    yield run, daemons, inv
    for fake in daemons.values():
        fake.stop()
    shutil.rmtree(d, ignore_errors=True)


def write_config(text: str) -> None:
    import os
    Path(os.environ["AISB_CONFIG"]).write_text(textwrap.dedent(text))
    config.reset()


def mutations(*daemons: FakeDaemon) -> list[tuple[str, str]]:
    return [(s.method, s.path) for d in daemons for s in d.seen if s.method in ("POST", "PUT", "DELETE")]


def snapshot(d: FakeDaemon, containers: list | None = None) -> None:
    d.on("GET", "/containers/json", json=containers or [])
    d.on("GET", "/images/json", json=[])
    d.on("GET", "/volumes", json={"Volumes": []})
    d.on("GET", "/networks", json=[])
    d.on("GET", "/info", json={"ContainersRunning": 1, "Containers": 2, "NCPU": 2, "MemTotal": 1 << 30,
                               "ServerVersion": "27.0", "OperatingSystem": "FakeOS"})


class Hook:
    """A local webhook sink: records every POST body."""

    def __init__(self) -> None:
        got = self.got = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(204)
                self.end_headers()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def hook(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    h = Hook()
    write_config(f"""
        [notify.hook]
        type = "webhook"
        url = "{h.url}"
    """)
    yield h
    h.close()


# --- tier matching of the inner op ---------------------------------------------------------------------

@pytest.mark.parametrize(("argv", "error"), [
    (("fleet", "query", "all", "--", "containers"), "give the op to run"),
    (("fleet", "query", "all", "--", "containers", "no-such-op"), "invalid op command"),
    (("fleet", "query", "all", "--", "fleet", "hosts"), "can't be nested"),
    (("fleet", "apply", "all", "--", "containers", "rm", "x"), "fleet destroy"),
    (("fleet", "destroy", "all", "--yes", "--", "containers", "list"), "fleet query"),
    (("fleet", "destroy", "all", "--yes", "--", "containers", "restart", "x"), "fleet apply"),
    (("fleet", "query", "all", "--", "containers", "stop", "x"), "fleet apply"),
])
def test_inner_op_tier_must_match_the_fleet_verb(fleet3, argv, error):
    run, daemons, _ = fleet3
    code, _, err = run(*argv)
    assert code != EXIT_OK and error in err
    assert not any(d.seen for d in daemons.values())       # rejected before any host was contacted


# --- destroy: plans only until --yes, on every host set -----------------------------------------------

@pytest.mark.parametrize("extra", [(), ("--batch", "1"), ("--batch", "1", "--fail-fast"), ("--parallel", "1"),
                                   ("--dry-run",)])
def test_destroy_without_yes_touches_no_host(fleet3, extra):
    run, daemons, _ = fleet3
    for d in daemons.values():
        d.on("DELETE", "/containers/old", status=204)
    code, out, _ = run("fleet", "destroy", "a,b,c", *extra, "--", "containers", "rm", "old", "--force")
    assert code in (EXIT_CONFIRM, EXIT_OK) and [p["host"] for p in out["planned"]] == ["a", "b", "c"]
    assert all(p["op"] == "containers.rm" and p["planned"][0]["method"] == "DELETE" for p in out["planned"])
    assert mutations(*daemons.values()) == []
    if "--dry-run" not in extra:
        assert code == EXIT_CONFIRM


def test_destroy_plan_reports_unreachable_hosts_and_still_changes_nothing(fleet3, tmp_path, monkeypatch):
    run, daemons, inv = fleet3
    data = json.loads(inv.read_text())
    data["hosts"]["remote"] = {"ssh": "ops@remote"}
    inv.write_text(json.dumps(data))
    monkeypatch.setenv("PATH", str(tmp_path))                  # no ssh client: the tunnel can't be opened
    code, out, _ = run("fleet", "destroy", "all", "--", "containers", "rm", "old")
    by = {p["host"]: p for p in out["planned"]}
    assert code == EXIT_CONFIRM and set(by) == {"a", "b", "c", "gone", "remote"}
    assert "not installed" in by["remote"]["error"] and "planned" in by["a"]
    assert mutations(*daemons.values()) == []


def test_destroy_with_yes_on_a_selection_only_touches_that_selection(fleet3):
    run, daemons, _ = fleet3
    for d in daemons.values():
        d.on("DELETE", "/containers/old", status=204)
    code, out, _ = run("fleet", "destroy", "@web", "--yes", "--", "containers", "rm", "old")
    assert code == EXIT_OK and out["op"] == "containers.rm" and out["summary"]["ok"] == 2
    assert ("DELETE", "/containers/old") in daemons["a"].calls() and ("DELETE", "/containers/old") in daemons["b"].calls()
    assert daemons["c"].seen == []


# --- rolling batches, --fail-fast, partial failures -----------------------------------------------------

def test_fail_fast_stops_later_batches(fleet3):
    run, daemons, _ = fleet3
    daemons["b"].on("POST", "/containers/api/restart", status=204)
    daemons["c"].on("POST", "/containers/api/restart", status=204)      # a has no route -> 404 -> failed
    code, out, _ = run("fleet", "apply", "a,b,c", "--batch", "1", "--fail-fast", "--", "containers", "restart", "api")
    assert code == EXIT_UNMET and out["summary"] == {"hosts": 3, "ok": 0, "failed": ["a"], "skipped": ["b", "c"]}
    assert mutations(daemons["b"], daemons["c"]) == []
    assert "1 host(s) failed: a" in out["reason"]


def test_without_fail_fast_every_batch_runs(fleet3):
    run, daemons, _ = fleet3
    for n in ("b", "c"):
        daemons[n].on("POST", "/containers/api/restart", status=204)
    code, out, _ = run("fleet", "apply", "a,b,c", "--batch", "1", "--", "containers", "restart", "api")
    assert code == EXIT_UNMET and out["summary"]["failed"] == ["a"] and out["summary"]["ok"] == 2
    assert "skipped" not in out["summary"]
    assert all(("POST", "/containers/api/restart") in daemons[n].calls() for n in ("b", "c"))


def test_fail_fast_with_a_good_first_batch_keeps_rolling(fleet3):
    run, daemons, _ = fleet3
    for d in daemons.values():
        d.on("POST", "/containers/api/restart", status=204)
    code, out, _ = run("fleet", "apply", "a,b,c", "--batch", "2", "--fail-fast", "--", "containers", "restart", "api")
    assert code == EXIT_OK and out["summary"] == {"hosts": 3, "ok": 3, "failed": []}


def test_policy_denial_on_one_host_is_reported_and_others_run(fleet3):
    run, daemons, _ = fleet3
    write_config("""
        [[policy.rules]]
        name = "eu is frozen"
        match = { hosts = "region=eu", tier = "mutate" }
        deny = true
    """)
    for d in daemons.values():
        d.on("POST", "/containers/api/restart", status=204)
    code, out, _ = run("fleet", "apply", "a,b,c", "--", "containers", "restart", "api")
    by = {r["host"]: r for r in out["results"]}
    assert code == EXIT_UNMET and out["summary"]["failed"] == ["a"] and "eu is frozen" in by["a"]["error"]
    assert by["b"]["ok"] and by["c"]["ok"]
    assert ("POST", "/containers/api/restart") not in daemons["a"].calls()
    assert all(("POST", "/containers/api/restart") in daemons[n].calls() for n in ("b", "c"))


def test_dry_run_apply_shows_policy_warning_per_host(fleet3):
    run, daemons, _ = fleet3
    write_config("""
        [[policy.rules]]
        name = "db needs care"
        match = { hosts = "@db", tier = "mutate" }
        deny = true
    """)
    code, out, _ = run("fleet", "apply", "b,c", "--dry-run", "--", "containers", "restart", "api")
    by = {p["host"]: p for p in out["planned"]}
    assert code == EXIT_OK and "db needs care" in json.dumps(by["c"]) and "db needs care" not in json.dumps(by["b"])
    assert mutations(*daemons.values()) == []


def test_query_unflattened_results_and_unreachable_host(fleet3):
    run, daemons, _ = fleet3
    for n in ("a", "b"):
        snapshot(daemons[n], [{"Id": n * 12, "Names": [f"/{n}-api"], "Image": "img", "State": "running",
                               "Status": "Up", "Labels": {}}])
    code, out, _ = run("fleet", "query", "a,b,gone", "--", "containers", "list")
    by = {r["host"]: r for r in out["results"]}
    assert code == EXIT_UNMET and by["a"]["result"][0]["name"] == "a-api" and by["gone"]["ok"] is False
    code, out, _ = run("fleet", "query", "a,b,gone", "--flat", "--", "containers", "list")
    assert [r["host"] for r in out["rows"]] == ["a", "b"] and set(out["errors"]) == {"gone"}


def test_query_flat_falls_back_when_results_are_not_lists(fleet3):
    run, daemons, _ = fleet3
    for n in ("a", "b"):
        daemons[n].on("GET", "/containers/x/json", json={"Id": "x", "Name": "/x", "State": {"Running": True}})
    code, out, _ = run("fleet", "query", "a,b", "--flat", "--", "containers", "inspect", "x")
    assert code == EXIT_OK and "rows" not in out and len(out["results"]) == 2


def test_fleet_shell_runs_on_local_hosts_and_refuses_tcp(tmp_path, monkeypatch, capsys):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"here": {}, "api": {"docker": "tcp://10.9.9.9:2376"}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))
    assert main(["fleet", "shell", "here", "--json", "--", "echo", "hi there"]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["results"][0]["result"]["stdout"] == "hi there\n"
    assert main(["fleet", "shell", "here", "--json", "--", "echo oops >&2; exit 3"]) == EXIT_UNMET
    out = json.loads(capsys.readouterr().out)
    assert out["reason"] == "1 host(s) failed: here" and out["results"][0]["error"] == "exit 3"
    assert main(["fleet", "shell", "api", "--json", "--", "true"]) == EXIT_UNMET
    assert "no shell access" in json.loads(capsys.readouterr().out)["results"][0]["error"]
    assert main(["fleet", "shell", "all", "--sudo", "--dry-run", "--json", "--", "df", "-h"]) == EXIT_OK
    plan = json.loads(capsys.readouterr().out)
    assert {p["shell"] for p in plan["planned"]} == {"sudo -n sh -c 'df -h'"}
    assert main(["fleet", "shell", "here", "--json"]) != EXIT_OK
    assert "give the command" in capsys.readouterr().err


# --- inventory ops ---------------------------------------------------------------------------------------

def test_hosts_on_empty_inventory_says_how_to_add(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AISB_FLEET", str(tmp_path / "none.json"))
    assert main(["fleet", "hosts", "--json"]) != EXIT_OK
    assert "aisb fleet add" in capsys.readouterr().err


def test_groups_remove_and_group_errors(fleet3):
    run, _, inv = fleet3
    data = json.loads(inv.read_text())
    data["groups"] = {"edge": ["@web", "c"]}
    inv.write_text(json.dumps(data))
    code, out, _ = run("fleet", "groups")
    by = {g["group"]: g for g in out}
    assert by["edge"] == {"group": "edge", "members": ["a", "b", "c"], "computed_from": ["@web", "c"]}
    assert by["web"]["members"] == ["a", "b"] and "computed_from" not in by["web"]
    code, _, err = run("fleet", "remove", "nope")
    assert code != EXIT_OK and "unknown host 'nope'" in err
    code, _, err = run("fleet", "group", "x")
    assert code != EXIT_OK and "--add and/or --remove" in err
    code, out, _ = run("fleet", "group", "web", "--remove", "b")
    assert out["removed"] == ["b"] and out["members"] == ["a"]
    code, out, _ = run("fleet", "group", "never", "--remove", "c")
    assert out["members"] == []
    code, out, _ = run("fleet", "remove", "c", "--dry-run")
    assert code == EXIT_OK and "c" in Inventory.load().hosts


def test_add_update_and_replace(fleet3):
    run, _, _ = fleet3
    code, out, _ = run("fleet", "add", "n1", "--ssh", "ops@n1", "--key", "~/.ssh/k", "--ssh-option", "ProxyJump=bastion",
                       "--label", "tier=1")
    assert out["action"] == "added" and out["next"] == ["aisb fleet ping n1"]
    code, out, _ = run("fleet", "add", "n1", "--port", "2222")
    assert out["action"] == "updated" and out["entry"]["ssh"] == "ops@n1" and out["entry"]["port"] == 2222
    code, out, _ = run("fleet", "add", "n1", "--ssh", "x@y", "--replace")
    assert out["entry"] == {"ssh": "x@y"}


def test_export_json_ssh_config_and_pyinfra(fleet3):
    run, _, _ = fleet3
    run("fleet", "add", "w1", "--ssh", "ops@10.1.1.1", "--port", "2200", "--key", "~/.ssh/w", "--group", "front-end.x",
        "--label", "tier=1", "--ssh-option", "ProxyJump=bastion", "--ssh-option", "garbage")
    run("fleet", "add", "w2", "--ssh", "alias-only", "--group", "front-end.x")
    run("fleet", "add", "t1", "--docker", "tcp://10.0.0.9:2376", "--group", "tcp-only")
    code, out, _ = run("fleet", "export", "w1,t1", "--format", "json")
    assert out == {"hosts": {"w1": {"ssh": "ops@10.1.1.1", "port": 2200, "key": "~/.ssh/w", "groups": ["front-end.x"],
                                    "labels": {"tier": "1"}, "ssh_options": ["ProxyJump=bastion", "garbage"]},
                             "t1": {"docker": "tcp://10.0.0.9:2376", "groups": ["tcp-only"]}}}
    code, out, _ = run("fleet", "export", "w1,w2,t1", "--format", "ssh-config")
    assert out["hosts"] == 3 and out["output"] == (
        "Host w1\n  HostName 10.1.1.1\n  User ops\n  Port 2200\n  IdentityFile ~/.ssh/w\n  ProxyJump bastion\n\n"
        "Host w2\n  HostName alias-only\n")
    code, out, _ = run("fleet", "export", "w1,w2,t1")
    assert "# skipped (no ssh, Docker endpoint only): t1" in out["output"]
    ns: dict = {}
    exec(compile(out["output"], "inventory.py", "exec"), ns)
    assert ns["front_end_x"] == [("w1", {"ssh_hostname": "10.1.1.1", "ssh_user": "ops", "ssh_port": 2200,
                                         "ssh_key": "~/.ssh/w", "aisb_labels": {"tier": "1"}}),
                                 ("w2", {"ssh_hostname": "alias-only"})]
    assert "tcp_only" not in ns and "web" not in ns     # groups with no exported (ssh) member are left out


def test_import_csv_json_and_dry_run(fleet3, tmp_path):
    run, _, _ = fleet3
    csv = tmp_path / "hosts.csv"
    csv.write_text("name,ssh,groups\nnew1,ops@1.1.1.1,web\nnew2,ops@1.1.1.2,db\nc,ops@1.1.1.3,db\n")
    code, out, _ = run("fleet", "import", str(csv), "--source", "csv", "--dry-run")
    assert code == EXIT_OK and "new1" not in Inventory.load().hosts
    code, out, _ = run("fleet", "import", str(csv), "--source", "csv", "--match", "new*", "--label", "src=csv")
    assert out["added"] == ["new1", "new2"] and out["updated"] == [] and out["next"] == ["aisb fleet ping new1,new2"]
    assert Inventory.load().hosts["new1"].labels == {"src": "csv"}
    js = tmp_path / "hosts.json"
    js.write_text(json.dumps({"hosts": {"new1": {"ssh": "root@9.9.9.9"}}}))
    code, out, _ = run("fleet", "import", str(js), "--source", "json", "--replace")
    assert out == {**out, "added": [], "updated": ["new1"], "next": []}
    assert Inventory.load().hosts["new1"].groups == ()


# --- health: ping, status (record/notify/gates), watch, trends, report, doctor ----------------------------

def test_ping(fleet3):
    run, daemons, _ = fleet3
    daemons["a"].on("GET", "/version", json={"Version": "27.1", "ApiVersion": "1.46", "Os": "linux", "Arch": "arm64"})
    code, out, _ = run("fleet", "ping", "a,gone")
    by = {r["host"]: r for r in out["results"]}
    assert code == EXIT_UNMET and by["a"]["result"]["docker"] == "27.1" and by["a"]["result"]["arch"] == "arm64"
    assert by["gone"]["ok"] is False and out["summary"]["failed"] == ["gone"]


def test_status_record_notify_and_trends_report(fleet3, hook):
    run, daemons, _ = fleet3
    for n in ("a", "b"):
        snapshot(daemons[n])
    code, out, _ = run("fleet", "status", "a,b,gone", "--no-doctor", "--record", "--notify", "hook", "--fail-on", "down")
    assert code == EXIT_UNMET and out["recorded"] == 3 and out["summary"]["down"] == 1
    assert out["hosts"][0]["host"] == "gone" and out["hosts"][0]["verdict"] == "down"
    assert out["notified"] == [{"sink": "hook", "sent": True, "type": "webhook", "status": 204}]
    assert hook.got[0]["level"] == "down" and "gone: down" in hook.got[0]["text"]
    assert out["hosts"][1]["containers"] == "1/2"
    code, tr, _ = run("fleet", "trends", "all")
    assert code == EXIT_OK and sorted(r["host"] for r in tr["hosts"]) == ["a", "b", "gone"] and tr["no_data"] == ["c"]
    code, rep, _ = run("fleet", "report", "all", "--slo", "99")
    assert rep["below_slo"] == ["gone"] and rep["no_data"] == ["c"]
    assert rep["fleet_uptime_pct"] == round(200 / 3, 3)


def test_status_notify_skips_when_nothing_at_level(fleet3, hook):
    run, daemons, _ = fleet3
    snapshot(daemons["a"])
    code, out, _ = run("fleet", "status", "a", "--no-doctor", "--notify", "hook", "--fail-on", "failing")
    assert "notified" not in out and hook.got == [] and out["ok"] is (out["hosts"][0]["verdict"] != "failing")


def test_trends_forecast_and_empty_report():
    now = time.time()
    for i, disk in enumerate([80.0, 85.0, 90.0]):
        metrics.record([{"host": "full", "verdict": "degraded", "disk_pct": disk, "reasons": ["disk / x%"]},
                        {"host": "flat", "verdict": "healthy", "disk_pct": 50.0}], ts=now - (2 - i) * 86400)
    import os

    from aisb import Docker
    inv = Path(os.environ["AISB_HOME"]) / "inv.json"
    inv.write_text(json.dumps({"hosts": {"full": {}, "flat": {}, "never": {}}}))
    tr = Docker("unix:///nonexistent").fleet.trends(inventory=str(inv))
    risk = tr["disk_full_within_14d"]
    assert [r["host"] for r in risk] == ["full"] and risk[0]["days_left"] == pytest.approx(2.0, abs=0.1)
    rep = Docker("unix:///nonexistent").fleet.report("never", inventory=str(inv))
    assert rep["fleet_uptime_pct"] is None and rep["hosts"] == [] and rep["no_data"] == ["never"]


def test_watch_reports_changes_notifies_and_gates(fleet3, hook):
    run, daemons, _ = fleet3
    polls = {"n": 0}
    snapshot(daemons["a"])

    def info(_):
        polls["n"] += 1
        return Reply(json={"NCPU": 2, "MemTotal": 1 << 30}) if polls["n"] == 1 else Reply(500, json={"message": "boom"})
    daemons["a"].on("GET", "/info", info)
    code, out, _ = run("fleet", "watch", "a", "--interval", "0.05", "--duration", "5", "--until-change", "--tail", "0",
                       "--notify", "hook", "--fail-on", "down", "--record")
    assert out["polls"] == 2 and out["events"][0]["host"] == "a" and out["events"][0]["to"] == "down"
    assert out["now"] == {"a": "down"} and out["attention"] == ["a"] and code == EXIT_UNMET
    assert hook.got and hook.got[0]["level"] == "down" and "a: went down" in hook.got[0]["text"]
    assert sum(len(v) for v in metrics.samples(since=0).values()) == 2


def test_watch_without_changes_runs_until_duration(fleet3):
    run, daemons, _ = fleet3
    code, out, _ = run("fleet", "watch", "gone", "--interval", "0.05", "--duration", "0.12")
    assert code == EXIT_OK and out["polls"] >= 2 and out["events"] == [] and "ok" not in out
    assert out["now"] == {"gone": "down"} and out["attention"] == ["gone"]


def test_doctor_across_hosts(fleet3):
    run, daemons, _ = fleet3
    snapshot(daemons["a"])
    code, out, _ = run("fleet", "doctor", "a,gone")
    assert code == EXIT_OK and out["problems"] == [] and set(out["unreachable"]) == {"gone"}
    assert out["summary"]["a"] == {"failing": 0, "degraded": 0, "healthy": 0}


# --- ship ------------------------------------------------------------------------------------------------

IMG = {"Id": "sha256:local", "RepoTags": ["app:1", "app:latest"], "RootFS": {"Layers": ["sha256:l1"]},
       "Architecture": "amd64", "Os": "linux"}


def test_ship_dry_run_plans_every_host(fleet3, daemon, host):
    run, daemons, _ = fleet3
    daemon.on("GET", "/images/app:1/json", json=IMG)
    code, out, _ = run("fleet", "ship", "app:1", "a,b", "--host", host, "--dry-run")
    assert code == EXIT_OK and [p["host"] for p in out["planned"]] == ["a", "b"]
    assert out["planned"][0]["tags"] == ["app:1", "app:latest"]
    assert not any(d.seen for d in daemons.values()) and ("GET", "/images/app:1/get") not in daemon.calls()


def test_ship_skips_host_that_has_the_image_under_another_tag(fleet3, daemon, host):
    run, daemons, _ = fleet3
    daemon.on("GET", "/images/app:1/json", json=IMG)
    daemon.on("GET", "/images/app:1/get", Reply(chunks=[b"tar"], content_type="application/x-tar"))
    daemons["a"].on("GET", "/images/app:1/json", json={**IMG, "RootFS": {"Layers": ["sha256:other"]}})  # another app:1
    daemons["a"].on("GET", "/images/app:latest/json", json=IMG)                                      # ...but same layers
    code, out, _ = run("fleet", "ship", "app:1", "a", "--host", host)
    assert code == EXIT_OK and out["results"][0]["result"] == {"action": "present"}
    assert ("POST", "/images/load") not in daemons["a"].calls()


def test_ship_loaded_by_id_retags_and_detects_failed_loads(fleet3, daemon, host):
    run, daemons, _ = fleet3
    a, b = daemons["a"], daemons["b"]
    daemon.on("GET", "/images/app:1/json", json=IMG)
    daemon.on("GET", "/images/app:1/get", Reply(chunks=[b"tar", b"-bytes"], content_type="application/x-tar"))
    tagged: list[dict] = []

    def tag(seen):
        tagged.append(seen.query)
        a.on("GET", "/images/app:1/json", json=IMG)            # present once tagged
        return Reply(status=201)
    a.on("POST", "/images/load", Reply(chunks=[b'{"stream":"Loaded image ID: sha256:abc\\n"}\n']))
    a.on("POST", "/images/sha256:abc/tag", tag)
    b.on("POST", "/images/load", Reply(chunks=[b'{"stream":"something odd\\n"}\n']))   # never becomes present
    code, out, _ = run("fleet", "ship", "app:1", "a,b", "--host", host)
    by = {r["host"]: r for r in out["results"]}
    assert code == EXIT_UNMET and by["a"]["result"] == {"action": "loaded", "bytes": 9}
    assert sorted((t["repo"], t["tag"]) for t in tagged) == [("app", "1"), ("app", "latest")]
    assert "load finished but app:1 is not there" in by["b"]["error"] and "something odd" in by["b"]["error"]


# --- logs --------------------------------------------------------------------------------------------------

def _logs(d: FakeDaemon, *lines: str) -> None:
    d.on("GET", "/containers/api/json", json={"Config": {"Tty": True}})
    d.on("GET", "/containers/api/logs", Reply(body="".join(f"{ln}\n" for ln in lines).encode(), content_type="text/plain"))


def test_logs_merge_into_one_timeline(fleet3):
    run, daemons, _ = fleet3
    _logs(daemons["a"], "2024-05-01T10:00:01.000000000Z a first", "2024-05-01T10:00:03.500000000Z a error: third")
    _logs(daemons["b"], "2024-05-01T10:00:02.250000000Z b second")
    code, out, _ = run("fleet", "logs", "a,b,gone", "api")
    assert code == EXIT_OK and out["lines"] == 3 and set(out["errors"]) == {"gone"}
    assert out["output"].splitlines() == ["10:00:01.000 a    | a first", "10:00:02.250 b    | b second",
                                          "10:00:03.500 a    | a error: third"]
    code, out, _ = run("fleet", "logs", "a,b", "api", "--grep", "error")
    assert out["lines"] == 1 and "third" in out["output"]
    code, out, _ = run("fleet", "logs", "a,b", "api", "--patterns")
    assert out["hosts"] == 2 and "top" in out and "errors" not in out


def test_logs_line_with_carriage_return_does_not_lose_the_host(fleet3):
    """Regression: a progress-bar line (`...\r...`) split into a fragment without a timestamp used to raise
    ValueError in the timestamp parser and drop every line of that host."""
    run, daemons, _ = fleet3
    _logs(daemons["a"], "2024-05-01T10:00:01.000000000Z downloading 10%\rdownloading 100%",
          "2024-05-01T10:00:02.000000000Z done")
    code, out, _ = run("fleet", "logs", "a", "api")
    assert code == EXIT_OK and "errors" not in out and out["lines"] == 2
    assert out["output"].splitlines()[-1].endswith("| done")


def test_logs_follow_dedupes_repeated_lines(fleet3, monkeypatch):
    run, daemons, _ = fleet3
    _logs(daemons["a"], "2024-05-01T10:00:01.000000000Z same line")
    code, out, _ = run("fleet", "logs", "a", "api", "--follow", "--seconds", "0.2")
    assert code == EXIT_OK and out["lines"] == 1                   # polled several times, kept once
    assert len([s for s in daemons["a"].seen if s.path.endswith("/logs")]) >= 2
    since = [s.query["since"] for s in daemons["a"].seen if s.path.endswith("/logs")]
    # the watermark moves to the last line seen, so later polls ask only for newer lines
    assert int(float(since[-1])) == calendar.timegm((2024, 5, 1, 10, 0, 1, 0, 0, 0)) != int(float(since[0]))


def test_logs_with_no_lines(fleet3):
    run, daemons, _ = fleet3
    _logs(daemons["a"])
    code, out, _ = run("fleet", "logs", "a", "api")
    assert out["lines"] == 0 and out["output"] == ""


# --- canary ---------------------------------------------------------------------------------------------

class Web:
    """A local HTTP server standing in for a container's published port."""

    def __init__(self, status: int, delay: float = 0.0) -> None:
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                time.sleep(delay)
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.port = self.srv.server_address[1]

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


def _service(d: FakeDaemon, *, logs: list[str], restarts: int = 0, running: bool = True, port: int | None = None) -> None:
    info = {"Id": "s" * 64, "Name": "/api", "RestartCount": restarts,
            "Config": {"Image": "sha256:img", "Tty": True, "Labels": {}},
            "State": {"Running": running, "Status": "running" if running else "exited",
                      "ExitCode": 0 if running else 1, "Restarting": False},
            "HostConfig": {"RestartPolicy": {"Name": "no"}},
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]} if port else {}}}
    d.on("GET", "/containers/api/json", json=info)
    d.on("GET", "/containers/api/logs", Reply(body="".join(f"{ln}\n" for ln in logs).encode(), content_type="text/plain"))
    d.on("GET", "/containers/json", json=[{"Id": "s" * 64, "Names": ["/api"], "State": "running"}])


def test_canary_rejects_overlap(fleet3):
    run, _, _ = fleet3
    code, _, err = run("fleet", "canary", "@web", "a", "--container", "api")
    assert code != EXIT_OK and "overlap" in err and "'a'" in err


def test_canary_go_when_canary_matches_baseline(fleet3):
    run, daemons, _ = fleet3
    for n in ("a", "b"):
        _service(daemons[n], logs=["info: started", "info: serving"])
    code, out, _ = run("fleet", "canary", "a", "b", "--container", "api")
    assert code == EXIT_OK and out["go"] is True and out["reasons"] == [] and "ok" not in out
    assert out["canary"]["errors_per_min"] == 0 and out["baseline"]["http_errors"] is None


def test_canary_no_go_on_errors_restarts_failing_and_unreachable(fleet3):
    run, daemons, _ = fleet3
    _service(daemons["a"], logs=[f"ERROR db timeout {i}" for i in range(40)], restarts=3, running=False)
    _service(daemons["b"], logs=["info: fine"])
    code, out, _ = run("fleet", "canary", "a,gone", "b", "--container", "api", "--since", "1m")
    assert code == EXIT_UNMET and out["go"] is False and out["reason"].startswith("no-go: ")
    text = " | ".join(out["reasons"])
    assert "canary hosts unreachable: gone" in text and "canary restarts 3 > baseline 0" in text
    assert "canary errors" in text
    assert out["canary"]["errors_per_min"] >= 40 * 0.9


def test_canary_http_probes_compare_errors_and_latency(fleet3):
    run, daemons, _ = fleet3
    good, bad = Web(200), Web(500, delay=0.05)
    try:
        _service(daemons["a"], logs=[], port=bad.port)
        _service(daemons["b"], logs=[], port=good.port)
        code, out, _ = run("fleet", "canary", "a", "b", "--container", "api", "--http", "/healthz", "--probes", "2",
                           "--max-latency-ratio", "1.0")
        assert code == EXIT_UNMET and out["canary"]["http_errors"] == 2 and out["baseline"]["http_errors"] == 0
        assert any("HTTP errors 2 > baseline 0" in r for r in out["reasons"])
        # swap roles: now the canary is the healthy one
        code, out, _ = run("fleet", "canary", "b", "a", "--container", "api", "--http", "/healthz", "--probes", "1")
        assert out["go"] is True and out["canary"]["p50_ms"] is not None
        # a port nobody listens on: the probe errors without a timing, so there is no latency to compare
        closed = Web(200)
        closed.close()
        _service(daemons["a"], logs=[], port=closed.port)
        code, out, _ = run("fleet", "canary", "a", "b", "--container", "api", "--http", "/", "--probes", "1")
        assert out["canary"]["p50_ms"] is None and out["canary"]["http_errors"] == 1 and out["go"] is False
    finally:
        good.close()
        bad.close()


# --- desired state: failure paths ----------------------------------------------------------------------------

STACK = {"name": "app", "services": {"web": {"image": "nginx:alpine", "ready": "running"}}}


@pytest.fixture
def desired(fleet3, tmp_path):
    run, daemons, _ = fleet3
    (tmp_path / "app.json").write_text(json.dumps(STACK))
    (tmp_path / "state.json").write_text(json.dumps({"assign": {"@web": "app.json"}}))
    return run, daemons, str(tmp_path / "state.json")


def _ctr(state: str = "running", digest: str | None = None) -> dict:
    s = stk.parse(STACK)
    return {"Id": "c" * 64, "Names": ["/app-web"], "State": state,
            "Labels": {stk.STACK_KEY: "app", stk.SERVICE_KEY: "web", stk.HASH_KEY: digest or s.services["web"].digest}}


def test_desired_state_with_no_assigned_host(desired):
    run, _, state = desired
    code, _, err = run("fleet", "diff", state, "@db")
    assert code != EXIT_OK and "no host in '@db' has stacks assigned" in err


def test_converge_reports_a_service_that_never_becomes_ready(desired):
    run, daemons, state = desired
    a = daemons["a"]
    a.on("GET", "/containers/json", json=[_ctr("exited")])
    a.on("GET", "/networks/app_default", json={"Id": "n"})
    a.on("GET", "/containers/app-web/json", json={"Config": {"Labels": _ctr()["Labels"]},
                                                  "State": {"Running": False, "Status": "exited"}})
    a.on("POST", "/containers/app-web/start", status=204)
    a.on("GET", "/containers/app-web/logs", body=b"", content_type="text/plain")
    daemons["b"].on("GET", "/containers/json", json=[_ctr()])
    code, out, _ = run("fleet", "converge", state, "--within", "0.3")
    by = {r["host"]: r for r in out["results"]}
    assert code == EXIT_UNMET and by["a"]["ok"] is False and "app: web did not become ready" in by["a"]["error"]
    assert by["b"]["result"] == {"stacks": {"app": {"action": "converged"}}}


def test_converge_dry_run_notes_unreachable_hosts(fleet3, tmp_path):
    run, daemons, _ = fleet3
    (tmp_path / "app.json").write_text(json.dumps(STACK))
    (tmp_path / "state.json").write_text(json.dumps({"assign": {"a,gone": ["app.json"]}}))
    daemons["a"].on("GET", "/containers/json", json=[_ctr(digest="old")])
    code, out, _ = run("fleet", "converge", str(tmp_path / "state.json"), "--dry-run")
    by = {p["host"]: p for p in out["planned"]}
    assert "error" in by["gone"] and by["a"]["stacks"]["app"] == {"drift": ["web"], "action": "converged"}
    code, out, _ = run("fleet", "replace-drifted", str(tmp_path / "state.json"))
    by = {p["host"]: p for p in out["planned"]}
    assert code == EXIT_CONFIRM and "error" in by["gone"] and by["a"]["stacks"]["app"]["replaced"] == ["web"]
    assert mutations(daemons["a"]) == []


def test_replace_drifted_no_drift_and_failed_recreate(desired):
    run, daemons, state = desired
    a, b = daemons["a"], daemons["b"]
    b.on("GET", "/containers/json", json=[_ctr()])                 # converged: nothing to replace
    rows = [_ctr(digest="old")]
    a.on("GET", "/containers/json", lambda _: Reply(json=rows))
    removed: list[str] = []

    def delete(seen):
        removed.append(seen.path)
        rows.clear()
        return Reply(status=204)
    a.on("DELETE", "/containers/c+", delete)
    a.on("GET", "/networks/app_default", json={"Id": "n"})
    a.on("POST", "/containers/create", status=201, json={"Id": "new"})
    a.on("POST", "/containers/app-web/start", status=204)
    a.on("GET", "/containers/app-web/logs", body=b"", content_type="text/plain")
    a.on("GET", "/containers/app-web/json", lambda _: Reply(json={
        "Config": {"Labels": _ctr()["Labels"]}, "State": {"Running": False, "Status": "exited"}}) if not rows and removed
        else Reply(404, json={"message": "no such container"}))
    code, out, _ = run("fleet", "replace-drifted", state, "--within", "0.3", "--yes")
    by = {r["host"]: r for r in out["results"]}
    assert by["b"]["result"] == {"stacks": "no drift"}
    assert removed == ["/containers/" + "c" * 64]
    assert code == EXIT_UNMET and "app: web did not become ready" in by["a"]["error"]
