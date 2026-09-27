"""`system` resource over the fake daemon: read ops, prune gating, fleet audit/doctor, remediate, incident,
blackbox/forensics, rightsize and watch."""

import itertools
import json
import time

import pytest

from aisb import state
from aisb.api.system import compact_event, config_dependencies, summarize_df
from aisb.cli import EXIT_CONFIRM, EXIT_DOCKER, EXIT_OK, EXIT_UNMET, EXIT_USAGE, main
from aisb.errors import DockerError
from aisb.ops import get_op, invoke

from conftest import Reply, frame

MIB = 1 << 20
MANAGED_FILTER = {"label": ["aisb.managed=true"]}


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str) -> tuple[int, object, str]:
        code = main([*argv, "--host", host, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def inspect(name: str, *, status: str = "running", exit_code: int = 0, host: dict | None = None,
            env: list[str] | None = None, **state_extra) -> dict:
    return {"Id": name, "Name": f"/{name}", "Image": "sha256:" + "a" * 64, "RestartCount": 0,
            "Config": {"Image": f"{name}:1", "Env": env or [], "Tty": False},
            "HostConfig": {"RestartPolicy": {"Name": "always"}, **(host or {})},
            "State": {"Status": status, "Running": status == "running", "ExitCode": exit_code,
                      "StartedAt": "2026-09-25T10:00:00.123456789Z", **state_extra}}


def serve(daemon, containers: dict[str, tuple[dict, bytes]], *, label_rows: list[str] | None = None) -> None:
    """Serve list/inspect/logs for containers whose id == name (so id and name routes coincide)."""
    rows = [{"Id": n, "Names": [f"/{n}"], "State": i["State"]["Status"], "Image": i["Config"]["Image"]}
            for n, (i, _) in containers.items()]

    def listing(seen):
        f = seen.filters() or {}
        if f.get("label") == ["aisb.managed=true"] and label_rows is not None:
            return Reply(json=[r for r in rows if r["Id"] in label_rows])
        return Reply(json=rows)
    daemon.on("GET", "/containers/json", listing)
    daemon.on("GET", "/images/json", json=[])
    for n, (info, logs) in containers.items():
        daemon.on("GET", f"/containers/{n}/json", json=info)
        daemon.on("GET", f"/containers/{n}/logs", Reply(body=frame(2, logs) if logs else b""))


# --- pure helpers -----------------------------------------------------------------------------------

def test_summarize_df_counts_reclaimable_and_tolerates_missing_sections():
    d = {"LayersSize": 1000,
         "Images": [{"Containers": 1, "Size": 400}, {"Containers": 0, "Size": 600}, {"Containers": -1, "Size": 5}],
         "Containers": [{"State": "running", "SizeRw": 10}, {"State": "exited", "SizeRw": 7}],
         "Volumes": [{"UsageData": {"RefCount": 1, "Size": 50}}, {"UsageData": {"RefCount": 0, "Size": 30}},
                     {"UsageData": {"RefCount": 0, "Size": -1}}, {"UsageData": None}],
         "BuildCache": [{"Size": 9, "InUse": True}, {"Size": 4, "InUse": False}]}
    assert summarize_df(d) == {
        "images": {"count": 3, "active": 1, "size": 1000, "reclaimable": 605},
        "containers": {"count": 2, "running": 1, "size": 17, "reclaimable": 7},
        "volumes": {"count": 4, "active": 1, "size": 80, "reclaimable": 30},   # Size -1 = unknown, never negative
        "build_cache": {"count": 2, "size": 13, "reclaimable": 4},
    }
    empty = summarize_df({"Images": None, "Containers": None, "Volumes": None, "BuildCache": None})
    assert all(v["count"] == 0 for v in empty.values())


@pytest.mark.parametrize(("event", "expected"), [
    ({}, {"time": None, "type": None, "action": None, "id": ""}),
    ({"Type": "network", "Action": "connect", "time": 5, "Actor": {"ID": "n" * 64, "Attributes": None}},
     {"time": 5, "type": "network", "action": "connect", "id": "n" * 12}),
    ({"Type": "container", "Action": "kill", "Actor": {"ID": "c1", "Attributes": {"signal": "9", "secret": "x"}}},
     {"time": None, "type": "container", "action": "kill", "id": "c1", "signal": "9"}),
])
def test_compact_event_keeps_only_known_attributes(event, expected):
    assert compact_event(event) == expected


def test_config_dependencies_by_name_alias_and_url(client, daemon):
    infos = {
        "api": {"Config": {"Env": ["REDIS_URL=redis://cache:6379/0", "DB=postgres://u:p@pg-alias:5432/app",
                                   "SELF=http://api:8080", "NOISE=hello", "BARE"]}},
        "db": {"Config": {"Env": None}, "NetworkSettings": {"Networks": {"n": {"Aliases": ["pg-alias", "db"]}}}},
        "cache": {"Config": {}, "NetworkSettings": {"Networks": {"n": {"Aliases": None}}}},
        "web": {"Config": {"Env": ["UPSTREAM=http://api"]}},
    }
    for n, i in infos.items():
        daemon.on("GET", f"/containers/{n}/json", json=i)
    rows = [{"Id": n, "Names": [f"/{n}"]} for n in infos]
    assert config_dependencies(client.transport, rows) == {"api": {"cache", "db"}, "web": {"api"}}


# --- read ops ---------------------------------------------------------------------------------------

def test_ping_version_info_df(cli, daemon, host):
    daemon.on("GET", "/version", json={"Version": "27.0", "ApiVersion": "1.43"})
    daemon.on("GET", "/info", json={"Name": "box", "Swarm": {"LocalNodeState": "inactive"}, "NCPU": 8})
    daemon.on("GET", "/system/df", json={"LayersSize": 1})
    assert cli("system", "ping")[1] == {"ok": True, "endpoint": host, "api_version": "1.43"}
    assert cli("system", "version")[1]["Version"] == "27.0"
    code, out, _ = cli("system", "info", "--fields", "NCPU,Swarm.LocalNodeState")
    assert code == EXIT_OK and out == {"NCPU": 8, "Swarm.LocalNodeState": "inactive"}
    assert cli("system", "df")[1]["images"] == {"count": 0, "active": 0, "size": 1, "reclaimable": 0}


def test_events_window_is_bounded_and_filters_forwarded(cli, daemon):
    lines = b"".join(json.dumps({"Type": "container", "Action": "start", "time": i}).encode() + b"\n" for i in range(5))
    daemon.on("GET", "/events", Reply(body=lines))
    code, out, _ = cli("system", "events", "--since", "100", "--until", "200", "--filter", "type=container",
                       "--filter", "container=web")
    assert code == EXIT_OK and len(out) == 5        # stream ended before --limit: everything returned
    q = daemon.seen[0].query
    assert (q["since"], q["until"]) == ("100", "200")
    assert daemon.seen[0].filters() == {"type": ["container"], "container": ["web"]}
    assert len(cli("system", "events", "--limit", "1")[1]) == 1


def test_info_daemon_error_exits_docker(cli, daemon):
    daemon.on("GET", "/info", status=500, json={"message": "boom"})
    code, out, err = cli("system", "info")
    assert (code, out) == (EXIT_DOCKER, None) and json.loads(err)["status"] == 500


# --- prune: DESTROY gating, --managed scoping, --volumes opt-in ---------------------------------------

def _prune_routes(daemon):
    daemon.on("POST", "/containers/prune", json={"ContainersDeleted": ["a", "b"], "SpaceReclaimed": 10})
    daemon.on("POST", "/images/prune", json={"ImagesDeleted": [{"Deleted": "x"}], "SpaceReclaimed": 20})
    daemon.on("POST", "/networks/prune", json={"NetworksDeleted": None})
    daemon.on("POST", "/volumes/prune", json={"VolumesDeleted": ["v"], "SpaceReclaimed": 30})


@pytest.mark.parametrize("extra", [(), ("--volumes",), ("--managed", "--volumes", "--all-images")])
def test_prune_without_yes_sends_nothing(cli, daemon, extra):
    _prune_routes(daemon)
    code, out, _ = cli("system", "prune", *extra)
    assert code == EXIT_CONFIRM and out["status"] == "confirmation_required"
    assert daemon.calls("POST") == []
    assert any(p["path"].endswith("/containers/prune") for p in out["planned"])


def test_prune_dry_run_sends_nothing_and_shows_volumes_only_when_asked(cli, daemon):
    _prune_routes(daemon)
    code, out, _ = cli("system", "prune", "--dry-run")
    assert code == EXIT_OK and daemon.calls("POST") == []
    assert [p["path"].rsplit("/", 2)[-2] for p in out["planned"]] == ["containers", "images", "networks"]
    code, out, _ = cli("system", "prune", "--dry-run", "--volumes")
    assert "volumes" in [p["path"].rsplit("/", 2)[-2] for p in out["planned"]] and daemon.calls("POST") == []


def test_prune_default_with_yes_skips_volumes(cli, daemon):
    _prune_routes(daemon)
    code, out, _ = cli("system", "prune", "--yes")
    assert code == EXIT_OK
    assert out == {"containers": {"deleted": 2, "space_reclaimed": 10},
                   "images": {"deleted": 1, "space_reclaimed": 20},
                   "networks": {"deleted": 0, "space_reclaimed": 0}}
    assert daemon.calls("POST") == [("POST", "/containers/prune"), ("POST", "/images/prune"),
                                    ("POST", "/networks/prune")]
    by = {s.path: s for s in daemon.seen}
    assert "filters" not in by["/containers/prune"].query and "filters" not in by["/networks/prune"].query
    assert by["/images/prune"].filters() == {"dangling": ["true"]}


def test_prune_managed_scopes_every_call_to_the_label(cli, daemon):
    _prune_routes(daemon)
    code, out, _ = cli("system", "prune", "--yes", "--managed", "--volumes", "--all-images")
    assert code == EXIT_OK and out["volumes"] == {"deleted": 1, "space_reclaimed": 30}
    by = {s.path: s.filters() for s in daemon.seen}
    assert by["/containers/prune"] == MANAGED_FILTER and by["/networks/prune"] == MANAGED_FILTER
    assert by["/images/prune"] == {"dangling": ["false"], **MANAGED_FILTER}
    assert by["/volumes/prune"] == {**MANAGED_FILTER, "all": ["true"]}   # named aisb volumes count too


def test_prune_unmanaged_volumes_only_anonymous(cli, daemon):
    _prune_routes(daemon)
    code, _, _ = cli("system", "prune", "--yes", "--volumes", "--no-containers", "--no-images", "--no-networks")
    assert code == EXIT_OK
    assert daemon.calls("POST") == [("POST", "/volumes/prune")]
    assert "filters" not in daemon.seen[0].query                             # never all=true without --managed


def test_prune_daemon_conflict_is_docker_error(cli, daemon):
    daemon.on("POST", "/containers/prune", status=409, json={"message": "a prune operation is already running"})
    code, out, err = cli("system", "prune", "--yes")
    assert code == EXIT_DOCKER and "already running" in err


# --- fleet doctor / audit -------------------------------------------------------------------------------

def test_doctor_managed_uses_label_filter_and_skips_logs_with_tail_0(cli, daemon):
    serve(daemon, {"ok": (inspect("ok"), b"")}, label_rows=["ok"])
    code, out, _ = cli("system", "doctor", "--managed", "--tail", "0")
    assert code == EXIT_OK and out["healthy"] == ["ok"] and "log lines" not in out["scope"]
    first = next(s for s in daemon.seen if s.path == "/containers/json")
    assert first.filters() == MANAGED_FILTER
    assert not any(s.path.endswith("/logs") for s in daemon.seen)


def _audit_fleet(daemon):
    risky = inspect("risky", host={"Privileged": True},
                    env=["DB_PASSWORD=hunter2hunter2"]) | {"Mounts": [{"Source": "/var/run/docker.sock",
                                                                        "Destination": "/s"}]}
    tidy = inspect("tidy", host={"Memory": 64 * MIB, "NanoCpus": 10**9, "PidsLimit": 100,
                                 "SecurityOpt": ["no-new-privileges:true"]})
    tidy["Config"]["User"] = "app"
    tidy["Config"]["Healthcheck"] = {"Test": ["CMD", "true"]}
    serve(daemon, {"risky": (risky, b""), "tidy": (tidy, b"")}, label_rows=["tidy"])
    img = "sha256:" + "a" * 64
    daemon.on("GET", f"/images/{img}/json", status=404, json={"message": "gone"})


def test_audit_ranks_worst_first_and_caches_image_lookups(cli, daemon):
    _audit_fleet(daemon)
    code, out, _ = cli("system", "audit")
    assert code == EXIT_OK and out["containers"] == 2
    assert [r["container"] for r in out["reports"]] == ["risky", "tidy"]
    risky = out["reports"][0]
    assert {"privileged", "docker-socket", "secret-in-env"} <= {f["code"] for f in risky["findings"]}
    assert all(f["severity"] != "info" for r in out["reports"] for f in r["findings"])   # default min: warning
    assert out["average_score"] == round(sum(r["score"] for r in out["reports"]) / 2)
    assert len([s for s in daemon.seen if s.path.startswith("/images/sha256")]) == 1   # 404 cached as {}
    assert list(out["most_common"].values()) == sorted(out["most_common"].values(), reverse=True)


@pytest.mark.parametrize(("argv", "names", "min_sev"), [
    (("--managed",), ["tidy"], "warning"),
    (("--container", "risky", "--min-severity", "critical"), ["risky"], "critical"),
    (("--container", "tidy", "--min-severity", "info"), ["tidy"], "info"),
])
def test_audit_scoping(cli, daemon, argv, names, min_sev):
    _audit_fleet(daemon)
    code, out, _ = cli("system", "audit", *argv)
    assert code == EXIT_OK and [r["container"] for r in out["reports"]] == names
    order = ["info", "warning", "critical"]
    assert all(order.index(f["severity"]) >= order.index(min_sev) for r in out["reports"] for f in r["findings"])
    if "--container" in argv:
        assert not any(s.path == "/containers/json" for s in daemon.seen)


def test_audit_empty_fleet(cli, daemon):
    daemon.on("GET", "/containers/json", json=None)
    assert cli("system", "audit")[1] == {"containers": 0, "average_score": None, "most_common": {}, "reports": []}


# --- remediate ------------------------------------------------------------------------------------------

def _remediate_fleet(daemon):
    serve(daemon, {
        "api": (inspect("api", status="exited", exit_code=1), b"ERROR request failed\n"),
        "oom": (inspect("oom", status="exited", exit_code=137, OOMKilled=True, host={"Memory": 100 * MIB}), b""),
        "cfg": (inspect("cfg", status="exited", exit_code=1), b"DATABASE_URL is not set\n"),
        "ok": (inspect("ok"), b""),
    })
    for n in ("api", "oom", "cfg", "ok"):
        daemon.on("POST", f"/containers/{n}/start", status=204)
    daemon.on("POST", "/containers/oom/update", json={"Warnings": []})


def test_remediate_dry_run_sends_nothing_and_lists_suggestions(cli, daemon):
    _remediate_fleet(daemon)
    code, out, _ = cli("system", "remediate", "--dry-run")
    assert code == EXIT_OK and out["status"] == "dry-run"
    assert daemon.calls("POST") == []                                   # the invariant: nothing was sent
    notes = [p for p in out["planned"] if "remediate" in p]
    assert {(p["remediate"], p["container"]) for p in notes} == {
        ("start-exited", "api"), ("raise-memory", "oom"), ("start-exited", "oom")}
    planned_posts = [p["path"] for p in out["planned"] if p.get("method") == "POST"]
    assert "/containers/cfg/start" not in [p.split("/v1.43")[-1] for p in planned_posts]  # suggestion, not action
    assert any(p.get("rule") == "missing-env" and p.get("container") == "cfg" for p in out["planned"])


def test_remediate_acts_and_audits(cli, daemon):
    _remediate_fleet(daemon)
    code, out, _ = cli("system", "remediate")
    assert code == EXIT_OK and out["checked"] == 3
    assert sorted((a["container"], a["rule"], a["status"]) for a in out["actions"]) == [
        ("api", "start-exited", "done"), ("oom", "raise-memory", "done"), ("oom", "start-exited", "done")]
    assert [s["rule"] for s in out["suggestions"]] == ["missing-env"]
    posts = daemon.calls("POST")
    assert ("POST", "/containers/cfg/start") not in posts
    upd = next(s for s in daemon.seen if s.path == "/containers/oom/update")
    assert upd.body["Memory"] == 128 * MIB


@pytest.mark.parametrize(("argv", "done"), [
    (("--rule", "raise-memory"), [("oom", "raise-memory")]),
    (("--container", "api"), [("api", "start-exited")]),
    (("--max-actions", "1"), None),
    (("--max-actions", "0"), []),
])
def test_remediate_filters(cli, daemon, argv, done):
    _remediate_fleet(daemon)
    code, out, _ = cli("system", "remediate", *argv)
    assert code == EXIT_OK
    got = [(a["container"], a["rule"]) for a in out["actions"]]
    if done is None:
        assert len(got) == 1
    else:
        assert got == done
    assert len(daemon.calls("POST")) == len(got)


def test_remediate_unknown_rule_is_usage_error_and_sends_nothing(cli, daemon):
    _remediate_fleet(daemon)
    code, _, err = cli("system", "remediate", "--rule", "reboot-host")
    assert code == EXIT_USAGE and "unknown rule" in err and daemon.seen == []


def test_remediate_reports_failed_action(cli, daemon):
    _remediate_fleet(daemon)
    daemon.on("POST", "/containers/api/start", status=500, json={"message": "port is already allocated"})
    code, out, _ = cli("system", "remediate", "--container", "api")
    assert code == EXIT_UNMET and out["ok"] is False and out["reason"] == "1 action(s) failed"
    assert out["actions"][0]["status"] == "failed" and "already allocated" in out["actions"][0]["error"]


def test_remediate_invoke_dry_run_api(client, daemon):
    _remediate_fleet(daemon)
    plan = invoke(client, get_op("system.remediate"), {"container": ["cfg"]}, dry_run=True)
    assert plan.status == "dry-run" and daemon.calls("POST") == []
    assert plan.planned == [{"container": "cfg", "rule": "missing-env",
                             "suggestion": plan.planned[0]["suggestion"]}]


# --- incident -------------------------------------------------------------------------------------------

def _ts(offset: float) -> str:
    t = time.time() - offset
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1e9):09d}Z"


def _incident_fleet(daemon):
    now = int(time.time())
    ev = [{"Type": "container", "Action": a, "time": now - dt, "Actor": {"ID": cid, "Attributes": attrs}}
          for a, dt, cid, attrs in [
              ("oom", 50, "db", {"name": "db"}),
              ("die", 49, "db", {"name": "db", "exitCode": "137"}),
              ("die", 40, "api", {"name": "api", "exitCode": "0"}),          # clean exit: not a signal
              ("health_status: unhealthy", 30, "api", {"name": "api"}),
              ("restart", 20, "api", {"name": "api"}),
              ("start", 10, "api", {"name": "api"}),
          ]] + [{"Type": "network", "Action": "connect", "time": now, "Actor": {"ID": "n"}},
                {"Type": "container", "Action": "die", "time": now, "Actor": {}}]
    daemon.on("GET", "/events", Reply(body=b"".join(json.dumps(e).encode() + b"\n" for e in ev)))
    api = inspect("api", env=["DB_URL=postgres://db:5432/app"])
    db = inspect("db", status="exited", exit_code=137, OOMKilled=True)
    serve(daemon, {"api": (api, b""), "db": (db, b"")})
    daemon.on("GET", "/containers/api/logs", Reply(body=frame(2, (
        f"{_ts(45)} ERROR connection refused to db:5432\n{_ts(44)} ERROR connection refused to db:5432\n"
        f"{_ts(43)} WARN retrying\n{_ts(42)} INFO 10%\rERROR 20%\n").encode())))
    daemon.on("GET", "/containers/db/logs", status=500, json={"message": "vanished"})


def test_incident_correlates_events_logs_and_config(cli, daemon):
    _incident_fleet(daemon)
    code, out, _ = cli("system", "incident", "--since", "5m")
    assert code == EXIT_OK
    assert out["window"]["to"] - out["window"]["from"] == pytest.approx(300, abs=5)
    assert "db" in out["chain"] and out["next"][0].startswith("aisb containers doctor ")
    assert any(n.startswith("aisb containers timeline") for n in out["next"])
    assert "config" in json.dumps(out)


def test_incident_markdown(cli, daemon):
    _incident_fleet(daemon)
    code, out, err = cli("system", "incident", "--format", "markdown")
    assert code == EXIT_OK, err
    assert set(out) == {"output", "summary"} and "last 30m" in out["output"]


def test_incident_quiet_window(cli, daemon):
    daemon.on("GET", "/events", Reply(body=b""))
    daemon.on("GET", "/containers/json", json=[])
    code, out, _ = cli("system", "incident")
    assert code == EXIT_OK and out["next"] == []


# --- blackbox / forensics -------------------------------------------------------------------------------

def test_blackbox_captures_dead_container_with_redacted_env(client, daemon):
    now = int(time.time())
    ev = [
        {"Type": "container", "Action": "create", "time": now, "Actor": {"ID": "job", "Attributes": {"name": "job"}}},
        {"Type": "container", "Action": "oom", "time": now, "Actor": {"ID": "job", "Attributes": {"name": "job"}}},
        {"Type": "container", "Action": "die", "time": now,
         "Actor": {"ID": "job", "Attributes": {"name": "job", "exitCode": "137"}}},
        {"Type": "container", "Action": "die", "time": now,       # duplicate of the same death: skipped
         "Actor": {"ID": "job", "Attributes": {"name": "job", "exitCode": "137"}}},
        {"status": "kill", "id": "gone" * 16, "time": now},        # old-style event, container already removed
    ]
    daemon.on("GET", "/containers/json", json=[{"Id": "tty1"}])
    daemon.on("GET", "/containers/tty1/json", json={"Config": {"Tty": True}})
    daemon.on("GET", "/containers/tty1/logs", Reply(body=b"tty line\npartial"))
    daemon.on("GET", "/containers/job/json", json=inspect("job", env=["API_TOKEN=abcdefghijkl", "MODE=x"]))
    daemon.on("GET", "/containers/job/logs", Reply(body=frame(1, b"2026-01-01T00:00:00Z starting\n")
                                                   + frame(2, b"2026-01-01T00:00:01Z Killed\n")))
    daemon.on("GET", "/events", Reply(body=b"".join(json.dumps(e).encode() + b"\n" for e in ev)))
    out = client.system.blackbox(seconds=1, max_records=10)
    assert [(c["container"], c["event"]) for c in out["captured"]] == [("job", "oom"), ("job", "die"),
                                                                     ("gone" * 3, "kill")]
    assert out["captured"][1]["exit_code"] == 137
    evq = next(s for s in daemon.seen if s.path == "/events")
    assert evq.filters() == {"type": ["container"], "event": ["create", "start", "die", "oom", "kill"]}
    rec = json.loads(open(out["captured"][1]["record"]).read())
    assert rec["inspect"]["State"]["ExitCode"] == 137 and "abcdefghijkl" not in json.dumps(rec)
    assert "MODE=x" in rec["inspect"]["Config"]["Env"]

    listed = client.system.forensics()
    assert {r["container"] for r in listed} == {"job", "gone" * 3}
    assert len(client.system.forensics(limit=1)) == 1
    rep = client.system.forensics("job")
    assert rep["records_for_container"] == 2 and rep["captured_event"] in ("oom", "die")
    assert "verdict" in rep and isinstance(rep["log_patterns"], list)


def test_blackbox_stops_at_max_records(client, daemon):
    ev = [{"Type": "container", "Action": "die", "time": i, "Actor": {"ID": f"c{i}", "Attributes": {"name": f"c{i}"}}}
          for i in range(3)]
    daemon.on("GET", "/containers/json", json=None)
    for i in range(3):
        daemon.on("GET", f"/containers/c{i}/json", json={"Name": f"/c{i}", "State": {"StartedAt": str(i)}})
    daemon.on("GET", "/events", Reply(body=b"".join(json.dumps(e).encode() + b"\n" for e in ev)))
    out = client.system.blackbox(seconds=1, max_records=2)
    assert [c["container"] for c in out["captured"]] == ["c0", "c1"]
    q = next(s for s in daemon.seen if s.path == "/events").query
    assert int(q["until"]) - int(q["since"]) in (0, 1, 2)


def test_forensics_unknown_name(client, daemon):
    with pytest.raises(ValueError, match="no blackbox record for 'ghost'"):
        client.system.forensics("ghost")
    assert client.system.forensics() == []
    state.write_json(state.home("blackbox") / "x-1-die.json", {"container": "x"})
    assert client.system.forensics()[0]["event"] is None


# --- rightsize ------------------------------------------------------------------------------------------

def _stats(i: int) -> dict:
    return {"cpu_stats": {"cpu_usage": {"total_usage": i * 10**8}, "system_cpu_usage": i * 10**9, "online_cpus": 2},
            "memory_stats": {"usage": 50 * MIB + i * MIB, "limit": 1 << 34, "stats": {"inactive_file": 0}},
            "pids_stats": {"current": 5}}


def test_rightsize_recommends_and_handles_vanishing(client, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "A", "Names": ["/app"]}, {"Id": "B", "Names": ["/gone"]}])
    n = {"i": 0}

    def stats(_):
        n["i"] += 1
        return Reply(json=_stats(n["i"]))
    daemon.on("GET", "/containers/A/stats", stats)
    daemon.on("GET", "/containers/B/stats", status=404, json={"message": "no such container"})
    daemon.on("GET", "/containers/A/json", json={"HostConfig": {}})
    out = client.system.rightsize(seconds=0.02, interval=0.01)
    by = {c["name"]: c for c in out["containers"]}
    assert "not enough samples" in by["gone"]["error"]
    assert "unlimited" in by["app"]["flags"] and out["commands"] == [by["app"]["command"]]
    assert out["summary"]["unlimited"] == 1
    assert daemon.seen[1].query == {"stream": "false", "one-shot": "true"}


def test_rightsize_unknown_container(client, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "A", "Names": ["/app"]}])
    with pytest.raises(ValueError, match="not running: nope"):
        client.system.rightsize(container=["app", "nope"], seconds=0, interval=1)
    assert not any("/stats" in s.path for s in daemon.seen)


# --- watch ----------------------------------------------------------------------------------------------

def test_watch_reports_changes_until_first_change(client, daemon):
    polls = {"n": 0}
    base = {"api": inspect("api")}

    def listing(_):
        polls["n"] += 1
        rows = [{"Id": "api", "Names": ["/api"], "State": "running"}]
        if polls["n"] > 2:
            rows.append({"Id": "new", "Names": ["/new"], "State": "exited"})
        return Reply(json=rows)
    daemon.on("GET", "/containers/json", listing)
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", "/containers/api/json", json=base["api"])
    daemon.on("GET", "/containers/new/json", json=inspect("new", status="exited", exit_code=137, OOMKilled=True))
    out = client.system.watch(interval=0.01, duration=5, until_change=True, tail=0)
    assert out["polls"] == 2
    assert out["changes"][0]["container"] == "new" and out["changes"][0]["change"] == "appeared"
    assert out["failing_now"] == ["new"] and out["next"] == ["aisb containers doctor new"]


def test_watch_classifies_transitions(client, daemon):
    seq = itertools.chain([("running", 0), ("exited", 1), ("exited", 1)], itertools.repeat(("running", 0)))
    cur = {"s": ("running", 0)}

    def listing(_):
        cur["s"] = next(seq)
        return Reply(json=[{"Id": "api", "Names": ["/api"], "State": cur["s"][0]}, {"Id": "x", "Names": ["/x"]}]
                     if cur["s"][0] == "running" else [{"Id": "api", "Names": ["/api"], "State": cur["s"][0]}])
    daemon.on("GET", "/containers/json", listing)
    daemon.on("GET", "/images/json", json=[])
    daemon.on("GET", "/containers/api/json", lambda s: Reply(json=inspect("api", status=cur["s"][0],
                                                                          exit_code=cur["s"][1])))
    daemon.on("GET", "/containers/x/json", json=inspect("x"))
    out = client.system.watch(interval=0.01, duration=0.3, tail=0)
    kinds = {(c["container"], c["change"]) for c in out["changes"]}
    assert ("api", "worse") in kinds and ("api", "better") in kinds and ("x", "gone") in kinds
    assert out["polls"] >= 3


def test_doctor_error_bubbles(client, daemon):
    daemon.on("GET", "/containers/json", status=500, json={"message": "daemon sad"})
    with pytest.raises(DockerError):
        client.system.doctor()
