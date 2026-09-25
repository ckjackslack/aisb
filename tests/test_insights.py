import json

import pytest

from aisb.insights import Facts, compare, diagnose, fingerprint, grep, take, template
from aisb.insights.logs import level_of
from aisb.insights.snapshot import load
from aisb.insights.triage import SIGNATURES

NEW, OLD = "sha256:" + "a" * 64, "sha256:" + "b" * 64


@pytest.mark.parametrize(("line", "expected"), [
    ("2026-09-25T10:00:00.123Z GET /items/42 200 13ms", "<ts> GET /items/<n> <n> <n>"),
    ("req 5f1c2e3a-1111-2222-3333-4444deadbeef from 10.0.0.7:5432", "req <uuid> from <ip>"),
    ("commit deadbeefcafe1234 at 12:01:02", "commit <hex> at <time>"),
    ("disk 93% full, 1.5GB free", "disk <n> full, <n> free"),
    ("user_42 v2 stays", "user_42 v2 stays"),  # identifiers keep their digits
])
def test_template_masks_variable_parts(line, expected):
    assert template(line) == expected


@pytest.mark.parametrize(("line", "level"), [
    ("FATAL: boom", "error"), ("Traceback (most recent call last):", "error"), ("level=warning x", "warn"),
    ("INFO started", "info"), ("DEBUG x", "debug"), ("hello", "other"),
])
def test_level_of(line, level):
    assert level_of(line) == level


def test_fingerprint_ranks_errors_first_and_flags_emerging():
    lines = [f"INFO GET /items/{i} 200" for i in range(95)] + ["", "WARN slow query 812ms"] + \
            [f"ERROR payment {i} failed" for i in range(3)]
    fp = fingerprint(lines, top=2)
    assert (fp["lines"], fp["patterns"]) == (100, 3)
    assert fp["levels"] == {"info": 95, "warn": 1, "error": 3}
    assert [p["template"] for p in fp["top"]] == ["ERROR payment <n> failed", "WARN slow query <n>"]
    assert fp["top"][0] | {"sample": ""} == {"template": "ERROR payment <n> failed", "level": "error", "count": 3,
                                             "first_line": 98, "last_line": 100, "sample": "",
                                             "numbers": [{"slot": 0, "unit": "", "first": 0.0, "last": 2.0,
                                                          "min": 0.0, "max": 2.0, "trend": "up"}]}
    assert fp["emerging"] == ["WARN slow query <n>", "ERROR payment <n> failed"]
    assert [p["level"] for p in fingerprint(lines, min_level="warn")["top"]] == ["error", "warn"]


def test_fingerprint_skips_emerging_on_short_logs():
    assert fingerprint(["ERROR a"])["emerging"] == []


def test_grep_numbers_context_and_separators():
    lines = ["a", "err 1", "b", "c", "d", "err 2", "e"]
    assert grep(lines, r"err", 1) == "1:a\n2:err 1\n3:b\n--\n5:d\n6:err 2\n7:e\n"
    assert grep(lines, "zzz") == ""
    with pytest.raises(ValueError, match="invalid regex"):
        grep(lines, "(")


@pytest.mark.parametrize(("line", "var"), [
    ("FATAL: DATABASE_URL is not set", "DATABASE_URL"),
    ("Missing required environment variable: REDIS_URL", "REDIS_URL"),
    ("SECRET_KEY must be set", "SECRET_KEY"),
    ("error: env var `API_TOKEN` missing", "API_TOKEN"),
    ("FATAL error happened", None),
    ("the requested file is missing", None),
])
def test_missing_env_signature(line, var):
    m = SIGNATURES[0].rx.search(line)
    assert (m and (m["var"] or m["var2"])) == var


def container(**state):
    base = {"Status": "running", "Running": True, "ExitCode": 0}
    return {"Name": "/api", "Image": NEW, "RestartCount": 0, "State": base | state,
            "Config": {"Image": "app:1.0", "Env": ["PORT=80"], "Cmd": ["serve"]}, "HostConfig": {}}


def codes(report):
    return [(f["severity"], f["code"]) for f in report["findings"]]


def test_healthy_container():
    assert diagnose(Facts("api", container(), image_id=NEW)) | {"findings": [], "state": {}} == {
        "container": "api", "verdict": "healthy", "likely_cause": None, "state": {}, "findings": []}


def test_crash_loop_with_missing_env_and_dependency():
    info = container(Status="restarting", Running=True, Restarting=True, ExitCode=1) | {"RestartCount": 7}
    logs = ("booting", "ERROR could not connect to db:5432: connection refused", "FATAL: DATABASE_URL is not set")
    report = diagnose(Facts("api", info, logs=logs, peers=frozenset({"api", "db"})))
    assert (report["verdict"], report["likely_cause"]) == ("failing", "missing-env")
    assert codes(report) == [("critical", "missing-env"), ("critical", "dependency-unreachable"), ("critical", "crash-loop")]
    env = report["findings"][0]
    assert "DATABASE_URL is NOT set in the container env" in env["evidence"]
    assert env["next"][0].startswith("aisb containers spec api")
    assert "aisb containers inspect db --fields State.Status,NetworkSettings.Networks" in report["findings"][1]["next"]


def test_dependency_that_does_not_exist_is_called_out():
    info = container(Status="exited", Running=False, ExitCode=1)
    report = diagnose(Facts("api", info, logs=("could not connect to cache:6379",), peers=frozenset({"api"})))
    dep = report["findings"][0]
    assert "no container named 'cache' exists on this host" in dep["evidence"]
    assert not any(n.startswith("aisb containers inspect cache") for n in dep["next"])


def test_missing_env_that_is_set_is_downgraded():
    info = container()
    info["Config"]["Env"].append("DATABASE_URL=x")
    assert codes(diagnose(Facts("api", info, logs=("DATABASE_URL is not set",)))) == [("info", "missing-env")]


@pytest.mark.parametrize(("state", "extra", "expected"), [
    ({"Status": "exited", "Running": False, "ExitCode": 137, "OOMKilled": True}, {},
     [("critical", "oom-killed"), ("info", "no-restart-policy")]),
    ({"Status": "exited", "Running": False, "ExitCode": 127}, {},
     [("critical", "command-not-found"), ("info", "no-restart-policy")]),
    ({"Status": "exited", "Running": False, "ExitCode": 137}, {},
     [("warning", "sigkill"), ("info", "no-restart-policy")]),
    ({"Status": "exited", "Running": False, "ExitCode": 143}, {}, [("info", "no-restart-policy"), ("info", "sigterm")]),
    ({"Status": "created", "Running": False}, {}, [("warning", "never-started")]),
    ({"Health": {"Status": "unhealthy", "FailingStreak": 4, "Log": [{"ExitCode": 1, "Output": "curl: (7) refused\n"}]}}, {},
     [("critical", "unhealthy")]),
    ({"Status": "created", "Running": False, "Error": "port is already allocated"}, {},
     [("critical", "start-error"), ("warning", "never-started")]),
    ({}, {"HostConfig": {"Privileged": True, "Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}},
     [("warning", "privileged"), ("warning", "docker-socket-mounted")]),
])
def test_state_and_config_rules(state, extra, expected):
    assert codes(diagnose(Facts("api", container(**state) | extra, image_id=NEW))) == expected


def test_stale_and_unpinned_image():
    info = container()
    info["Config"]["Image"] = "app"
    assert codes(diagnose(Facts("api", info, image_id=OLD))) == [("warning", "stale-image"), ("info", "unpinned-image")]


def test_generic_crash_signature_only_claims_unexplained_lines():
    info = container(Status="exited", Running=False, ExitCode=1)
    only_env = diagnose(Facts("api", info, logs=("FATAL: DATABASE_URL is not set",)))
    assert "app-crash" not in {c for _, c in codes(only_env)}
    both = diagnose(Facts("api", info, logs=("FATAL: DATABASE_URL is not set", "panic: nil map")))
    assert "app-crash" in {c for _, c in codes(both)}


def test_resource_rules():
    stats = {"cpu_percent": 180.0, "memory": {"used": 95, "limit": 100, "percent": 95.0}}
    assert codes(diagnose(Facts("api", container(), image_id=NEW, stats=stats))) == [
        ("warning", "memory-pressure"), ("info", "cpu-hot")]


def raw_container(name, id_, state="running", image="app:1"):
    return {"Id": id_ * 64, "Names": [f"/{name}"], "Image": image, "ImageID": NEW, "State": state, "Labels": {}}


def test_snapshot_compare_detects_added_removed_recreated():
    before = take([raw_container("web", "1"), raw_container("old", "2")],
                  [{"Id": OLD, "RepoTags": ["app:1"]}], [{"Name": "data"}], [{"Name": "bridge", "Id": "n" * 64}], now=1)
    after = take([raw_container("web", "3", state="exited"), raw_container("new", "4")],
                 [{"Id": OLD, "RepoTags": ["app:1"]}, {"Id": NEW, "RepoTags": ["app:2"]}],
                 [{"Name": "data"}], [{"Name": "bridge", "Id": "n" * 64}], now=2)
    diff = compare(before, after)
    assert diff["containers"]["added"] == ["new"] and diff["containers"]["removed"] == ["old"]
    web = diff["containers"]["changed"][0]
    assert (web["name"], web["recreated"], web["changes"]["state"]) == ("web", True, ["running", "exited"])
    assert diff["images"] | {"changed": []} == {"added": ["a" * 12], "removed": [], "changed": [], "tags": {"a" * 12: ["app:2"]}}
    assert diff["cleanup"] == ["aisb containers rm new --force --dry-run", f"aisb images rmi {'a' * 12} --dry-run"]
    assert diff["summary"]["volumes"] == {"added": 0, "removed": 0, "changed": 0}


def test_snapshot_load_validates(tmp_path):
    good, bad = tmp_path / "s.json", tmp_path / "x.json"
    good.write_text(json.dumps(take([], [], [], [], now=5)))
    bad.write_text("{}")
    assert load(good)["taken"] == 5
    with pytest.raises(ValueError, match="not an aisb snapshot"):
        load(bad)


def test_facts_failing_property():
    assert not Facts("a", container()).failing
    assert Facts("a", container(Status="exited", ExitCode=2)).failing
    assert not Facts("a", container(Status="exited", ExitCode=0)).failing


def test_oom_within_seconds_points_at_runaway_allocation():
    info = container(Status="exited", Running=False, ExitCode=137, OOMKilled=True,
                     StartedAt="2026-09-25T10:00:00.1Z", FinishedAt="2026-09-25T10:00:00.5Z")
    oom = diagnose(Facts("hog", info))["findings"][0]
    assert "lived 0.4s after start" in oom["evidence"]
    assert any("runaway allocation" in e for e in oom["evidence"])
    assert "fix the allocation first" in oom["next"][1]


def test_unexplained_errors_degrade_a_running_container():
    logs = tuple(f"INFO GET /items/{i} 200" for i in range(40)) + ("ERROR payment 42 failed: upstream timeout",) * 3
    report = diagnose(Facts("noisy", container(), logs=logs, image_id=NEW))
    assert (report["verdict"], report["likely_cause"]) == ("degraded", None)
    err = report["findings"][0]
    assert (err["code"], err["summary"]) == ("log-errors", "3 unexplained error lines (new at the end of the log)")
    assert list(err["evidence"]) == ["3x ERROR payment <n> failed: upstream timeout"]


def test_signature_explained_errors_are_not_double_reported():
    info = container(Status="exited", Running=False, ExitCode=1)
    report = diagnose(Facts("api", info, logs=("ERROR could not connect to db:5432: connection refused",)))
    assert "log-errors" not in {c for _, c in codes(report)}


def test_fingerprint_surfaces_numeric_trends_and_repeated_ids():
    lines = [f"GET /x took {ms}ms status 200" for ms in (5, 9, 7, 40, 120)]
    lines += ["retry job 5f1c2e3a-1111-2222-3333-4444deadbeef failed"] * 3
    lines += ["tick 3", "tick 3", "tick 3"]
    top = {p["template"]: p for p in fingerprint(lines)["top"]}
    latency = top["GET /x took <n> status <n>"]["numbers"]
    assert latency == [{"slot": 0, "unit": "ms", "first": 5.0, "last": 120.0, "min": 5.0, "max": 120.0, "trend": "up"}]
    assert top["retry job <uuid> failed"]["repeated_ids"] == {"uuid": "5f1c2e3a-1111-2222-3333-4444deadbeef"}
    assert "numbers" not in top["tick <n>"]  # constant values are not a trend


@pytest.mark.parametrize(("values", "trend"), [((1, 5, 9), "up"), ((9, 5, 1), "down"), ((1, 9, 5), None)])
def test_trend_direction(values, trend):
    (p,) = fingerprint([f"v {v}" for v in values])["top"]
    assert p["numbers"][0].get("trend") == trend
