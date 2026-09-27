"""`containers` ops not covered elsewhere: rm/stop/limit/exec/cp/wait/logs caps, secrets, envcheck, compare,
timeline, debug, top, spec, patterns."""

import json
import socket
import time

import pytest

from aisb.api.containers import compare_specs, port_open
from aisb.cli import EXIT_CONFIRM, EXIT_DOCKER, EXIT_OK, EXIT_UNMET, EXIT_USAGE, main
from aisb.errors import NotFound

from conftest import Reply, frame, tar_of

MIB = 1 << 20


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str) -> tuple[int, object, str]:
        code = main([*argv, "--host", host, "--json"] if "--" not in argv else
                    [*argv[:argv.index("--")], "--host", host, "--json", *argv[argv.index("--"):]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def info(name="web", **state) -> dict:
    return {"Id": name * 4, "Name": f"/{name}", "Image": "sha256:" + "ab" * 32,
            "Config": {"Image": f"{name}:1", "Env": ["A=1"], "Tty": False, "Cmd": ["serve"]},
            "HostConfig": {"Memory": 128 * MIB, "NanoCpus": 5 * 10**8, "PidsLimit": 50},
            "State": {"Status": "running", "Running": True, "StartedAt": "2026-09-25T10:00:00Z"} | state}


# --- rm / stop / restart / start ------------------------------------------------------------------------

@pytest.mark.parametrize(("extra", "code", "query"), [
    ((), EXIT_CONFIRM, None),
    (("--yes",), EXIT_OK, {"force": "false", "v": "false"}),
    (("--yes", "--force", "--volumes"), EXIT_OK, {"force": "true", "v": "true"}),
])
def test_rm_is_gated_and_forwards_flags(cli, daemon, extra, code, query):
    daemon.on("DELETE", "/containers/web", status=204)
    rc, out, _ = cli("containers", "rm", "web", *extra)
    assert rc == code
    if query is None:
        assert daemon.calls("DELETE") == [] and out["status"] == "confirmation_required"
    else:
        assert out == {"removed": "web"} and daemon.seen[-1].query == query


@pytest.mark.parametrize(("status", "code"), [(404, EXIT_DOCKER), (409, EXIT_DOCKER), (500, EXIT_DOCKER)])
def test_rm_daemon_errors(cli, daemon, status, code):
    daemon.on("DELETE", "/containers/web", status=status, json={"message": f"err {status}"})
    rc, out, err = cli("containers", "rm", "web", "--yes")
    assert (rc, out) == (code, None) and json.loads(err)["status"] == status


@pytest.mark.parametrize(("op", "argv", "query"), [
    ("stop", ("--grace", "3"), {"t": "3"}),
    ("restart", (), {"t": "10"}),
    ("start", (), {}),
])
def test_lifecycle_actions(cli, daemon, op, argv, query):
    daemon.on("POST", f"/containers/web/{op}", status=204)
    assert cli("containers", op, "web", *argv)[:2] == (EXIT_OK, {"ref": "web", "changed": True})
    assert daemon.seen[0].query == query


def test_start_already_started_is_not_a_change(cli, daemon):
    daemon.on("POST", "/containers/web/start", status=304)
    assert cli("containers", "start", "web")[1] == {"ref": "web", "changed": False}


def test_stop_dry_run_sends_nothing(cli, daemon):
    daemon.on("POST", "/containers/web/stop", status=204)
    code, out, _ = cli("containers", "stop", "web", "--dry-run")
    assert code == EXIT_OK and daemon.seen == [] and out["planned"][0]["path"].endswith("/containers/web/stop")


# --- limit ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("argv", "body"), [
    (("--memory", "256m"), {"Memory": 256 * MIB, "MemorySwap": 512 * MIB}),
    (("--memory", "0"), {"Memory": 0, "MemorySwap": -1}),
    (("--cpus", "1.5"), {"NanoCpus": 1_500_000_000}),
    (("--pids", "0"), {"PidsLimit": -1}),
    (("--pids", "64", "--cpus", "0"), {"PidsLimit": 64, "NanoCpus": 0}),
])
def test_limit_bodies(cli, daemon, argv, body):
    daemon.on("GET", "/containers/web/json", json=info())
    daemon.on("POST", "/containers/web/update", json={"Warnings": ["swap limit ignored"]})
    code, out, _ = cli("containers", "limit", "web", *argv)
    assert code == EXIT_OK and out["applied"] == body and daemon.seen[-1].body == body
    assert out["before"] == {"memory": 128 * MIB, "cpus": 0.5, "pids": 50}
    assert out["warnings"] == ["swap limit ignored"]


def test_limit_needs_a_value_and_reports_unlimited_before(cli, daemon):
    assert cli("containers", "limit", "web")[0] == EXIT_USAGE and daemon.seen == []
    daemon.on("GET", "/containers/web/json", json={"HostConfig": None})
    daemon.on("POST", "/containers/web/update", json=None)
    out = cli("containers", "limit", "web", "--memory", "1g")[1]
    assert out["before"] == {"memory": None, "cpus": None, "pids": None} and out["warnings"] == []


def test_limit_dry_run_sends_no_update(cli, daemon):
    daemon.on("GET", "/containers/web/json", json=info())
    code, out, _ = cli("containers", "limit", "web", "--memory", "64m", "--dry-run")
    assert code == EXIT_OK and daemon.calls("POST") == []
    assert out["planned"][0]["body"] == {"Memory": 64 * MIB, "MemorySwap": 128 * MIB}


# --- exec / cp ------------------------------------------------------------------------------------------

def test_exec_passes_options_and_caps_output(cli, daemon):
    created = daemon.execs("web", [(b"x" * 100, b"warn\n", 3)])
    code, out, _ = cli("containers", "exec", "web", "--workdir", "/app", "--user", "1000", "--env", "A=1",
                       "--max-bytes", "10", "--", "sh", "-c", "work")
    assert code == EXIT_OK and out["exit_code"] == 3
    assert out["truncated"] and out["output"].endswith("xxxxxwarn\n")        # keeps the last 10 bytes
    assert out["output"].count("x") == 5
    assert created[0].body == {"Cmd": ["sh", "-c", "work"], "AttachStdout": True, "AttachStderr": True,
                               "WorkingDir": "/app", "User": "1000", "Env": ["A=1"]}


def test_exec_on_missing_container(cli, daemon):
    code, _, err = cli("containers", "exec", "ghost", "--", "true")
    assert code == EXIT_DOCKER and json.loads(err)["status"] == 404


def test_cp_both_directions(cli, daemon, tmp_path):
    daemon.on("GET", "/containers/web/archive", Reply(body=tar_of({"conf/a.txt": b"hi"}, dirs=("conf",)),
                                                     content_type="application/x-tar"))
    code, out, _ = cli("containers", "cp", "web:/etc/conf", str(tmp_path))
    assert code == EXIT_OK and (tmp_path / "conf" / "a.txt").read_bytes() == b"hi"
    assert daemon.seen[0].query == {"path": "/etc/conf"}
    src = tmp_path / "up.txt"
    src.write_text("payload")
    daemon.on("PUT", "/containers/web/archive", status=200)
    code, out, _ = cli("containers", "cp", str(src), "web:/tmp")
    assert code == EXIT_OK and out == {"copied": [str(src)], "dest": "web:/tmp"}
    put = daemon.seen[-1]
    assert put.query == {"path": "/tmp"} and b"payload" in put.body


def test_cp_empty_archive_and_both_containers(cli, daemon, tmp_path):
    daemon.on("GET", "/containers/web/archive", Reply(body=b"", content_type="application/x-tar"))
    assert cli("containers", "cp", "web:/nothing", str(tmp_path))[1] == {"copied": [], "dest": str(tmp_path)}
    assert cli("containers", "cp", "a:/x", "b:/y")[0] == EXIT_USAGE


# --- wait -----------------------------------------------------------------------------------------------

def test_wait_invalid_regex(cli, daemon):
    code, _, err = cli("containers", "wait", "web", "--log", "(unclosed")
    assert code == EXIT_USAGE and "invalid --log regex" in err and daemon.seen == []


def test_wait_for_port_and_exited(cli, daemon):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    try:
        daemon.on("GET", "/containers/web/json", json=info())
        code, out, _ = cli("containers", "wait", "web", "--port", f"127.0.0.1:{srv.getsockname()[1]}", "--running")
        assert code == EXIT_OK and out["conditions"] == {"running": True, "port": True}
    finally:
        srv.close()
    daemon.on("GET", "/containers/web/json", json=info(Status="exited", Running=False, ExitCode=0))
    assert cli("containers", "wait", "web", "--exited")[1]["conditions"] == {"exited": True}


def test_wait_reports_unhealthy_with_health_output(cli, daemon):
    st = {"Health": {"Status": "unhealthy", "Log": [{"Output": "  curl: (7) refused \n"}]}}
    daemon.on("GET", "/containers/web/json", json=info(**st))
    daemon.on("GET", "/containers/web/logs", Reply(body=frame(2, b"booting\n")))
    code, out, _ = cli("containers", "wait", "web", "--healthy", "--within", "5")
    assert out["ok"] is False and out["reason"] == "healthcheck reports unhealthy"
    assert out["health_output"] == "curl: (7) refused" and "booting" in out["log_tail"]


# --- port_open / compare_specs --------------------------------------------------------------------------

def test_port_open():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert port_open(f"127.0.0.1:{port}") and port_open(str(port))            # host defaults to loopback
        assert port_open(f"elsewhere:{port}", reach=lambda h, p: ("127.0.0.1", p))
    finally:
        srv.close()
    assert not port_open(f"127.0.0.1:{port}", timeout=0.5)
    assert not port_open("127.0.0.1:notaport")


def test_compare_specs_lists_scalars_and_masked_env():
    a = {"image": "x:1", "ports": ["80:80"], "env": ["DB_PASSWORD=a", "SAME=1", "ONLY_A=1"], "cmd": None}
    b = {"image": "x:2", "ports": None, "env": ["DB_PASSWORD=b", "SAME=1", "API_TOKEN="], "cmd": None}
    out = compare_specs(a, b)
    assert out["identical"] is False and out["same"] == ["cmd"]
    assert out["different"]["ports"] == {"only_in_a": ["80:80"], "only_in_b": []}
    assert out["different"]["image"] == {"a": "x:1", "b": "x:2"}
    assert out["different"]["env"] == {"only_in_a": {"ONLY_A": "1"}, "only_in_b": {"API_TOKEN": ""},
                                       "different": {"DB_PASSWORD": {"a": "***", "b": "***"}}}
    assert compare_specs(a, a)["identical"] is True


def test_compare_op(cli, daemon):
    daemon.on("GET", "/containers/a/json", json=info("a"))
    b = info("b")
    b["Config"]["Env"] = ["A=2"]
    daemon.on("GET", "/containers/b/json", json=b)
    code, out, _ = cli("containers", "compare", "a", "b")
    assert code == EXIT_OK and out["different"]["env"]["different"] == {"A": {"a": "1", "b": "2"}}
    assert "image_id" in out["same"]


# --- read helpers: spec / top / patterns / logs caps ----------------------------------------------------

def test_spec_top_patterns(cli, daemon):
    daemon.on("GET", "/containers/web/json", json=info())
    daemon.on("GET", "/containers/web/top", json={"Titles": ["PID", "CMD"], "Processes": [["1", "serve"]]})
    daemon.on("GET", "/containers/web/logs", Reply(body=frame(2, b"ERROR a 1\nERROR a 2\ninfo ok\n")))
    assert cli("containers", "spec", "web")[1]["image"] == "web:1"
    assert cli("containers", "top", "web")[1] == [{"PID": "1", "CMD": "serve"}]
    code, out, _ = cli("containers", "patterns", "web", "--level", "error", "--since", "1h")
    assert code == EXIT_OK and out["top"][0]["count"] == 2
    assert "since" in next(s for s in daemon.seen if s.path.endswith("/logs")).query


def test_top_without_processes(cli, daemon):
    daemon.on("GET", "/containers/web/top", json={"Titles": ["PID"], "Processes": None})
    assert cli("containers", "top", "web")[1] == []


@pytest.mark.parametrize(("argv", "query"), [
    (("--tail", "0", "--stream", "stdout"), {"stdout": "true", "stderr": "false", "tail": "all"}),
    (("--stream", "stderr", "--timestamps"), {"stdout": "false", "stderr": "true", "tail": "200", "timestamps": "true"}),
])
def test_logs_query_and_cap(cli, daemon, argv, query):
    daemon.on("GET", "/containers/web/json", json=info())
    daemon.on("GET", "/containers/web/logs", Reply(body=frame(1, b"a" * 50 + b"\n" + b"z" * 20 + b"\n")))
    code, out, _ = cli("containers", "logs", "web", "--max-bytes", "25", *argv)
    assert code == EXIT_OK and out["truncated"] and out["output"].endswith("z" * 20 + "\n")
    got = next(s for s in daemon.seen if s.path.endswith("/logs")).query
    assert {k: got.get(k) for k in query} == query


# --- secrets / envcheck ---------------------------------------------------------------------------------

def test_secrets_env_history_and_files(cli, daemon):
    i = info()
    i["Config"]["Env"] = ["DB_PASSWORD=supersecret1"]
    daemon.on("GET", "/containers/web/json", json=i)
    daemon.on("GET", r"/images/sha256:[0-9a-f]+/history",
              json=[{"CreatedBy": "/bin/sh -c #(nop) ENV API_TOKEN=abcdef123456", "Size": 0}])
    files = {"app/.env": b"STRIPE=sk_live_" + b"a" * 24 + b"\n", "app/id_rsa": b"-----BEGIN RSA PRIVATE KEY-----\n",
             "app/logo.png": b"\x89PNG\0\0\0binary", "app/big.txt": b"x" * (256 * 1024 + 1)}
    daemon.on("GET", "/containers/web/archive", Reply(body=tar_of(files, dirs=("app",)),
                                                     content_type="application/x-tar"))
    code, out, _ = cli("containers", "secrets", "web", "--path", "/app/")
    assert code == EXIT_OK
    kinds = {(f["kind"], f["where"]) for f in out["findings"]}
    assert ("secret-in-env", "env:DB_PASSWORD") in kinds
    assert ("secret-in-image-history", "layer 0:API_TOKEN") in kinds
    assert {("sensitive-file", "/app/.env"), ("stripe-key", "/app/.env"), ("sensitive-file", "/app/id_rsa"),
            ("private-key", "/app/id_rsa")} <= kinds
    assert out["files_scanned"] == 2 and out["count"] == len(out["findings"])
    assert "supersecret1" not in json.dumps(out)


def test_secrets_image_gone(cli, daemon):
    daemon.on("GET", "/containers/web/json", json=info())
    code, out, _ = cli("containers", "secrets", "web")
    assert code == EXIT_OK and out == {"container": "web", "count": 0, "files_scanned": 0, "findings": []}


def test_envcheck_scans_sources_entrypoint_and_inline_command(cli, daemon):
    i = info()
    i["Config"].update({"WorkingDir": "/work", "Entrypoint": ["/start.sh"],
                        "Cmd": ["sh", "-c", "exec app --port ${PORT:?}"], "Env": ["DATABASE_URL=x", "PORT=1"]})
    daemon.on("GET", "/containers/web/json", json=i)

    def archive(seen):
        path = seen.query["path"]
        if path == "/work":
            return Reply(body=tar_of({"work/main.py": b"import os\nos.environ['DATABSE_URL']\nos.getenv('REDIS_HOST')\n",
                                      "work/blob.bin": b"\0\0"}, dirs=("work",)), content_type="application/x-tar")
        if path == "/start.sh":
            return Reply(body=tar_of({"start.sh": b"#!/bin/sh\n: \"${SECRET_KEY:?}\"\n"}),
                         content_type="application/x-tar")
        return Reply(404, json={"message": "no such file"})
    daemon.on("GET", "/containers/web/archive", archive)
    code, out, err = cli("containers", "envcheck", "web")
    assert code == EXIT_UNMET and out["ok"] is False and out["files_scanned"] == 3                  # main.py, start.sh, <command>
    text = json.dumps(out)
    assert "REDIS_HOST" in text and "SECRET_KEY" in text and "DATABSE_URL" in text


# --- timeline / debug -----------------------------------------------------------------------------------

def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1e9):09d}Z"


def test_timeline_merges_filters_and_fingerprints(cli, daemon):
    t = 1_800_000_000.5
    for name, lines in (("api", [(t + 1, "ERROR db down"), (t + 3, "INFO retry")]),
                        ("db", [(t + 2, "FATAL shutting down")])):
        daemon.on("GET", f"/containers/{name}/json", json=info(name))
        body = f"{_ts(t)} 10%\r20%\n" + "".join(f"{_ts(w)} {m}\n" for w, m in lines)   # bare \r: no ts after it
        daemon.on("GET", f"/containers/{name}/logs", Reply(body=frame(1, body.encode())))
    code, out, err = cli("containers", "timeline", "api", "db", "--since", "1h")
    assert code == EXIT_OK and out["lines"] == 5
    rows = out["output"].splitlines()
    assert [r.split(" | ")[1] for r in rows] == ["10%", "10%", "ERROR db down", "FATAL shutting down", "INFO retry"]
    assert rows[2].split()[1] == "api" and rows[2].split()[0].endswith(".500")
    out = cli("containers", "timeline", "api", "db", "--grep", "down")[1]
    assert out["lines"] == 2
    out = cli("containers", "timeline", "api", "db", "--patterns")[1]
    assert out["containers"] == ["api", "db"] and "top" in out and "output" not in out


def test_timeline_and_debug_need_arguments(cli, daemon):
    assert cli("containers", "timeline")[0] == EXIT_USAGE
    assert cli("containers", "debug", "web")[0] == EXIT_USAGE
    assert daemon.seen == []


def test_debug_sidecar_is_always_removed(cli, daemon):
    daemon.on("GET", "/containers/web/json", json=info())
    daemon.on("POST", "/containers/create", status=201, json={"Id": "s" * 64})
    daemon.on("POST", f"/containers/{'s' * 64}/start", status=500, json={"message": "cannot join namespace"})
    daemon.on("DELETE", f"/containers/{'s' * 64}", status=204)
    code, _, err = cli("containers", "debug", "web", "--", "ss", "-tlnp")
    assert code == EXIT_DOCKER and "cannot join namespace" in err
    assert daemon.calls("DELETE") == [("DELETE", f"/containers/{'s' * 64}")]
    body = next(s for s in daemon.seen if s.path == "/containers/create").body
    assert body["HostConfig"]["NetworkMode"] == "container:" + "web" * 4 and body["Cmd"] == ["ss", "-tlnp"]


def test_create_from_without_pull_raises(client, daemon):
    from aisb.api.containers import Containers
    from aisb.models import RunSpec
    with pytest.raises(NotFound):
        Containers(client.transport).create_from(RunSpec(image="nope:1"), pull=False)
    assert daemon.calls("POST") == [("POST", "/containers/create")]


def test_doctor_skips_image_lookup_for_digest_refs(client, daemon):
    i = info()
    i["Config"]["Image"] = "sha256:" + "ab" * 32
    daemon.on("GET", "/containers/web/json", json=i)
    daemon.on("GET", "/containers/web/logs", Reply(body=b""))
    daemon.on("GET", "/containers/json", json=[])
    daemon.on("GET", "/containers/web/stats", json={"read": "0001-01-01T00:00:00Z"})
    rep = client.containers.doctor("web")
    assert rep["container"] == "web"
    assert not any(s.path.startswith("/images/") for s in daemon.seen)
