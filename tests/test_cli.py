import json
import subprocess
import sys
from pathlib import Path

import pytest

from aisb.cli import EXIT_CONFIRM, EXIT_DOCKER, EXIT_OK, EXIT_USAGE, main
from conftest import Reply, frame

SRC = Path(__file__).parents[1] / "src"
CID = "f" * 64


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str) -> tuple[int, object, str]:
        code = main([*argv, "--host", host, "--json"] if "--" not in argv else
                    [*argv[:argv.index("--")], "--host", host, "--json", *argv[argv.index("--"):]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def test_list_json(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": CID, "Names": ["/web"], "Image": "nginx", "State": "running"}])
    code, out, _ = cli("containers", "list", "--all", "--managed", "--label", "team=x")
    assert code == EXIT_OK and out[0]["name"] == "web"
    assert daemon.seen[0].query["all"] == "true"
    assert daemon.seen[0].filters() == {"label": ["team=x", "aisb.managed=true"]}


def test_logs_demux_and_truncation(cli, daemon):
    daemon.on("GET", "/containers/web/json", json={"Config": {"Tty": False}})
    daemon.on("GET", "/containers/web/logs", Reply(body=frame(1, b"a" * 50) + frame(2, b"END\n"),
                                                   content_type="application/vnd.docker.multiplexed-stream"))
    code, out, _ = cli("containers", "logs", "web", "--tail", "5", "--since", "1700000000", "--max-bytes", "10")
    assert code == EXIT_OK and out["truncated"] and out["output"].endswith("aaaaaaEND\n")
    q = daemon.seen[-1].query
    assert (q["tail"], q["since"], q["stdout"], q["stderr"]) == ("5", "1700000000", "true", "true")


def test_exec_reports_exit_code(cli, daemon):
    daemon.on("POST", "/containers/web/exec", json={"Id": "e1"})
    daemon.on("POST", "/exec/e1/start", Reply(body=frame(1, b"hi\n")))
    daemon.on("GET", "/exec/e1/json", json={"ExitCode": 2})
    code, out, _ = cli("containers", "exec", "web", "--user", "app", "--", "sh", "-c", "echo hi; exit 2")
    assert (code, out) == (EXIT_OK, {"exit_code": 2, "output": "hi\n", "truncated": False})
    assert daemon.seen[0].body == {"Cmd": ["sh", "-c", "echo hi; exit 2"], "AttachStdout": True,
                                   "AttachStderr": True, "User": "app"}


def test_run_attached_waits_collects_and_removes(cli, daemon):
    daemon.on("POST", "/containers/create", status=201, json={"Id": CID})
    daemon.on("POST", f"/containers/{CID}/start", status=204)
    daemon.on("POST", f"/containers/{CID}/wait", json={"StatusCode": 3})
    daemon.on("GET", f"/containers/{CID}/json", json={"Config": {"Tty": False}})
    daemon.on("GET", f"/containers/{CID}/logs", Reply(body=frame(1, b"out\n")))
    daemon.on("DELETE", f"/containers/{CID}", status=204)
    code, out, _ = cli("containers", "run", "alpine", "--rm", "--port", "8080:80", "--", "sh", "-c", "exit 3")
    assert code == EXIT_OK and out == {"id": CID[:12], "exit_code": 3, "output": "out\n", "truncated": False}
    create = daemon.seen[0]
    assert "AutoRemove" not in create.body["HostConfig"]  # attached --rm is done by aisb after logs are read
    assert create.body["Cmd"] == ["sh", "-c", "exit 3"]
    assert daemon.calls()[-1] == ("DELETE", f"/containers/{CID}")


def test_run_spec_file_with_flag_override(cli, daemon, tmp_path):
    spec = tmp_path / "s.json"
    spec.write_text(json.dumps({"image": "ignored", "name": "svc", "env": {"A": "1"}, "restart": "always"}))
    daemon.on("POST", "/containers/create", status=201, json={"Id": CID})
    daemon.on("POST", f"/containers/{CID}/start", status=204)
    code, out, _ = cli("containers", "run", "nginx:1", "--spec", str(spec), "--detach", "--env", "B=2")
    body = daemon.seen[0]
    assert code == EXIT_OK and out["name"] == "svc"
    assert (body.query["name"], body.body["Image"], body.body["Env"]) == ("svc", "nginx:1", ["B=2"])
    assert body.body["HostConfig"]["RestartPolicy"]["Name"] == "always"


@pytest.mark.parametrize(("extra", "code", "sent"), [
    ((), EXIT_CONFIRM, False),
    (("--dry-run",), EXIT_OK, False),
    (("--yes",), EXIT_OK, True),
])
def test_destroy_gating(cli, daemon, extra, code, sent):
    daemon.on("DELETE", "/images/nginx:1", json=[{"Untagged": "nginx:1"}])
    rc, out, _ = cli("images", "rmi", "nginx:1", *extra)
    assert rc == code
    assert (daemon.calls() == [("DELETE", "/images/nginx:1")]) is sent
    if code == EXIT_CONFIRM:
        assert out["status"] == "confirmation_required" and "--yes" in out["hint"]


def test_stop_not_modified_is_success(cli, daemon):
    daemon.on("POST", "/containers/web/stop", status=304)
    assert cli("containers", "stop", "web", "--grace", "2")[:2] == (EXIT_OK, {"ref": "web", "changed": False})
    assert daemon.seen[0].query == {"t": "2"}


def test_docker_error_goes_to_stderr(cli, daemon):
    code, out, err = cli("containers", "inspect", "ghost")
    assert (code, out) == (EXIT_DOCKER, None)
    assert json.loads(err) | {"message": ""} == {"error": "NotFound", "status": 404, "message": ""}


@pytest.mark.parametrize("argv", [
    ("containers", "exec", "web"),                      # missing command
    ("containers", "cp", "a", "b"),                     # neither side is CONTAINER:PATH
    ("containers", "run", "alpine", "--port", "x:y"),   # invalid port
    ("system", "events", "--filter", "novalue"),
])
def test_usage_errors(cli, daemon, argv):
    daemon.on("POST", "/containers/create", status=201, json={"Id": CID})
    assert cli(*argv)[0] == EXIT_USAGE


def test_trailing_command_rejected_for_ops_without_one(host):
    with pytest.raises(SystemExit) as info:
        main(["containers", "list", "--host", host, "--", "x"])
    assert info.value.code == 2


def test_events_are_bounded(cli, daemon):
    events = b"".join(json.dumps({"Type": "container", "Action": a, "time": 1,
                                  "Actor": {"ID": CID, "Attributes": {"name": "web", "exitCode": "1", "x": "y"}}}).encode() + b"\n"
                      for a in ("die", "start", "die"))
    daemon.on("GET", "/events", chunks=[events[:30], events[30:]])
    code, out, _ = cli("system", "events", "--since", "5m", "--filter", "event=die", "--limit", "2")
    assert code == EXIT_OK and [e["action"] for e in out] == ["die", "start"]
    assert out[0] == {"time": 1, "type": "container", "action": "die", "id": CID[:12], "name": "web", "exitCode": "1"}
    assert daemon.seen[0].filters() == {"event": ["die"]}


def test_human_output_renders_table(host, daemon, capsys):
    daemon.on("GET", "/containers/json", json=[{"Id": CID, "Names": ["/web"], "Image": "nginx", "State": "up",
                                                "Ports": [{"PrivatePort": 80, "Type": "tcp"}]}])
    assert main(["containers", "list", "--host", host, "--no-json"]) == EXIT_OK
    header, row = capsys.readouterr().out.splitlines()
    assert header.split() == ["ID", "NAME", "IMAGE", "STATE", "STATUS", "PORTS", "CREATED"]
    assert row.split()[:3] == [CID[:12], "web", "nginx"]


def test_runtime_imports_are_stdlib_only():
    code = (f"import sys; sys.path.insert(0, {str(SRC)!r}); import aisb, aisb.cli; "
            "print('\\n'.join(sorted({m.split('.')[0] for m in sys.modules})))")
    mods = set(subprocess.run([sys.executable, "-S", "-E", "-c", code], capture_output=True, text=True, check=True).stdout.split())
    assert mods - set(sys.stdlib_module_names) - {"aisb", "__main__"} == set()
