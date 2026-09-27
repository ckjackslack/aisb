"""pyinfra integration against the fake daemon: operations run inside pyinfra's own host context, facts are
gathered through the @aisb connector (exec in a container), and connector edge cases."""

import io
import json
import logging
import tarfile

import pytest

pytest.importorskip("pyinfra")

from pyinfra.api import Config, Inventory, OperationError, State, StringCommand  # noqa: E402
from pyinfra.api.connect import connect_all  # noqa: E402
from pyinfra.api.exceptions import InventoryError  # noqa: E402
from pyinfra.context import ctx_host, ctx_state  # noqa: E402

from aisb import stack as stk  # noqa: E402
from aisb.contrib.pyinfra import PYZ, facts  # noqa: E402
from aisb.contrib.pyinfra import command as cmd  # noqa: E402
from aisb.contrib.pyinfra import operations as ops  # noqa: E402

from conftest import Reply, tar_of  # noqa: E402


@pytest.fixture
def box(daemon, host, monkeypatch):
    """A connected @aisb/web host; `answers` queues the stdout of each fact command executed in the container."""
    monkeypatch.setenv("DOCKER_HOST", host)
    daemon.on("GET", "/containers/web/json", json={"State": {"Running": True}})
    answers: list[tuple[bytes, bytes, int]] = []
    created = daemon.execs("web", answers)
    inv = Inventory((["@aisb/web"], {}))
    state = State(inv, Config())
    connect_all(state)
    h = inv.get_host("@aisb/web")

    def run(op, *args, **kwargs) -> list:
        with ctx_state.use(state), ctx_host.use(h):
            return list(op._inner(*args, **kwargs))

    def answer(*outs: object) -> None:
        answers.extend((json.dumps(o).encode() if not isinstance(o, bytes) else o, b"", 0) for o in outs)
    return run, answer, created, h


def text(commands: list) -> list[str]:
    return [c if isinstance(c, str) else repr(c) for c in commands]


# --- limits / ready / call -----------------------------------------------------------------------------

@pytest.mark.parametrize(("live", "want", "expected"), [
    ({"Memory": 0, "NanoCpus": 0}, {"memory": "256m", "cpus": 0.5}, "--memory 256m --cpus 0.5"),
    ({"Memory": 268435456, "NanoCpus": 500000000}, {"memory": "256m", "cpus": 0.5}, None),
    ({"PidsLimit": 100}, {"pids": 100}, None),
    ({"PidsLimit": 0}, {"pids": -1}, None),                          # both mean "unlimited"
    ({"PidsLimit": None}, {"pids": 50}, "--pids 50"),
    ({"Memory": 268435456}, {"memory": "512m"}, "--memory 512m"),
])
def test_limits_only_changes_what_differs(box, live, want, expected):
    run, answer, created, _ = box
    answer({"HostConfig": live})
    out = run(ops.limits, container="web", **want)
    assert "containers inspect web --fields HostConfig" in created[0].body["Cmd"][2]
    if expected is None:
        assert out == []
    else:
        (line,) = out
        assert line.startswith(f"python3 {PYZ} containers limit web ") and expected in line


def test_limits_on_a_host_without_the_container(box):
    run, answer, _, _ = box
    answer(None)
    assert run(ops.limits, container="ghost", memory="1g") == [f"python3 {PYZ} containers limit ghost --memory 1g --json"]


def test_ready_and_call(box):
    run, _, created, _ = box
    assert run(ops.ready, container="db", within=30, pyz="/opt/aisb.pyz", python="python3.12") == \
        ["python3.12 /opt/aisb.pyz svc ready db --within 30 --json"]
    assert run(ops.call, "containers", "exec", "web", cmd=["nginx", "-s", "reload"]) == \
        [f"python3 {PYZ} containers exec web --json -- nginx -s reload"]
    assert run(ops.call, "containers", "restart", "web", dry_run=True) == \
        [f"python3 {PYZ} containers restart web --dry-run --json"]
    assert run(ops.call, "containers", "rm", "web", confirm=True, force=True) == \
        [f"python3 {PYZ} containers rm web --force --yes --json"]
    assert run(ops.call, "containers", "rm", "web", dry_run=True) == [f"python3 {PYZ} containers rm web --dry-run --json"]
    assert run(ops.call, "containers", "stop", "web", confirm=True) == [f"python3 {PYZ} containers stop web --json"]
    assert created == []                                               # no facts needed: nothing ran in the box


@pytest.mark.parametrize(("args", "kwargs", "error"), [
    (("containers", "rm", "web"), {}, "destroy tier: pass confirm=True"),
    (("containers", "list"), {"dry_run": True}, "read tier; there is nothing to dry-run"),
    (("containers", "nuke"), {}, "unknown aisb op containers.nuke"),
])
def test_call_refuses(box, args, kwargs, error):
    run, _, _, _ = box
    with pytest.raises((OperationError, ValueError), match=error):
        run(ops.call, *args, **kwargs)


# --- stack / install --------------------------------------------------------------------------------------

@pytest.fixture
def shop(tmp_path) -> tuple[str, stk.Stack]:
    f = tmp_path / "shop.json"
    f.write_text(json.dumps({"name": "shop", "services": {"db": {"image": "postgres:16"}, "api": {"image": "api:1"}}}))
    return str(f), stk.load(f)


def _row(s: stk.Stack, svc: str, *, state: str = "running", digest: str | None = None) -> dict:
    return {"State": state, "Labels": {stk.STACK_KEY: s.name, stk.SERVICE_KEY: svc,
                                       stk.HASH_KEY: digest or s.services[svc].digest}}


def test_stack_absent(box, shop):
    run, answer, _, _ = box
    src, s = shop
    answer([_row(s, "db")])
    assert run(ops.stack, src=src, present=False, volumes=True) == \
        [f"python3 {PYZ} stack down shop --volumes --yes --json"]


def test_stack_absent_when_nothing_is_there(box, shop):
    run, answer, _, _ = box
    answer(b"null")
    assert run(ops.stack, src=shop[0], present=False) == []


def test_stack_drift_is_only_reported_without_recreate(box, shop, caplog):
    run, answer, _, _ = box
    src, s = shop
    answer([_row(s, "db", digest="old"), _row(s, "api")], *[b""] * 10)
    with caplog.at_level(logging.WARNING):
        out = text(run(ops.stack, src=src))
    assert not any("stack down" in c or "stack up" in c for c in out)
    assert any("FileUploadCommand" in c and "/etc/aisb/stacks/shop.json" in c for c in out)
    assert "config drift in db" in caplog.text


def test_stack_recreates_drift_and_starts_missing(box, shop):
    run, answer, _, _ = box
    src, s = shop
    answer([_row(s, "db", digest="old")], *[b""] * 10)
    out = text(run(ops.stack, src=src, recreate_drifted=True, within=5, remote_dir="/srv/stacks/"))
    assert f"python3 {PYZ} stack down shop --service db --yes --json" in out
    assert out[-1] == f"python3 {PYZ} stack up /srv/stacks/shop.json --within 5 --json"


def test_stack_converged_is_a_noop(box, shop):
    run, answer, _, _ = box
    src, s = shop
    answer([_row(s, "db"), _row(s, "api")], *[b""] * 10)
    out = text(run(ops.stack, src=src))
    assert not any("stack " in c for c in out if not c.startswith(("StringCommand", "FileUpload")))


def test_install_uploads_the_bundle(box, monkeypatch):
    run, answer, _, _ = box
    monkeypatch.setattr(ops, "_BUNDLE", None)
    answer(*[b""] * 10)
    out = text(run(ops.install, path="/opt/x/aisb.pyz"))
    assert any("FileUploadCommand" in c and "/opt/x/aisb.pyz" in c for c in out)
    assert ops._BUNDLE is not None and ops._bundle() is ops._BUNDLE          # built once, reused


# --- facts ------------------------------------------------------------------------------------------------

def test_fact_commands():
    assert facts.AisbDoctor().requires_command(python="py3") == "py3"
    assert "svc list --json" in facts.AisbServices().command()
    line = facts.AisbContainer().command("web", fields="State")
    assert "containers inspect web --fields State" in line and line.endswith("2>/dev/null || echo null")
    assert facts.AisbDoctor().command(tail=5).endswith("|| [ $? -eq 4 ]") and "--tail 5" in facts.AisbDoctor().command(tail=5)
    assert cmd.shell(["system", "ping"]) == f"python3 {PYZ} system ping"


# --- connector edge cases ----------------------------------------------------------------------------------

def test_connector_needs_a_target_and_a_non_empty_stack(daemon, host, monkeypatch):
    from aisb.contrib.pyinfra.connector import AisbConnector
    monkeypatch.setenv("DOCKER_HOST", host)
    with pytest.raises(InventoryError, match="needs a target"):
        list(AisbConnector.make_names_data(""))
    daemon.on("GET", "/containers/json", json=[])
    with pytest.raises(InventoryError, match="no running containers in aisb stack 'shop'"):
        list(AisbConnector.make_names_data("stack:shop"))


def test_connector_reports_daemon_errors_on_connect(daemon, host, monkeypatch):
    from pyinfra.api.exceptions import PyinfraError
    monkeypatch.setenv("DOCKER_HOST", host)
    state = State(Inventory((["@aisb/ghost"], {})), Config())             # inspect -> 404
    with pytest.raises(PyinfraError, match="No hosts remaining"):
        connect_all(state)


def test_connector_stdin_staging_printing_and_exec_errors(box, daemon):
    _, answer, created, h = box
    daemon.on("PUT", "/containers/web/archive", status=200)
    answer(b"got it\n", b"")
    ok, out = h.run_shell_command(StringCommand("cat"), _stdin=["line1", "line2\n"], print_input=True,
                                  print_output=True)
    assert ok and out.stdout_lines == ["got it"]
    shell_line = created[0].body["Cmd"][2]
    assert "< /tmp/.aisb-stdin-" in shell_line and "rm -f /tmp/.aisb-stdin-" in shell_line
    put = next(s for s in daemon.seen if s.method == "PUT")
    with tarfile.open(fileobj=io.BytesIO(put.body)) as tar:
        (member,) = tar.getmembers()
        assert tar.extractfile(member).read() == b"line1\nline2\n"  # type: ignore[union-attr]
    ok, _ = h.run_shell_command(StringCommand("true"), _stdin="single")
    assert ok
    daemon.on("POST", "/containers/web/exec", status=409, json={"message": "container is paused"})
    ok, out = h.run_shell_command(StringCommand("true"))
    assert not ok and "paused" in out.stderr


def test_connector_file_transfer_printing_and_missing_file(box, daemon):
    _, _, _, h = box
    daemon.on("PUT", "/containers/web/archive", status=200)
    assert h.put_file(io.StringIO("text"), "/app.conf", print_output=True)
    put = next(s for s in daemon.seen if s.method == "PUT")
    assert put.query["path"] == "/"
    daemon.on("GET", "/containers/web/archive", Reply(body=tar_of({"a": b"1"}), content_type="application/x-tar"))
    buf = io.BytesIO()
    assert h.get_file("/a", buf, print_output=True) and buf.getvalue() == b"1"
    daemon.on("GET", "/containers/web/archive", status=404, json={"message": "no such file"})
    with pytest.raises(OSError, match="does not exist"):
        h.get_file("/nope", io.BytesIO())

