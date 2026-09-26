"""aisb bundle (stdlib) and the pyinfra integration (skipped when pyinfra isn't installed)."""

import io
import json
import subprocess
import sys
import tarfile
import zipfile

import pytest

from aisb import bundle
from conftest import Reply, tar_of


# --- bundle ----------------------------------------------------------------------------------------

def test_bundle_is_deterministic_and_stdlib_only(tmp_path):
    a, b = bundle.build(), bundle.build()
    assert a == b and a.startswith(bundle.SHEBANG)
    names = zipfile.ZipFile(io.BytesIO(a[len(bundle.SHEBANG):])).namelist()
    assert "__main__.py" in names and "aisb/cli.py" in names
    assert not any(n.startswith("aisb/contrib/") or "__pycache__" in n for n in names)


def test_bundle_runs_isolated(tmp_path):
    info = bundle.write(tmp_path / "aisb.pyz")
    # -I: no site-packages, no PYTHONPATH, no cwd on sys.path -> only the bundle and the stdlib
    out = subprocess.run([sys.executable, "-I", info["bundle"], "docs"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "containers" in out.stdout


pyinfra = pytest.importorskip("pyinfra")

from pyinfra.api import Config, Inventory, State, StringCommand  # noqa: E402
from pyinfra.api.connect import connect_all  # noqa: E402
from pyinfra.api.exceptions import PyinfraError  # noqa: E402

from aisb import stack as stk  # noqa: E402
from aisb.contrib.pyinfra import command as cmd  # noqa: E402
from aisb.contrib.pyinfra import facts  # noqa: E402
from aisb.contrib.pyinfra.operations import _plan  # noqa: E402


# --- command building ------------------------------------------------------------------------------

@pytest.mark.parametrize(("options", "expected"), [
    ({"within": 60}, ["--within", "60"]),
    ({"no_wait": True, "managed": False, "x": None}, ["--no-wait"]),
    ({"env": ["A=1", "B=2"]}, ["--env", "A=1", "--env", "B=2"]),
    ({"label": {"k": "v"}}, ["--label", "k=v"]),
])
def test_flags(options, expected):
    assert cmd.flags(options) == expected


def test_argv_validates_ops_and_confirm():
    assert cmd.argv("containers", "rm", ["web"], {"force": True}, confirm=True) == \
        ["containers", "rm", "web", "--force", "--yes", "--json"]
    assert cmd.argv("containers", "exec", ["web"], cmd=["ls", "/"])[-3:] == ["--", "ls", "/"]
    with pytest.raises(ValueError, match="unknown aisb op"):
        cmd.argv("containers", "nuke")
    with pytest.raises(ValueError, match="confirm only applies"):
        cmd.argv("containers", "stop", ["web"], confirm=True)


def test_shell_quotes_and_tolerates_missing_bundle():
    line = cmd.shell(cmd.argv("db", "query", ["pg", "select 'x'; drop"]), pyz="/opt/a b.pyz", tolerate_missing=True)
    assert line.startswith("if [ -f '/opt/a b.pyz' ]") and "'select '\"'\"'x'\"'\"'; drop'" in line
    assert line.endswith("else echo null; fi")


# --- facts -----------------------------------------------------------------------------------------

def test_generic_fact_is_read_only():
    assert "containers inspect web" in facts.Aisb().command("containers", "inspect", args=["web"])
    with pytest.raises(ValueError, match="facts are read-only"):
        facts.Aisb().command("containers", "rm", args=["web"])


@pytest.mark.parametrize(("lines", "value"), [(['{"a": 1}'], {"a": 1}), (["null"], None), ([], None)])
def test_fact_process(lines, value):
    assert facts.AisbDoctor().process(lines) == value


def test_stack_fact_filters_by_label():
    assert "--label aisb.stack=shop" in facts.AisbStack().command("shop")


# --- stack convergence plan ------------------------------------------------------------------------

@pytest.fixture
def shop(tmp_path) -> stk.Stack:
    f = tmp_path / "shop.json"
    f.write_text(json.dumps({"name": "shop", "services": {
        "db": {"image": "postgres:16"}, "cache": {"image": "redis:7"},
        "api": {"image": "api:1", "depends_on": ["db", "cache"]}, "worker": {"image": "api:1"}}}))
    return stk.load(f)


def _row(s: stk.Stack, svc: str, *, state="running", digest: str | None = None) -> dict:
    return {"state": state, "labels": {stk.SERVICE_KEY: svc, stk.HASH_KEY: digest or s.services[svc].digest}}


def test_plan_classifies_services(shop):
    rows = [_row(shop, "db"), _row(shop, "cache", state="exited"), _row(shop, "api", digest="old")]
    assert _plan(shop, rows) == {"missing": ["worker"], "stopped": ["cache"], "drift": ["api"], "ok": ["db"]}


def test_plan_without_bundle_means_everything_missing(shop):
    assert _plan(shop, None)["missing"] == list(shop.order)


# --- @aisb connector through pyinfra's own API, against the fake daemon ----------------------------------

@pytest.fixture
def pyinfra_host(daemon, host, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", host)
    daemon.on("GET", "/containers/web/json", json={"State": {"Running": True}})
    inv = Inventory((["@aisb/web"], {}))
    state = State(inv, Config())
    connect_all(state)
    return inv.get_host("@aisb/web")


def test_connector_runs_commands_via_exec(pyinfra_host, daemon):
    created = daemon.execs("web", [(b"hi\n", b"warn\n", 0), (b"", b"boom\n", 3)])
    ok, out = pyinfra_host.run_shell_command(StringCommand("echo", "hi"))
    assert ok and out.stdout_lines == ["hi"] and out.stderr_lines == ["warn"]
    assert created[0].body["Cmd"][:2] == ["sh", "-c"] and "echo hi" in created[0].body["Cmd"][2]
    ok, out = pyinfra_host.run_shell_command(StringCommand("false"), _success_exit_codes=[0, 3])
    assert ok and out.stderr == "boom"


def test_connector_files_via_archive_api(pyinfra_host, daemon):
    daemon.on("PUT", "/containers/web/archive", status=200)
    daemon.on("GET", "/containers/web/archive", Reply(body=tar_of({"app.conf": b"x=1\n"}),
                                                      content_type="application/x-tar"))
    assert pyinfra_host.put_file(io.BytesIO(b"x=1\n"), "/etc/app/app.conf")
    put = next(s for s in daemon.seen if s.method == "PUT")
    assert put.query["path"] == "/etc/app"
    with tarfile.open(fileobj=io.BytesIO(put.body)) as tar:
        assert tar.extractfile("app.conf").read() == b"x=1\n"  # type: ignore[union-attr]
    buf = io.BytesIO()
    assert pyinfra_host.get_file("/etc/app/app.conf", buf) and buf.getvalue() == b"x=1\n"


def test_connector_refuses_stopped_container(daemon, host, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", host)
    daemon.on("GET", "/containers/web/json", json={"State": {"Running": False}})
    state = State(Inventory((["@aisb/web"], {})), Config())
    with pytest.raises(PyinfraError, match="No hosts remaining"):
        connect_all(state)
    assert {h.name for h in state.failed_hosts} == {"@aisb/web"}


def test_stack_target_expands_to_containers(daemon, host, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", host)
    daemon.on("GET", "/containers/json", json=[{"Names": ["/shop-db"]}, {"Names": ["/shop-api"]}])
    inv = Inventory((["@aisb/stack:shop"], {}))
    assert sorted(h.name for h in inv) == ["@aisb/shop-api", "@aisb/shop-db"]
    assert json.loads(next(s for s in daemon.seen if s.path == "/containers/json").query["filters"]) == \
        {"label": ["aisb.stack=shop"]}


def test_entry_point_registered():
    from importlib.metadata import entry_points
    assert any(e.name == "aisb" for e in entry_points(group="pyinfra.connectors"))
