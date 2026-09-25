"""Live daemon round-trips; skipped when no Docker endpoint is reachable."""

import json
import uuid
from collections.abc import Iterator

import pytest

from aisb import Docker, DockerError, NotFound, get_op, invoke
from aisb.errors import BadRequest

IMAGE = "alpine:3.20"


def _live() -> Docker | None:
    try:
        d = Docker(timeout=120)
        d.system.ping()
        return d
    except DockerError:
        return None


pytestmark = [pytest.mark.docker, pytest.mark.skipif(_live() is None, reason="no reachable Docker daemon")]


@pytest.fixture
def docker() -> Docker:
    return _live()  # type: ignore[return-value]


@pytest.fixture
def name(docker: Docker) -> Iterator[str]:
    n = f"aisb-test-{uuid.uuid4().hex[:8]}"
    yield n
    try:
        docker.containers.rm(n, force=True, volumes=True)
    except NotFound:
        pass


def test_run_attached_roundtrip(docker):
    out = docker.containers.run(IMAGE, "sh", "-c", "echo out; echo err >&2; exit 4", rm=True)
    assert out["exit_code"] == 4
    assert sorted(out["output"].split()) == ["err", "out"]


def test_detached_lifecycle(docker, name, tmp_path):
    docker.containers.run(IMAGE, "sh", "-c", "echo ready; sleep 60", name=name, detach=True, env=["X=42"])
    assert any(c.name == name for c in docker.containers.ls(managed=True))
    assert docker.containers.inspect(name, fields="State.Running")["State.Running"] is True
    assert docker.containers.exec_(name, "sh", "-c", "echo $X")["output"] == "42\n"
    assert "ready" in docker.containers.logs(name)["output"]
    assert docker.containers.stats(name)["pids"] >= 1

    (tmp_path / "f.txt").write_text("payload")
    docker.containers.cp(str(tmp_path / "f.txt"), f"{name}:/tmp")
    docker.containers.cp(f"{name}:/tmp/f.txt", str(tmp_path / "back"))
    assert (tmp_path / "back" / "f.txt").read_text() == "payload"
    assert {"path": "/tmp/f.txt", "kind": "added"} in docker.containers.diff(name)

    assert docker.containers.stop(name, grace=1)["changed"] is True
    assert docker.containers.stop(name, grace=1)["changed"] is False


def test_destroy_requires_confirmation(docker, name):
    docker.containers.run(IMAGE, "true", name=name)
    preview = invoke(docker, get_op("containers.rm"), {"ref": name})
    assert preview.status == "confirm"
    assert docker.containers.inspect(name, fields="Name")["Name"] == f"/{name}"
    invoke(docker, get_op("containers.rm"), {"ref": name}, confirm=True)
    with pytest.raises(NotFound):
        docker.containers.inspect(name)


def test_doctor_explains_command_not_found(docker, name):
    with pytest.raises(BadRequest, match="executable file not found"):  # the daemon rejects the start itself
        docker.containers.run(IMAGE, "no-such-binary", name=name, detach=True)
    report = docker.containers.doctor(name, stats=False)
    assert report["verdict"] == "failing"
    found = {f["code"] for f in report["findings"]}
    assert {"start-error", "command-not-found"} <= found


def test_wait_fails_fast_and_matches_logs(docker, name):
    docker.containers.run(IMAGE, "sh", "-c", "echo 'server ready'; sleep 1; exit 5", name=name, detach=True)
    ok = docker.containers.wait_for(name, log="server ready", within=30, interval=0.2)
    assert ok["ok"] and ok["matched"] == "server ready"
    dead = docker.containers.wait_for(name, log="never printed", within=60, interval=0.2)
    assert not dead["ok"] and dead["exit_code"] == 5 and dead["elapsed"] < 30


def test_snapshot_changes_sees_new_container(docker, name, tmp_path):
    path = tmp_path / "before.json"
    path.write_text(json.dumps(docker.system.snapshot()))
    docker.containers.run(IMAGE, "true", name=name)
    diff = docker.system.changes(str(path))
    assert name in diff["containers"]["added"]
    assert f"aisb containers rm {name} --force --dry-run" in diff["cleanup"]
