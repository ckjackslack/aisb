import inspect
from pathlib import Path

import pytest

from aisb import Tier, get_op, invoke, registry
from aisb.ops import render_markdown, usage
from conftest import Reply

DOCS = Path(__file__).parents[1] / ".claude/skills/docker/references/commands.md"


@pytest.mark.parametrize(("qualname", "tier"), [
    ("containers.list", Tier.READ), ("containers.logs", Tier.READ), ("containers.run", Tier.MUTATE),
    ("containers.exec", Tier.MUTATE), ("containers.rm", Tier.DESTROY), ("images.rmi", Tier.DESTROY),
    ("images.build", Tier.MUTATE), ("volumes.rm", Tier.DESTROY), ("system.prune", Tier.DESTROY),
    ("system.events", Tier.READ),
])
def test_tiers(qualname, tier):
    assert get_op(qualname).tier is tier


def test_every_op_is_documented_and_well_formed():
    for ops in registry().values():
        for o in ops.values():
            assert o.summary, o.qualname
            kinds = [p.kind for p in o.params]
            assert kinds == sorted(kinds), f"{o.qualname}: positionals must precede keyword-only params"
            assert inspect.Parameter.VAR_KEYWORD not in kinds


def test_op_params_do_not_shadow_cli_globals():
    reserved = {"host", "timeout", "json", "dry_run", "yes", "resource", "op", "_op"}
    clashes = {(o.qualname, p.name) for ops in registry().values() for o in ops.values() for p in o.params
               if p.name in reserved}
    assert not clashes


def test_destructive_ops_are_the_only_rm_like_ones():
    destroy = {o.qualname for ops in registry().values() for o in ops.values() if o.tier is Tier.DESTROY}
    assert destroy == {"containers.rm", "images.rmi", "networks.rm", "volumes.rm", "system.prune", "db.restore"}


def test_json_schema_for_run():
    s = get_op("containers.run").json_schema()
    assert s["required"] == ["image"]
    assert s["properties"]["cmd"] == {"type": "array", "items": {"type": "string"},
                                      "description": "command and arguments (put them after --)"}
    assert s["properties"]["label"]["type"] == "object"
    assert s["properties"]["pull"]["default"] is True
    assert get_op("containers.logs").json_schema()["properties"]["stream"]["enum"] == ["all", "stdout", "stderr"]


def test_usage_line():
    assert usage(get_op("containers.exec")) == (
        "aisb containers exec REF [-- CMD...] [--workdir WORKDIR] [--user USER] [--env ENV]... "
        "[--max-bytes MAX_BYTES] [--dry-run]")


def test_call_validates_arguments(client):
    with pytest.raises(ValueError, match="unknown argument"):
        get_op("containers.list").call(client, {"bogus": 1})
    with pytest.raises(ValueError, match="missing argument"):
        get_op("containers.inspect").call(client, {})


def test_destroy_without_confirm_previews_and_sends_nothing(client, daemon):
    out = invoke(client, get_op("containers.rm"), {"ref": "web", "force": True})
    assert out.status == "confirm"
    assert out.planned == [{"method": "DELETE", "path": "/containers/web", "query": {"force": True, "v": False}}]
    assert daemon.calls() == []


def test_destroy_with_confirm_executes(client, daemon):
    daemon.on("DELETE", "/containers/web", status=204)
    assert invoke(client, get_op("containers.rm"), {"ref": "web"}, confirm=True).result == {"removed": "web"}
    assert daemon.calls() == [("DELETE", "/containers/web")]


def test_dry_run_plans_the_full_run_flow(client, daemon):
    out = invoke(client, get_op("containers.run"), {"image": "alpine", "cmd": ["echo", "hi"], "rm": True}, dry_run=True)
    assert [(p["method"], p["path"]) for p in out.planned] == [
        ("POST", "/containers/create"), ("POST", "/containers/dry-run-id/start"),
        ("POST", "/containers/dry-run-id/wait"), ("GET", "/containers/dry-run-id/json"),
        ("GET", "/containers/dry-run-id/logs"), ("DELETE", "/containers/dry-run-id"),
    ]
    assert out.planned[0]["body"]["Labels"] == {"aisb.managed": "true"}
    assert [m for m, _ in daemon.calls()] == ["GET"]  # only the read-only preflight reached the daemon
    assert out.warnings == ["image 'alpine' is not local: it will be pulled"]


def test_run_preflight_predicts_failures(client, daemon):
    daemon.on("GET", "/containers/web/json", json={"Id": "x"})
    daemon.on("GET", "/images/nginx/json", json={"Id": "sha256:1"})
    daemon.on("GET", "/containers/json", json=[{"Names": ["/other"], "Ports": [{"PublicPort": 8080, "PrivatePort": 80}]}])
    out = invoke(client, get_op("containers.run"), {
        "image": "nginx", "name": "web", "network": "app-net", "volume": ["pgdata:/data", "/host:/h"],
        "port": ["8080:80", "9090:90"], "detach": True}, dry_run=True)
    assert out.warnings == [
        "a container named 'web' already exists: create would fail with 409 (remove or rename it)",
        "network 'app-net' does not exist (aisb networks create app-net)",
        "volume 'pgdata' does not exist: Docker will create it empty",
        "host port 8080 is already published by running container 'other'",
    ]
    assert out.payload()["warnings"] == out.warnings


def test_real_run_skips_preflight(client, daemon):
    daemon.on("POST", "/containers/create", status=201, json={"Id": "c" * 64})
    daemon.on("POST", r"/containers/c+/start", status=204)
    assert "warnings" not in get_op("containers.run").call(client, {"image": "nginx", "detach": True})
    assert not [p for m, p in daemon.calls() if m == "GET"]


def test_read_ops_ignore_dry_run(client, daemon):
    daemon.on("GET", "/containers/json", json=[])
    assert invoke(client, get_op("containers.list"), {}, dry_run=True).status == "ok"


def test_run_pulls_missing_image_then_retries(client, daemon):
    creates = iter([Reply(404, json={"message": "No such image: alpine:latest"}), Reply(201, json={"Id": "c" * 64})])
    daemon.on("POST", "/containers/create", lambda s: next(creates))
    daemon.on("POST", "/images/create", chunks=[b'{"status":"Pulling"}\n{"status":"Status: Downloaded"}\n'])
    daemon.on("POST", r"/containers/c+/start", status=204)
    out = get_op("containers.run").call(client, {"image": "alpine", "detach": True})
    assert out == {"id": "c" * 12, "name": None, "status": "started"}
    pull = next(s for s in daemon.seen if s.path == "/images/create")
    assert pull.query == {"fromImage": "alpine", "tag": "latest"}
    assert daemon.calls("POST") == [("POST", "/containers/create"), ("POST", "/images/create"),
                                    ("POST", "/containers/create"), ("POST", f"/containers/{'c' * 64}/start")]


def test_commands_reference_is_up_to_date():
    assert DOCS.read_text() == render_markdown(), "run: PYTHONPATH=src python -m aisb docs > " + str(DOCS)
