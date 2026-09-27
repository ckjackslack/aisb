"""Desired state (diff/converge/replace-drifted), compose import (YAML subset), inventory import sources."""

import json
import shutil
import tempfile
import textwrap
from pathlib import Path

import pytest

from aisb import compose, yamlish
from aisb import stack as stk
from aisb.cli import EXIT_CONFIRM, EXIT_OK, main
from aisb.fleet import sources
from aisb.fleet.inventory import Inventory

from conftest import FakeDaemon, Reply

# --- YAML subset ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("text", "value"), [
    ("a: 1\nb: true\nc: null\nd: 1.5\ne: '2'\nf: \"x\\ty\"\ng: yes\n",
     {"a": 1, "b": True, "c": None, "d": 1.5, "e": "2", "f": "x\ty", "g": "yes"}),
    ("- a\n- b: 1\n  c: 2\n- [x, 'y z']\n", ["a", {"b": 1, "c": 2}, ["x", "y z"]]),
    ("k:\n- 1\n- 2\n", {"k": [1, 2]}),                                    # sequence at the key's indent
    ("k: {a: 1, b: [2, 3]}\n", {"k": {"a": 1, "b": [2, 3]}}),
    ("s: |\n  one\n  two\n\nt: x\n", {"s": "one\ntwo\n", "t": "x"}),
    ("s: >-\n  one\n  two\n", {"s": "one two"}),
    ("u: http://x:80/a#frag # comment\n", {"u": "http://x:80/a#frag"}),
    ("'a: b': c\n", {"a: b": "c"}),
    ("---\n# only a comment\nx: 1\n", {"x": 1}),
    ("x:\n", {"x": None}),
])
def test_yaml_subset(text, value):
    assert yamlish.loads(text) == value


@pytest.mark.parametrize(("text", "error"), [
    ("a: &x 1\nb: *x\n", "anchors"), ("<<: {a: 1}\n", "merge keys"), ("a: !!str 1\n", "tags"),
    ("a: 1\na: 2\n", "duplicate key"), ("a: [1, 2\n", "unterminated"), ("a: 1\n  b: 2\n", "unexpected indentation"),
    ("a: 1\n---\nb: 2\n", "multiple documents"), ('a: "x\n', "unterminated"),
])
def test_yaml_rejects(text, error):
    with pytest.raises(yamlish.YAMLError, match=error):
        yamlish.loads(text)


# --- compose -> stack ------------------------------------------------------------------------------

def test_compose_translation(tmp_path, monkeypatch):
    (tmp_path / "app.env").write_text("# comment\nexport TOKEN='t0k'\nMODE=dev\n")
    monkeypatch.setenv("FROM_HOST", "yes-please")
    monkeypatch.delenv("NOT_SET_HERE", raising=False)
    data = yamlish.loads(textwrap.dedent("""
        name: Shop App
        services:
          db:
            image: postgres:16
            healthcheck: {test: ["CMD-SHELL", "pg_isready"]}
            volumes: [pgdata:/var/lib/postgresql/data]
          api:
            build: ./api
            command: ./run --port 80
            env_file: app.env
            environment: [MODE=prod, FROM_HOST, NOT_SET_HERE]
            ports:
              - "8080:80"
              - {target: 53, published: 5353, protocol: udp, host_ip: 127.0.0.1}
            volumes:
              - ./conf:/etc/app:ro
              - {type: bind, source: ./data, target: /data}
            depends_on: {db: {condition: service_healthy}}
            deploy: {resources: {limits: {memory: 256m, cpus: "0.5"}}}
            ulimits: {nofile: 1024}
            restart: unless-stopped
        volumes: {pgdata: {}}
        secrets: {x: {file: s}}
    """))
    res = compose.convert(data, base=tmp_path)
    s = res["stack"]
    assert s["name"] == "shop-app" and s["volumes"] == ["pgdata"]
    api = s["services"]["api"]
    assert api["image"] == "shop-app-api:latest" and api["cmd"] == ["./run", "--port", "80"]
    assert api["env"] == {"TOKEN": "t0k", "MODE": "prod", "FROM_HOST": "yes-please"}
    assert api["ports"] == ["8080:80", "127.0.0.1:5353:53/udp"]
    assert api["volumes"] == [f"{tmp_path}/conf:/etc/app:ro", f"{tmp_path}/data:/data"]
    assert (api["memory"], api["cpus"], api["restart"]) == ("256m", 0.5, "unless-stopped")
    assert s["services"]["db"]["ready"] == "healthy" and s["services"]["db"]["health_cmd"] == "pg_isready"
    assert {"service": "api", "key": "ulimits"} in res["unsupported"] and res["unsupported_top_level"] == ["secrets"]
    assert any("NOT_SET_HERE" in n for n in res["notes"]) and any("images build ./api" in n for n in res["notes"])
    stk.parse(s)  # a valid stack


def test_stack_import_cli(tmp_path, capsys):
    f = tmp_path / "compose.yaml"
    f.write_text("services:\n  web:\n    image: nginx:alpine\n")
    assert main(["stack", "import", str(f), "--name", "site", "--out", str(tmp_path / "s.json"), "--json"]) == EXIT_OK
    assert json.loads((tmp_path / "s.json").read_text()) == {"name": "site", "services": {"web": {"image": "nginx:alpine"}}}


# --- desired state over a fake daemon ---------------------------------------------------------------

STACK = {"name": "app", "services": {"web": {"image": "nginx:alpine", "ready": "running"}}}


@pytest.fixture
def world(tmp_path, monkeypatch, capsys):
    d = Path(tempfile.mkdtemp(prefix="aisb-d-", dir="/tmp"))
    daemon = FakeDaemon(d / "a.sock")
    daemon.start()
    (tmp_path / "stacks").mkdir()
    (tmp_path / "stacks" / "app.json").write_text(json.dumps(STACK))
    (tmp_path / "state.json").write_text(json.dumps({"assign": {"@web": ["stacks/app.json"]}}))
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"a": {"docker": f"unix://{daemon.sock}", "groups": ["web"]},
                                         "b": {"docker": f"unix://{daemon.sock}", "groups": ["db"]}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        code = main([*argv, "--json"])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    yield run, daemon, str(tmp_path / "state.json")
    daemon.stop()
    shutil.rmtree(d, ignore_errors=True)


def _container(state: str = "running", digest: str | None = None) -> dict:
    s = stk.parse(STACK)
    return {"Id": "c" * 64, "Names": ["/app-web"], "State": state,
            "Labels": {stk.STACK_KEY: "app", stk.SERVICE_KEY: "web", stk.HASH_KEY: digest or s.services["web"].digest}}


def test_diff_reports_missing_drift_and_unassigned(world):
    run, daemon, state = world
    rows: list[dict] = []
    daemon.on("GET", "/containers/json", lambda _: Reply(json=rows))
    code, out, _ = run("fleet", "diff", state)
    assert code == EXIT_OK and out["needs_converge"] == ["a"]
    assert out["results"][0]["result"]["stacks"]["app"]["missing"] == ["web"]
    rows[:] = [_container(digest="old"), {"Id": "x", "Names": ["/other-x"], "State": "running",
                                          "Labels": {stk.STACK_KEY: "other"}}]
    res = run("fleet", "diff", state)[1]["results"][0]["result"]
    assert res["stacks"]["app"]["drift"] == ["web"] and res["unassigned_stacks"] == ["other"]
    rows[:] = [_container()]
    assert run("fleet", "diff", state)[1]["converged"] == ["a"]


def test_converge_starts_stopped_and_replace_needs_yes(world):
    run, daemon, state = world
    running = {"yes": False}                    # a stateful container: stopped until /start is called
    rows = [_container(state="exited")]
    daemon.on("GET", "/containers/json", lambda _: Reply(json=rows))
    daemon.on("GET", "/networks/app_default", json={"Id": "n"})
    daemon.on("GET", "/containers/app-web/json", lambda _: Reply(json={
        "Config": {"Labels": _container()["Labels"]},
        "State": {"Running": running["yes"], "Status": "running" if running["yes"] else "exited"}}))

    def start(_):
        running["yes"] = True
        return Reply(status=204)
    daemon.on("POST", "/containers/app-web/start", start)
    code, out, _ = run("fleet", "converge", state, "--dry-run")
    assert code == EXIT_OK and out["planned"][0]["host"] == "a"
    assert ("POST", "/containers/app-web/start") not in daemon.calls()
    code, out, _ = run("fleet", "converge", state)
    assert code == EXIT_OK and ("POST", "/containers/app-web/start") in daemon.calls()
    rows[:] = [_container(digest="old")]
    code, plan, _ = run("fleet", "replace-drifted", state)
    assert code == EXIT_CONFIRM and plan["planned"][0]["stacks"]["app"]["up"] == {
        "recreates": ["web"], "from": str(Path(state).parent / "stacks" / "app.json")}


def test_desired_state_validation(tmp_path):
    inv = Inventory({})
    (tmp_path / "s.json").write_text("{}")
    with pytest.raises(ValueError, match="needs an `assign`"):
        from aisb.fleet import desired
        desired.load(tmp_path / "s.json", inv)


# --- inventory sources -----------------------------------------------------------------------------------

AWS = {"Reservations": [{"Instances": [
    {"InstanceId": "i-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5", "PublicIpAddress": "3.3.3.3",
     "Placement": {"AvailabilityZone": "eu-west-1a"},
     "Tags": [{"Key": "Name", "Value": "web 1"}, {"Key": "Role", "Value": "Web"}, {"Key": "aws:autoscaling", "Value": "x"},
              {"Key": "Team-Name", "Value": "shop"}]},
    {"InstanceId": "i-2", "State": {"Name": "stopped"}, "PrivateIpAddress": "10.0.0.6"},
]}]}


def test_aws_source():
    (h,) = sources.aws(json.dumps(AWS), user="ubuntu")
    assert (h.name, h.ssh, h.groups) == ("web-1", "ubuntu@10.0.0.5", ("web",))
    assert h.labels == {"name": "web 1", "role": "Web", "team-name": "shop", "instance_id": "i-1", "az": "eu-west-1a"}
    assert sources.aws(json.dumps(AWS), public=True)[0].ssh == "ec2-user@3.3.3.3"


def test_csv_json_and_ssh_config_sources():
    rows = sources.table("name,ssh,port,groups,labels\nweb1,ops@10.0.0.1,2222,web;prod,region=eu;tier=1\n,skip,,,\n")
    assert rows[0].port == 2222 and rows[0].groups == ("web", "prod") and rows[0].labels == {"region": "eu", "tier": "1"}
    assert [h.name for h in sources.json_hosts('[{"name": "a", "ssh": "x"}]')] == ["a"]
    assert [h.name for h in sources.json_hosts('{"hosts": {"b": {}}}')] == ["b"]
    cfg = "Host *\n  User x\nHost bastion jump.example.com\n  HostName 1.1.1.1\nHost web-?\n"
    assert [(h.name, h.ssh) for h in sources.ssh_config(cfg)] == [("bastion", "bastion"),
                                                                   ("jump.example.com", "jump.example.com")]


def test_fleet_import_merges(tmp_path, monkeypatch, capsys):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {"web-1": {"ssh": "old@x", "groups": ["legacy"], "labels": {"keep": "1"}}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))
    (tmp_path / "aws.json").write_text(json.dumps(AWS))
    code = main(["fleet", "import", str(tmp_path / "aws.json"), "--source", "aws", "--group", "cloud", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK and out["updated"] == ["web-1"] and out["added"] == []
    h = Inventory.load().hosts["web-1"]
    assert h.groups == ("legacy", "web", "cloud") and h.labels["keep"] == "1" and h.ssh == "ec2-user@10.0.0.5"
