import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aisb import stack as stk
from aisb.api.containers import compare_specs
from aisb.api.net import parse_listeners
from aisb.cli import EXIT_CONFIRM, EXIT_OK, main
from aisb.insights.audit import audit, mask, scan_env, scan_history, scan_text, slim
from aisb.mcp import Server
from aisb.ops import Tier
from aisb.services.queues import parse_kafka_table
from aisb.services.sql import diff_schema
from conftest import Reply, frame, tar_of


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"] if "--" not in argv else
                    [*argv[:argv.index("--")], "--host", host, "--json", *argv[argv.index("--"):]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


# --- stack --------------------------------------------------------------------------------

STACK = {"name": "shop", "volumes": ["pgdata"], "services": {
    "db": {"image": "postgres:16", "env": {"POSTGRES_PASSWORD": "x"}, "volumes": ["pgdata:/data", "/host:/h"]},
    "cache": {"image": "redis:7"},
    "api": {"image": "api:1", "depends_on": ["db", "cache"], "ports": ["8080:80"], "ready": {"log": "listening"}},
}}


def test_stack_parse_names_order_and_labels():
    s = stk.parse(STACK)
    assert (s.network, s.volumes) == ("shop_default", ("shop_pgdata",))
    assert s.order.index("api") > s.order.index("db") and s.order.index("api") > s.order.index("cache")
    db = s.services["db"]
    assert db.spec.name == "shop-db" and db.spec.aliases == ("db",) and db.spec.network == "shop_default"
    assert db.spec.volumes == ("shop_pgdata:/data", "/host:/h")
    api = db.spec.to_api()
    assert api["NetworkingConfig"] == {"EndpointsConfig": {"shop_default": {"Aliases": ["db"]}}}
    assert api["Labels"] | {"aisb.hash": ""} == {"aisb.stack": "shop", "aisb.service": "db", "aisb.hash": "",
                                                 "aisb.managed": "true"}
    assert s.dependents("db") == ["api"]


def test_stack_hash_tracks_config():
    a = stk.parse(STACK).services["cache"].digest
    changed = json.loads(json.dumps(STACK))
    changed["services"]["cache"]["cmd"] = ["redis-server", "--maxmemory", "64mb"]
    assert stk.parse(STACK).services["cache"].digest == a != stk.parse(changed).services["cache"].digest


@pytest.mark.parametrize(("mutate", "error"), [
    (lambda d: d["services"]["db"].update(depends_on=["api"]), "dependency cycle"),
    (lambda d: d["services"]["api"].update(depends_on=["nope"]), "unknown service"),
    (lambda d: d["services"]["db"].update(ready="soon"), "'ready' must be"),
    (lambda d: d["services"]["db"].update(network="x"), "managed by the stack"),
    (lambda d: d.update(name="Bad Name"), "lowercase 'name'"),
    (lambda d: d.update(extra=1), "unknown stack keys"),
    (lambda d: d["services"]["db"].update(imag="typo"), "unknown RunSpec keys"),
])
def test_stack_validation(mutate, error):
    data = json.loads(json.dumps(STACK))
    mutate(data)
    with pytest.raises(ValueError, match=error):
        stk.parse(data)


def test_stack_up_creates_in_order_and_detects_drift(cli, daemon, tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"name": "st", "services": {"a": {"image": "x"}, "b": {"image": "y", "depends_on": ["a"]}}}))
    spec_b = stk.load(f).services["b"]
    daemon.on("GET", "/networks/st_default", status=404, json={"message": "no"})
    daemon.on("POST", "/networks/create", status=201, json={"Id": "n"})
    daemon.on("GET", "/containers/st-a/json", status=404, json={"message": "no"})
    daemon.on("GET", "/containers/st-b/json", json={"Config": {"Labels": {"aisb.hash": "stale"}}, "State": {"Running": True}})
    daemon.on("POST", "/containers/create", status=201, json={"Id": "c1"})
    daemon.on("POST", "/containers/st-a/start", status=204)
    code, out, _ = cli("stack", "up", str(f), "--no-wait")
    assert code == EXIT_OK and [(s["service"], s["action"]) for s in out["services"]] == [("a", "created"), ("b", "drift")]
    create = next(s for s in daemon.seen if s.path == "/containers/create")
    assert create.query["name"] == "st-a" and create.body["HostConfig"]["NetworkMode"] == "st_default"
    assert spec_b.digest != "stale"


def test_stack_down_is_destroy_tier(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "c" * 64, "Names": ["/st-a"], "Labels": {"aisb.service": "a"}}])
    daemon.on("GET", "/networks", json=[{"Id": "n1", "Name": "st_default"}])
    daemon.on("GET", "/networks/n1", json={"Containers": {"c" * 64: {"Name": "st-a"}}})
    code, out, _ = cli("stack", "down", "st")
    assert code == EXIT_CONFIRM and [p["method"] for p in out["planned"]] == ["DELETE", "DELETE"]
    assert json.loads(daemon.seen[0].query["filters"]) == {"label": ["aisb.stack=st"]}


def test_stack_down_keeps_network_with_foreign_containers(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "c" * 64, "Names": ["/st-a"], "Labels": {"aisb.service": "a"}}])
    daemon.on("GET", "/networks", json=[{"Id": "n1", "Name": "st_default"}])
    daemon.on("GET", "/networks/n1", json={"Containers": {"c" * 64: {"Name": "st-a"}, "f" * 64: {"Name": "intruder"}}})
    daemon.on("DELETE", r"/containers/c+", status=204)
    code, out, _ = cli("stack", "down", "st", "--yes")
    assert code == EXIT_OK and out["removed_networks"] == [] and "intruder" in out["kept_networks"][0]["reason"]
    assert ("DELETE", "/networks/n1") not in daemon.calls()


# --- pure analyses --------------------------------------------------------------------------

def test_diff_schema():
    a = {"t": {"columns": {"id": {"type": "int"}, "x": {"type": "text"}}, "indexes": {"pk": "(id)"}}, "gone": {"columns": {}, "indexes": {}}}
    b = {"t": {"columns": {"id": {"type": "bigint"}, "y": {"type": "text"}}, "indexes": {"pk": "(id)"}}, "new": {"columns": {}, "indexes": {}}}
    d = diff_schema(a, b)
    assert (d["tables_only_in_a"], d["tables_only_in_b"], d["identical"]) == (["gone"], ["new"], False)
    assert d["changed"]["t"] == {"columns": {"only_in_a": ["x"], "only_in_b": ["y"],
                                             "different": {"id": {"a": {"type": "int"}, "b": {"type": "bigint"}}}}}
    assert diff_schema(a, a)["identical"]


def test_compare_specs_masks_secrets():
    d = compare_specs({"image": "a:1", "env": ["DB_PASSWORD=one", "MODE=x"], "ports": ["80"]},
                      {"image": "a:2", "env": ["DB_PASSWORD=two", "EXTRA=1"], "ports": ["80"]})
    assert d["different"]["image"] == {"a": "a:1", "b": "a:2"} and "ports" in d["same"]
    assert d["different"]["env"] == {"only_in_a": {"MODE": "x"}, "only_in_b": {"EXTRA": "1"},
                                     "different": {"DB_PASSWORD": {"a": "***", "b": "***"}}}


@pytest.mark.parametrize(("text", "kind"), [
    ("AKIAABCDEFGHIJKLMNOP", "aws-access-key-id"), ("ghp_" + "a" * 36, "github-token"),
    ("xoxb-123456789012-abc", "slack-token"), ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
    ("postgres://admin:hunter2@db:5432/x", "url-with-password"), ("sk_live_" + "a" * 24, "stripe-key"),
])
def test_scan_text_kinds(text, kind):
    assert [h["kind"] for h in scan_text(f"x {text} y", "f")] == [kind]


def test_scan_env_and_history():
    hits = scan_env(["DB_PASSWORD=supersecret", "API_TOKEN=changeme", "PASSWORD_FILE=/run/s", "LOG=debug"])
    assert [(h["where"], h["sample"]) for h in hits] == [("env:DB_PASSWORD", "supe***")]
    hist = [{"created_by": "|1 NPM_TOKEN=ghp_" + "b" * 36 + " /bin/sh -c npm ci"}, {"created_by": "ENV MODE=prod"}]
    kinds = {h["kind"] for h in scan_history(hist)}
    assert kinds == {"secret-in-image-history", "github-token"}
    assert mask("abcdefghij") == "abcd***" and mask("short") == "***"


def container(**over):
    base = {"Name": "/x", "Config": {"Image": "app:1.2", "User": "app", "Env": [], "Healthcheck": {"Test": ["CMD", "true"]}},
            "HostConfig": {"Memory": 1, "NanoCpus": 1, "PidsLimit": 100, "SecurityOpt": ["no-new-privileges:true"],
                           "RestartPolicy": {"Name": "always"}}, "Mounts": [], "NetworkSettings": {"Ports": {}},
            "State": {"Running": True}}
    for k, v in over.items():
        base[k] = {**base.get(k, {}), **v} if isinstance(v, dict) else v
    return base


def test_audit_clean_container_scores_100():
    assert audit(container()) == {"container": "x", "score": 100, "findings": []}


def test_audit_flags_the_classics():
    r = audit(container(
        HostConfig={"Privileged": True},
        Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/s", "RW": True},
                {"Type": "bind", "Source": "/", "Destination": "/host", "RW": False}],
        NetworkSettings={"Ports": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}],
                                   "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}},
        Config={"Image": "app", "User": "", "Env": ["STRIPE_SECRET_KEY=sk_live_" + "c" * 24]}))
    codes = [f["code"] for f in r["findings"]]
    assert codes[:3] == ["privileged", "docker-socket", "datastore-exposed"]
    assert {"sensitive-mount", "runs-as-root", "unpinned-image"} <= set(codes)
    assert codes.count("secret-in-env") + codes.count("stripe-key") == 1  # one finding per variable
    assert r["score"] == 0


def test_slim_hints():
    hist = [{"created_by": "CMD [\"app\"]", "size": 0},
            {"created_by": "RUN apt-get install -y gcc && pip install flask", "size": 300 << 20},
            {"created_by": "RUN apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*", "size": 5 << 20},
            {"created_by": "ADD rootfs.tar /", "size": 80 << 20}]
    r = slim(hist, 385 << 20)
    assert r["largest"][0]["created_by"].startswith("RUN apt-get install -y gcc")
    assert sorted({h["code"] for h in r["hints"]}) == ["apt-lists-kept", "apt-recommends", "build-tools-in-final", "pip-cache"]
    assert r["over_50mb"] == 2


def test_parse_listeners():
    text = ("  sl  local_address rem_address   st\n"
            "   0: 0100007F:2328 00000000:0000 0A 0\n"
            "   1: 00000000:1538 00000000:0000 0A 0\n"
            "   2: 0100007F:1538 0100007F:9999 01 0\n"
            "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 0\n")
    assert parse_listeners(text) == [("0.0.0.0", 5432), ("127.0.0.1", 9000), ("::", 80)]


def test_parse_kafka_table():
    text = ("\nGROUP   TOPIC  PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG  CONSUMER-ID  HOST  CLIENT-ID\n"
            "billing orders 0          1               3               2    -            -     -\n"
            "billing orders 1          -               0               -    -            -     -\n")
    rows = parse_kafka_table(text)
    assert [(r["PARTITION"], r["LAG"]) for r in rows] == [("0", "2"), ("1", "-")]


# --- ops through the fake daemon ------------------------------------------------------------

def test_net_probe_finds_loopback_only_listener(cli, daemon):
    net = {"NetworkSettings": {"Networks": {"app": {"IPAddress": "10.0.0.2"}}}}
    daemon.on("GET", "/containers/api/json", json={"Name": "/api", **net})
    daemon.on("GET", "/containers/db/json", json={"Name": "/db", "Config": {"ExposedPorts": {"5432/tcp": {}}}, **net})
    daemon.execs("db", [(b"  sl  local_address\n   0: 0100007F:1538 00000000:0000 0A 0\n", b"cat: /proc/net/tcp6: No such file", 1)])
    daemon.execs("api", [(b"IP 10.0.0.3\n", b"", 0), (b"FAIL nc\n", b"", 0)])
    code, out, _ = cli("net", "probe", "api", "db")
    assert (out["ok"], out["broken_at"], out["port"]) == (False, "listening", 5432)
    assert out["steps"][1]["fix"] == "bind the server to 0.0.0.0 (or ::)"


def test_debug_sidecar_shares_namespaces_and_cleans_up(cli, daemon):
    daemon.on("GET", "/containers/nosh/json", json={"Id": "t" * 64})
    daemon.on("POST", "/containers/create", status=201, json={"Id": "s" * 64})
    daemon.on("POST", r"/containers/s+/start", status=204)
    daemon.on("POST", r"/containers/s+/wait", json={"StatusCode": 0})
    daemon.on("GET", r"/containers/s+/json", json={"Config": {"Tty": False}})
    daemon.on("GET", r"/containers/s+/logs", Reply(body=frame(1, b"open\n")))
    daemon.on("DELETE", r"/containers/s+", status=204)
    code, out, _ = cli("containers", "debug", "nosh", "--", "nc", "-z", "localhost", "80")
    assert (code, out["exit_code"], out["output"]) == (EXIT_OK, 0, "open\n")
    host = next(s for s in daemon.seen if s.path == "/containers/create").body["HostConfig"]
    assert host["NetworkMode"] == host["PidMode"] == "container:" + "t" * 64
    assert daemon.calls("DELETE") == [("DELETE", "/containers/" + "s" * 64)]


def test_timeline_merges_by_timestamp(cli, daemon):
    daemon.on("GET", "/containers/a/json", json={"Config": {"Tty": True}})
    daemon.on("GET", "/containers/b/json", json={"Config": {"Tty": True}})
    daemon.on("GET", "/containers/a/logs", Reply(body=b"2026-01-01T00:00:01.000000000Z a1\n2026-01-01T00:00:03.000000000Z a3\n"))
    daemon.on("GET", "/containers/b/logs", Reply(body=b"2026-01-01T00:00:02.000000000Z b2\n"))
    code, out, _ = cli("containers", "timeline", "a", "b")
    assert [line.split("| ")[1] for line in out["output"].splitlines()] == ["a1", "b2", "a3"]


def test_volume_backup_uses_never_started_helper(cli, daemon, tmp_path):
    daemon.on("GET", "/volumes/data", json={"Name": "data"})
    daemon.on("POST", "/containers/create", status=201, json={"Id": "h" * 64})
    daemon.on("GET", r"/containers/h+/archive", chunks=[tar_of({"v/a.txt": b"hello"}, dirs=("v",))])
    daemon.on("DELETE", r"/containers/h+", status=204)
    out_file = tmp_path / "b.tar.gz"
    code, out, _ = cli("volumes", "backup", "data", str(out_file))
    assert code == EXIT_OK and out_file.stat().st_size == out["file_bytes"]
    create = next(s for s in daemon.seen if s.path == "/containers/create")
    assert create.body["HostConfig"]["Binds"] == ["data:/v:ro"]
    assert not any(s.path.endswith("/start") for s in daemon.seen)
    assert cli("volumes", "restore", "data", str(out_file))[0] == EXIT_CONFIRM


def test_kafka_peek_and_rabbit_queues(cli, daemon):
    daemon.on("GET", "/containers/k/json", json={"Name": "/k", "State": {"Running": True}, "Config": {"Image": "apache/kafka:3.8.0"}})
    daemon.execs("k", [(b"CreateTime:1700000000000\tPartition:1\tOffset:4\tu1\t{\"a\": 1}\nCreateTime:1\tPartition:0\tOffset:0\tnull\tplain\n",
                        b"Processed a total of 2 messages\n", 0)])
    code, out, _ = cli("kafka", "peek", "k", "orders")
    assert out["messages"] == [{"partition": 1, "offset": 4, "timestamp": 1700000000000, "key": "u1", "value": '{"a": 1}'},
                               {"partition": 0, "offset": 0, "timestamp": 1, "key": None, "value": "plain"}]
    daemon.on("GET", "/containers/r/json", json={"Name": "/r", "State": {"Running": True}, "Config": {"Image": "rabbitmq:3"}})
    created = daemon.execs("r", [(b'[{"name":"a","messages":1},{"name":"b","messages":9}]', b"", 0)])
    code, out, _ = cli("rabbit", "queues", "r")
    assert [q["name"] for q in out] == ["b", "a"] and created[0].body["Cmd"][:3] == ["rabbitmqctl", "-q", "list_queues"]


@pytest.fixture
def es_server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._reply({"status": "yellow", "cluster_name": "c", "number_of_nodes": 1} if "health" in self.path else
                        [{"index": "books", "health": "yellow", "docs.count": "3", "store.size": "100", "pri": "1", "rep": "1"},
                         {"index": ".security", "docs.count": "1"}])

        def do_POST(self):
            q = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.server.last = (self.path, q, self.headers.get("Authorization"))  # type: ignore[attr-defined]
            self._reply({"took": 2, "hits": {"total": {"value": 1}, "hits": [{"_index": "books", "_id": "1", "_score": 1.0,
                                                                                "_source": {"title": "Dune"}}]}})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def test_elasticsearch_over_http(cli, daemon, es_server):
    port = es_server.server_address[1]
    daemon.on("GET", "/containers/es/json", json={
        "Name": "/es", "State": {"Running": True}, "Config": {"Image": "elasticsearch:8.15.0", "Env": ["ELASTIC_PASSWORD=pw"]},
        "NetworkSettings": {"Ports": {"9200/tcp": [{"HostIp": "0.0.0.0", "HostPort": str(port)}]}}})
    assert cli("es", "health", "es")[1]["status"] == "yellow"
    assert [i["index"] for i in cli("es", "indices", "es")[1]] == ["books"]
    code, out, _ = cli("es", "search", "es", "books", '{"query": {"match": {"title": "dune"}}}', "--limit", "3")
    assert out["hits"] == [{"index": "books", "id": "1", "score": 1.0, "title": "Dune"}]
    path, body, auth = es_server.last
    assert (path, body["size"], auth.startswith("Basic ")) == ("/books/_search", 3, True)


# --- MCP ----------------------------------------------------------------------------------

def test_mcp_protocol(client, daemon):
    srv = Server(lambda: client)
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
    assert init["result"]["protocolVersion"] == "2025-03-26" and "tools" in init["result"]["capabilities"]
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tools = {t["name"]: t for t in srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
    assert tools["containers_rm"]["annotations"]["destructiveHint"] and "confirm" in tools["containers_rm"]["inputSchema"]["properties"]
    assert "dry_run" in tools["db_exec"]["inputSchema"]["properties"] and "dry_run" not in tools["db_query"]["inputSchema"]["properties"]
    plan = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "containers_rm", "arguments": {"ref": "web"}}})["result"]
    assert json.loads(plan["content"][0]["text"])["status"] == "confirmation_required" and daemon.calls() == []
    daemon.on("DELETE", "/containers/web", status=204)
    done = srv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "containers_rm", "arguments": {"ref": "web", "confirm": True}}})["result"]
    assert not done["isError"] and daemon.calls() == [("DELETE", "/containers/web")]
    bad = srv.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "containers_list",
                                                                                     "arguments": {"bogus": 1}}})["result"]
    assert bad["isError"]
    assert srv.handle({"jsonrpc": "2.0", "id": 6, "method": "nope"})["error"]["code"] == -32601


def test_mcp_read_only_toolset_and_stdio():
    srv = Server(lambda: None, max_tier=Tier.READ)
    out = io.StringIO()
    srv.serve(io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n\nnot json\n'), out)
    first, second = (json.loads(line) for line in out.getvalue().splitlines())
    assert all(t["annotations"]["readOnlyHint"] for t in first["result"]["tools"])
    assert second["error"]["code"] == -32700
