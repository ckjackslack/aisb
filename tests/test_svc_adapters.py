"""Non-SQL adapters through their boundaries: Kafka/RabbitMQ/Redis/Mongo/web-server CLIs via exec, and the
management/search HTTP APIs via a local HTTP server standing in for the published port."""

import base64
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from aisb.services import REGISTRY, Adapter, ServiceError, Target
from aisb.services.mongo import Mongo
from aisb.services.queues import Kafka, RabbitMQ, Search, parse_kafka_table
from aisb.services.redis import Redis, parse_info
from aisb.services.web import Caddy, HAProxy, Httpd, Nginx
from test_services_more import Engine, info, make, queue

from conftest import Reply, tar_of

OK = (b"", b"", 0)
MISSING = (b"", b'exec: "x": executable file not found in $PATH', 127)


class Api:
    """A local HTTP server playing a service's published port; records requests, replies from a table."""

    def __init__(self, routes: dict[tuple[str, str], tuple[int, Any]]) -> None:
        self.seen: list[tuple[str, str, Any, dict[str, str]]] = []
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _any(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                api.seen.append((self.command, self.path, body, dict(self.headers)))
                status, obj = routes.get((self.command, self.path.split("?")[0]), (404, {"error": "nope"}))
                data = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _any

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def api():
    servers: list[Api] = []

    def start(routes: dict[tuple[str, str], tuple[int, Any]]) -> Api:
        servers.append(Api(routes))
        return servers[-1]
    yield start
    for s in servers:
        s.close()


def published(port_in: int, host_port: int, ip: str = "0.0.0.0") -> dict[str, Any]:
    return {f"{port_in}/tcp": [{"HostIp": ip, "HostPort": str(host_port)}]}


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- kafka ------------------------------------------------------------------------------------

KAFKA = info("k", "apache/kafka:3.8.0")

GROUPS = """
Consumer group 'idle' has no active members.

GROUP           TOPIC           PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG             CONSUMER-ID     HOST            CLIENT-ID
idle            orders          0          5               9               4               -               -               -
idle            orders          1          5               5               0

GROUP           TOPIC           PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG             CONSUMER-ID     HOST            CLIENT-ID
busy            orders          0          1               21              20              c-1             /10.0.0.2       app
busy            payments        0          -               3               -               c-2             /10.0.0.3       app
busy            payments        1
"""


@pytest.mark.parametrize(("text", "expected"), [
    ("", []),
    ("garbage line\nmore\n", []),                                   # no header yet: nothing is a row
    ("GROUP TOPIC PARTITION LAG\ng t 0 5\n", [{"GROUP": "g", "TOPIC": "t", "PARTITION": "0", "LAG": "5"}]),
    ("GROUP TOPIC A B C D\ng t 1\n", [{"GROUP": "g", "TOPIC": "t", "A": "1", "B": "-", "C": "-", "D": "-"}]),
    ("GROUP TOPIC A B C D E\ng t 1\n", []),                          # too short to be a row
])
def test_parse_kafka_table_samples(text, expected):
    assert parse_kafka_table(text) == expected


def test_kafka_groups_aggregate_lag_and_members(client, daemon):
    eng = Engine(daemon, "k", KAFKA, queue((GROUPS.encode(), b"", 0)))
    groups = make(client, Kafka, KAFKA).groups()
    assert [(g["group"], g["lag"], g["members"], g["idle"], g["partitions"]) for g in groups] == [
        ("busy", 20, 2, False, 2), ("idle", 4, 0, True, 2)]
    assert groups[0]["topics"] == ["orders", "payments"]
    cmd = eng.calls[0][0]
    assert cmd[:2] == ["sh", "-c"] and cmd[3:] == ["_", "kafka-consumer-groups", "--bootstrap-server", "localhost:9092",
                                                   "--describe", "--all-groups"]


TOPICS = """Topic: orders\tTopicId: abc\tPartitionCount: 2\tReplicationFactor: 3\tConfigs:
\tTopic: orders\tPartition: 0\tLeader: 1\tReplicas: 1,2,3\tIsr: 1,2,3
\tTopic: orders\tPartition: 1\tLeader: 1\tReplicas: 1,2,3\tIsr: 1
Topic: __consumer_offsets\tTopicId: x\tPartitionCount: 50\tReplicationFactor: 1\tConfigs: a=b
\tTopic: ghost\tPartition: 0\tLeader: 1\tReplicas: 1,2\tIsr: 1
"""


def test_kafka_topics_and_stats(client, daemon):
    eng = Engine(daemon, "k", KAFKA | {"Config": {**KAFKA["Config"], "Env": ["AISB_KAFKA_BOOTSTRAP=broker:29092"]}},
                 queue((TOPICS.encode(), b"", 0), (TOPICS.encode(), b"", 0), (TOPICS.encode(), b"", 0), (b"", b"", 0),
                       (b"orders\n", b"", 0)))
    k = make(client, Kafka, info("k", "apache/kafka:3.8.0", ("AISB_KAFKA_BOOTSTRAP=broker:29092",)))
    assert k.topics() == [{"topic": "orders", "partitions": 2, "replication": 3, "under_replicated": 1}]
    assert [t["topic"] for t in k.topics(internal=True)] == ["__consumer_offsets", "orders"]
    assert k.stats() == {"topics": 1, "under_replicated_partitions": 1, "groups": []}
    assert k.probe() == "kafka-topics --list"
    assert all(c[0][c[0].index("--bootstrap-server") + 1] == "broker:29092" for c in eng.calls)


def test_kafka_tool_failure(client, daemon):
    Engine(daemon, "k", KAFKA, queue((b"", b"no kafka-topics in this image\n", 127)))
    with pytest.raises(ServiceError, match="kafka: kafka-topics exited 127: no kafka-topics in this image"):
        make(client, Kafka, KAFKA).topics()


@pytest.mark.parametrize(("out", "err", "code", "messages"), [
    (b"", b"", 0, []),
    (b"NO_TIMESTAMP\tPartition:0\tOffset:1\tk\tv\twith\ttabs\n", b"", 1,
     [{"partition": 0, "offset": 1, "timestamp": None, "key": "k", "value": "v\twith\ttabs"}]),
    (b"LogAppendTime:5\tPartition:2\tOffset:3\tonly-value\n", b"org.apache.kafka.common.errors.TimeoutException", 2,
     [{"partition": 2, "offset": 3, "timestamp": 5, "key": None, "value": "only-value"}]),
    (b"CreateTime:1\tPartition:0\tOffset:0\n", b"", 0,
     [{"partition": 0, "offset": 0, "timestamp": 1, "key": None, "value": ""}]),
])
def test_kafka_peek_parsing(client, daemon, out, err, code, messages):
    eng = Engine(daemon, "k", KAFKA, queue((out, err, code)))
    assert make(client, Kafka, KAFKA).peek("--weird topic", limit=3, seconds=2) == messages
    cmd = eng.calls[0][0]
    assert cmd[cmd.index("--topic") + 1] == "--weird topic" and cmd[cmd.index("--timeout-ms") + 1] == "2000"
    assert "--group" not in cmd  # never joins (or commits for) a consumer group


def test_kafka_peek_failure(client, daemon):
    Engine(daemon, "k", KAFKA, queue((b"", b"UnknownTopicOrPartition\n", 2)))
    with pytest.raises(ServiceError, match="console consumer exited 2: UnknownTopicOrPartition"):
        make(client, Kafka, KAFKA).peek("t", limit=1, seconds=1)


# --- rabbitmq ------------------------------------------------------------------------------------

@pytest.mark.parametrize(("env", "user", "password", "vhost"), [
    ((), "guest", "guest", None),
    (("RABBITMQ_DEFAULT_USER=u", "RABBITMQ_DEFAULT_PASS=p", "RABBITMQ_DEFAULT_VHOST=/"), "u", "p", None),
    (("RABBITMQ_DEFAULT_VHOST=prod",), "guest", "guest", "prod"),
])
def test_rabbit_credentials(env, user, password, vhost):
    r = RabbitMQ(None, Target.from_inspect(info("r", "rabbitmq:3", env)))  # type: ignore[arg-type]
    assert (r.user(), r.password(), r.database()) == (user, password, vhost)
    assert r.url(reveal=True).startswith(f"amqp://{user}:{password}@")


def test_rabbit_ctl_exchanges_and_stats(client, daemon):
    rabbit = info("r", "rabbitmq:3-management", ("RABBITMQ_DEFAULT_VHOST=prod",))
    queues = [{"name": "a", "messages": 0, "consumers": 1}, {"name": "b", "messages": 7, "messages_unacknowledged": 2,
                                                              "consumers": 0}]
    eng = Engine(daemon, "r", rabbit, queue(
        (b'[{"name": "", "type": "direct"}, {"name": "amq.topic", "type": "topic", "durable": true}]', b"", 0),
        (b"\n", b"", 0),
        (json.dumps(queues).encode(), b"", 0), (b'[{"name": "c1"}]', b"", 0), (b"Node reports no alarms\n", b"", 0),
        (json.dumps(queues).encode(), b"", 0), (b"[]", b"", 0), (b"memory alarm on node x\n", b"", 0),
        OK, (b"", b"Error: unable to connect\n", 69)))
    r = make(client, RabbitMQ, rabbit)
    assert r.exchanges("/") == [{"name": "amq.topic", "type": "topic", "durable": True}]
    assert r.queues("/") == []
    s = r.stats()
    assert (s["queues"], s["messages"], s["unacked"], s["queues_without_consumers"], s["connections"], s["alarms"]) == (
        2, 7, 2, ["b"], 1, None)
    assert s["top_queues"][0]["name"] == "b"
    assert r.stats()["alarms"] == "memory alarm on node x"
    assert eng.calls[2][0][:5] == ["rabbitmqctl", "-q", "list_queues", "-p", "prod"]
    assert r.probe() == "rabbitmq-diagnostics ping"
    with pytest.raises(ServiceError, match="rabbitmq-diagnostics exited 69"):
        r.probe()


def test_rabbit_peek_via_management_api(client, daemon, api):
    msgs = [{"routing_key": "k", "exchange": "", "redelivered": False, "properties": {}, "payload": "hi",
             "payload_encoding": "string", "message_count": 0}]
    srv = api({("POST", "/api/queues/%2F/jobs%2Fhigh/get"): (200, msgs)})
    rabbit = info("r", "rabbitmq:3-management", ("RABBITMQ_DEFAULT_USER=u", "RABBITMQ_DEFAULT_PASS=p:w"),
                  ports=published(15672, srv.port))
    got = make(client, RabbitMQ, rabbit).peek("jobs/high", vhost="/", limit=2)
    assert got == [{"routing_key": "k", "exchange": "", "redelivered": False, "properties": {}, "payload": "hi",
                    "encoding": "string"}]
    method, path, body, headers = srv.seen[0]
    assert body == {"count": 2, "ackmode": "ack_requeue_true", "encoding": "auto", "truncate": 50000}
    assert base64.b64decode(headers["Authorization"].split()[1]) == b"u:p:w"


def test_rabbit_peek_errors(client, daemon, api):
    srv = api({})
    with pytest.raises(ServiceError, match="management API 404"):
        make(client, RabbitMQ, info("r", "rabbitmq:3", ports=published(15672, srv.port))).peek("q", vhost="/", limit=1)
    with pytest.raises(ServiceError, match="management API not reachable"):
        make(client, RabbitMQ, info("r", "rabbitmq:3", ips=())).peek("q", vhost="/", limit=1)
    with pytest.raises(ServiceError, match="management API unreachable at 127.0.0.1"):
        make(client, RabbitMQ, info("r", "rabbitmq:3", ports=published(15672, closed_port()))).peek(
            "q", vhost="/", limit=1)
    with pytest.raises(ServiceError, match="unreachable at 127.0.0.254:15672"):  # the container-IP route
        make(client, RabbitMQ, info("r", "rabbitmq:3", ips=("127.0.0.254",))).peek("q", vhost="/", limit=1)


# --- elasticsearch / opensearch ----------------------------------------------------------------------

@pytest.mark.parametrize(("image", "env", "user"), [
    ("opensearchproject/opensearch:2", ("OPENSEARCH_INITIAL_ADMIN_PASSWORD=x",), "admin"),
    ("elasticsearch:8.15.0", ("ELASTIC_PASSWORD=x",), "elastic"),
    ("elasticsearch:7", (), None),
])
def test_search_users(image, env, user):
    assert Search(None, Target.from_inspect(info("es", image, env))).user() == user  # type: ignore[arg-type]


def test_search_ops(client, daemon, api):
    srv = api({
        ("GET", "/_cluster/health"): (200, {"status": "red", "cluster_name": "c", "number_of_nodes": 1, "extra": 1}),
        ("POST", "/logs-*,..%2Fx/_search"): (200, {"took": 1, "hits": {"total": 5, "hits": [{"_id": "1"}]},
                                                           "aggregations": {"n": {"value": 5}}}),
        ("GET", "/_cat/indices"): (200, None),
    })
    es = make(client, Search, info("es", "elasticsearch:7", ports=published(9200, srv.port)))
    with pytest.raises(ServiceError, match="cluster status red"):
        es.probe()
    assert es.stats() == {"cluster_name": "c", "status": "red", "number_of_nodes": 1, "active_shards": None,
                          "unassigned_shards": None, "active_shards_percent_as_number": None}
    assert es.indices() == []
    res = es.search("logs-*,../x", {"query": {"match_all": {}}}, limit=1)
    assert res == {"took_ms": 1, "total": 5, "hits": [{"index": None, "id": "1", "score": None}],
                   "aggregations": {"n": {"value": 5}}}
    assert "Authorization" not in srv.seen[0][3]


def test_search_errors(client, daemon, api):
    srv = api({("GET", "/_cluster/health"): (200, {"status": "green"})})
    es = make(client, Search, info("es", "elasticsearch:8", ports=published(9200, srv.port)))
    assert es.probe() == "cluster green"
    with pytest.raises(ServiceError, match=r"GET /_nodes -> 404"):
        es.request("GET", "/_nodes")
    with pytest.raises(ServiceError, match="neither published nor reachable"):
        make(client, Search, info("es", "elasticsearch:8", ips=())).request("GET", "/")
    with pytest.raises(ServiceError, match="unreachable at 127.0.0.254:9200"):  # the container-IP route
        make(client, Search, info("es", "elasticsearch:8", ips=("127.0.0.254",))).request("GET", "/")
    with pytest.raises(ServiceError, match="elasticsearch: unreachable at 127.0.0.1"):  # plain, then TLS, both refused
        make(client, Search, info("es", "elasticsearch:8", ports=published(9200, closed_port()))).request("GET", "/")


# --- web servers ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("image", "cls"), [("nginx:1", Nginx), ("httpd:2.4", Httpd), ("caddy:2", Caddy),
                                            ("haproxy:3", HAProxy), ("openresty/openresty", Nginx)])
def test_web_detection(image, cls):
    assert REGISTRY.detect(Target.from_inspect(info("w", image)))[0] is cls


def test_web_probe_routes(client, daemon, api):
    srv = api({})
    assert make(client, Nginx, info("w", "nginx", ports=published(80, srv.port))).probe() == f"tcp 127.0.0.1:{srv.port}"
    assert make(client, Nginx, info("w", "nginx", ports=published(80, srv.port, "127.0.0.1"))).probe() == \
        f"tcp 127.0.0.1:{srv.port}"
    with pytest.raises(ServiceError, match="nothing listening on 127.0.0.254:80"):
        make(client, Nginx, info("w", "nginx", ips=("127.0.0.254",))).probe()
    with pytest.raises(ServiceError, match="neither published nor reachable"):
        make(client, Httpd, info("w", "httpd", ips=())).probe()


def test_web_check_and_reload(client, daemon):
    kills = []
    daemon.on("POST", "/containers/w/kill", lambda s: kills.append(s.query) or Reply(204, body=b""))
    eng = Engine(daemon, "w", info("w", "caddy"), queue((b"Valid configuration\n", b"", 0), (b"", b"", 0),
                                                         (b"", b"reload: connection refused\n", 1)))
    caddy = make(client, Caddy, info("w", "caddy"))
    assert caddy.check() == {"ok": True, "command": " ".join(Caddy.check_argv), "output": "Valid configuration"}
    assert caddy.reload() == {"reloaded": True, "via": " ".join(Caddy.reload_argv or ())}
    with pytest.raises(ServiceError, match="caddy: reload failed: reload: connection refused"):
        caddy.reload()
    assert eng.calls[1][0] == list(Caddy.reload_argv or ())
    assert make(client, HAProxy, info("w", "haproxy")).reload() == {"reloaded": True, "via": "signal SIGUSR2 to PID 1"}
    assert kills == [{"signal": "SIGUSR2"}]


# --- redis ----------------------------------------------------------------------------------------

REDIS = info("cache", "redis:7", ("REDIS_USERNAME=app", "REDIS_PASSWORD=pw"))


@pytest.mark.parametrize(("text", "parsed"), [
    ("", {}),
    ("no colon here\r\n\r\n", {}),
    ("redis_version:7.2.4\r\nuptime_in_seconds:10\r\n", {"server": {"redis_version": "7.2.4", "uptime_in_seconds": 10}}),
    ("# Memory\r\nused_memory_human:1.5M\r\nratio:1.25\r\n# Empty\r\n",
     {"memory": {"used_memory_human": "1.5M", "ratio": 1.25}}),
    ("# Keyspace\r\ndb0:keys=1,expires=0,avg_ttl=0\r\ndb1:keys=2\r\n",
     {"keyspace": {"db0": {"keys": 1, "expires": 0, "avg_ttl": 0}, "db1": {"keys": 2}}}),
    ("# Commandstats\r\ncmdstat_get:calls=2,usec=3,usec_per_call=1.50\r\n",
     {"commandstats": {"cmdstat_get": {"calls": 2, "usec": 3, "usec_per_call": 1.5}}}),
    ("# Server\r\nexecutable:/usr/bin/redis:server\r\n", {"server": {"executable": "/usr/bin/redis:server"}}),
])
def test_parse_info_samples(text, parsed):
    assert parse_info(text) == parsed


def test_redis_cli_binary_fallback_user_and_auth_env(client, daemon):
    eng = Engine(daemon, "cache", REDIS, queue(MISSING, (b"PONG\n", b"", 0), MISSING, MISSING, MISSING))
    r = make(client, Redis, REDIS)
    assert r.probe() == "PING"
    assert [c[0][0] for c in eng.calls] == ["redis-cli", "valkey-cli"]
    assert eng.calls[1][0][1:4] == ["--user", "app", "PING"] and eng.calls[1][1] == {"REDISCLI_AUTH": "pw"}
    with pytest.raises(ServiceError, match="no redis-cli in container"):
        r.probe()


@pytest.mark.parametrize("reply", [b"(error) NOAUTH Authentication required.\n", b"WRONGTYPE Operation against a key\n",
                                   b"ERR unknown command\n", b"NOPERM this user has no permissions\n"])
def test_redis_errors_on_exit_zero_are_raised(client, daemon, reply):
    Engine(daemon, "cache", REDIS, queue((reply, b"", 0)))
    with pytest.raises(ServiceError, match="redis: "):
        make(client, Redis, REDIS).info()


def test_redis_ops(client, daemon):
    info_text = (b"# Server\r\nredis_version:7.2.4\r\nuptime_in_seconds:5\r\n# Stats\r\nkeyspace_hits:3\r\n"
                 b"keyspace_misses:1\r\n# Replication\r\nrole:master\r\n")
    eng = Engine(daemon, "cache", REDIS, queue(
        (b"LOADING\n", b"", 0), (info_text, b"", 0), (b"# Stats\r\nkeyspace_hits:0\r\n", b"", 0),
        (b"\n", b"", 0), (b'{"key": "k", "type": "none", "ttl": -2}\n', b"", 0),
        (b"k1\n\nk2\n", b"", 0), (b'[{"key": "k1"}]\n', b"", 0),
        (b"ERR Error running script: @user_script:1: Script attempted to access nonexistent global variable\n", b"", 0),
        (b"(error) ERR Unknown Redis command called from script\n", b"", 0), (b"OK\n", b"", 0),
        (b"(error) ERR This Redis command is not allowed from script\n", b"", 0), (b"1\n2.5\nx\n", b"", 0)))
    r = make(client, Redis, REDIS)
    with pytest.raises(ServiceError, match="PING -> 'LOADING'"):
        r.probe()
    s = r.stats()
    assert (s["version"], s["hit_rate_percent"], s["role"], s["uptime_seconds"]) == ("7.2.4", 75.0, "master", 5)
    assert r.stats()["hit_rate_percent"] is None
    assert r.lua("return nil", []) is None
    assert r.get("k", limit=5)["type"] == "none"
    assert r.scan("k*", limit=10, type_="hash") == {"pattern": "k*", "count": 2, "truncated": False, "keys": [{"key": "k1"}]}
    assert eng.calls[5][0][-2:] == ["--type", "hash"]
    with pytest.raises(ServiceError, match="nonexistent global"):
        r.command(["GET", "k"])  # a real script error is not mistaken for "unscriptable"
    assert r.command(["SUBSCRIBE", "x"]) == {"reply": "OK", "via": "redis-cli"}
    assert r.command(["CLIENT", "LIST"]) == {"reply": [1, 2.5, "x"], "via": "redis-cli"}


def test_redis_password_from_file_secret(client, daemon):
    daemon.on("GET", "/containers/cache/archive", Reply(body=tar_of({"pw": b"s3cret\n"}), content_type="application/x-tar"))
    r = make(client, Redis, info("cache", "redis:7", ("REDIS_PASSWORD_FILE=/run/secrets/pw",)))
    assert r.password() == "s3cret" and r.url(reveal=True) == "redis://:s3cret@172.17.0.9:6379"
    assert r.url() == "redis://:***@172.17.0.9:6379"


# --- mongo ---------------------------------------------------------------------------------------

MONGO = info("mdb", "mongo:7", ("MONGO_INITDB_DATABASE=app",))


def test_mongo_js_env_and_results(client, daemon):
    eng = Engine(daemon, "mdb", MONGO, queue(
        (b'__AISB__[{"name": "users", "type": "collection", "count": 2}]\n', b"", 0),
        (b'__AISB__{"version": "7.0.1"}\n', b"", 0), (b"__AISB__1\n", b"", 0)))
    m = make(client, Mongo, MONGO)
    assert m.collections(None) == [{"name": "users", "type": "collection", "count": 2}]
    assert m.stats() == {"version": "7.0.1"}
    assert m.probe() == "ping ok=1"
    env = eng.calls[0][1]
    assert env == {"AISB_DB": "app"}  # no user/password when the container has none
    assert eng.calls[0][0][:4] == ["mongosh", "--quiet", "--norc", "--eval"]


@pytest.mark.parametrize(("result", "message"), [
    (MISSING, "mongosh not found in container"),
    ((b"", b"MongoServerError: Authentication failed.\n", 1), "Authentication failed"),
    ((b"SyntaxError: Unexpected token\n", b"", 0), "SyntaxError: Unexpected token"),
])
def test_mongo_js_failures(client, daemon, result, message):
    Engine(daemon, "mdb", MONGO, queue(result))
    with pytest.raises(ServiceError, match=message):
        make(client, Mongo, MONGO).js("return 1", database="other")


@pytest.mark.parametrize("bad", [("{x: 1}", "{}", "{}"), ("{}", "[", "{}"), ("{}", "{}", "nope")])
def test_mongo_find_validates_all_json_inputs(client, daemon, bad):
    eng = Engine(daemon, "mdb", MONGO, queue())
    with pytest.raises(ValueError, match="must be JSON"):
        make(client, Mongo, MONGO).find("c", filter_=bad[0], projection=bad[1], sort=bad[2], limit=1, database=None)
    assert eng.calls == []


# --- base adapter: detection, credentials, URLs ------------------------------------------------------

def test_target_from_sparse_inspect():
    t = Target.from_inspect({"Config": {"Env": ["A=1=2", "B"], "Entrypoint": ["tini", "--"], "Cmd": ["run", "--flag=v"],
                                        "ExposedPorts": {"9000/udp": {}, "80/tcp": {}}},
                             "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "", "HostPort": ""},
                                                                      {"HostIp": "", "HostPort": "8080"}],
                                                           "81/tcp": None},
                                                 "Networks": {"a": {"IPAddress": ""}, "b": {"IPAddress": "10.0.0.2"}}}})
    assert (t.name, t.env, t.cmd, t.exposed, t.published, t.ips, t.running) == (
        "", {"A": "1=2", "B": ""}, ("tini", "--", "run", "--flag=v"), (80, 9000), {80: ("0.0.0.0", 8080)},
        ("10.0.0.2",), False)
    assert t.arg("--flag") == "v" and t.arg("--") == "run" and t.arg("run") == "--flag=v" and t.arg("--nope") is None
    assert Target.from_inspect({}).image == ""


@pytest.mark.parametrize(("image", "env", "exposed", "kind", "why"), [
    ("acme/queue:1", ("RABBITMQ_ERLANG_COOKIE=x",), (5672,), "rabbitmq", "env RABBITMQ_ERLANG_COOKIE + port"),
    ("acme/queue:1", ("RABBITMQ_ERLANG_COOKIE=x",), (), None, ""),
    ("acme/search:1", (), (9200,), "elasticsearch", "port 9200"),
    ("confluentinc/cp-kafka:7", (), (), "kafka", "image confluentinc/cp-kafka:7"),
    ("registry:5000/team/mongo@sha256:abc", (), (), "mongo", "image registry:5000/team/mongo@sha256:abc"),
])
def test_detection_scores(image, env, exposed, kind, why):
    cls, reason = REGISTRY.detect(Target.from_inspect(info("x", image, env, exposed=exposed)))
    assert (cls.kind if cls else None, reason) == (kind, why)


@pytest.mark.parametrize(("ports", "ips", "expected", "note"), [
    (published(6379, 7000, "::"), (), "redis://[::1]:7000", False),
    (published(6379, 7000, "10.1.2.3"), (), "redis://10.1.2.3:7000", False),
    ({}, (), "redis://unpublished:6379", True),
])
def test_urls_by_binding(ports, ips, expected, note):
    r = Redis(None, Target.from_inspect(info("c", "redis:7", ports=ports, ips=ips)))  # type: ignore[arg-type]
    assert r.url() == expected and ("note" in r.connection_info()) is note


def test_url_quotes_credentials_and_database():
    from aisb.services.sql import Postgres
    pg = Postgres(None, Target.from_inspect(info("p", env=("POSTGRES_USER=a@b", "POSTGRES_PASSWORD=p/w:@",  # type: ignore[arg-type]
                                                               "POSTGRES_DB=my db"), ports=published(5432, 5433))))
    assert pg.url(reveal=True, host="db.local") == "postgresql://a%40b:p%2Fw%3A%40@db.local:5433/my%20db"
    assert pg.connection_info() == {"kind": "postgres", "user": "a@b", "database": "my db", "password": "***",
                                    "url": "postgresql://a%40b:***@127.0.0.1:5433/my%20db"}
    assert pg.connection_info(reveal=True)["password"] == "p/w:@"


def test_adapter_without_scheme_or_ports():
    class Bare(Adapter):
        kind = "bare"
        image_rx = __import__("re").compile("(?!)")
    b = Bare(None, Target.from_inspect(info("b", "x")))  # type: ignore[arg-type]
    assert (b.url(), b.reachability(), b.default_port(), b.user(), b.password(), b.database()) == (
        None, None, None, None, None, None)
    assert b.connection_info() == {"kind": "bare", "user": None, "database": None, "password": None, "url": None}
    assert REGISTRY.detect(Target.from_inspect(info("b", "busybox"))) == (None, "")


def test_read_file_empty_archive_and_run_errors(client, daemon):
    daemon.on("GET", "/containers/cache/archive", Reply(body=b"", content_type="application/x-tar"))
    Engine(daemon, "cache", REDIS, queue((b"out-only\n", b"", 3)))
    r = make(client, Redis, info("cache", "redis:7", ("REDIS_PASSWORD_FILE=/empty",)))
    assert r.read_file("/empty") == "" and r.password() is None  # an empty secret file means no password
    with pytest.raises(ServiceError, match="redis: sh exited 3: out-only"):
        r.run(["sh", "-c", "exit 3"])

