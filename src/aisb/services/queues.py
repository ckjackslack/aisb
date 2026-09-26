"""Message brokers and search: Kafka and RabbitMQ via their CLIs inside the container, Elasticsearch/OpenSearch over HTTP."""

import base64
import http.client
import json
import re
import ssl
from typing import Any
from urllib.parse import quote

from .base import Adapter, ServiceError, register

# Kafka images put the scripts in different places (and Confluent drops the .sh suffix).
_KAFKA = r'''T="$1"; shift
for c in "$T.sh" "/opt/kafka/bin/$T.sh" "/opt/bitnami/kafka/bin/$T.sh" "$T"; do
  if command -v "$c" >/dev/null 2>&1; then exec "$c" "$@"; fi
done
echo "no $T in this image" >&2; exit 127'''


def parse_kafka_table(text: str) -> list[dict[str, str]]:
    """Whitespace-aligned CLI tables (kafka-consumer-groups) -> records; repeated headers start new blocks."""
    rows: list[dict[str, str]] = []
    header: list[str] = []
    for line in text.splitlines():
        cells = line.split()
        if not cells:
            continue
        if cells[0] == "GROUP" and "TOPIC" in cells:
            header = cells
            continue
        if header and len(cells) >= len(header) - 3:  # CONSUMER-ID/HOST/CLIENT-ID are "-" or absent when idle
            rows.append(dict(zip(header, cells + ["-"] * (len(header) - len(cells)))))
    return rows


def _num(v: str) -> int | None:
    return int(v) if v.lstrip("-").isdigit() else None


@register
class Kafka(Adapter):
    kind = "kafka"
    image_rx = re.compile(r"^(kafka|cp-kafka|cp-server)$")
    env_hints = ("KAFKA_",)
    ports = (9092,)
    scheme = "kafka"

    def bootstrap(self) -> str:
        return self.t.env.get("AISB_KAFKA_BOOTSTRAP", "localhost:9092")

    def tool(self, name: str, *args: str) -> str:
        res = self.run(["sh", "-c", _KAFKA, "_", name, "--bootstrap-server", self.bootstrap(), *args], check=False)
        if not res.ok:
            raise ServiceError(f"kafka: {name} exited {res.code}: {(res.stderr or res.stdout).strip()[-1500:]}")
        return res.stdout

    def topics(self, *, internal: bool = False) -> list[dict[str, Any]]:
        out, topics = self.tool("kafka-topics", "--describe"), {}
        for line in out.splitlines():
            if line.startswith("Topic:") and "PartitionCount" in line:
                f = dict(re.findall(r"(\w+):\s*(\S*)", line))
                topics[f["Topic"]] = {"topic": f["Topic"], "partitions": _num(f.get("PartitionCount", "")),
                                      "replication": _num(f.get("ReplicationFactor", "")), "under_replicated": 0}
            elif (m := re.search(r"Topic:\s*(\S+)\s+Partition:.*Replicas:\s*(\S+)\s+Isr:\s*(\S+)", line)) and m[1] in topics:
                if len(m[3].split(",")) < len(m[2].split(",")):
                    topics[m[1]]["under_replicated"] += 1
        return sorted((t for t in topics.values() if internal or not t["topic"].startswith("__")),
                      key=lambda t: t["topic"])

    def groups(self) -> list[dict[str, Any]]:
        rows = parse_kafka_table(self.tool("kafka-consumer-groups", "--describe", "--all-groups"))
        out: dict[str, dict[str, Any]] = {}
        for r in rows:
            g = out.setdefault(r["GROUP"], {"group": r["GROUP"], "lag": 0, "topics": set(), "members": set(), "partitions": 0})
            g["lag"] += _num(r.get("LAG", "")) or 0
            g["topics"].add(r.get("TOPIC"))
            g["partitions"] += 1
            if r.get("CONSUMER-ID", "-") != "-":
                g["members"].add(r["CONSUMER-ID"])
        return [{**g, "topics": sorted(g["topics"]), "members": len(g["members"]), "idle": not g["members"]}
                for g in sorted(out.values(), key=lambda g: -g["lag"])]

    def peek(self, topic: str, *, limit: int, seconds: int) -> list[dict[str, Any]]:
        """Read without a consumer group: nothing is committed, other consumers are unaffected."""
        res = self.run(["sh", "-c", _KAFKA, "_", "kafka-console-consumer", "--bootstrap-server", self.bootstrap(),
                        "--topic", topic, "--from-beginning", "--max-messages", str(limit), "--timeout-ms",
                        str(seconds * 1000), "--property", "print.partition=true", "--property", "print.offset=true",
                        "--property", "print.key=true", "--property", "print.timestamp=true"], check=False)
        if res.code not in (0, 1, None) and "TimeoutException" not in res.stderr:
            raise ServiceError(f"kafka: console consumer exited {res.code}: {res.stderr.strip()[-1500:]}")
        msgs = []
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            meta = dict(p.split(":", 1) for p in parts if re.match(r"^(CreateTime|LogAppendTime|Partition|Offset):", p))
            rest = [p for p in parts if not re.match(r"^(CreateTime|LogAppendTime|Partition|Offset|NO_TIMESTAMP)", p)]
            key, value = (rest[0], "\t".join(rest[1:])) if len(rest) > 1 else (None, rest[0] if rest else "")
            msgs.append({"partition": _num(meta.get("Partition", "")), "offset": _num(meta.get("Offset", "")),
                         "timestamp": _num(meta.get("CreateTime", meta.get("LogAppendTime", ""))),
                         "key": None if key == "null" else key, "value": value})
        return msgs

    def probe(self) -> str:
        self.tool("kafka-topics", "--list")
        return "kafka-topics --list"

    def stats(self) -> dict[str, Any]:
        topics = self.topics()
        return {"topics": len(topics), "under_replicated_partitions": sum(t["under_replicated"] for t in topics),
                "groups": self.groups()}


@register
class RabbitMQ(Adapter):
    kind = "rabbitmq"
    image_rx = re.compile(r"^rabbitmq")
    env_hints = ("RABBITMQ_",)
    ports = (5672,)
    scheme = "amqp"

    def user(self) -> str:
        return self.secret("RABBITMQ_DEFAULT_USER") or "guest"

    def password(self) -> str:
        return self.secret("RABBITMQ_DEFAULT_PASS") or "guest"

    def database(self) -> str | None:
        vhost = self.secret("RABBITMQ_DEFAULT_VHOST")
        return None if vhost in (None, "/") else vhost

    def ctl(self, *args: str) -> Any:
        res = self.run(["rabbitmqctl", "-q", *args, "--formatter", "json"])
        text = res.stdout.strip()
        return json.loads(text) if text else []

    def queues(self, vhost: str) -> list[dict[str, Any]]:
        rows = self.ctl("list_queues", "-p", vhost, "name", "type", "messages", "messages_ready",
                        "messages_unacknowledged", "consumers", "state")
        return sorted(rows, key=lambda r: -(r.get("messages") or 0))

    def exchanges(self, vhost: str) -> list[dict[str, Any]]:
        return [r for r in self.ctl("list_exchanges", "-p", vhost, "name", "type", "durable") if r.get("name")]

    def peek(self, queue: str, *, vhost: str, limit: int) -> list[dict[str, Any]]:
        """Management API get with requeue: messages go back to the queue (they get the redelivered flag)."""
        port = 15672
        host, hport = (("127.0.0.1", self.t.published[port][1]) if port in self.t.published
                       else (self.t.ips[0], port) if self.t.ips else (None, None))
        if host is None:
            raise ServiceError("rabbitmq: management API not reachable (use a *-management image)")
        conn = http.client.HTTPConnection(host, hport, timeout=10)
        auth = base64.b64encode(f"{self.user()}:{self.password()}".encode()).decode()
        body = json.dumps({"count": limit, "ackmode": "ack_requeue_true", "encoding": "auto", "truncate": 50000})
        try:
            conn.request("POST", f"/api/queues/{quote(vhost, safe='')}/{quote(queue, safe='')}/get", body=body,
                         headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read()
        except OSError as e:
            raise ServiceError(f"rabbitmq: management API unreachable at {host}:{hport}: {e}") from None
        finally:
            conn.close()
        if resp.status >= 400:
            raise ServiceError(f"rabbitmq: management API {resp.status}: {data[:300].decode(errors='replace')}")
        return [{"routing_key": m.get("routing_key"), "exchange": m.get("exchange"), "redelivered": m.get("redelivered"),
                 "properties": m.get("properties"), "payload": m.get("payload"), "encoding": m.get("payload_encoding")}
                for m in json.loads(data)]

    def probe(self) -> str:
        self.run(["rabbitmq-diagnostics", "-q", "ping"])
        return "rabbitmq-diagnostics ping"

    def stats(self) -> dict[str, Any]:
        queues = self.queues(self.database() or "/")
        conns = self.ctl("list_connections", "name")
        alarms = self.run(["rabbitmq-diagnostics", "-q", "alarms"], check=False).stdout.strip()
        return {"queues": len(queues), "messages": sum(q.get("messages") or 0 for q in queues),
                "unacked": sum(q.get("messages_unacknowledged") or 0 for q in queues),
                "queues_without_consumers": [q["name"] for q in queues if not q.get("consumers") and q.get("messages")],
                "connections": len(conns), "alarms": None if not alarms or "no alarms" in alarms else alarms,
                "top_queues": queues[:5]}


@register
class Search(Adapter):
    kind = "elasticsearch"
    image_rx = re.compile(r"^(elasticsearch|opensearch)$")
    env_hints = ("ELASTIC_", "OPENSEARCH_")
    ports = (9200,)
    scheme = "http"

    def user(self) -> str | None:
        return "admin" if "opensearch" in self.t.image else "elastic" if self.password() else None

    def password(self) -> str | None:
        return self.secret("ELASTIC_PASSWORD", "OPENSEARCH_INITIAL_ADMIN_PASSWORD")

    def request(self, method: str, path: str, body: Any = None) -> Any:
        port = 9200
        host, hport = (("127.0.0.1", self.t.published[port][1]) if port in self.t.published
                       else (self.t.ips[0], port) if self.t.ips else (None, None))
        if host is None:
            raise ServiceError("elasticsearch: port 9200 is neither published nor reachable by IP")
        headers = {"Content-Type": "application/json"}
        if self.password():
            headers["Authorization"] = "Basic " + base64.b64encode(f"{self.user()}:{self.password()}".encode()).decode()
        payload = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None
        for tls in (False, True):  # 8.x / OpenSearch default to TLS with a self-signed cert
            conn = http.client.HTTPSConnection(host, hport, timeout=15, context=ssl._create_unverified_context()) \
                if tls else http.client.HTTPConnection(host, hport, timeout=15)  # noqa: S323
            try:
                conn.request(method, path, body=payload, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
            except (OSError, http.client.HTTPException) as e:
                last = e
                continue
            finally:
                conn.close()
            if resp.status >= 400:
                raise ServiceError(f"elasticsearch: {method} {path} -> {resp.status}: {data[:500].decode(errors='replace')}")
            return json.loads(data) if data else None
        raise ServiceError(f"elasticsearch: unreachable at {host}:{hport}: {last}")

    def probe(self) -> str:
        status = self.request("GET", "/_cluster/health").get("status")
        if status not in ("green", "yellow"):
            raise ServiceError(f"elasticsearch: cluster status {status}")
        return f"cluster {status}"

    def stats(self) -> dict[str, Any]:
        h = self.request("GET", "/_cluster/health")
        return {k: h.get(k) for k in ("cluster_name", "status", "number_of_nodes", "active_shards",
                                      "unassigned_shards", "active_shards_percent_as_number")}

    def indices(self) -> list[dict[str, Any]]:
        rows = self.request("GET", "/_cat/indices?format=json&bytes=b&s=index") or []
        return [{"index": r.get("index"), "health": r.get("health"), "docs": _num(r.get("docs.count") or ""),
                 "bytes": _num(r.get("store.size") or ""), "primaries": _num(r.get("pri") or ""),
                 "replicas": _num(r.get("rep") or "")} for r in rows if not str(r.get("index", "")).startswith(".")]

    def search(self, index: str, query: dict[str, Any], *, limit: int) -> dict[str, Any]:
        res = self.request("POST", f"/{quote(index, safe=',*')}/_search", {**query, "size": limit})
        hits = res.get("hits", {})
        total = hits.get("total")
        return {"took_ms": res.get("took"), "total": total.get("value") if isinstance(total, dict) else total,
                "hits": [{"index": h.get("_index"), "id": h.get("_id"), "score": h.get("_score"), **(h.get("_source") or {})}
                         for h in hits.get("hits", [])],
                **({"aggregations": res["aggregations"]} if "aggregations" in res else {})}
