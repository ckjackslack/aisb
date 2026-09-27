"""`net` ops against the fake daemon: observed service graph (json, mermaid, declared vs observed), network map,
layer-by-layer probe failures, and `net tls` against real local TLS listeners (self-signed certs via openssl)."""

import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from aisb import Docker

from conftest import FakeDaemon

LISTEN, EST = "0A", "01"
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def hexaddr(ip: str, port: int) -> str:
    return f"{bytes(ipaddress.IPv4Address(ip).packed[::-1]).hex().upper()}:{port:04X}"


def table(*socks: tuple[str, int, str, int, str]) -> bytes:
    """/proc/net/tcp text for (local ip, local port, remote ip, remote port, state) rows."""
    rows = [f"   {i}: {hexaddr(a, p)} {hexaddr(b, q)} {st} 00000000:00000000 00:00000000 00000000 0 0 1\n"
            for i, (a, p, b, q, st) in enumerate(socks)]
    return (HEADER + "".join(rows)).encode()


def nets(**ips: str) -> dict:
    return {"NetworkSettings": {"Networks": {n: {"IPAddress": ip} for n, ip in ips.items()}}}


# --- graph / observe ---------------------------------------------------------------------------------------

WEB, DB = "10.0.0.2", "10.0.0.3"


def _topology(daemon: FakeDaemon, prefix: str = "", samples: int = 1) -> None:
    web, db, dless, other = (f"{prefix}{n}" for n in ("web", "db", "distroless", "other"))
    daemon.on("GET", "/containers/json", json=[
        {"Names": [f"/{web}"], **nets(app=WEB)},
        {"Names": [f"/{db}"], **nets(app=DB)},
        {"Names": [f"/{dless}"], **nets(app="10.0.0.4")},
        {"Names": [f"/{other}"], "NetworkSettings": {"Networks": {"none": {"IPAddress": ""}}}},
    ])
    web_socks = table(
        (WEB, 40000, DB, 5432, EST),           # web -> db:5432
        (WEB, 40001, DB, 9999, EST),           # to db, but db doesn't listen there: neither edge nor egress
        ("127.0.0.1", 40002, "127.0.0.1", 6379, EST),  # loopback: ignored
        (WEB, 40003, "93.184.216.34", 443, EST),       # egress
        (WEB, 40004, DB, 0, "06"),             # TIME_WAIT: ignored
    )
    db_socks = table(
        ("0.0.0.0", 5432, "0.0.0.0", 0, LISTEN),
        (DB, 5432, WEB, 40000, EST),           # the server side of web's edge: known peer, not a client
        (DB, 5432, "172.17.0.1", 5555, EST),   # an external client
    )
    daemon.execs(web, [(web_socks, b"", 0)] * samples)
    daemon.execs(db, [(db_socks, b"cat: can't open '/proc/net/tcp6'", 1)] * samples)
    daemon.execs(dless, [(b"", b"exec: cat: not found", 127)])
    daemon.execs(other, [(table(), b"", 0)] * samples)


def test_graph_edges_egress_clients_and_unobserved(client, daemon):
    _topology(daemon, samples=2)
    g = client.net.graph_(samples=2, interval=0)
    assert g["edges"] == [{"from": "web", "to": "db", "port": 5432, "connections": 2}]
    assert g["egress"] == [{"from": "web", "to": "93.184.216.34:443", "connections": 2}]
    assert g["external_clients"] == [{"client": "172.17.0.1", "to": "db", "port": 5432, "connections": 2}]
    nodes = {n["container"]: n for n in g["nodes"]}
    assert nodes["distroless"]["observed"] is False and nodes["db"]["listens"] == [5432]
    assert g["isolated"] == ["other"]
    # the distroless container is tried once and then skipped in later samples
    execs = [s.path for s in daemon.seen if s.method == "POST" and s.path.endswith("/exec")]
    assert execs.count("/containers/distroless/exec") == 1 and execs.count("/containers/web/exec") == 2


def test_observe_can_be_limited_to_some_containers(client, daemon):
    _topology(daemon)
    nodes = client.net.observe(containers=["web", "db"])
    assert sorted(nodes) == ["db", "web"] and nodes["web"].ips == {WEB}
    assert not any("/containers/other/exec" in p for _, p in daemon.calls("POST"))


def test_graph_mermaid(client, daemon):
    _topology(daemon)
    out = client.net.graph_(samples=1, format="mermaid")
    assert out["edges"] == 1
    lines = out["output"].splitlines()
    assert lines[0] == "graph LR" and '  n2["distroless (unobserved)"]' in lines
    assert "  n0 -->|5432| n1" in lines and '  n0 -.->|egress| x0(("93.184.216.34:443"))' in lines


def test_graph_compares_declared_dependencies_with_observed_traffic(client, daemon, tmp_path):
    _topology(daemon, prefix="shop-")
    stack = tmp_path / "stack.json"
    stack.write_text(json.dumps({"name": "shop", "services": {
        "db": {"image": "postgres:16"}, "cache": {"image": "redis:7"},
        "web": {"image": "web:1", "depends_on": ["cache"]},
    }}))
    g = client.net.graph_(samples=1, stack=str(stack))
    assert g["undeclared_dependencies"] == ["web -> db"]
    assert g["unused_declared"] == ["web -> cache"]


def test_graph_with_nothing_running(client, daemon):
    daemon.on("GET", "/containers/json", json=None)
    assert client.net.graph_(samples=1) == {"nodes": [], "edges": [], "egress": [], "external_clients": [],
                                            "isolated": []}


# --- map ------------------------------------------------------------------------------------------------------

def test_map_lists_members_aliases_and_flags_default_bridge(client, daemon):
    cid = "abcdef123456" + "0" * 52
    daemon.on("GET", "/networks", json=[
        {"Id": "h", "Name": "host"}, {"Id": "n", "Name": "none"},
        {"Id": "b", "Name": "bridge", "Driver": "bridge"},
        {"Id": "a", "Name": "app", "Driver": "bridge", "Internal": True},
        {"Id": "e", "Name": "empty", "Driver": "overlay"},
    ])
    daemon.on("GET", "/networks/b", json={"Containers": {"c2": {"Name": "old", "IPv4Address": "172.17.0.2/16"}}})
    daemon.on("GET", "/networks/a", json={"Containers": {
        cid: {"Name": "web", "IPv4Address": "10.0.0.2/24"}, "c3": {"Name": "db"}}})
    daemon.on("GET", "/networks/e", json=None)
    daemon.on("GET", f"/containers/{cid}/json",
              json={"NetworkSettings": {"Networks": {"app": {"Aliases": ["abcdef123456", "www", "frontend"]}}}})
    daemon.on("GET", "/containers/c2/json", json={})
    daemon.on("GET", "/containers/c3/json", json=None)
    out = client.net.map_()
    assert [n["network"] for n in out["networks"]] == ["app", "bridge", "empty"]
    app, bridge, empty = out["networks"]
    assert app == {"network": "app", "driver": "bridge", "internal": True, "dns_by_name": True, "containers": [
        {"container": "db", "ip": "", "aliases": []},
        {"container": "web", "ip": "10.0.0.2", "aliases": ["frontend", "www"]}]}
    assert bridge["dns_by_name"] is False and bridge["containers"][0]["ip"] == "172.17.0.2"
    assert empty == {"network": "empty", "driver": "overlay", "internal": False, "dns_by_name": True, "containers": []}


# --- probe -------------------------------------------------------------------------------------------------------

LISTEN_5432 = table(("0.0.0.0", 5432, "0.0.0.0", 0, LISTEN))


def _src(daemon: FakeDaemon, **ips: str) -> None:
    daemon.on("GET", "/containers/api/json", json={"Name": "/api", **nets(**(ips or {"app": "10.0.0.2"}))})


def _dst(daemon: FakeDaemon, name: str = "db", **ips: str) -> None:
    daemon.on("GET", f"/containers/{name}/json", json={"Name": f"/{name}", "Config": {"ExposedPorts": {"5432/tcp": {}}},
                                                      **nets(**(ips or {"app": "10.0.0.3"}))})


def test_probe_all_layers_ok(client, daemon):
    _src(daemon)
    _dst(daemon)
    daemon.execs("db", [(LISTEN_5432, b"", 0)])
    created = daemon.execs("api", [(b"IP 10.0.0.3\n", b"", 0), (b"OK nc\n", b"", 0)])
    out = client.net.probe("api", "db")
    assert (out["ok"], out["broken_at"], out["port"], out["dst"]) == (True, None, 5432, "db")
    assert [(s["step"], s["ok"]) for s in out["steps"]] == [
        ("shared-network", True), ("listening", True), ("dns", True), ("tcp", True)]
    assert out["steps"][3]["via"] == "nc" and created[1].body["Cmd"][-2:] == ["10.0.0.3", "5432"]


def test_probe_finds_destination_by_dns_alias_on_a_later_network(client, daemon):
    daemon.on("GET", "/containers/api/json", json={"Name": "/api", **nets(front="10.1.0.2", app="10.0.0.2")})
    daemon.on("GET", "/containers/cache/json", status=404, json={"message": "No such container: cache"})
    daemon.on("GET", "/networks/front", json={"Containers": {"api-id": {}}})
    daemon.on("GET", "/networks/app", json={"Containers": {"api-id": {}, "redis-id": {}}})
    daemon.on("GET", "/containers/api-id/json", json={"Name": "/api", **nets(front="10.1.0.2", app="10.0.0.2")})
    daemon.on("GET", "/containers/redis-id/json", json={
        "Name": "/redis-1", "Config": {"ExposedPorts": {"6379/tcp": {}}},
        "NetworkSettings": {"Networks": {"app": {"IPAddress": "10.0.0.9", "Aliases": ["cache", "redis"]}}}})
    daemon.execs("redis-1", [(table(("0.0.0.0", 6379, "0.0.0.0", 0, LISTEN)), b"", 0)])
    daemon.execs("api", [(b"IP 10.0.0.9\n", b"", 0), (b"OK bash\n", b"", 0)])
    out = client.net.probe("api", "cache")
    assert (out["ok"], out["dst"], out["port"]) == (True, "redis-1", 6379)
    assert out["steps"][0]["networks"] == ["app"]


def test_probe_external_host(client, daemon):
    daemon.on("GET", "/containers/api/json", json={"Name": "/api", **nets(app="10.0.0.2")})
    daemon.on("GET", "/containers/example.com/json", status=404, json={"message": "no such container"})
    daemon.on("GET", "/networks/app", json={"Containers": {"api-id": {}}})
    daemon.on("GET", "/containers/api-id/json", json={"Name": "/api", **nets(app="10.0.0.2")})
    daemon.execs("api", [(b"IP 93.184.216.34\n", b"", 0), (b"OK python3\n", b"", 0)])
    out = client.net.probe("api", "example.com", port=443)
    assert out["ok"] is True and out["dst"] == "example.com"
    assert [s["step"] for s in out["steps"]] == ["dns", "tcp"]


def test_probe_external_host_without_port_is_an_error(client, daemon):
    daemon.on("GET", "/containers/api/json", json={"Name": "/api"})
    daemon.on("GET", "/containers/example.com/json", status=404, json={"message": "no such container"})
    with pytest.raises(ValueError, match="no --port given and 'example.com' exposes none"):
        client.net.probe("api", "example.com")


@pytest.mark.parametrize(("src_nets", "dst_nets", "ok", "detail"), [
    ({"bridge": "172.17.0.2"}, {"bridge": "172.17.0.3"}, False, "only the default bridge: no DNS by container name"),
    ({"front": "10.1.0.2"}, {"back": "10.2.0.3"}, False, "api is on ['front'], db on ['back']"),
])
def test_probe_network_problems(client, daemon, src_nets, dst_nets, ok, detail):
    _src(daemon, **src_nets)
    _dst(daemon, **dst_nets)
    daemon.execs("db", [(LISTEN_5432, b"", 0)])
    daemon.execs("api", [(b"", b"", 2), (b"FAIL nc\n", b"", 0)])
    out = client.net.probe("api", "db")
    step = out["steps"][0]
    assert (step["ok"], step["detail"]) == (ok, detail)
    assert step["fix"].startswith("aisb networks create app-net")
    assert out["broken_at"] == "shared-network" and out["ok"] is False


@pytest.mark.parametrize(("proc", "ok", "detail"), [
    (table(("0.0.0.0", 8080, "0.0.0.0", 0, LISTEN)), False, "nothing listens on port 5432 in db"),
    (table(("127.0.0.1", 5432, "0.0.0.0", 0, LISTEN)), False,
     "db listens on 5432 on loopback only: other containers can't connect"),
    (b"", None, "can't read /proc/net/tcp in db (no cat)"),
])
def test_probe_listening_step(client, daemon, proc, ok, detail):
    _src(daemon)
    _dst(daemon)
    daemon.execs("db", [(proc, b"", 0 if proc else 127)])
    daemon.execs("api", [(b"IP 10.0.0.3\n", b"", 0), (b"FAIL nc\n", b"", 0)])
    out = client.net.probe("api", "db")
    step = out["steps"][1]
    assert (step["step"], step["ok"], step["detail"]) == ("listening", ok, detail)
    assert out["ok"] is False


@pytest.mark.parametrize(("code", "stderr"), [(127, b""), (126, b""), (1, b"OCI runtime exec failed: exec: \"sh\": "
                                                                            b"executable file not found in $PATH")])
def test_probe_source_without_shell(client, daemon, code, stderr):
    _src(daemon)
    _dst(daemon)
    daemon.execs("db", [(LISTEN_5432, b"", 0)])
    daemon.execs("api", [(b"", stderr, code)])
    out = client.net.probe("api", "db")
    assert out["ok"] is None and out["detail"] == "api has no shell; run the checks from a sidecar"
    assert out["next"] == ["aisb containers debug api -- nc -zv db 5432"]
    assert [s["step"] for s in out["steps"]] == ["shared-network", "listening"]


@pytest.mark.parametrize(("dns_out", "tcp_out", "dns", "tcp", "ok", "broken"), [
    # no resolver tool: dns undetermined; tcp to the name still works
    (b"NOTOOL\n", b"OK nc\n", (None, None, "no resolver tool in the source image"), (True, "nc", None), True, None),
    # name doesn't resolve, connection to the name fails
    (b"", b"FAIL bash\n", (False, None, "'db' does not resolve from api"),
     (False, "bash", "connection to db:5432 failed"), False, "dns"),
    # resolves, but connection fails
    (b"IP 10.0.0.3\n", b"FAIL nc\n", (True, "10.0.0.3", None),
     (False, "nc", "connection to 10.0.0.3:5432 failed"), False, "tcp"),
    # no tcp tool: undetermined overall
    (b"IP 10.0.0.3\n", b"NOTOOL\n", (True, "10.0.0.3", None),
     (None, None, "no nc/bash/python3 in the source image"), False, None),
    # the tcp check printed nothing at all
    (b"IP 10.0.0.3\n", b"", (True, "10.0.0.3", None),
     (False, None, "connection to 10.0.0.3:5432 failed"), False, "tcp"),
])
def test_probe_dns_and_tcp_steps(client, daemon, dns_out, tcp_out, dns, tcp, ok, broken):
    _src(daemon)
    _dst(daemon)
    daemon.execs("db", [(LISTEN_5432, b"", 0)])
    daemon.execs("api", [(dns_out, b"", 0), (tcp_out, b"", 0)])
    out = client.net.probe("api", "db")
    d, t = out["steps"][2], out["steps"][3]
    assert (d["ok"], d["resolved"], d["detail"]) == dns
    assert (t["ok"], t["via"], t["detail"]) == tcp
    assert (out["ok"], out["broken_at"]) == (ok, broken)


# --- tls -----------------------------------------------------------------------------------------------------------

def _cert(d: Path, name: str, days: int) -> Path:
    crt = d / f"{name}.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", str(days),
                    "-subj", f"/CN={name}", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                    "-keyout", str(crt.with_suffix(".key")), "-out", str(crt)], check=True, capture_output=True)
    return crt


@pytest.fixture(scope="module")
def certs(tmp_path_factory) -> dict[str, Path]:
    if not shutil.which("openssl"):
        pytest.skip("needs the openssl CLI to make test certificates")
    d = tmp_path_factory.mktemp("net-tls")
    return {"short": _cert(d, "short.test", 2), "long": _cert(d, "long.test", 90)}


class TLSServer:
    """Accepts connections on 127.0.0.1; `behaviour(n)` for the n-th connection: 'tls' (handshake) or 'close'."""

    def __init__(self, cert: Path | None, behaviour: Callable[[int], str]) -> None:
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.sock.settimeout(0.02)  # accept() polls so close() can stop the thread
        self.stopped = threading.Event()
        self.port = self.sock.getsockname()[1]
        self.ctx = None
        if cert:
            self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ctx.load_cert_chain(cert, cert.with_suffix(".key"))
        self.behaviour, self.n = behaviour, 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stopped.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5)
            self.n += 1
            with conn:
                if self.behaviour(self.n) == "tls" and self.ctx:
                    try:
                        with self.ctx.wrap_socket(conn, server_side=True) as s:
                            s.recv(1)
                    except OSError:
                        pass

    def close(self) -> None:
        self.stopped.set()
        self.thread.join(5)
        self.sock.close()


@pytest.fixture
def tls_server() -> Iterator[Callable[..., TLSServer]]:
    servers: list[TLSServer] = []

    def start(cert: Path | None, behaviour: Callable[[int], str] = lambda n: "tls") -> TLSServer:
        servers.append(TLSServer(cert, behaviour))
        return servers[-1]
    yield start
    for s in servers:
        s.close()


def _published(daemon: FakeDaemon, port: int, host_ip: str = "0.0.0.0") -> None:
    daemon.on("GET", "/containers/web/json", json={"Name": "/web", "NetworkSettings": {
        "Ports": {"443/tcp": [{"HostIp": host_ip, "HostPort": str(port)}]}}})


def test_tls_self_signed_expiring_cert(client, daemon, certs, tls_server, monkeypatch, tmp_path):
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "empty.pem"))  # trust nothing
    (tmp_path / "empty.pem").write_text("")
    srv = tls_server(certs["short"])
    _published(daemon, srv.port)
    out = client.net.tls("web")
    assert out["endpoint"] == f"127.0.0.1:{srv.port}" and out["via"] == f"published 127.0.0.1:{srv.port} -> 443"
    assert out["subject"] == "commonName=short.test" == out["issuer"] and out["self_signed"] is True
    assert sorted(out["san"]) == ["127.0.0.1", "localhost"]
    assert out["verified"] is False and "self-signed" in out["verify_error"]
    assert 0 < out["days_left"] <= 2 and out["expired"] is False
    assert out["ok"] is False and out["reason"] == f"certificate expires in {out['days_left']} days"
    assert out["protocol"].startswith("TLS") and out["cipher"]


def test_tls_trusted_cert_with_time_left(client, daemon, certs, tls_server, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(certs["long"]))
    srv = tls_server(certs["long"])
    _published(daemon, srv.port)
    out = client.net.tls("web", server_name="localhost")
    assert out["verified"] is True and "verify_error" not in out
    assert out["ok"] is True and "reason" not in out and 89 < out["days_left"] <= 90


def test_tls_verification_connection_dropped(client, daemon, certs, tls_server):
    srv = tls_server(certs["long"], lambda n: "tls" if n == 1 else "close")
    _published(daemon, srv.port)
    out = client.net.tls("web", seconds=5)
    assert out["verified"] is False and out["verify_error"]
    assert out["subject"] == "commonName=long.test"


@pytest.mark.parametrize("kind", ["refused", "plain"])
def test_tls_handshake_failure(client, daemon, tls_server, kind):
    if kind == "refused":
        s = socket.create_server(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
    else:
        port = tls_server(None, lambda n: "close").port  # accepts TCP, never speaks TLS
    _published(daemon, port)
    out = client.net.tls("web", seconds=5)
    assert out["ok"] is False and out["reason"].startswith(f"TLS handshake with 127.0.0.1:{port} failed: ")
    assert out["via"] == f"published 127.0.0.1:{port} -> 443"


def test_tls_via_fleet_dialer(daemon, certs, tls_server, host):
    """A fleet host dials through a forwarder: `t.reach` maps the Docker-host address to a local one."""
    srv = tls_server(certs["long"])
    daemon.on("GET", "/containers/web/json", json={"Name": "/web", **nets(app="10.9.9.9")})
    d = Docker(host, timeout=5)
    d.transport.dialer = lambda h, p: ("127.0.0.1", srv.port) if (h, p) == ("10.9.9.9", 8443) else (h, p)
    out = d.net.tls("web", port=8443)
    assert out["endpoint"] == "10.9.9.9:8443" and out["subject"] == "commonName=long.test"
    assert out["via"].startswith("container IP 10.9.9.9:8443")
