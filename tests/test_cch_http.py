"""http get/send/record/replay against a real local HTTP server (the "container"), plus the pcap/HTTP parsing and
body comparison in insights.traffic. Only the Docker daemon, the clock's sleep and the network edge are faked."""

import http.client
import json
import socket
import struct
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aisb.insights import traffic
from aisb.ops import Tier, get_op, invoke
from aisb.transport import Endpoint, Transport

from conftest import Reply, Seen, tar_of

# --- a real upstream "container" ---------------------------------------------------------------

Route = tuple[int, dict[str, str], bytes]


class Upstream:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Route | Callable[[dict[str, Any]], Route]] = {}
        self.seen: list[dict[str, Any]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: Any) -> None:
                pass

            def _any(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                req = {"method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": body}
                outer.seen.append(req)
                route = outer.routes.get((self.command, self.path)) or outer.routes.get(("*", self.path)) or \
                    (404, {"Content-Type": "text/plain"}, b"nope")
                status, headers, data = route(req) if callable(route) else route
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def up() -> Iterator[Upstream]:
    u = Upstream()
    yield u
    u.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ctr(name: str = "api", *, published: dict[int, tuple[str, int]] | None = None, exposed: tuple[int, ...] = (),
        ips: tuple[str, ...] = ("10.9.9.9",)) -> dict[str, Any]:
    return {"Id": f"{name}-full-id", "Name": f"/{name}",
            "Config": {"Image": "shop/api:1", "ExposedPorts": {f"{p}/tcp": {} for p in exposed}},
            "NetworkSettings": {"Ports": {f"{c}/tcp": [{"HostIp": ip, "HostPort": str(h)}]
                                          for c, (ip, h) in (published or {}).items()},
                                "Networks": {f"n{i}": {"IPAddress": ip} for i, ip in enumerate(ips)}},
            "State": {"Running": True}}


def serve(daemon, up: Upstream, name: str = "api") -> None:
    daemon.on("GET", f"/containers/{name}/json", json=ctr(name, published={8080: ("127.0.0.1", up.port)}))


# --- resolve -----------------------------------------------------------------------------------


@pytest.mark.parametrize(("inspect", "port", "want"), [
    (ctr(published={80: ("0.0.0.0", 18080)}), None, ("127.0.0.1", 18080, "published 127.0.0.1:18080 -> 80")),
    (ctr(published={80: ("", 18080)}), 80, ("127.0.0.1", 18080, "published 127.0.0.1:18080 -> 80")),
    (ctr(published={80: ("::", 18080)}), None, ("::1", 18080, "published ::1:18080 -> 80")),
    (ctr(published={80: ("192.168.1.4", 1), 443: ("0.0.0.0", 2)}), None, ("192.168.1.4", 1, "published 192.168.1.4:1 -> 80")),
    (ctr(exposed=(9000, 9001)), None, ("10.9.9.9", 9000, "container IP 10.9.9.9:9000 (not published; reachable from a Linux Docker host)")),
    (ctr(), None, ("10.9.9.9", 80, "container IP 10.9.9.9:80 (not published; reachable from a Linux Docker host)")),
    (ctr(published={80: ("0.0.0.0", 1)}), 5000, ("10.9.9.9", 5000, "container IP 10.9.9.9:5000 (not published; reachable from a Linux Docker host)")),
])
def test_resolve(client, daemon, inspect, port, want):
    daemon.on("GET", "/containers/api/json", json=inspect)
    assert client.http.resolve("api", port) == want


def test_resolve_unreachable(client, daemon):
    daemon.on("GET", "/containers/api/json", json=ctr(ips=()))
    with pytest.raises(ValueError, match="not published and the container has no IP"):
        client.http.resolve("api", None)


def test_resolve_remote_docker_host_uses_its_hostname(daemon):
    from aisb.api.http import Http
    t = Transport(Endpoint("tcp://docker.example:2375"))
    t._version = "1.43"
    calls: list[str] = []
    t.json = lambda method, path, **kw: calls.append(path) or ctr(published={80: ("0.0.0.0", 18080)})  # type: ignore[method-assign]
    assert Http(t).resolve("api", None)[:2] == ("docker.example", 18080)


def test_tiers():
    assert get_op("http.get").tier is Tier.READ and get_op("http.record").tier is Tier.READ
    assert get_op("http.send").tier is Tier.MUTATE and get_op("http.replay").tier is Tier.MUTATE


# --- get / send --------------------------------------------------------------------------------


def test_get_json_with_headers_masked_cookie(client, daemon, up):
    serve(daemon, up)
    up.routes[("GET", "/health")] = (200, {"Content-Type": "application/json", "Set-Cookie": "sid=secret",
                                           "X-Request-Id": "r1", "X-Other": "hidden"}, b'{"ok": true}')
    r = client.http.get("api", "health", header=["X-Trace=1"])
    assert r["ok"] and r["status"] == 200 and r["body"] == {"ok": True} and not r["truncated"]
    assert r["url"] == f"http://127.0.0.1:{up.port}/health"
    assert r["headers"]["set-cookie"] == "***" and r["headers"]["x-request-id"] == "r1" and "x-other" not in r["headers"]
    assert up.seen[0]["headers"]["User-Agent"] == "aisb" and up.seen[0]["headers"]["X-Trace"] == "1"


@pytest.mark.parametrize(("ctype", "data", "max_bytes", "body", "truncated"), [
    ("application/json", b"{not json", 100, "{not json", False),
    ("application/json", b'{"a": 1234567}', 5, '{"a":', True),       # truncated JSON is shown as text
    ("text/plain", b"hello", 100, "hello", False),
    ("application/octet-stream", b"\x00\x01\x02", 100, "<3 bytes application/octet-stream>", False),
    ("", b"\x00\x01", 100, "<2 bytes binary>", False),
    ("application/octet-stream", b"plain enough", 100, "plain enough", False),
])
def test_get_body_rendering(client, daemon, up, ctype, data, max_bytes, body, truncated):
    serve(daemon, up)
    up.routes[("GET", "/")] = (200, {"Content-Type": ctype} if ctype else {}, data)
    r = client.http.get("api", max_bytes=max_bytes)
    assert (r["body"], r["truncated"]) == (body, truncated)


def test_get_http_error_and_head(client, daemon, up):
    serve(daemon, up)
    up.routes[("*", "/x")] = (503, {"Content-Type": "text/plain", "Retry-After": "5"}, b"busy")
    r = client.http.get("api", "/x")
    assert r["ok"] is False and r["status"] == 503 and r["reason"] == "Service Unavailable"
    assert r["headers"]["retry-after"] == "5"
    assert client.http.get("api", "/x", head=True)["body"] == ""
    assert up.seen[-1]["method"] == "HEAD"


def test_get_connection_refused_is_reported_not_raised(client, daemon):
    port = free_port()
    daemon.on("GET", "/containers/api/json", json=ctr(published={80: ("127.0.0.1", port)}))
    r = client.http.get("api", "/")
    assert r["ok"] is False and r["error"].startswith("ConnectionRefusedError") and r["url"].endswith(f":{port}/")


def test_get_https_against_plain_http_fails_cleanly(client, daemon, up):
    serve(daemon, up)
    r = client.http.get("api", https=True, insecure=True, seconds=2)
    assert r["ok"] is False and r["url"].startswith("https://")


def test_send_json_and_data_and_file(client, daemon, up, tmp_path):
    serve(daemon, up)
    up.routes[("*", "/items")] = (201, {"Content-Type": "application/json"}, b'{"id": 1}')
    r = client.http.send("api", "/items", json_data='{"a":  1}')
    assert r["status"] == 201 and up.seen[-1]["body"] == b'{"a": 1}'
    assert up.seen[-1]["headers"]["Content-Type"] == "application/json"
    client.http.send("api", "/items", method="put", data="raw body")
    assert (up.seen[-1]["method"], up.seen[-1]["body"]) == ("PUT", b"raw body")
    (tmp_path / "b.bin").write_bytes(b"from file")
    client.http.send("api", "/items", data=f"@{tmp_path / 'b.bin'}")
    assert up.seen[-1]["body"] == b"from file"
    client.http.send("api", "/items", method="DELETE")
    assert (up.seen[-1]["method"], up.seen[-1]["body"]) == ("DELETE", b"")


def test_send_invalid_json_is_rejected_before_any_request(client, daemon, up):
    serve(daemon, up)
    with pytest.raises(ValueError):
        client.http.send("api", "/items", json_data="{nope")
    assert up.seen == [] and daemon.calls() == []


def test_send_dry_run_notes_request_masks_secrets_and_sends_nothing(client, daemon, up):
    serve(daemon, up)
    out = invoke(client, get_op("http.send"), {"ref": "api", "path": "/items", "method": "patch", "data": "abc",
                                               "header": ["Authorization=Bearer x", "X-Api-Key=k", "Cookie=sid=1",
                                                          "X-Mode=a"]},
                 dry_run=True)
    assert out.planned == [{"http": "PATCH", "url": f"http://127.0.0.1:{up.port}/items",
                            "via": f"published 127.0.0.1:{up.port} -> 8080",
                            "headers": {"Authorization": "***", "X-Api-Key": "***", "Cookie": "***", "X-Mode": "a"},
                            "body_bytes": 3}]
    assert up.seen == []


# --- record (proxy) ----------------------------------------------------------------------------


def record_with(monkeypatch, traffic_fn: Callable[[int], None], listen: int) -> None:
    """Replace the recording window with real client traffic sent through the proxy."""
    def sleep(_s: float) -> None:
        traffic_fn(listen)
    monkeypatch.setattr("aisb.api.http.time.sleep", sleep)


def call(port: int, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None
         ) -> tuple[int, bytes]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def test_record_proxy_forwards_and_records_with_secrets_masked(client, daemon, up, tmp_path, monkeypatch):
    serve(daemon, up)
    up.routes[("GET", "/a")] = (200, {"Content-Type": "application/json", "Set-Cookie": "s=1"}, b'{"n": 1}')
    up.routes[("POST", "/b")] = (201, {"Content-Type": "text/plain"}, b"made")
    up.routes[("HEAD", "/a")] = (200, {}, b"")
    got: list[tuple[int, bytes]] = []
    listen = free_port()

    def clients(port: int) -> None:
        got.append(call(port, "GET", "/a", headers={"Authorization": "Bearer t0p", "Cookie": "sid=c00kie"}))
        got.append(call(port, "POST", "/b", body=b"payload", headers={"Content-Type": "text/plain"}))
        got.append(call(port, "HEAD", "/a"))
    record_with(monkeypatch, clients, listen)
    out = tmp_path / "rec.jsonl"
    r = client.http.record("api", out=str(out), seconds=5, listen=listen)
    assert got == [(200, b'{"n": 1}'), (201, b"made"), (200, b"")]
    assert r == {"written": str(out), "exchanges": 3, "methods": {"GET": 1, "POST": 1, "HEAD": 1}, "via": "proxy",
                 "note": "auth and cookie header values are masked"}
    text = out.read_text()
    assert "t0p" not in text and "c00kie" not in text
    rows = [json.loads(line) for line in text.splitlines()]
    assert rows[0]["req_headers"]["Authorization"] == "***" and rows[0]["resp_headers"]["Set-Cookie"] == "***"
    assert rows[0]["resp_body"] == {"text": '{"n": 1}', "bytes": 8, "truncated": False}
    assert rows[1]["req_body"]["text"] == "payload" and rows[1]["status"] == 201
    assert "Host" not in up.seen[0]["headers"] or up.seen[0]["headers"]["Host"] != f"127.0.0.1:{listen}"
    with pytest.raises(OSError):  # the proxy is gone after the window
        call(listen, "GET", "/a")


def test_record_proxy_upstream_down_records_502(client, daemon, tmp_path, monkeypatch):
    dead = free_port()
    daemon.on("GET", "/containers/api/json", json=ctr(published={80: ("127.0.0.1", dead)}))
    got: list[tuple[int, bytes]] = []
    listen = free_port()
    record_with(monkeypatch, lambda p: got.append(call(p, "GET", "/x")), listen)
    r = client.http.record("api", out=str(tmp_path / "r.jsonl"), listen=listen)
    assert got[0][0] == 502 and got[0][1].startswith(b"aisb proxy:") and r["exchanges"] == 1


def test_record_proxy_without_traffic(client, daemon, up, tmp_path, monkeypatch):
    serve(daemon, up)
    listen = free_port()
    record_with(monkeypatch, lambda p: None, listen)
    r = client.http.record("api", out=str(tmp_path / "r.jsonl"), listen=listen)
    assert r["exchanges"] == 0 and r["note"] == f"no traffic; send requests to http://127.0.0.1:{listen}"
    assert (tmp_path / "r.jsonl").read_text() == ""


# --- record (tcpdump sidecar) ------------------------------------------------------------------


def _pkt(src: str, sport: int, dst: str, dport: int, seq: int, payload: bytes, *, flags: int = 0x18) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                       bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + tcp


def _pcap(*frames: bytes, linktype: int = 101, magic: int = 0xA1B2C3D4, endian: str = "<", frac: int = 0) -> bytes:
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack(endian + "IIII", 1000 + i, frac, len(f), len(f)) + f
    return out


C, S = ("10.0.0.3", 40000), ("10.0.0.2", 8080)
REQ = b"GET /p HTTP/1.1\r\nHost: api\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi"


def _sidecar(daemon, pcap: bytes | None, *, wait: Reply | None = None) -> list[Seen]:
    created: list[Seen] = []
    daemon.on("GET", "/containers/api/json", json=ctr(exposed=(8080,)))
    daemon.on("POST", "/containers/create", lambda s: created.append(s) or Reply(201, json={"Id": "dump1"}))
    daemon.on("POST", "/containers/dump1/start", status=204)
    daemon.on("POST", "/containers/dump1/wait", wait or Reply(json={"StatusCode": 0}))
    daemon.on("GET", "/containers/dump1/archive",
              Reply(body=tar_of({"aisb.pcap": pcap}), content_type="application/x-tar") if pcap is not None
              else Reply(404, json={"message": "no such file"}))
    daemon.on("DELETE", "/containers/dump1", status=204)
    return created


def test_record_tcpdump_parses_the_capture_and_removes_the_sidecar(client, daemon, tmp_path):
    created = _sidecar(daemon, _pcap(_pkt(*C, *S, 1, REQ), _pkt(*S, *C, 7, RESP)))
    out = tmp_path / "r.jsonl"
    r = client.http.record("api", out=str(out), via="tcpdump", seconds=3)
    assert r["exchanges"] == 1 and r["methods"] == {"GET": 1} and r["via"] == "tcpdump"
    body = created[0].body
    assert body["HostConfig"]["NetworkMode"] == "container:api-full-id"
    assert "timeout 3 tcpdump" in body["Cmd"][2] and "tcp port 8080" in body["Cmd"][2]
    assert sorted(body["HostConfig"]["CapAdd"]) == ["NET_ADMIN", "NET_RAW"]
    assert ("DELETE", "/containers/dump1") in daemon.calls()
    row = json.loads(out.read_text())
    assert (row["path"], row["status"], row["resp_body"]["text"]) == ("/p", 200, "hi")


def test_record_tcpdump_no_capture_file(client, daemon, tmp_path):
    _sidecar(daemon, None)
    r = client.http.record("api", out=str(tmp_path / "r.jsonl"), via="tcpdump", port=9999, seconds=1)
    assert r["exchanges"] == 0 and r["note"] == "no traffic seen"


def test_record_tcpdump_sidecar_removed_even_when_wait_fails(client, daemon, tmp_path):
    from aisb import errors
    _sidecar(daemon, b"", wait=Reply(500, json={"message": "wait broke"}))
    with pytest.raises(errors.APIError, match="wait broke"):
        client.http.record("api", out=str(tmp_path / "r.jsonl"), via="tcpdump", seconds=1)
    assert ("DELETE", "/containers/dump1") in daemon.calls()
    assert not (tmp_path / "r.jsonl").exists()


# --- replay ------------------------------------------------------------------------------------


def write_rows(path: Path, rows: list[dict[str, Any]]) -> str:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows) + "\n")
    return str(path)


def row(method: str, path: str, status: int | None, text: str | None = None, ms: float | None = 10.0,
        **kw: Any) -> dict[str, Any]:
    return {"method": method, "path": path, "status": status, "ms": ms,
            "resp_body": {"text": text} if text is not None else None, **kw}


def test_replay_compares_status_and_bodies_and_honours_ignore(client, daemon, up, tmp_path):
    serve(daemon, up, "v2")
    up.routes[("GET", "/same")] = (200, {"Content-Type": "application/json"},
                                   b'{"id": "6f1c1b3e-8a3f-4b7a-9d2e-1c2b3a4d5e6f", "v": 1}')
    up.routes[("GET", "/meta")] = (200, {}, b'{"v": 1, "meta": {"requestId": "zzz", "host": "b"}}')
    up.routes[("GET", "/diff")] = (200, {}, b'{"price": 12}')
    up.routes[("GET", "/gone")] = (404, {}, b"")
    up.routes[("HEAD", "/h")] = (200, {}, b"")
    up.routes[("POST", "/w")] = (201, {}, b"")
    f = write_rows(tmp_path / "r.jsonl", [
        row("GET", "/same", 200, '{"id": "0a1b2c3d-8a3f-4b7a-9d2e-1c2b3a4d5e6f", "v": 1}'),
        row("GET", "/meta", 200, '{"v": 1, "meta": {"requestId": "aaa", "host": "a"}}'),
        row("GET", "/diff", 200, '{"price": 10}'),
        row("GET", "/gone", 200, ""),
        row("HEAD", "/h", 200, "anything"),
        row("POST", "/w", 201, ""),
    ])
    r = client.http.replay(f, to="v2", ignore=["meta.*"])
    assert r["replayed"] == 5 and r["to"] == "v2" and r["match_rate"] == 0.6
    assert (r["status_mismatches"], r["body_mismatches"]) == (1, 1)
    mism = {m["path"]: m for m in r["mismatches"]}
    assert mism["/diff"]["diffs"] == [{"path": "price", "recorded": 10, "replayed": 12}]
    assert mism["/gone"]["status"] == [200, 404] and "/meta" not in mism and "/h" not in mism
    assert r["latency_ratio"]["p50"] >= 0 and set(r["latency_ratio"]) == {"p50", "p95"}
    assert [s["method"] for s in up.seen] == ["GET", "GET", "GET", "GET", "HEAD"]  # POST not replayed by default
    # without --ignore the volatile meta differs
    again = client.http.replay(f, to="v2")
    assert "/meta" in {m["path"] for m in again["mismatches"]}


def test_replay_all_methods_sends_bodies_but_never_masked_headers(client, daemon, up, tmp_path):
    serve(daemon, up, "v2")
    up.routes[("POST", "/w")] = (201, {}, b"")
    f = write_rows(tmp_path / "r.jsonl", [
        row("POST", "/w", 201, "", req_body={"text": "payload"},
            req_headers={"Authorization": "***", "Content-Type": "text/plain", "Host": "old", "Content-Length": "7",
                         "X-Keep": "1"}),
    ])
    r = client.http.replay(f, to="v2", all_methods=True, limit=10)
    assert r["match_rate"] == 1.0
    sent = up.seen[0]
    assert sent["body"] == b"payload" and sent["headers"]["X-Keep"] == "1"
    assert "Authorization" not in sent["headers"] and sent["headers"]["Host"] != "old"


def test_replay_limit_and_no_timing(client, daemon, up, tmp_path):
    serve(daemon, up, "v2")
    up.routes[("GET", "/a")] = (200, {}, b"x")
    f = write_rows(tmp_path / "r.jsonl", [row("GET", "/a", 200, "x", ms=None)] * 5)
    r = client.http.replay(f, to="v2", limit=2)
    assert r["replayed"] == 2 and r["latency_ratio"] is None and len(up.seen) == 2


def test_replay_unreachable_target_counts_as_status_mismatch(client, daemon, tmp_path):
    daemon.on("GET", "/containers/v2/json", json=ctr("v2", published={80: ("127.0.0.1", free_port())}))
    f = write_rows(tmp_path / "r.jsonl", [row("GET", "/a", 200, "x")])
    r = client.http.replay(f, to="v2")
    assert r["status_mismatches"] == 1 and r["mismatches"][0]["status"] == [200, None] and r["match_rate"] == 0.0


def test_replay_empty_recording(client, daemon, up, tmp_path):
    serve(daemon, up, "v2")
    (tmp_path / "e.jsonl").write_text("")
    r = client.http.replay(str(tmp_path / "e.jsonl"), to="v2")
    assert r["replayed"] == 0 and r["match_rate"] is None and r["latency_ratio"] is None


def test_replay_dry_run_sends_nothing(client, daemon, up, tmp_path):
    serve(daemon, up, "v2")
    f = write_rows(tmp_path / "r.jsonl", [row("GET", f"/p{i}", 200, "") for i in range(25)])
    out = invoke(client, get_op("http.replay"), {"file": f, "to": "v2"}, dry_run=True)
    assert len(out.planned) == 20 and out.planned[0] == {"http": "GET", "url": f"http://127.0.0.1:{up.port}/p0"}
    assert up.seen == []


# --- insights.traffic --------------------------------------------------------------------------


@pytest.mark.parametrize(("data", "ctype", "limit", "want"), [
    (b"\x00\x01\x02", "application/octet-stream", 10, {"b64": "AAEC", "bytes": 3, "truncated": False}),
    (b"\x00abc", "application/json", 2, {"text": "\x00a", "bytes": 4, "truncated": True}),
    (b"hello", "", 10, {"text": "hello", "bytes": 5, "truncated": False}),
])
def test_body_repr(data, ctype, limit, want):
    assert traffic.body_repr(data, ctype, limit) == want


def test_safe_headers():
    assert traffic.safe_headers({"X-Api-Key": "k", "proxy-authorization": "p", "Accept": "*/*"}) == \
        {"X-Api-Key": "***", "proxy-authorization": "***", "Accept": "*/*"}


def _eth(ip: bytes, vlan: bool = False) -> bytes:
    return b"\0" * 12 + (b"\x81\x00\x00\x05" if vlan else b"") + b"\x08\x00" + ip


def _sll(ip: bytes) -> bytes:
    return b"\0" * 14 + b"\x08\x00" + ip


def _sll2(ip: bytes) -> bytes:
    return b"\x08\x00" + b"\0" * 18 + ip


def _ip6(src: str, dst: str, tcp: bytes) -> bytes:
    import ipaddress
    return struct.pack(">IHBB", 6 << 28, len(tcp), 6, 64) + ipaddress.IPv6Address(src).packed + \
        ipaddress.IPv6Address(dst).packed + tcp


def _tcp(sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload


@pytest.mark.parametrize(("linktype", "wrap"), [
    (1, lambda ip: _eth(ip)), (1, lambda ip: _eth(ip, vlan=True)), (113, _sll), (276, _sll2), (101, lambda ip: ip),
    (12, lambda ip: ip),
])
def test_link_layers(linktype, wrap):
    pcap = _pcap(wrap(_pkt(*C, *S, 1, REQ)), wrap(_pkt(*S, *C, 5, RESP)), linktype=linktype)
    ex = traffic.exchanges_from_pcap(pcap, 8080)
    assert [(e["method"], e["status"]) for e in ex] == [("GET", 200)]


@pytest.mark.parametrize(("magic", "endian", "frac", "ts"), [
    (0xA1B2C3D4, ">", 500000, 1000.5),        # big-endian microseconds
    (0xA1B23C4D, "<", 250000000, 1000.25),    # little-endian nanoseconds
    (0xA1B23C4D, ">", 750000000, 1000.75),    # big-endian nanoseconds
])
def test_pcap_variants(magic, endian, frac, ts):
    pcap = _pcap(_pkt(*C, *S, 1, REQ), magic=magic, endian=endian, frac=frac)
    assert [t for t, _, _ in traffic.packets(pcap)] == [ts]


def test_ipv6_and_ignored_frames():
    tcp_req = _tcp(40000, 8080, 1, REQ)
    tcp_resp = _tcp(8080, 40000, 9, RESP)
    udp = bytearray(_pkt(*C, *S, 1, b"x"))
    udp[9] = 17
    frames = [
        _ip6("fd00::3", "fd00::2", tcp_req), _ip6("fd00::2", "fd00::3", tcp_resp),
        bytes(udp),                                        # not TCP
        _pkt(*C, *S, 1, b"")[:20] + b"\0" * 4,           # truncated TCP header
        _pkt(*C, *S, 5, b"", flags=0x10),                  # pure ACK: no payload
    ]
    pcap = _pcap(*frames)
    ex = traffic.exchanges_from_pcap(pcap, 8080)
    assert [(e["method"], e["path"], e["status"]) for e in ex] == [("GET", "/p", 200)]
    assert traffic.exchanges_from_pcap(_pcap(_pkt(*C, *S, 1, REQ), linktype=147), 8080) == []  # unknown link type
    assert list(traffic.packets(b"short")) == []


def test_reassembly_keeps_only_the_new_tail_of_overlapping_segments():
    data = b"GET /long HTTP/1.1\r\nX: 1\r\n\r\n"
    pcap = _pcap(_pkt(*C, *S, 100, data[:10]), _pkt(*C, *S, 105, data[5:20]), _pkt(*C, *S, 102, data[2:8]),
                 _pkt(*C, *S, 120, data[20:]))
    assert traffic.streams(pcap)[(*C, *S)][1] == data


def test_request_without_response_and_other_ports():
    pcap = _pcap(_pkt(*C, *S, 1, REQ), _pkt("10.0.0.3", 40001, "10.0.0.2", 9999, 1, REQ))
    ex = traffic.exchanges_from_pcap(pcap, 8080)
    assert len(ex) == 1 and ex[0]["status"] is None and ex[0]["resp_body"] is None and ex[0]["resp_headers"] == {}


@pytest.mark.parametrize(("data", "want"), [
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n",
     [(200, b"abc")]),                                                          # final CRLF missing
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n", [(200, b"abc")]),  # truncated
    (b"HTTP/1.1 OK\r\n\r\n", [(0, b"")]),                                       # no numeric status
    (b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", [(204, b""), (200, b"x")]),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n", []),                          # headers never finished
])
def test_parse_http_responses(data, want):
    assert [(m["status"], m["body"]) for m in traffic.parse_http(data, requests=False)] == want


def test_parse_http_request_without_path():
    assert traffic.parse_http(b"GET\r\n\r\n", requests=True)[0]["path"] == "/"


@pytest.mark.parametrize(("a", "b", "ignore", "want"), [
    ('{"a": [1, 2]}', '{"a": [1, 2, 3]}', [], [{"path": "a", "recorded": [1, 2], "replayed": [1, 2, 3]}]),
    ('{"a": [1, {"b": 2}]}', '{"a": [1, {"b": 3}]}', [], [{"path": "a[1].b", "recorded": 2, "replayed": 3}]),
    ('{"a": 1}', '{"b": 1}', [], [{"path": "a", "recorded": 1, "replayed": "<missing>"},
                                  {"path": "b", "recorded": "<missing>", "replayed": 1}]),
    ('{"items": [{"at": 1}, {"at": 2}]}', '{"items": [{"at": 5}, {"at": 6}]}', ["items.*.at"], []),
    ('[1]', '[2]', [], [{"path": "[0]", "recorded": 1, "replayed": 2}]),
    ('1', '2', [], [{"path": "$", "recorded": 1, "replayed": 2}]),
    ("req 42 done", "req 97 done", [], []),                                    # text: volatile numbers masked
    ("ok", "error", [], [{"path": "$", "recorded": "ok", "replayed": "error"}]),
    ('{"x": 1}', "not json", [], [{"path": "$", "recorded": '{"x": <n>}', "replayed": "not json"}]),
])
def test_compare_bodies(a, b, ignore, want):
    assert traffic.compare_bodies(a, b, ignore) == want


def test_compare_bodies_caps_diffs_at_five():
    a = json.dumps({f"k{i}": i for i in range(9)})
    b = json.dumps({f"k{i}": -i - 1 for i in range(9)})
    assert len(traffic.compare_bodies(a, b, [])) == 5


def test_normalize_ignores_whole_subtrees():
    assert traffic.normalize({"a": {"b": [1, 2]}, "c": 3}, ["a"]) == {"a": "<ignored>", "c": 3}
