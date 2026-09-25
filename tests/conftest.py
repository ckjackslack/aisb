"""Fake Docker daemon on a unix socket: mocks the process boundary, not aisb internals."""

import json
import re
import shutil
import socketserver
import tempfile
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

from aisb import Docker

API = "1.43"


@dataclass(frozen=True)
class Seen:
    method: str
    path: str        # version prefix stripped
    raw_path: str
    query: dict[str, str]
    body: Any

    def filters(self) -> Any:
        return json.loads(self.query["filters"]) if "filters" in self.query else None


@dataclass
class Reply:
    status: int = 200
    json: Any = None
    body: bytes = b""
    chunks: list[bytes] | None = None
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)

    def payload(self) -> bytes:
        return json.dumps(self.json).encode() if self.json is not None else self.body


Responder = Reply | Callable[[Seen], Reply]


class FakeDaemon:
    def __init__(self, sock: Path) -> None:
        self.sock = sock
        self.routes: list[tuple[str, re.Pattern[str], Responder]] = []
        self.seen: list[Seen] = []
        self._server = socketserver.ThreadingUnixStreamServer(str(sock), _Handler)
        self._server.fake = self  # type: ignore[attr-defined]
        self._server.daemon_threads = True

    def on(self, method: str, pattern: str, reply: Responder | None = None, **kw: Any) -> "FakeDaemon":
        self.routes.insert(0, (method, re.compile(pattern), reply if reply is not None else Reply(**kw)))
        return self

    def calls(self, method: str | None = None) -> list[tuple[str, str]]:
        return [(s.method, s.path) for s in self.seen if method in (None, s.method)]

    def start(self) -> None:
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:
        pass

    def address_string(self) -> str:
        return "fake"

    def _dispatch(self) -> None:
        fake: FakeDaemon = self.server.fake  # type: ignore[attr-defined]
        url = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if url.path == "/_ping":
            return self._send(Reply(body=b"OK", content_type="text/plain", headers={"Api-Version": API}))
        body: Any = raw
        if raw and self.headers.get("Content-Type") == "application/json":
            body = json.loads(raw)
        seen = Seen(self.command, re.sub(r"^/v[\d.]+", "", url.path), url.path, dict(parse_qsl(url.query)), body)
        fake.seen.append(seen)
        for method, rx, reply in fake.routes:
            if method == self.command and rx.fullmatch(seen.path):
                return self._send(reply(seen) if callable(reply) else reply)
        self._send(Reply(404, json={"message": f"no route for {self.command} {seen.path}"}))

    do_GET = do_POST = do_PUT = do_DELETE = _dispatch

    def _send(self, r: Reply) -> None:
        self.send_response(r.status)
        self.send_header("Content-Type", r.content_type)
        self.send_header("Connection", "close")
        for k, v in r.headers.items():
            self.send_header(k, v)
        if r.chunks is not None:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in r.chunks:
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        else:
            data = r.payload()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


def frame(stream: int, data: bytes) -> bytes:
    """One multiplexed stdout(1)/stderr(2) frame."""
    return bytes([stream, 0, 0, 0]) + len(data).to_bytes(4, "big") + data


@pytest.fixture
def daemon() -> Iterator[FakeDaemon]:
    tmp = Path(tempfile.mkdtemp(prefix="aisb-", dir="/tmp"))  # short path: AF_UNIX limit ~108 bytes
    fake = FakeDaemon(tmp / "d.sock")
    fake.start()
    yield fake
    fake.stop()
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def host(daemon: FakeDaemon) -> str:
    return f"unix://{daemon.sock}"


@pytest.fixture
def client(host: str) -> Docker:
    return Docker(host, timeout=5)
