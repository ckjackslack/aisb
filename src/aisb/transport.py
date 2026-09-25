"""HTTP transport to the Docker Engine API over a unix socket or TCP (+TLS)."""

import http.client
import json
import os
import socket
import ssl
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import EllipsisType
from typing import Any
from urllib.parse import urlencode, urlsplit

from .errors import DockerUnavailable, error_for

DRY_ID = "dry-run-id"
FALLBACK_VERSION = "1.41"
SOCKETS = ("/var/run/docker.sock", "~/.docker/run/docker.sock", "~/.colima/default/docker.sock")
CHUNK = 64 * 1024

Timeout = float | None | EllipsisType  # ``...`` means "use the transport default"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float | None = None) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


@dataclass(frozen=True, slots=True)
class Endpoint:
    url: str
    tls: ssl.SSLContext | None = None

    def connection(self, timeout: float | None) -> http.client.HTTPConnection:
        parts = urlsplit(self.url)
        if parts.scheme == "unix":
            return UnixHTTPConnection(parts.path, timeout)
        host, port = parts.hostname or "localhost", parts.port or (2376 if self.tls else 2375)
        if self.tls:
            return http.client.HTTPSConnection(host, port, timeout=timeout, context=self.tls)
        return http.client.HTTPConnection(host, port, timeout=timeout)


def resolve_endpoint(host: str | None = None, env: Mapping[str, str] = os.environ) -> Endpoint:
    """Explicit host > $DOCKER_HOST > first existing well-known socket."""
    host = host or env.get("DOCKER_HOST")
    if not host:
        paths = [os.path.expanduser(p) for p in SOCKETS]
        return Endpoint(f"unix://{next((p for p in paths if os.path.exists(p)), paths[0])}")
    scheme = urlsplit(host).scheme
    if scheme == "unix":
        return Endpoint(host)
    if scheme in ("tcp", "http", "https"):
        tls = scheme == "https" or env.get("DOCKER_TLS_VERIFY", "") not in ("", "0")
        return Endpoint(host, _tls_context(env.get("DOCKER_CERT_PATH")) if tls else None)
    raise ValueError(f"unsupported DOCKER_HOST scheme: {host!r}")


def _tls_context(cert_path: str | None) -> ssl.SSLContext:
    base = Path(cert_path or "~/.docker").expanduser()
    ca, cert, key = base / "ca.pem", base / "cert.pem", base / "key.pem"
    ctx = ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
    if cert.exists() and key.exists():
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _query_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(v)
    return str(v)


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    path: str
    query: Mapping[str, Any] = field(default_factory=dict)
    body: Any = None
    data: bytes | None = None
    content_type: str | None = None

    @property
    def target(self) -> str:
        qs = urlencode({k: _query_value(v) for k, v in self.query.items() if v is not None})
        return f"{self.path}?{qs}" if qs else self.path

    def payload(self) -> tuple[bytes | None, dict[str, str]]:
        if self.body is not None:
            return json.dumps(self.body).encode(), {"Content-Type": "application/json"}
        if self.data is not None:
            return self.data, {"Content-Type": self.content_type or "application/octet-stream"}
        return None, {}

    def preview(self) -> dict[str, Any]:
        out: dict[str, Any] = {"method": self.method, "path": self.path}
        if query := {k: v for k, v in self.query.items() if v is not None}:
            out["query"] = query
        if self.body is not None:
            out["body"] = self.body
        elif self.data is not None:
            out["body"] = f"<{len(self.data)} bytes {self.content_type}>"
        return out


def _message(raw: bytes) -> str:
    try:
        return str(json.loads(raw).get("message", "")).strip()
    except (ValueError, AttributeError):
        return raw.decode(errors="replace").strip()


class Transport:
    """Stateless request executor; one connection per request, API version negotiated once."""

    def __init__(self, endpoint: Endpoint, *, timeout: float | None = 60.0, version: str | None = None) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self._version = version
        self._plan: list[Request] | None = None

    @property
    def version(self) -> str:
        if self._version is None:
            with self._open(Request("GET", "/_ping"), versioned=False) as resp:
                resp.read()
                self._version = resp.getheader("Api-Version") or FALLBACK_VERSION
        return self._version

    @contextmanager
    def dry_run(self) -> Iterator[list[Request]]:
        """Record mutating requests instead of sending them; reads still execute."""
        prev, self._plan = self._plan, []
        try:
            yield self._plan
        finally:
            self._plan = prev

    @property
    def planning(self) -> bool:
        """True inside dry_run(): ops may run extra read-only preflight checks."""
        return self._plan is not None

    def _intercept(self, req: Request) -> bool:
        if self._plan is None or (req.method == "GET" and DRY_ID not in req.path):
            return False
        self._plan.append(req)
        return True

    @contextmanager
    def _open(self, req: Request, *, timeout: Timeout = ..., versioned: bool = True) -> Iterator[http.client.HTTPResponse]:
        target = f"/v{self.version}{req.target}" if versioned else req.target
        conn = self.endpoint.connection(self.timeout if timeout is ... else timeout)
        data, headers = req.payload()
        try:
            try:
                conn.request(req.method, target, body=data, headers=headers)
                resp = conn.getresponse()
            except (FileNotFoundError, ConnectionRefusedError, PermissionError, socket.gaierror) as e:
                raise DockerUnavailable(f"cannot reach Docker at {self.endpoint.url}: {e}") from e
            if resp.status >= 300:
                raise error_for(resp.status, _message(resp.read()))
            yield resp
        finally:
            conn.close()

    def _req(self, method: str, path: str, query: Mapping[str, Any] | None, body: Any,
             data: bytes | None, content_type: str | None) -> Request:
        return Request(method, path, query or {}, body, data, content_type)

    def json(self, method: str, path: str, *, query: Mapping[str, Any] | None = None, body: Any = None,
             data: bytes | None = None, content_type: str | None = None, timeout: Timeout = ...) -> Any:
        req = self._req(method, path, query, body, data, content_type)
        if self._intercept(req):
            return {"Id": DRY_ID}
        with self._open(req, timeout=timeout) as resp:
            raw = resp.read()
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode(errors="replace")

    def raw(self, method: str, path: str, *, query: Mapping[str, Any] | None = None, body: Any = None,
            data: bytes | None = None, content_type: str | None = None, timeout: Timeout = ...) -> bytes:
        req = self._req(method, path, query, body, data, content_type)
        if self._intercept(req):
            return b""
        with self._open(req, timeout=timeout) as resp:
            return resp.read()

    def stream(self, method: str, path: str, *, query: Mapping[str, Any] | None = None, body: Any = None,
               data: bytes | None = None, content_type: str | None = None, timeout: Timeout = ...) -> Iterator[bytes]:
        req = self._req(method, path, query, body, data, content_type)
        if self._intercept(req):
            return iter(())
        return self._chunks(req, timeout)

    def _chunks(self, req: Request, timeout: Timeout) -> Iterator[bytes]:
        with self._open(req, timeout=timeout) as resp:
            while chunk := resp.read1(CHUNK):
                yield chunk
