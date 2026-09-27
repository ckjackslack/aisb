"""Supply-chain network clients against local fakes: an HTTPS registry (self-signed cert trusted through
SSL_CERT_FILE), a token server, and an OSV API. Credential handling is checked at the wire."""

import base64
import json
import os
import shutil
import ssl
import subprocess
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aisb import supply

Handler = Callable[[BaseHTTPRequestHandler], tuple[int, dict[str, str], bytes]]


class Server:
    """A tiny HTTP(S) server: `route(method, path) -> (status, headers, body)`; every request is recorded."""

    def __init__(self, route: Handler, *, cert: Path | None = None, bind: str = "127.0.0.1") -> None:
        seen = self.seen = []

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.body = self.rfile.read(n) if n else b""
                seen.append({"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"),
                             "host": self.headers.get("Host")})
                status, headers, body = route(self)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            do_GET = do_POST = do_HEAD = _any

        self.srv = ThreadingHTTPServer((bind, 0), H)
        if cert:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(cert, cert.with_suffix(".key"))
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture(scope="module")
def cert(tmp_path_factory) -> Path:
    if not shutil.which("openssl"):
        pytest.skip("needs the openssl CLI to make a test certificate")
    d = tmp_path_factory.mktemp("tls")
    crt = d / "reg.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost", "-keyout", str(crt.with_suffix(".key")),
                    "-out", str(crt)], check=True, capture_output=True)
    return crt


@pytest.fixture
def tls(cert, monkeypatch, tmp_path):
    """Trust the test certificate only; no proxy for loopback; an empty docker config."""
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(var, "127.0.0.1,localhost")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "docker"))
    servers: list[Server] = []

    def start(route: Handler, *, https: bool = True) -> Server:
        s = Server(route, cert=cert if https else None)
        servers.append(s)
        return s
    yield start
    for s in servers:
        s.close()


def docker_login(tmp_path: Path, registry: str, user: str = "u", password: str = "p") -> str:
    auth = supply.basic_auth(user, password)
    (tmp_path / "docker").mkdir(exist_ok=True)
    (tmp_path / "docker" / "config.json").write_text(json.dumps({"auths": {registry: {"auth": auth}}}))
    return auth


def test_basic_auth():
    assert base64.b64decode(supply.basic_auth("a", "b:c")) == b"a:b:c"


# --- registry: bearer and basic flows ---------------------------------------------------------------

def bearer_registry(realm: Callable[[], str], digest: str = "sha256:abc", token: str = "TOK") -> Handler:
    def route(h: BaseHTTPRequestHandler) -> tuple[int, dict[str, str], bytes]:
        if h.headers.get("Authorization") == f"Bearer {token}":
            return 200, {"Docker-Content-Digest": digest}, b""
        return 401, {"WWW-Authenticate": f'Bearer realm="{realm()}",service="fake"'}, b""
    return route


def token_server(key: str = "token", value: str = "TOK") -> Handler:
    return lambda h: (200, {"Content-Type": "application/json"}, json.dumps({key: value}).encode())


@pytest.mark.parametrize("key", ["token", "access_token"])
def test_bearer_flow_anonymous(tls, key):
    tok = tls(token_server(key))
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{tok.port}/token"))
    assert supply.remote_digest(f"127.0.0.1:{reg.port}/team/app:v1") == "sha256:abc"
    assert [r["auth"] for r in reg.seen] == [None, "Bearer TOK"]
    assert reg.seen[0]["method"] == "HEAD" and reg.seen[0]["path"] == "/v2/team/app/manifests/v1"
    (t,) = tok.seen
    assert t["auth"] is None and "scope=repository%3Ateam%2Fapp%3Apull" in t["path"] and "service=fake" in t["path"]


def test_bearer_flow_sends_docker_login_to_the_token_server(tls, tmp_path):
    tok = tls(token_server())
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{tok.port}/token"))
    auth = docker_login(tmp_path, f"127.0.0.1:{reg.port}")
    assert supply.remote_digest(f"127.0.0.1:{reg.port}/app@sha256:pinned") == "sha256:abc"
    assert tok.seen[0]["auth"] == f"Basic {auth}"
    assert reg.seen[-1]["path"] == "/v2/app/manifests/sha256:pinned"
    assert all(r["auth"] != f"Basic {auth}" for r in reg.seen)       # the registry itself only sees the token


def test_docker_login_is_looked_up_by_https_key_too(tls, tmp_path):
    tok = tls(token_server())
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{tok.port}/token"))
    auth = docker_login(tmp_path, f"https://127.0.0.1:{reg.port}")
    supply.remote_digest(f"127.0.0.1:{reg.port}/app")
    assert tok.seen[0]["auth"] == f"Basic {auth}"


@pytest.mark.parametrize("content", ["not json", '{"auths": {"x": {}}}', None])
def test_unreadable_or_unrelated_docker_config_means_anonymous(tls, tmp_path, content):
    tok = tls(token_server())
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{tok.port}/token"))
    if content is not None:
        (tmp_path / "docker").mkdir()
        (tmp_path / "docker" / "config.json").write_text(content)
    supply.remote_digest(f"127.0.0.1:{reg.port}/app")
    assert tok.seen[0]["auth"] is None


def test_basic_challenge_uses_docker_login(tls, tmp_path):
    holder: dict[str, str] = {}

    def route(h):
        if h.headers.get("Authorization") == f"Basic {holder['auth']}":
            return 200, {"Docker-Content-Digest": "sha256:basic"}, b""
        return 401, {"WWW-Authenticate": 'Basic realm="reg"'}, b""
    reg = tls(route)
    holder["auth"] = docker_login(tmp_path, f"127.0.0.1:{reg.port}")
    assert supply.remote_digest(f"127.0.0.1:{reg.port}/app:1") == "sha256:basic"
    assert [r["auth"] for r in reg.seen] == [None, f"Basic {holder['auth']}"]


def test_basic_challenge_without_login_fails_without_retry(tls):
    reg = tls(lambda h: (401, {"WWW-Authenticate": 'Basic realm="reg"'}, b""))
    with pytest.raises(supply.SupplyError, match=r"app:1: HTTP 401"):
        supply.remote_digest(f"127.0.0.1:{reg.port}/app:1")
    assert len(reg.seen) == 1


def test_token_that_is_still_rejected_gives_up_after_one_retry(tls):
    tok = tls(token_server(value="WRONG"))
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{tok.port}/token"))
    with pytest.raises(supply.SupplyError, match="HTTP 401"):
        supply.remote_digest(f"127.0.0.1:{reg.port}/app")
    assert len(reg.seen) == 2 and len(tok.seen) == 1


@pytest.mark.parametrize(("route", "error"), [
    (lambda h: (200, {}, b""), "did not return a digest for app:1"),
    (lambda h: (404, {}, b""), "app:1: HTTP 404"),
    (lambda h: (401, {"WWW-Authenticate": 'Bearer service="x"'}, b""), "unusable auth challenge"),
    (lambda h: (401, {}, b""), "HTTP 401"),
])
def test_registry_errors(tls, route, error):
    reg = tls(route)
    with pytest.raises(supply.SupplyError, match=error):
        supply.remote_digest(f"127.0.0.1:{reg.port}/app:1")


def test_token_server_failures(tls):
    bad_json = tls(lambda h: (200, {}, b"<html>"))
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{bad_json.port}/token"))
    with pytest.raises(supply.SupplyError, match="token from https://127.0.0.1"):
        supply.remote_digest(f"127.0.0.1:{reg.port}/app")
    down = tls(lambda h: (500, {}, b""))
    reg2 = tls(bearer_registry(lambda: f"https://127.0.0.1:{down.port}/token"))
    with pytest.raises(supply.SupplyError, match="HTTP Error 500"):
        supply.remote_digest(f"127.0.0.1:{reg2.port}/app")


def test_untrusted_registry_certificate_is_refused(tls, monkeypatch):
    reg = tls(lambda h: (200, {"Docker-Content-Digest": "sha256:x"}, b""))
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent-ca.pem")      # our self-signed cert is no longer trusted
    with pytest.raises(supply.SupplyError, match="CERTIFICATE_VERIFY_FAILED|certificate verify failed"):
        supply.remote_digest(f"127.0.0.1:{reg.port}/app")


def test_registry_connection_refused(tls):
    s = tls(lambda h: (200, {}, b""))
    port = s.port
    s.close()
    with pytest.raises(supply.SupplyError, match=f"127.0.0.1:{port}: "):
        supply.remote_digest(f"127.0.0.1:{port}/app")


# --- credential scoping --------------------------------------------------------------------------------

def test_credentials_never_follow_a_redirect_to_another_host(tls, tmp_path):
    """A registry answering the authenticated manifest request with a redirect must not make aisb hand the
    Authorization header (docker-login Basic credentials) to the redirect target."""
    other = tls(lambda h: (200, {"Docker-Content-Digest": "sha256:elsewhere"}, b""))
    holder: dict[str, str] = {}

    def route(h):
        if h.headers.get("Authorization") == f"Basic {holder['auth']}":
            return 307, {"Location": f"https://localhost:{other.port}/v2/app/manifests/1"}, b""
        return 401, {"WWW-Authenticate": 'Basic realm="reg"'}, b""
    reg = tls(route)
    holder["auth"] = docker_login(tmp_path, f"127.0.0.1:{reg.port}")
    assert supply.remote_digest(f"127.0.0.1:{reg.port}/app:1") == "sha256:elsewhere"
    assert other.seen and all(r["auth"] is None for r in other.seen)


def test_same_origin_redirect_keeps_the_token(tls):
    tok = tls(token_server())
    holder: dict[str, int] = {}

    def route(h):
        if h.path.startswith("/moved/") and h.headers.get("Authorization") == "Bearer TOK":
            return 200, {"Docker-Content-Digest": "sha256:moved"}, b""
        if h.headers.get("Authorization") == "Bearer TOK":
            return 307, {"Location": f"https://127.0.0.1:{holder['port']}/moved/app"}, b""
        return 401, {"WWW-Authenticate": f'Bearer realm="https://127.0.0.1:{tok.port}/token"'}, b""
    reg = tls(route)
    holder["port"] = reg.port
    assert supply.remote_digest(f"127.0.0.1:{reg.port}/app") == "sha256:moved"


def test_token_request_does_not_follow_redirects_with_credentials(tls, tmp_path):
    sink = tls(token_server())
    tok = tls(lambda h: (302, {"Location": f"https://localhost:{sink.port}/token"}, b""))
    reg = tls(bearer_registry(lambda: f"https://127.0.0.1:{tok.port}/token"))
    auth = docker_login(tmp_path, f"127.0.0.1:{reg.port}")
    supply.remote_digest(f"127.0.0.1:{reg.port}/app")
    assert tok.seen[0]["auth"] == f"Basic {auth}"                   # the realm the registry named gets it
    assert all(r["auth"] is None for r in sink.seen)                # ...a host it redirects to does not


def test_realm_on_another_host_receives_the_login(tls, tmp_path):
    """Documented behaviour (same as the Docker CLI): the registry's challenge picks the token realm, and the
    docker-login credentials for that registry are sent there, even when it is on a different host."""
    tok = tls(token_server())
    reg = tls(bearer_registry(lambda: f"https://localhost:{tok.port}/token"))
    auth = docker_login(tmp_path, f"127.0.0.1:{reg.port}")
    supply.remote_digest(f"127.0.0.1:{reg.port}/app")
    assert tok.seen[0]["host"] == f"localhost:{tok.port}" and tok.seen[0]["auth"] == f"Basic {auth}"


# --- OSV ------------------------------------------------------------------------------------------------

@pytest.fixture
def osv(tls, monkeypatch):
    batches: list[dict[str, Any]] = []

    def route(h):
        if h.command == "POST":
            body = json.loads(h.body)
            batches.append(body)
            return 200, {}, json.dumps({"results": [{"vulns": [{"id": f"V-{q['package']['name']}"}]}
                                                    if q["package"]["name"] != "clean" else {}
                                                    for q in body["queries"]]}).encode()
        vid = h.path.rsplit("/", 1)[-1]
        if vid == "MISSING":
            return 404, {}, b""
        return 200, {}, json.dumps({"id": vid, "summary": "s"}).encode()
    srv = tls(route, https=False)
    monkeypatch.setenv("AISB_OSV_URL", f"http://127.0.0.1:{srv.port}/")
    return srv, batches


def test_osv_ids_are_chunked_and_aligned(osv):
    _, batches = osv
    qs = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": "1"} for n in ("a", "clean", "b")]
    assert supply.osv_ids(qs, chunk=2) == [["V-a"], [], ["V-b"]]
    assert [len(b["queries"]) for b in batches] == [2, 1]
    assert supply.osv_base().endswith(str(osv[0].port))              # trailing slash trimmed


def test_osv_vuln_is_cached_until_ttl(osv):
    srv, _ = osv
    assert supply.osv_vuln("GHSA-x:y")["id"] == "GHSA-x:y"
    first = len(srv.seen)
    supply.osv_vuln("GHSA-x:y")
    assert len(srv.seen) == first                                    # served from the cache
    supply.osv_vuln("GHSA-x:y", ttl=0)
    assert len(srv.seen) == first + 1
    from aisb import state
    assert list((state.home("cache", "osv")).glob("GHSA-x_y.json"))  # path-safe cache file name


def test_osv_http_and_network_errors(osv, monkeypatch):
    with pytest.raises(supply.SupplyError, match=r"/v1/vulns/MISSING: HTTP 404"):
        supply.osv_vuln("MISSING")
    monkeypatch.setenv("AISB_OSV_URL", "http://127.0.0.1:1")
    with pytest.raises(supply.SupplyError, match=r"http://127.0.0.1:1/v1/querybatch: "):
        supply.osv_ids([{"package": {"name": "a"}}])


def test_osv_cache_expires(osv):
    srv, _ = osv
    supply.osv_vuln("OLD-1")
    from aisb import state
    f = state.home("cache", "osv") / "OLD-1.json"
    old = time.time() - 2 * 86400
    os.utime(f, (old, old))
    n = len(srv.seen)
    supply.osv_vuln("OLD-1")
    assert len(srv.seen) == n + 1
