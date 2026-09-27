"""`images` ops that read an image's filesystem (sbom, vulns, diff) through a transient helper on the fake daemon,
and `images updates` against a local HTTPS registry (self-signed cert trusted through SSL_CERT_FILE)."""

import shutil
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aisb.errors import APIError

from conftest import FakeDaemon, Reply, Seen, tar_of


def serve_images(daemon: FakeDaemon, images: dict[str, dict[str, bytes]], configs: dict[str, dict] | None = None,
                 ) -> list[str]:
    """Each image's rootfs is served from the archive of the transient helper created from it."""
    ids = {img: f"helper{i}" for i, img in enumerate(images)}
    deleted: list[str] = []

    def create(seen: Seen) -> Reply:
        return Reply(201, json={"Id": ids[seen.body["Image"]]})

    def delete(seen: Seen) -> Reply:
        deleted.append(seen.path.rsplit("/", 1)[1])
        return Reply(204)

    daemon.on("POST", "/containers/create", create)
    daemon.on("DELETE", r"/containers/helper\d+", delete)
    for img, files in images.items():
        daemon.on("GET", f"/containers/{ids[img]}/archive", Reply(body=tar_of(files, dirs=("usr",)),
                                                                   content_type="application/x-tar"))
        daemon.on("GET", f"/images/{img}/json", json={"Config": (configs or {}).get(img, {})})
    return deleted


def dist(name: str, version: str) -> dict[str, bytes]:
    return {f"usr/lib/python3/site-packages/{name}-{version}.dist-info/METADATA":
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()}


# --- sbom / vulns -------------------------------------------------------------------------------------------

def test_sbom_cyclonedx(client, daemon):
    deleted = serve_images(daemon, {"app:1": dist("requests", "2.31.0") | dist("Flask", "3.0.0")})
    bom = client.images.sbom("app:1", format="cyclonedx")
    assert bom["bomFormat"] == "CycloneDX" and bom["metadata"]["component"]["name"] == "app:1"
    assert [(c["name"], c["version"]) for c in bom["components"]] == [("Flask", "3.0.0"), ("requests", "2.31.0")]
    assert deleted == ["helper0"]  # the helper never outlives the op


def test_vulns_lookup_failure_names_the_mirror_setting(client, daemon, monkeypatch):
    s = socket.create_server(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens there
    monkeypatch.setenv("AISB_OSV_URL", f"http://127.0.0.1:{port}")
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    serve_images(daemon, {"app:1": dist("requests", "2.31.0")})
    with pytest.raises(APIError, match=r"vulnerability lookup failed: .*querybatch.*set \$AISB_OSV_URL"):
        client.images.vulns("app:1")


# --- diff ------------------------------------------------------------------------------------------------------

def test_diff_files_packages_and_config(client, daemon):
    a = dist("requests", "2.30.0") | {"app/main.py": b"print(1)\n", "app/old.txt": b"x"}
    b = dist("requests", "2.31.0") | {"app/main.py": b"print(2)\n", "app/new.txt": b"yy"}
    deleted = serve_images(daemon, {"app:1": a, "app:2": b}, configs={
        "app:1": {"Env": ["A=1"], "User": "root"}, "app:2": {"Env": ["A=1", "B=2"], "User": "app"}})
    out = client.images.diff("app:1", "app:2", top=5)
    assert (out["a"], out["b"]) == ("app:1", "app:2")
    files = out["files"]
    assert (files["added"], files["removed"], files["changed"]) == (2, 2, 1)  # + the renamed dist-info METADATA
    changes = {c["path"]: c["change"] for c in files["largest_changes"]}
    assert (changes["/app/new.txt"], changes["/app/old.txt"], changes["/app/main.py"]) == ("added", "removed", "changed")
    assert out["packages"]["upgraded"] == [{"ecosystem": "pypi", "name": "requests", "from": "2.30.0", "to": "2.31.0"}]
    assert set(out["config"]) == {"Env", "User"}
    assert sorted(deleted) == ["helper0", "helper1"]


# --- updates --------------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cert(tmp_path_factory) -> Path:
    if not shutil.which("openssl"):
        pytest.skip("needs the openssl CLI to make a test certificate")
    d = tmp_path_factory.mktemp("reg-tls")
    crt = d / "reg.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(crt.with_suffix(".key")),
                    "-out", str(crt)], check=True, capture_output=True)
    return crt


@pytest.fixture
def registry(cert, monkeypatch, tmp_path) -> Iterator[tuple[str, list[str]]]:
    """An anonymous HTTPS registry: HEAD /v2/<repo>/manifests/<tag> -> digest from DIGESTS (404 if unknown)."""
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "docker"))
    seen: list[str] = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_HEAD(self):
            seen.append(self.path)
            digest = DIGESTS.get(self.path.removeprefix("/v2/"))
            self.send_response(200 if digest else 404)
            if digest:
                self.send_header("Docker-Content-Digest", digest)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, cert.with_suffix(".key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    yield f"127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()
    srv.server_close()


DIGESTS = {"app/manifests/1": "sha256:new", "app/manifests/2": "sha256:same", "app/manifests/3": "sha256:remote",
           "app/manifests/4": "sha256:desc"}


def _local(daemon: FakeDaemon, reg: str) -> None:
    daemon.on("GET", f"/images/{reg}/app:1/json", json={"Id": "sha256:1", "RepoDigests": [f"{reg}/app@sha256:old"]})
    daemon.on("GET", f"/images/{reg}/app:2/json", json={"Id": "sha256:2", "RepoDigests": [f"{reg}/app@sha256:same"]})
    daemon.on("GET", f"/images/{reg}/app:3/json", json={"Id": "sha256:3", "RepoDigests": ["no-digest"]})  # built here
    daemon.on("GET", f"/images/{reg}/app:4/json",  # containerd image store: digest only on the descriptor
              json={"Id": "sha256:4", "RepoDigests": [], "Descriptor": {"digest": "sha256:desc"}})
    daemon.on("GET", f"/images/{reg}/app:5/json", json={"Id": "sha256:5"})  # the registry doesn't know the tag
    daemon.on("GET", f"/images/{reg}/gone:1/json", status=404, json={"message": "No such image"})
    daemon.on("GET", f"/images/{reg}/broken:1/json", status=500, json={"message": "storage driver failure"})


def test_updates_statuses(client, daemon, registry):
    reg, seen = registry
    _local(daemon, reg)
    refs = [f"{reg}/{r}" for r in ("app:1", "app:2", "app:3", "app:4", "app:5", "gone:1", "broken:1", "app:1")]
    out = {r["image"].removeprefix(f"{reg}/"): r for r in client.images.updates(*refs)}
    assert list(out) == ["app:1", "app:2", "app:3", "app:4", "app:5", "gone:1", "broken:1"]  # de-duplicated
    assert out["app:1"] == {"image": f"{reg}/app:1", "status": "outdated", "local": ["sha256:old"],
                            "remote": "sha256:new", "next": f"aisb images pull {reg}/app:1"}
    assert (out["app:2"]["status"], out["app:2"]["local"]) == ("current", ["sha256:same"]) and "next" not in out["app:2"]
    assert (out["app:3"]["status"], out["app:3"]["local"]) == ("local-only", [])
    assert (out["app:4"]["status"], out["app:4"]["local"]) == ("current", ["sha256:desc"])
    assert out["app:5"]["status"] == "unknown" and "HTTP 404" in out["app:5"]["error"]
    assert out["gone:1"]["status"] == "missing" and "No such image" in out["gone:1"]["error"]
    assert out["broken:1"]["status"] == "error" and "storage driver failure" in out["broken:1"]["error"]
    assert "/v2/app/manifests/1" in seen and not any("gone" in p or "broken" in p for p in seen)


def test_updates_defaults_to_running_containers_images(client, daemon, registry):
    reg, _ = registry
    _local(daemon, reg)
    daemon.on("GET", "/containers/json", json=[
        {"Image": f"{reg}/app:2"}, {"Image": f"{reg}/app:1"}, {"Image": f"{reg}/app:2"},
        {"Image": "sha256:" + "ab" * 32}, {"Image": ""}, {}])
    out = client.images.updates()
    assert [(r["image"], r["status"]) for r in out] == [(f"{reg}/app:1", "outdated"), (f"{reg}/app:2", "current")]


def test_updates_all_tagged_local_images(client, daemon, registry):
    reg, _ = registry
    _local(daemon, reg)
    daemon.on("GET", "/images/json", json=[
        {"RepoTags": [f"{reg}/app:2", f"{reg}/app:4"]}, {"RepoTags": ["<none>:<none>"]}, {"RepoTags": None}])
    out = client.images.updates(all=True)
    assert [(r["image"], r["status"]) for r in out] == [(f"{reg}/app:2", "current"), (f"{reg}/app:4", "current")]


@pytest.mark.parametrize("route", ["/images/json", "/containers/json"])
def test_updates_with_nothing_to_check(client, daemon, route):
    daemon.on("GET", route, json=None)
    assert client.images.updates(all=route == "/images/json") == []
