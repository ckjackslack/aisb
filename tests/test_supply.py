"""Supply chain: OSV matching (CVSS, severities, fixed versions), registry digests, image vulns/updates ops."""

import io
import json
import threading
import urllib.error
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aisb import supply
from aisb.cli import EXIT_OK, main
from aisb.insights import vulns
from aisb.insights.packages import Inventory, Package


@pytest.mark.parametrize(("vector", "score"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5), ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:2.0/AV:N", None), ("CVSS:3.1/AV:X/AC:L", None),
])
def test_cvss3(vector, score):
    assert vulns.cvss3(vector) == score


@pytest.mark.parametrize(("eco", "os_", "expected"), [
    ("apk", {"id": "alpine", "version": "3.20.10"}, "Alpine:v3.20"),
    ("dpkg", {"id": "debian", "version": "12"}, "Debian:12"),
    ("dpkg", {"id": "ubuntu", "version": "24.04"}, "Ubuntu:24.04:LTS"),
    ("dpkg", {"id": "ubuntu", "version": "23.10"}, "Ubuntu:23.10"),
    ("pypi", {}, "PyPI"), ("rpm", {"id": "rhel", "version": "9"}, None), ("apk", {"id": "wolfi"}, None),
])
def test_osv_ecosystem(eco, os_, expected):
    assert vulns.osv_ecosystem(eco, os_) == expected


ADVISORIES = {
    "CVE-A": {"id": "CVE-A", "summary": "openssl: bad", "severity": [{"type": "CVSS_V3",
              "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
              "affected": [{"package": {"name": "openssl", "ecosystem": "Alpine:v3.20"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.7-r0"}]}]}]},
    "GHSA-B": {"id": "GHSA-B", "aliases": ["CVE-2024-1"], "database_specific": {"severity": "MODERATE"},
               "affected": [{"package": {"name": "flask", "ecosystem": "PyPI"}, "ranges": [{"events": [{"fixed": "3.0.3"}]}]}]},
    "X-C": {"id": "X-C", "details": "no severity info"},
}


def test_report_orders_filters_and_extracts_fixes():
    comps = [{"ecosystem": "apk", "name": "openssl", "version": "3.1.4-r0"},
             {"ecosystem": "pypi", "name": "Flask", "version": "3.0.0"},
             {"ecosystem": "rpm", "name": "glibc", "version": "2.34"}]
    qs, owners, skipped = vulns.queries(comps, {"id": "alpine", "version": "3.20.3"})
    assert skipped == ["rpm"] and qs[1] == {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "3.0.0"}
    rep = vulns.report(owners, [["CVE-A"], ["GHSA-B", "X-C"]], ADVISORIES, qs)
    assert [(f["id"], f["severity"], f["fixed"]) for f in rep["findings"]] == [
        ("CVE-A", "critical", ["3.1.7-r0"]), ("GHSA-B", "medium", ["3.0.3"]), ("X-C", "unknown", [])]
    assert rep["counts"]["critical"] == 1 and rep["fixable"] == 2 and rep["findings"][1]["aliases"] == ["CVE-2024-1"]
    high = vulns.report(owners, [["CVE-A"], ["GHSA-B"]], ADVISORIES, qs, min_severity="high")
    assert [f["id"] for f in high["findings"]] == ["CVE-A"]


# --- registry -------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("ref", "parsed"), [
    ("nginx", ("registry-1.docker.io", "library/nginx", "latest")),
    ("nginx:1.27", ("registry-1.docker.io", "library/nginx", "1.27")),
    ("bitnami/redis:7", ("registry-1.docker.io", "bitnami/redis", "7")),
    ("ghcr.io/org/app:v2", ("ghcr.io", "org/app", "v2")),
    ("localhost:5000/app", ("localhost:5000", "app", "latest")),
    ("reg.example.com/a/b@sha256:ab", ("reg.example.com", "a/b", "sha256:ab")),
])
def test_parse_ref(ref, parsed):
    assert supply.parse_ref(ref) == parsed


def test_remote_digest_bearer_flow(monkeypatch):
    seen: list[tuple[str, str | None]] = []

    class Resp(io.BytesIO):
        def __init__(self, body: bytes = b"", headers: dict | None = None):
            super().__init__(body)
            self.headers = headers or {}

    def fake_open(req, timeout=20):
        seen.append((req.full_url, req.headers.get("Authorization")))
        if req.full_url.startswith("https://auth.example/token"):
            assert "scope=repository%3Alibrary%2Falpine%3Apull" in req.full_url
            return Resp(json.dumps({"token": "T"}).encode())
        if req.headers.get("Authorization") != "Bearer T":
            h = Message()
            h["WWW-Authenticate"] = 'Bearer realm="https://auth.example/token",service="registry.docker.io"'
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", h, None)
        assert "application/vnd.oci.image.index.v1+json" in req.headers["Accept"]
        return Resp(headers={"Docker-Content-Digest": "sha256:new"})
    monkeypatch.setattr(supply, "_open", fake_open)
    assert supply.remote_digest("alpine:3.20") == "sha256:new"
    assert [u.split("?")[0] for u, _ in seen] == ["https://registry-1.docker.io/v2/library/alpine/manifests/3.20",
                                                  "https://auth.example/token",
                                                  "https://registry-1.docker.io/v2/library/alpine/manifests/3.20"]


# --- ops ----------------------------------------------------------------------------------------------------

@pytest.fixture
def osv(monkeypatch):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            results = [{"vulns": [{"id": "CVE-A"}]} if q["package"]["name"] == "openssl" else {}
                       for q in body["queries"]]
            self._send({"results": results})

        def do_GET(self):
            self._send(ADVISORIES[self.path.rsplit("/", 1)[-1]])

        def _send(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("AISB_OSV_URL", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    yield
    srv.shutdown()


def test_images_vulns_op(osv, monkeypatch, host, capsys):
    from aisb.api.images import Images
    inv = Inventory(packages=[Package("apk", "openssl", "3.1.4-r0", "lib/apk/db/installed"),
                              Package("apk", "musl", "1.2.5-r0", "lib/apk/db/installed")],
                    os={"id": "alpine", "version": "3.20.3"})
    monkeypatch.setattr(Images, "inventory", lambda self, ref, hash_files=False: inv)  # skip the fs walk
    assert main(["images", "vulns", "app:1", "--host", host, "--json"]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert (out["queried"], out["vulnerable_packages"], out["counts"]["critical"]) == (2, 1, 1)
    assert out["findings"][0]["fixed"] == ["3.1.7-r0"]


def test_images_updates_op(daemon, host, monkeypatch, capsys):
    daemon.on("GET", "/containers/json", json=[{"Image": "app:1"}, {"Image": "sha256:abc"}, {"Image": "db:2"}])
    daemon.on("GET", "/images/app:1/json", json={"RepoDigests": ["app@sha256:old"]})
    daemon.on("GET", "/images/db:2/json", json={"RepoDigests": ["db@sha256:same"]})
    monkeypatch.setattr(supply, "remote_digest", lambda ref: {"app:1": "sha256:new", "db:2": "sha256:same"}[ref])
    assert main(["images", "updates", "--host", host, "--json"]) == EXIT_OK
    out = {r["image"]: r for r in json.loads(capsys.readouterr().out)}
    assert out["app:1"]["status"] == "outdated" and out["app:1"]["next"] == "aisb images pull app:1"
    assert out["db:2"]["status"] == "current" and "sha256:abc" not in out
