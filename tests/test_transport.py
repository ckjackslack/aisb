import pytest

from aisb import errors
from aisb.transport import DRY_ID, Endpoint, Request, Transport, resolve_endpoint
from conftest import API, Reply


@pytest.mark.parametrize(("host", "env", "url", "tls"), [
    ("unix:///x.sock", {}, "unix:///x.sock", False),
    (None, {"DOCKER_HOST": "tcp://h:2375"}, "tcp://h:2375", False),
    (None, {"DOCKER_HOST": "tcp://h:2376", "DOCKER_TLS_VERIFY": "1"}, "tcp://h:2376", True),
    ("https://h", {}, "https://h", True),
])
def test_resolve_endpoint(host, env, url, tls):
    ep = resolve_endpoint(host, env)
    assert (ep.url, ep.tls is not None) == (url, tls)


def test_resolve_endpoint_prefers_existing_socket(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p.endswith(".docker/run/docker.sock"))
    assert resolve_endpoint(None, {}).url.endswith(".docker/run/docker.sock")


def test_resolve_endpoint_rejects_unknown_scheme():
    with pytest.raises(ValueError, match="unsupported"):
        resolve_endpoint("ssh://box")


def test_version_is_negotiated_and_prefixed(client, daemon):
    daemon.on("GET", "/info", json={"ok": 1})
    assert client.transport.json("GET", "/info") == {"ok": 1}
    assert daemon.seen[0].raw_path == f"/v{API}/info"
    assert client.transport.version == API


@pytest.mark.parametrize(("status", "exc"), [
    (304, errors.NotModified), (400, errors.BadRequest), (404, errors.NotFound),
    (409, errors.Conflict), (500, errors.APIError), (503, errors.APIError),
])
def test_status_maps_to_typed_error(client, daemon, status, exc):
    daemon.on("GET", "/x", status=status, json={"message": "boom "})
    with pytest.raises(exc) as info:
        client.transport.json("GET", "/x")
    # 304 responses carry no body by HTTP semantics, so the message falls back to the status.
    assert (info.value.status, str(info.value)) == (status, "HTTP 304" if status == 304 else "boom")


def test_unreachable_socket_is_unavailable(tmp_path):
    t = Transport(Endpoint(f"unix://{tmp_path}/missing.sock"), timeout=1)
    with pytest.raises(errors.DockerUnavailable, match="cannot reach Docker"):
        t.json("GET", "/info")


def test_query_encoding():
    r = Request("GET", "/p", {"a": True, "b": False, "c": None, "f": {"label": ["x=1"]}, "n": 3})
    assert r.target == "/p?a=true&b=false&f=%7B%22label%22%3A+%5B%22x%3D1%22%5D%7D&n=3"


def test_chunked_stream(client, daemon):
    daemon.on("GET", "/s", chunks=[b"ab", b"cd", b"ef"])
    assert b"".join(client.transport.stream("GET", "/s")) == b"abcdef"


def test_dry_run_records_writes_but_runs_reads(client, daemon):
    daemon.on("GET", "/r", json=[1])
    t = client.transport
    with t.dry_run() as plan:
        assert t.json("GET", "/r") == [1]
        assert t.json("POST", "/w", body={"a": 1}) == {"Id": DRY_ID}
        assert t.raw("GET", f"/c/{DRY_ID}/logs") == b""
        assert list(t.stream("DELETE", "/d")) == []
    assert [(r.method, r.path) for r in plan] == [("POST", "/w"), ("GET", f"/c/{DRY_ID}/logs"), ("DELETE", "/d")]
    assert daemon.calls() == [("GET", "/r")]


def test_non_json_body_is_returned_as_text(client, daemon):
    daemon.on("GET", "/t", Reply(body=b"plain", content_type="text/plain"))
    assert client.transport.json("GET", "/t") == "plain"
