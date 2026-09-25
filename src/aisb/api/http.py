"""HTTP requests to a container by name: the published port (or container IP) is resolved for you."""

import http.client
import json
import ssl
import time
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from ..ops import Resource, Tier, op
from ..services import Target
from ..transport import SECRET_KEY
from ..util import clip, kv, q

Ref = Annotated[str, "container name or id"]
Port = Annotated[int | None, "container port (default: first published, else first exposed)"]
Headers = Annotated[dict[str, str] | None, "request header KEY=VALUE"]
_SHOWN = ("content-type", "content-length", "location", "server", "cache-control", "www-authenticate",
          "x-request-id", "retry-after", "set-cookie")


class Http(Resource, name="http"):
    def resolve(self, ref: str, port: int | None) -> tuple[str, int, str]:
        t = Target.from_inspect(self.t.json("GET", f"/containers/{q(ref)}/json"))
        cport = port or (min(t.published) if t.published else t.exposed[0] if t.exposed else 80)
        if cport in t.published:
            ip, hport = t.published[cport]
            docker_host = urlsplit(self.t.endpoint.url)
            host = docker_host.hostname if docker_host.scheme != "unix" and docker_host.hostname else \
                "127.0.0.1" if ip in ("0.0.0.0", "") else "::1" if ip == "::" else ip
            return host, hport, f"published {host}:{hport} -> {cport}"
        if not t.ips:
            raise ValueError(f"port {cport} of {ref!r} is not published and the container has no IP")
        return t.ips[0], cport, f"container IP {t.ips[0]}:{cport} (not published; reachable from a Linux Docker host)"

    def _request(self, ref: str, path: str, *, method: str, body: bytes | None, headers: dict[str, str],
                 port: int | None, https: bool, insecure: bool, max_bytes: int, seconds: float) -> dict[str, Any]:
        host, hport, via = self.resolve(ref, port)
        if not path.startswith("/"):
            path = "/" + path
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()  # noqa: S323
        conn = http.client.HTTPSConnection(host, hport, timeout=seconds, context=ctx) if https \
            else http.client.HTTPConnection(host, hport, timeout=seconds)
        start = time.monotonic()
        try:
            conn.request(method, path, body=body, headers={"User-Agent": "aisb", **headers})
            resp = conn.getresponse()
            ttfb = time.monotonic() - start
            raw = resp.read(max_bytes + 1)
        except OSError as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}", "via": via,
                    "url": f"{'https' if https else 'http'}://{host}:{hport}{path}"}
        finally:
            conn.close()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        shown = {k: ("***" if k == "set-cookie" else hdrs[k]) for k in _SHOWN if k in hdrs}
        ctype = hdrs.get("content-type", "")
        truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        body_out: Any
        if "json" in ctype and not truncated:
            try:
                body_out = json.loads(raw)
            except ValueError:
                body_out = raw.decode(errors="replace")
        elif ctype.startswith(("text/", "application/xml", "application/javascript")) or b"\0" not in raw[:1024]:
            body_out = clip(raw.decode(errors="replace"), max_bytes)["output"]
        else:
            body_out = f"<{len(raw)} bytes {ctype or 'binary'}>"
        return {"ok": resp.status < 400, "status": resp.status, "reason": resp.reason,
                "url": f"{'https' if https else 'http'}://{host}:{hport}{path}", "via": via,
                "ttfb_ms": int(ttfb * 1000), "total_ms": int((time.monotonic() - start) * 1000),
                "headers": shown, "body": body_out, "truncated": truncated}

    @op(Tier.READ)
    def get(self, ref: Ref, path: Annotated[str, "request path"] = "/", *, port: Port = None, header: Headers = None,
            https: bool = False, insecure: Annotated[bool, "skip TLS verification (self-signed dev certs)"] = False,
            head: Annotated[bool, "send HEAD instead of GET"] = False,
            max_bytes: Annotated[int, "max body bytes read"] = 16 * 1024,
            seconds: Annotated[float, "request timeout"] = 10.0) -> dict[str, Any]:
        """GET a container endpoint: status, timing, key headers, body (parsed when JSON). Exit 4 on HTTP errors."""
        return self._request(ref, path, method="HEAD" if head else "GET", body=None, headers=kv(header), port=port,
                             https=https, insecure=insecure, max_bytes=max_bytes, seconds=seconds)

    @op(Tier.MUTATE)
    def send(self, ref: Ref, path: Annotated[str, "request path"] = "/", *,
             method: Annotated[str, "POST, PUT, PATCH, DELETE ..."] = "POST",
             data: Annotated[str | None, "request body, or @file to read it from a host file"] = None,
             json_data: Annotated[str | None, "JSON body (validated; sets Content-Type)"] = None,
             header: Headers = None, port: Port = None, https: bool = False, insecure: bool = False,
             max_bytes: int = 16 * 1024, seconds: float = 30.0) -> dict[str, Any]:
        """Send a non-GET request to a container endpoint (state-changing, so mutate tier)."""
        headers = kv(header)
        body: bytes | None = None
        if json_data is not None:
            body = json.dumps(json.loads(json_data)).encode()
            headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = Path(data[1:]).expanduser().read_bytes() if data.startswith("@") else data.encode()
        if self.t.planning:
            host, hport, via = self.resolve(ref, port)
            safe = {k: "***" if SECRET_KEY.search(k) else v for k, v in headers.items()}
            self.t.note(http=method.upper(), url=f"{'https' if https else 'http'}://{host}:{hport}{path}", via=via,
                        headers=safe, body_bytes=len(body or b""))
            return {}
        return self._request(ref, path, method=method.upper(), body=body, headers=headers, port=port, https=https,
                             insecure=insecure, max_bytes=max_bytes, seconds=seconds)
