"""HTTP requests to a container by name: the published port (or container IP) is resolved for you."""

import http.client
import json
import ssl
import threading
import time
from pathlib import Path
from typing import Annotated, Any, Literal
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


    # --- record & replay ------------------------------------------------------------------------
    @op(Tier.READ)
    def record(self, ref: Ref, *, out: Annotated[str, "host .jsonl file for the exchanges"],
               seconds: Annotated[float, "how long to record"] = 60.0,
               via: Annotated[Literal["proxy", "tcpdump"], "proxy: clients use --listen; tcpdump: passive capture"] = "proxy",
               listen: Annotated[int, "proxy mode: host port clients send traffic to"] = 18099,
               port: Port = None, max_body: Annotated[int, "bytes kept per body"] = 64 * 1024,
               image: Annotated[str, "tcpdump mode: toolbox image"] = "nicolaka/netshoot:v0.13") -> dict[str, Any]:
        """Record real HTTP exchanges with a container: through a recording reverse proxy, or passively with a
        tcpdump sidecar in its network namespace (pcap parsed on the host). Replay them with `http replay`."""
        from ..insights import traffic
        path = Path(out).expanduser()
        if via == "tcpdump":
            exchanges = self._record_pcap(ref, seconds=seconds, port=port, image=image, max_body=max_body)
        else:
            exchanges = self._record_proxy(ref, seconds=seconds, listen=listen, port=port, max_body=max_body)
        path.write_text("".join(json.dumps(e) + "\n" for e in exchanges))
        methods: dict[str, int] = {}
        for e in exchanges:
            methods[e["method"]] = methods.get(e["method"], 0) + 1
        return {"written": str(path), "exchanges": len(exchanges), "methods": methods, "via": via,
                "note": "auth and cookie header values are masked" if exchanges else
                        (f"no traffic; send requests to http://127.0.0.1:{listen}" if via == "proxy" else "no traffic seen")}

    def _record_proxy(self, ref: str, *, seconds: float, listen: int, port: int | None,
                      max_body: int) -> list[dict[str, Any]]:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from ..insights import traffic
        host, hport, _ = self.resolve(ref, port)
        exchanges: list[dict[str, Any]] = []
        lock = threading.Lock()

        class Proxy(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: Any) -> None:
                pass

            def _forward(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
                start = time.monotonic()
                conn = http.client.HTTPConnection(host, hport, timeout=30)
                try:
                    conn.request(self.command, self.path, body=body or None, headers=headers)
                    resp = conn.getresponse()
                    data = resp.read()
                    status, rheaders = resp.status, dict(resp.getheaders())
                except OSError as e:
                    status, rheaders, data = 502, {"Content-Type": "text/plain"}, f"aisb proxy: {e}".encode()
                finally:
                    conn.close()
                ms = round((time.monotonic() - start) * 1000, 2)
                self.send_response(status)
                for k, v in rheaders.items():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)
                with lock:
                    exchanges.append({"t": time.time(), "method": self.command, "path": self.path,
                                      "req_headers": traffic.safe_headers(dict(self.headers.items())),
                                      "req_body": traffic.body_repr(body, self.headers.get("Content-Type", ""), max_body),
                                      "status": status, "resp_headers": traffic.safe_headers(rheaders),
                                      "resp_body": traffic.body_repr(data, rheaders.get("Content-Type", ""), max_body),
                                      "ms": ms})

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _forward

        server = ThreadingHTTPServer(("127.0.0.1", listen), Proxy)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
        try:
            time.sleep(seconds)
        finally:
            server.shutdown()
            server.server_close()
        return sorted(exchanges, key=lambda e: e["t"])

    def _record_pcap(self, ref: str, *, seconds: float, port: int | None, image: str,
                     max_body: int) -> list[dict[str, Any]]:
        from ..insights import traffic
        from ..models import RunSpec
        from ..rootfs import read_file
        from .containers import Containers
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        t = Target.from_inspect(info)
        cport = port or (t.exposed[0] if t.exposed else 80)
        ctr = Containers(self.t)
        # Write to a file, not stdout: Docker's log driver stores output as UTF-8 text and corrupts binary.
        spec = RunSpec(image=image, cmd=("sh", "-c", f"timeout {int(seconds)} tcpdump -i any -U -s 0 "
                                         f"-w /tmp/aisb.pcap tcp port {cport} 2>/dev/null; true"),
                       network=f"container:{info['Id']}", cap_add=("NET_RAW", "NET_ADMIN"), labels={"aisb.record": ref})
        cid = ctr.create_from(spec)
        try:
            self.t.json("POST", f"/containers/{cid}/start")
            self.t.json("POST", f"/containers/{cid}/wait", timeout=None)
            pcap = read_file(self.t, cid, "/tmp/aisb.pcap") or b""  # the archive API works on stopped containers
        finally:
            self.t.json("DELETE", f"/containers/{cid}", query={"force": True})
        return traffic.exchanges_from_pcap(pcap, cport, max_body=max_body)

    @op(Tier.MUTATE)
    def replay(self, file: Annotated[str, "recording from `http record`"], *, to: Annotated[str, "container to replay against"],
               port: Port = None, all_methods: Annotated[bool, "also replay non-GET/HEAD requests (they change state)"] = False,
               ignore: Annotated[list[str] | None, "JSON paths to ignore, e.g. meta.requestId or items.*.updatedAt"] = None,
               limit: Annotated[int, "max exchanges replayed"] = 500) -> dict[str, Any]:
        """Replay recorded traffic against another container (e.g. the new version) and compare status codes,
        JSON bodies (volatile ids/timestamps masked) and latency. Shadow testing without touching production."""
        from ..insights import traffic
        rows = [json.loads(line) for line in Path(file).expanduser().read_text().splitlines() if line.strip()]
        rows = [r for r in rows if all_methods or r["method"] in ("GET", "HEAD")][:limit]
        host, hport, via = self.resolve(to, port)
        if self.t.planning:
            for r in rows[:20]:
                self.t.note(http=r["method"], url=f"http://{host}:{hport}{r['path']}")
            return {}
        results, ratios = [], []
        for r in rows:
            body = (r.get("req_body") or {}).get("text", "").encode() or None
            headers = {k: v for k, v in (r.get("req_headers") or {}).items()
                       if v != "***" and k.lower() not in ("host", "content-length", "connection")}
            start = time.monotonic()
            conn = http.client.HTTPConnection(host, hport, timeout=30)
            try:
                conn.request(r["method"], r["path"], body=body, headers=headers)
                resp = conn.getresponse()
                data, status = resp.read(), resp.status
            except OSError as e:
                data, status = str(e).encode(), None
            finally:
                conn.close()
            ms = (time.monotonic() - start) * 1000
            recorded = (r.get("resp_body") or {}).get("text", "")
            diffs = traffic.compare_bodies(recorded, data.decode(errors="replace"), ignore or []) \
                if r["method"] != "HEAD" else []
            if r.get("ms"):
                ratios.append(ms / max(r["ms"], 0.01))
            results.append({"method": r["method"], "path": r["path"], "status": [r.get("status"), status],
                            "status_match": r.get("status") == status, "body_match": not diffs, "diffs": diffs,
                            "ms": [r.get("ms"), round(ms, 2)]})
        ratios.sort()
        matched = [x for x in results if x["status_match"] and x["body_match"]]
        return {"replayed": len(results), "to": to, "via": via,
                "match_rate": round(len(matched) / len(results), 3) if results else None,
                "status_mismatches": sum(not x["status_match"] for x in results),
                "body_mismatches": sum(x["status_match"] and not x["body_match"] for x in results),
                "latency_ratio": {"p50": round(ratios[len(ratios) // 2], 2), "p95": round(ratios[int(len(ratios) * 0.95)], 2)}
                if ratios else None,
                "mismatches": [x for x in results if not (x["status_match"] and x["body_match"])][:20]}
