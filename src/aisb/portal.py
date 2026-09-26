"""`aisb portal`: a zero-dependency local web UI over the op registry.

Security model: loopback bind by default, a per-run token required on every /api call (X-AISB-Token), a Host
header allowlist against DNS rebinding, read ops always, mutate ops only with --allow mutate, destroy never.
"""

import argparse
import hmac
import json
import secrets
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .errors import DockerError
from .ops import EMPTY, Op, Tier, invoke, jsonable, registry

# Ops that touch host files or run for a long time are not offered through a browser; neither are
# host-path arguments (the UI must never become a way to read or write the host filesystem).
HOST_EFFECTS = frozenset({"system.blackbox", "system.events", "http.record", "containers.cp", "images.build"})
HOST_PARAMS = frozenset({"out", "file", "spec", "env_file"})
CACHE_S = 3.0


def exposed_ops(allow: Tier) -> dict[str, Op]:
    tiers = {Tier.READ} | ({Tier.MUTATE} if allow is Tier.MUTATE else set())
    return {f"{o.resource}.{o.name}": o for ops in registry().values() for o in ops.values()
            if o.tier in tiers and f"{o.resource}.{o.name}" not in HOST_EFFECTS
            and not any(p.name in HOST_PARAMS and p.default is EMPTY for p in o.params)}


def overview(client: Any) -> dict[str, Any]:
    ctrs = [jsonable(c) if not isinstance(c, dict) else c for c in client.containers.ls(all=True)]
    doctor = client.system.doctor(tail=50)
    verdicts = {p["container"]: p for p in doctor["problems"]}
    try:
        services = {s["container"]: s for s in client.svc.ls()}
    except DockerError:
        services = {}
    rows = []
    for c in ctrs:
        name = c.get("name")
        p = verdicts.get(name)
        s = services.get(name) or {}
        rows.append({**{k: c.get(k) for k in ("name", "image", "state", "status", "ports")},
                     "verdict": p["verdict"] if p else ("healthy" if c.get("state") == "running" else c.get("state")),
                     "likely_cause": p["likely_cause"] if p else None, "findings": p["findings"] if p else [],
                     "service": s.get("kind"), "url": s.get("url")})
    return {"at": time.time(), "summary": doctor["summary"], "containers": rows}


class Portal:
    def __init__(self, client_factory: Callable[[], Any], *, allow: Tier = Tier.READ, token: str | None = None,
                 hosts: frozenset[str] = frozenset()) -> None:
        self.factory, self.allow = client_factory, allow
        self.token = token or secrets.token_urlsafe(24)
        self.hosts = hosts
        self.ops = exposed_ops(allow)
        self._cache: tuple[float, dict[str, Any]] | None = None
        self._lock = threading.Lock()

    def cached_overview(self) -> dict[str, Any]:
        with self._lock:
            if self._cache and time.monotonic() - self._cache[0] < CACHE_S:
                return self._cache[1]
            data = overview(self.factory())
            self._cache = (time.monotonic(), data)
            return data

    def call(self, qualname: str, args: dict[str, Any]) -> tuple[int, Any]:
        o = self.ops.get(qualname)
        if o is None:
            return 403, {"error": f"{qualname} is not available in the portal (allow={self.allow})"}
        args = dict(args)
        if banned := sorted(HOST_PARAMS & args.keys()):
            return 403, {"error": f"host-file arguments are not accepted by the portal: {', '.join(banned)}"}
        dry_run = bool(args.pop("dry_run", False))
        try:
            outcome = invoke(self.factory(), o, args, dry_run=dry_run)
        except DockerError as e:
            return 502, e.as_dict()
        except (ValueError, TypeError) as e:
            return 400, {"error": "UsageError", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            return 500, {"error": type(e).__name__, "message": str(e)}
        if o.tier is not Tier.READ:
            with self._lock:
                self._cache = None
        return 200, outcome.payload()

    def catalog(self) -> list[dict[str, Any]]:
        return [{"op": k, "tier": o.tier, "summary": o.summary, "params": o.json_schema()}
                for k, o in self.ops.items()]

    def handler(self) -> type[BaseHTTPRequestHandler]:
        portal = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "aisb-portal"

            def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
                pass

            def _send(self, code: int, body: bytes, ctype: str) -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                 "connect-src 'self'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body)

            def _json(self, code: int, data: Any) -> None:
                self._send(code, json.dumps(data, default=jsonable).encode(), "application/json")

            def _guard(self, api: bool) -> bool:
                if self.headers.get("Host", "") not in portal.hosts:
                    self._json(421, {"error": "unexpected Host header"})
                    return False
                if api and not hmac.compare_digest(self.headers.get("X-AISB-Token", ""), portal.token):
                    self._json(401, {"error": "missing or invalid X-AISB-Token"})
                    return False
                return True

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if not self._guard(path.startswith("/api/")):
                    return
                if path == "/":
                    page = PAGE.replace("__TOKEN__", portal.token).replace("__ALLOW__", portal.allow.value)
                    self._send(200, page.encode(), "text/html; charset=utf-8")
                elif path == "/api/overview":
                    try:
                        self._json(200, portal.cached_overview())
                    except DockerError as e:
                        self._json(502, e.as_dict())
                    except Exception as e:  # noqa: BLE001 - keep the UI answering with a readable error
                        self._json(500, {"error": type(e).__name__, "message": str(e)})
                elif path == "/api/ops":
                    self._json(200, portal.catalog())
                else:
                    self._json(404, {"error": "not found"})

            def do_POST(self) -> None:
                if not self._guard(True):
                    return
                parts = self.path.split("?", 1)[0].strip("/").split("/")
                if len(parts) != 4 or parts[:2] != ["api", "op"]:
                    return self._json(404, {"error": "use POST /api/op/<resource>/<op>"})
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    args = json.loads(self.rfile.read(n) or b"{}") if n <= 1 << 20 else None
                except ValueError:
                    args = None
                if not isinstance(args, dict):
                    return self._json(400, {"error": "body must be a JSON object of op arguments (max 1 MiB)"})
                self._json(*portal.call(f"{parts[2]}.{parts[3]}", args))

        return Handler

    def server(self, bind: str, port: int) -> ThreadingHTTPServer:
        srv = ThreadingHTTPServer((bind, port), self.handler())
        real = srv.server_address[1]
        if not self.hosts:
            self.hosts = frozenset(f"{h}:{real}" for h in {bind, "127.0.0.1", "localhost", "[::1]"})
        srv.daemon_threads = True
        return srv


def main(argv: list[str] | None = None) -> int:
    from .client import Docker
    p = argparse.ArgumentParser(prog="aisb portal", description="local web UI (read-only unless --allow mutate)")
    p.add_argument("--host", help="Docker endpoint (default: $DOCKER_HOST or local socket)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--bind", default="127.0.0.1", help="listen address (keep it loopback unless you know why)")
    p.add_argument("--allow", choices=["read", "mutate"], default="read", help="highest op tier the UI may run")
    p.add_argument("--token", help="fixed token (default: random per run)")
    args = p.parse_args(argv)
    version = Docker(args.host).transport.version  # negotiate once, reuse for every per-request client
    portal = Portal(lambda: Docker(args.host, timeout=120, version=version), allow=Tier(args.allow), token=args.token)
    srv = portal.server(args.bind, args.port)
    url = f"http://{'127.0.0.1' if args.bind in ('0.0.0.0', '::') else args.bind}:{srv.server_address[1]}/"
    print(json.dumps({"url": url, "token": portal.token, "allow": args.allow, "ops": len(portal.ops)}), flush=True)
    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: listening on {args.bind}; anyone who can reach it and knows the token can run ops",
              file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>aisb portal</title>
<style>
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mute:#6b6b66;--card:#fff;--line:#e3e3de;--acc:#2f5fd0;
--ok:#1f8a4c;--warn:#b7791f;--bad:#c53030;--code:#f0f0ec}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#131412;--fg:#e8e8e3;--mute:#9a9a93;
--card:#1c1d1b;--line:#2e2f2c;--acc:#7aa2ff;--ok:#48bb78;--warn:#ecc94b;--bad:#fc8181;--code:#252623}}
:root[data-theme=dark]{--bg:#131412;--fg:#e8e8e3;--mute:#9a9a93;--card:#1c1d1b;--line:#2e2f2c;--acc:#7aa2ff;
--ok:#48bb78;--warn:#ecc94b;--bad:#fc8181;--code:#252623}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
header{display:flex;gap:12px;align-items:center;padding:14px 20px;border-bottom:1px solid var(--line)}
h1{font-size:16px;margin:0}.sp{flex:1}.mute{color:var(--mute)}button{font:inherit;cursor:pointer;
border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:4px 10px}
button.danger{border-color:var(--bad);color:var(--bad)}main{display:grid;grid-template-columns:1fr;gap:16px;padding:16px 20px}
@media(min-width:1000px){main.open{grid-template-columns:1fr 480px}}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--mute);font-size:12px;text-transform:uppercase}tr.row{cursor:pointer}
tr.row:hover,tr.sel{background:var(--code)}.chip{display:inline-block;border-radius:10px;padding:0 8px;font-size:12px;
border:1px solid currentColor}.healthy{color:var(--ok)}.degraded{color:var(--warn)}.failing,.exited,.dead{color:var(--bad)}
.created,.paused{color:var(--mute)}aside{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;
min-width:0}pre{background:var(--code);padding:10px;border-radius:6px;overflow:auto;max-height:420px;font-size:12px}
textarea{width:100%;min-height:70px;font:12px ui-monospace,monospace;background:var(--code);color:var(--fg);
border:1px solid var(--line);border-radius:6px;padding:8px}a{color:var(--acc)}.row2{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
code{font:12px ui-monospace,monospace}@media(max-width:700px){.hide-s{display:none}header,main{padding-left:16px;padding-right:16px}}
</style></head><body>
<header><h1>aisb portal</h1><span class="mute" id="sum"></span><span class="sp"></span>
<span class="mute">allow: __ALLOW__</span><button id="theme">theme</button><button id="refresh">refresh</button></header>
<main id="main"><div style="min-width:0;overflow-x:auto"><table><thead><tr><th>container</th><th>verdict</th>
<th class="hide-s">image</th><th class="hide-s">status</th><th>service</th></tr></thead><tbody id="rows"></tbody></table></div>
<aside id="drawer" hidden></aside></main>
<script>
const TOKEN="__TOKEN__", ALLOW="__ALLOW__";
const $=s=>document.querySelector(s), esc=s=>String(s??"").replace(/[&<>"']/g,c=>"&#"+c.charCodeAt(0)+";");
async function api(path,body){const r=await fetch(path,{method:body?"POST":"GET",
 headers:{"X-AISB-Token":TOKEN,"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
 const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw j;return j}
const op=(o,a)=>api("/api/op/"+o.replace(".","/"),a||{});
let data=null, sel=null;
async function load(){try{data=await api("/api/overview")}catch(e){$("#rows").innerHTML=`<tr><td colspan=5>${esc(JSON.stringify(e))}</td></tr>`;return}
 const s=data.summary;$("#sum").textContent=`${s.failing} failing · ${s.degraded} degraded · ${s.healthy} healthy`;
 $("#rows").innerHTML=data.containers.map(c=>`<tr class="row${c.name===sel?" sel":""}" data-n="${esc(c.name)}">
 <td><b>${esc(c.name)}</b>${c.likely_cause?`<div class="mute">${esc(c.likely_cause)}</div>`:""}</td>
 <td><span class="chip ${esc(c.verdict)}">${esc(c.verdict)}</span></td><td class="hide-s">${esc(String(c.image).startsWith("sha256:")?c.image.slice(0,19):c.image)}</td>
 <td class="hide-s mute">${esc(c.status)}</td><td>${c.service?esc(c.service):""}${c.url&&/^https?:/.test(c.url)?
 ` <a href="${esc(c.url)}" target="_blank" rel="noopener">open</a>`:""}</td></tr>`).join("");
 document.querySelectorAll("tr.row").forEach(tr=>tr.onclick=()=>open(tr.dataset.n))}
function block(title,obj){return `<h3>${esc(title)}</h3><pre>${esc(typeof obj==="string"?obj:JSON.stringify(obj,null,1))}</pre>`}
async function open(name){sel=name;$("#main").classList.add("open");const d=$("#drawer");d.hidden=false;
 document.querySelectorAll("tr.row").forEach(tr=>tr.classList.toggle("sel",tr.dataset.n===name));
 const c=data.containers.find(x=>x.name===name)||{};
 d.innerHTML=`<div class="row2"><h2 style="margin:0;flex:1">${esc(name)}</h2><button id="close">×</button></div>
 ${c.url?`<div class="row2"><code>${esc(c.url)}</code><button id="copy">copy</button></div>`:""}
 ${ALLOW==="mutate"?`<div class="row2"><button id="restart">restart</button><button class="danger" id="stop">stop</button></div>`:""}
 <div id="doc" class="mute">running doctor…</div><div id="sql"></div><div id="svc"></div>`;
 $("#close").onclick=()=>{sel=null;d.hidden=true;$("#main").classList.remove("open");load()};
 if(c.url)$("#copy").onclick=()=>navigator.clipboard.writeText(c.url);
 if(ALLOW==="mutate"){for(const a of ["restart","stop"])$("#"+a).onclick=async()=>{
  if(!confirm(`${a} ${name}?`))return;try{await op("containers."+a,{ref:name})}catch(e){alert(JSON.stringify(e))}load()}}
 if(["postgres","mysql","mariadb","sqlite"].includes(c.service)){$("#sql").innerHTML=`<h3>read-only SQL</h3>
  <textarea id="q">select 1</textarea><div class="row2"><button id="run">run</button></div><div id="qr"></div>`;
  $("#run").onclick=async()=>{try{$("#qr").innerHTML=block("result",await op("db.query",{ref:name,sql:$("#q").value}))}
  catch(e){$("#qr").innerHTML=block("error",e)}}}
 try{const r=await op("containers.doctor",{ref:name,tail:300});$("#doc").innerHTML=
  block("doctor: "+r.verdict,{likely_cause:r.likely_cause,findings:(r.findings||[]).map(f=>`${f.severity}:${f.code}: ${f.summary}`),
  next:r.next})+block("log patterns",(r.log_patterns||r.logs||[]))}catch(e){$("#doc").innerHTML=block("doctor failed",e)}
 if(c.service){try{$("#svc").innerHTML=block("service stats",await op("svc.stats",{ref:name}))}catch(e){}}}
$("#refresh").onclick=load;
$("#theme").onclick=()=>{const r=document.documentElement,cur=r.dataset.theme||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light");
 r.dataset.theme=cur==="dark"?"light":"dark";try{localStorage.setItem("aisb-theme",r.dataset.theme)}catch(e){}};
try{const t=localStorage.getItem("aisb-theme");if(t)document.documentElement.dataset.theme=t}catch(e){}
load();setInterval(()=>{if(!document.hidden)load()},10000);
</script></body></html>
"""

if __name__ == "__main__":
    raise SystemExit(main())
