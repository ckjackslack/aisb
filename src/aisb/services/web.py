"""Web servers and proxies: validate config, then reload gracefully (never reload a broken config)."""

import re
from typing import Any

from ..util import q
from .base import Adapter, ServiceError, register


class ConfigReloadable(Adapter):
    check_argv: tuple[str, ...] = ()
    reload_argv: tuple[str, ...] | None = None
    reload_signal: str | None = None

    def probe(self) -> str:
        from ..api.containers import port_open
        port = self.default_port() or 80
        if port in self.t.published:
            host = "127.0.0.1" if self.t.published[port][0] in ("0.0.0.0", "") else self.t.published[port][0]
            addr = (host, self.t.published[port][1])
        elif self.t.ips:
            addr = (self.t.ips[0], port)
        else:
            raise ServiceError(f"{self.kind}: port {port} is neither published nor reachable by IP")
        if not port_open(f"{addr[0]}:{addr[1]}"):
            raise ServiceError(f"{self.kind}: nothing listening on {addr[0]}:{addr[1]}")
        return f"tcp {addr[0]}:{addr[1]}"

    def check(self) -> dict[str, Any]:
        res = self.run(list(self.check_argv), check=False)
        text = (res.stdout + res.stderr).strip()
        return {"ok": res.code == 0, "command": " ".join(self.check_argv), "output": text[-4000:]}

    def reload(self) -> dict[str, Any]:
        if self.reload_signal:
            self.ctr.t.json("POST", f"/containers/{q(self.t.name)}/kill", query={"signal": self.reload_signal})
            return {"reloaded": True, "via": f"signal {self.reload_signal} to PID 1"}
        res = self.run(list(self.reload_argv or ()), check=False)
        if not res.ok:
            raise ServiceError(f"{self.kind}: reload failed: {(res.stderr or res.stdout).strip()}")
        return {"reloaded": True, "via": " ".join(self.reload_argv or ())}


@register
class Nginx(ConfigReloadable):
    kind = "nginx"
    image_rx = re.compile(r"^(nginx|openresty|nginx-unprivileged)")
    env_hints = ("NGINX_",)
    ports = (80, 443)
    scheme = "http"
    check_argv = ("nginx", "-t")
    reload_argv = ("nginx", "-s", "reload")


@register
class Httpd(ConfigReloadable):
    kind = "httpd"
    image_rx = re.compile(r"^(httpd|apache)")
    ports = (80, 443)
    scheme = "http"
    check_argv = ("httpd", "-t")
    reload_argv = ("httpd", "-k", "graceful")


@register
class Caddy(ConfigReloadable):
    kind = "caddy"
    image_rx = re.compile(r"^caddy")
    ports = (80, 443)
    scheme = "http"
    check_argv = ("caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
    reload_argv = ("caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")


@register
class HAProxy(ConfigReloadable):
    kind = "haproxy"
    image_rx = re.compile(r"^haproxy")
    ports = (80, 443, 8404)
    scheme = "http"
    check_argv = ("haproxy", "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg")
    reload_signal = "SIGUSR2"  # the official image runs master-worker mode; USR2 reloads workers
