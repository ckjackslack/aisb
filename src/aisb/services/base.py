"""Service adapters: detect what runs in a container and talk to it with its own tools.

An adapter never needs a client on the host. It runs the service's native CLI *inside* the
container through exec, with credentials discovered from the container's env (or `*_FILE`
secrets read through the archive API), and parses the output into plain data.
"""

import io
import re
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import quote

from ..errors import APIError
from ..util import q

if TYPE_CHECKING:
    from ..api.containers import Containers, ExecResult


@dataclass(frozen=True, slots=True)
class Target:
    """What we know about a container that runs a service."""
    name: str
    image: str
    env: dict[str, str]
    cmd: tuple[str, ...]
    exposed: tuple[int, ...]
    published: dict[int, tuple[str, int]]   # container port -> (host ip, host port)
    ips: tuple[str, ...]
    running: bool

    @classmethod
    def from_inspect(cls, info: Mapping[str, Any]) -> "Target":
        cfg, net = info.get("Config") or {}, info.get("NetworkSettings") or {}
        published: dict[int, tuple[str, int]] = {}
        for key, binds in (net.get("Ports") or {}).items():
            for b in binds or []:
                if b.get("HostPort"):
                    published.setdefault(int(key.split("/")[0]), (b.get("HostIp") or "0.0.0.0", int(b["HostPort"])))
        return cls(
            name=(info.get("Name") or "").lstrip("/"),
            image=cfg.get("Image") or "",
            env=dict(e.partition("=")[::2] for e in cfg.get("Env") or []),
            cmd=tuple([*(cfg.get("Entrypoint") or []), *(cfg.get("Cmd") or [])]),
            exposed=tuple(sorted(int(p.split("/")[0]) for p in cfg.get("ExposedPorts") or {})),
            published=published,
            ips=tuple(n["IPAddress"] for n in (net.get("Networks") or {}).values() if n.get("IPAddress")),
            running=bool((info.get("State") or {}).get("Running")),
        )

    def arg(self, flag: str) -> str | None:
        """Value of `--flag value` or `--flag=value` in the container command."""
        for i, a in enumerate(self.cmd):
            if a == flag and i + 1 < len(self.cmd):
                return self.cmd[i + 1]
            if a.startswith(flag + "="):
                return a.split("=", 1)[1]
        return None


class ServiceError(APIError):
    """The service's own tool failed (bad SQL, auth error, ...)."""


class Adapter:
    kind: ClassVar[str]
    image_rx: ClassVar[re.Pattern[str]]
    env_hints: ClassVar[tuple[str, ...]] = ()
    ports: ClassVar[tuple[int, ...]] = ()
    scheme: ClassVar[str] = ""

    def __init__(self, ctr: "Containers", target: Target) -> None:
        self.ctr, self.t = ctr, target

    # --- detection ---------------------------------------------------------------------------
    @classmethod
    def score(cls, t: Target) -> tuple[int, str]:
        repo = t.image.split("@")[0].rsplit("/", 1)[-1].split(":")[0]  # 'docker.io/bitnami/redis:7' -> 'redis'
        if cls.image_rx.search(repo):
            return 3, f"image {t.image}"
        if hint := next((k for k in t.env if k.startswith(cls.env_hints)), None) if cls.env_hints else None:
            return 2, f"env {hint}"
        if port := next((p for p in cls.ports if p in t.exposed), None):
            return 1, f"port {port}"
        return 0, ""

    # --- credentials -------------------------------------------------------------------------
    def secret(self, *names: str) -> str | None:
        """First of NAME or NAME_FILE (Docker secrets) that is set."""
        for n in names:
            if (v := self.t.env.get(n)) is not None:
                return v
            if path := self.t.env.get(f"{n}_FILE"):
                return self.read_file(path).rstrip("\n")
        return None

    def read_file(self, path: str) -> str:
        data = self.ctr.t.raw("GET", f"/containers/{q(self.t.name)}/archive", query={"path": path})
        if not data:
            return ""
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            member = next(m for m in tar if m.isfile())
            return tar.extractfile(member).read().decode(errors="replace")  # type: ignore[union-attr]

    def user(self) -> str | None:
        return None

    def password(self) -> str | None:
        return None

    def database(self) -> str | None:
        return None

    def default_port(self) -> int | None:
        return next((p for p in self.ports if p in self.t.exposed), self.ports[0] if self.ports else None)

    # --- host-side connection info -----------------------------------------------------------
    def url(self, *, reveal: bool = False, host: str = "127.0.0.1") -> str | None:
        port = self.default_port()
        if not self.scheme or port is None:
            return None
        if port in self.t.published:
            ip, hport = self.t.published[port]
            addr = f"{host if ip in ('0.0.0.0', '') else '[::1]' if ip == '::' else ip}:{hport}"
        else:
            addr = f"{self.t.ips[0] if self.t.ips else 'unpublished'}:{port}"
        user, pw = self.user(), self.password()
        auth = ""
        if user:
            auth = quote(user, safe="") + (f":{quote(pw, safe='') if reveal else '***'}" if pw else "") + "@"
        elif pw:
            auth = f":{quote(pw, safe='') if reveal else '***'}@"
        db = self.database()
        return f"{self.scheme}://{auth}{addr}{'/' + quote(db, safe='') if db else ''}"

    def reachability(self) -> str | None:
        """Why the URL may not work from the host, if the service port is not published."""
        port = self.default_port()
        if port is None or port in self.t.published:
            return None
        return (f"port {port} is not published: the container IP works only from a Linux Docker host "
                f"(publish it, e.g. --port 127.0.0.1:{port}:{port}, or use `aisb` commands, which run inside)")

    def connection_info(self, *, reveal: bool = False) -> dict[str, Any]:
        info = {"kind": self.kind, "user": self.user(), "database": self.database(),
                "password": ("***" if not reveal else self.password()) if self.password() else None,
                "url": self.url(reveal=reveal)}
        return {**info, "note": note} if (note := self.reachability()) else info

    # --- exec --------------------------------------------------------------------------------
    def run(self, argv: list[str], *, env: dict[str, str | None] | None = None, check: bool = True) -> "ExecResult":
        pairs = [f"{k}={v}" for k, v in (env or {}).items() if v is not None]
        res = self.ctr.run_in(self.t.name, argv, env=pairs or None)
        if check and not res.ok:
            msg = (res.stderr or res.stdout).strip()
            raise ServiceError(f"{self.kind}: {argv[0]} exited {res.code}: {msg[-2000:]}")
        return res


@dataclass(slots=True)
class Registry:
    adapters: dict[str, type[Adapter]] = field(default_factory=dict)

    def register(self, cls: type[Adapter]) -> type[Adapter]:
        self.adapters[cls.kind] = cls
        return cls

    def detect(self, t: Target) -> tuple[type[Adapter] | None, str]:
        best = max(((cls.score(t), cls) for cls in self.adapters.values()), key=lambda x: x[0][0], default=None)
        if not best or best[0][0] == 0:
            return None, ""
        return best[1], best[0][1]


REGISTRY = Registry()
register = REGISTRY.register
