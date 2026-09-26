"""Compact views of API objects and the declarative container RunSpec."""

import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Self

from .util import MANAGED_KEY, compact, kv


def _short(id_: str) -> str:
    return id_.removeprefix("sha256:")[:12]


def _port(p: Mapping[str, Any]) -> str:
    inner = f"{p.get('PrivatePort')}/{p.get('Type', 'tcp')}"
    if p.get("PublicPort"):
        return f"{p.get('IP') or '0.0.0.0'}:{p['PublicPort']}->{inner}"
    return inner


@dataclass(frozen=True, slots=True)
class Container:
    id: str
    name: str
    image: str
    state: str
    status: str
    ports: list[str]
    labels: dict[str, str]
    created: int

    @classmethod
    def from_api(cls, d: Mapping[str, Any]) -> Self:
        names = d.get("Names") or [""]
        return cls(
            id=_short(d["Id"]),
            name=names[0].lstrip("/"),
            image=d.get("Image", ""),
            state=d.get("State", ""),
            status=d.get("Status", ""),
            ports=sorted({_port(p) for p in d.get("Ports") or []}),
            labels=d.get("Labels") or {},
            created=d.get("Created", 0),
        )


@dataclass(frozen=True, slots=True)
class Image:
    id: str
    tags: list[str]
    size: int
    created: int
    containers: int

    @classmethod
    def from_api(cls, d: Mapping[str, Any]) -> Self:
        tags = [t for t in d.get("RepoTags") or [] if t != "<none>:<none>"]
        return cls(_short(d["Id"]), tags, d.get("Size", 0), d.get("Created", 0), d.get("Containers", -1))


@dataclass(frozen=True, slots=True)
class Network:
    id: str
    name: str
    driver: str
    scope: str
    internal: bool

    @classmethod
    def from_api(cls, d: Mapping[str, Any]) -> Self:
        return cls(_short(d["Id"]), d["Name"], d.get("Driver", ""), d.get("Scope", ""), bool(d.get("Internal")))


@dataclass(frozen=True, slots=True)
class Volume:
    name: str
    driver: str
    mountpoint: str
    labels: dict[str, str]

    @classmethod
    def from_api(cls, d: Mapping[str, Any]) -> Self:
        return cls(d["Name"], d.get("Driver", ""), d.get("Mountpoint", ""), d.get("Labels") or {})


_SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?", re.I)
_SCALE = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}


def parse_size(value: str | int) -> int:
    if isinstance(value, int):
        return value
    if not (m := _SIZE.fullmatch(value.strip())):
        raise ValueError(f"invalid size: {value!r}")
    return int(float(m[1]) * _SCALE[m[2].lower()])


def parse_port(spec: str) -> tuple[str, dict[str, str] | None]:
    """'[ip:]host:container[/proto]' or 'container[/proto]' -> (key, binding)."""
    addr, _, proto = spec.partition("/")
    parts = addr.split(":")
    if not 1 <= len(parts) <= 3 or not parts[-1].isdigit():
        raise ValueError(f"invalid port mapping: {spec!r}")
    key = f"{parts[-1]}/{proto or 'tcp'}"
    if len(parts) == 1:
        return key, None
    ip, host = (parts[0], parts[1]) if len(parts) == 3 else ("", parts[0])
    return key, {"HostIp": ip, "HostPort": host}


def parse_restart(policy: str) -> dict[str, Any]:
    name, _, count = policy.partition(":")
    if name not in ("no", "always", "unless-stopped", "on-failure"):
        raise ValueError(f"invalid restart policy: {policy!r}")
    return {"Name": name, "MaximumRetryCount": int(count or 0)}


@dataclass(frozen=True, slots=True)
class RunSpec:
    """Everything needed to create a container; loadable from JSON (keys = field names)."""

    image: str
    cmd: tuple[str, ...] = ()
    entrypoint: str | None = None
    name: str | None = None
    env: tuple[str, ...] = ()
    ports: tuple[str, ...] = ()
    volumes: tuple[str, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)
    restart: str | None = None
    network: str | None = None
    workdir: str | None = None
    user: str | None = None
    memory: str | None = None
    cpus: float | None = None
    tty: bool = False
    rm: bool = False
    health_cmd: str | None = None
    aliases: tuple[str, ...] = ()   # DNS names on `network`
    pid: str | None = None          # e.g. "container:web" to share a process namespace
    hostname: str | None = None
    cap_add: tuple[str, ...] = ()   # e.g. ("NET_ADMIN",) for tc in a sidecar

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        known = {f.name for f in fields(cls)}
        if unknown := set(data) - known:
            raise ValueError(f"unknown RunSpec keys: {sorted(unknown)}")
        norm = dict(data)
        if isinstance(norm.get("env"), Mapping):
            norm["env"] = [f"{k}={v}" for k, v in norm["env"].items()]
        if isinstance(norm.get("cmd"), str):
            norm["cmd"] = shlex.split(norm["cmd"])
        for key in ("cmd", "env", "ports", "volumes", "aliases", "cap_add"):
            if key in norm:
                norm[key] = tuple(norm[key])
        if "labels" in norm:
            norm["labels"] = kv(norm["labels"])
        return cls(**norm)

    @classmethod
    def load(cls, path: str | Path) -> Self:
        return cls.from_dict(json.loads(Path(path).expanduser().read_text()))

    def merge(self, **overrides: Any) -> Self:
        """Apply overrides that were actually given (None/empty/False are 'not given')."""
        given = {k: v for k, v in overrides.items() if v not in (None, (), [], {}, False)}
        if "labels" in given:
            given["labels"] = {**self.labels, **given["labels"]}
        return replace(self, **given)

    def to_api(self, *, auto_remove: bool = False) -> dict[str, Any]:
        exposed: dict[str, dict] = {}
        bindings: dict[str, list[dict[str, str]]] = {}
        for spec in self.ports:
            key, binding = parse_port(spec)
            exposed[key] = {}
            if binding:
                bindings.setdefault(key, []).append(binding)
        binds = [v for v in self.volumes if ":" in v]
        anonymous = {v: {} for v in self.volumes if ":" not in v}
        host = compact({
            "Binds": binds or None,
            "PortBindings": bindings or None,
            "RestartPolicy": parse_restart(self.restart) if self.restart else None,
            "NetworkMode": self.network,
            "Memory": parse_size(self.memory) if self.memory else None,
            "NanoCpus": int(self.cpus * 1e9) if self.cpus else None,
            "AutoRemove": auto_remove or None,
            "PidMode": self.pid,
            "CapAdd": list(self.cap_add) or None,
        })
        endpoint = {self.network: {"Aliases": list(self.aliases)}} if self.network and self.aliases else None
        return compact({
            "Image": self.image,
            "Cmd": list(self.cmd) or None,
            "Entrypoint": shlex.split(self.entrypoint) if self.entrypoint else None,
            "Env": list(self.env) or None,
            "Labels": {**self.labels, MANAGED_KEY: "true"},
            "WorkingDir": self.workdir,
            "User": self.user,
            "Tty": self.tty or None,
            "ExposedPorts": exposed or None,
            "Volumes": anonymous or None,
            "Healthcheck": {"Test": ["CMD-SHELL", self.health_cmd]} if self.health_cmd else None,
            "Hostname": self.hostname,
            "HostConfig": host,
            "NetworkingConfig": {"EndpointsConfig": endpoint} if endpoint else None,
        })
