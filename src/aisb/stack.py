"""Stack files: a few services, their dependencies and readiness, as plain JSON. No Compose needed.

    {"name": "shop",
     "volumes": ["pgdata"],
     "services": {
       "db":  {"image": "postgres:16-alpine", "env": {"POSTGRES_PASSWORD": "dev"},
               "volumes": ["pgdata:/var/lib/postgresql/data"]},
       "api": {"image": "shop-api:dev", "depends_on": ["db"], "ports": ["8080:80"],
               "ready": {"log": "listening on"}}}}

Service keys are RunSpec fields plus `depends_on` and `ready`. `ready` is "probe" (a real
SELECT 1 / PING, the default for known services), "running", "healthy", {"log": REGEX} or
{"port": "HOST:PORT"}. Declared volumes are prefixed with the stack name; everything else is
used as written. Services reach each other by service name on the stack network.
"""

import graphlib
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .models import RunSpec

STACK_KEY, SERVICE_KEY, HASH_KEY = "aisb.stack", "aisb.service", "aisb.hash"
_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_READY = ("probe", "running", "healthy")


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    spec: RunSpec
    depends_on: tuple[str, ...]
    ready: str | dict[str, str]
    digest: str

    @property
    def container(self) -> str:
        return self.spec.name or ""


@dataclass(frozen=True, slots=True)
class Stack:
    name: str
    network: str
    volumes: tuple[str, ...]
    services: dict[str, Service]
    order: tuple[str, ...]

    def dependents(self, svc: str) -> list[str]:
        return [s.name for s in self.services.values() if svc in s.depends_on]


def _prefix_volume(mount: str, stack: str, declared: set[str]) -> str:
    src, sep, rest = mount.partition(":")
    return f"{stack}_{src}{sep}{rest}" if sep and src in declared else mount


def parse(data: Mapping[str, Any]) -> Stack:
    name = str(data.get("name") or "")
    if not _NAME.match(name):
        raise ValueError(f"stack needs a lowercase 'name' ([a-z0-9_.-]), got {name!r}")
    raw = data.get("services") or {}
    if not isinstance(raw, Mapping) or not raw:
        raise ValueError("stack needs a non-empty 'services' object")
    if unknown := set(data) - {"name", "services", "volumes"}:
        raise ValueError(f"unknown stack keys: {sorted(unknown)}")
    declared = set(data.get("volumes") or [])
    network = f"{name}_default"
    services: dict[str, Service] = {}
    for svc, conf in raw.items():
        if not _NAME.match(svc):
            raise ValueError(f"invalid service name {svc!r}")
        conf = dict(conf)
        deps = tuple(conf.pop("depends_on", ()))
        ready = conf.pop("ready", "probe")
        if not (ready in _READY or isinstance(ready, Mapping) and set(ready) <= {"log", "port"} and ready):
            raise ValueError(f"{svc}: 'ready' must be one of {_READY} or {{'log': REGEX}} / {{'port': HOST:PORT}}")
        if forbidden := {"name", "network", "aliases"} & set(conf):
            raise ValueError(f"{svc}: {sorted(forbidden)} are managed by the stack")
        spec = RunSpec.from_dict(conf)
        spec = replace(spec, name=f"{name}-{svc}", network=network, aliases=(svc,),
                       volumes=tuple(_prefix_volume(v, name, declared) for v in spec.volumes),
                       labels={**spec.labels, STACK_KEY: name, SERVICE_KEY: svc})
        digest = hashlib.sha256(json.dumps(spec.to_api(), sort_keys=True).encode()).hexdigest()[:16]
        spec = replace(spec, labels={**spec.labels, HASH_KEY: digest})
        services[svc] = Service(svc, spec, deps, dict(ready) if isinstance(ready, Mapping) else ready, digest)
    for s in services.values():
        if missing := set(s.depends_on) - services.keys():
            raise ValueError(f"{s.name}: depends_on unknown service(s) {sorted(missing)}")
    try:
        order = tuple(graphlib.TopologicalSorter({s.name: s.depends_on for s in services.values()}).static_order())
    except graphlib.CycleError as e:
        raise ValueError(f"dependency cycle: {' -> '.join(e.args[1])}") from None
    return Stack(name, network, tuple(f"{name}_{v}" for v in sorted(declared)), services, order)


def load(path: str | Path) -> Stack:
    try:
        return parse(json.loads(Path(path).expanduser().read_text()))
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: invalid JSON: {e}") from None
