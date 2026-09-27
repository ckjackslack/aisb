"""docker-compose -> aisb stack file. Pure translation; every key that can't be carried over is reported."""

import os
import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import yamlish

# compose keys dropped on purpose: the stack network replaces them, or they have no RunSpec field
_IGNORED = {"networks", "container_name", "logging", "stop_grace_period", "stop_signal", "deploy", "expose",
            "extends", "profiles", "platform", "pull_policy", "init", "tty", "stdin_open", "sysctls", "ulimits",
            "security_opt", "devices", "dns", "extra_hosts", "secrets", "configs", "shm_size", "ipc", "pid",
            "network_mode", "read_only", "tmpfs", "mem_reservation", "cap_drop", "links", "external_links",
            "domainname", "mac_address", "userns_mode", "cgroup_parent", "group_add", "oom_score_adj",
            "memswap_limit", "cpu_shares", "cpuset", "labels_from", "annotations", "attach", "develop", "scale"}


def _env(value: Any, base: Path, env_file: Any, notes: list[str], svc: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in [env_file] if isinstance(env_file, (str, dict)) else env_file or []:
        path = str((f.get("path") if isinstance(f, dict) else f) or "")
        if not path:
            continue
        p = (base / path).resolve()
        if not p.exists():
            notes.append(f"{svc}: env_file {path} not found; its variables are missing")
            continue
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.removeprefix("export ").partition("=")
                out[key.strip()] = val.strip().strip("'\"")
    items = value.items() if isinstance(value, Mapping) else \
        [(e.partition("=")[0], e.partition("=")[2] if "=" in e else None) for e in value or []]
    for k, raw in items:
        v = raw
        if v is None:
            if (host := os.environ.get(k)) is None:
                notes.append(f"{svc}: {k} takes its value from the environment at deploy time; "
                             f"it was unset here, so it is left out")
                continue
            v = host
        out[str(k)] = "" if v is None else str(v).lower() if isinstance(v, bool) else str(v)
    return out


def _port(p: Any) -> str:
    if isinstance(p, Mapping):
        target, published = p.get("target"), p.get("published")
        proto = f"/{p['protocol']}" if p.get("protocol") and p["protocol"] != "tcp" else ""
        host_ip = f"{p['host_ip']}:" if p.get("host_ip") else ""
        return f"{host_ip}{published}:{target}{proto}" if published else f"{target}{proto}"
    return str(p)


def _volume(v: Any, base: Path) -> str:
    if isinstance(v, Mapping):
        src, dst = v.get("source"), v["target"]
        ro = ":ro" if v.get("read_only") else ""
        if v.get("type") == "bind" and src and not str(src).startswith("/"):
            src = str((base / str(src)).expanduser().resolve())
        return f"{src}:{dst}{ro}" if src else str(dst)
    src, sep, rest = str(v).partition(":")
    if sep and src.startswith((".", "~")):
        src = str((base / src).expanduser().resolve()) if src.startswith(".") else str(Path(src).expanduser())
    return f"{src}{sep}{rest}"


def _health(h: Mapping[str, Any]) -> str | None:
    test = h.get("test")
    if h.get("disable") or test in (None, ["NONE"], "NONE"):
        return None
    if isinstance(test, str):
        return test
    if test and test[0] == "CMD-SHELL":
        return " ".join(test[1:])
    if test and test[0] == "CMD":
        return shlex.join(test[1:])
    return None


def convert(data: Mapping[str, Any], *, base: Path, name: str | None = None) -> dict[str, Any]:
    if not isinstance(data, Mapping) or not isinstance(data.get("services"), Mapping):
        raise ValueError("not a compose file: no `services` mapping")
    notes: list[str] = []
    unsupported: list[dict[str, str]] = []
    stack_name = re.sub(r"[^a-z0-9_.-]", "-", (name or data.get("name") or base.name or "stack").lower()).strip("-.")
    services: dict[str, Any] = {}
    healthy_deps: set[str] = set()
    for svc, c in data["services"].items():
        c = c or {}
        spec: dict[str, Any] = {}
        if "image" in c:
            spec["image"] = str(c["image"])
        elif "build" in c:
            spec["image"] = f"{stack_name}-{svc}:latest"
            notes.append(f"{svc}: has `build` but no `image`; build it first, e.g. "
                         f"`aisb images build {c['build'] if isinstance(c['build'], str) else c['build'].get('context', '.')} "
                         f"--tag {spec['image']}`")
        else:
            raise ValueError(f"service {svc}: needs image (or build)")
        if "build" in c and "image" in c:
            notes.append(f"{svc}: `build` is ignored; the stack uses image {c['image']}")
        for key, val in c.items():
            if key in ("image", "build"):
                continue
            if key == "command":
                spec["cmd"] = shlex.split(val) if isinstance(val, str) else [str(x) for x in val]
            elif key == "entrypoint":
                spec["entrypoint"] = val.strip() if isinstance(val, str) else shlex.join(map(str, val))
            elif key in ("environment", "env_file"):
                continue  # merged below
            elif key == "ports":
                spec["ports"] = [_port(p) for p in val]
            elif key == "volumes":
                spec["volumes"] = [_volume(v, base) for v in val]
            elif key == "depends_on":
                deps = list(val) if isinstance(val, (list, Mapping)) else [val]
                spec["depends_on"] = [str(d) for d in deps]
                if isinstance(val, Mapping):
                    healthy_deps |= {d for d, cond in val.items() if (cond or {}).get("condition") == "service_healthy"}
            elif key == "restart":
                spec["restart"] = str(val)
            elif key == "healthcheck":
                if cmd := _health(val):
                    spec["health_cmd"] = cmd
            elif key == "working_dir":
                spec["workdir"] = str(val)
            elif key in ("user", "hostname"):
                spec[key] = str(val)
            elif key == "cap_add":
                spec["cap_add"] = [str(x) for x in val]
            elif key == "privileged":
                spec["privileged"] = bool(val)
            elif key == "mem_limit":
                spec["memory"] = str(val)
            elif key == "cpus":
                spec["cpus"] = float(val)
            elif key == "labels":
                spec["labels"] = dict(val) if isinstance(val, Mapping) else dict(x.partition("=")[::2] for x in val)
            elif key.startswith("x-"):
                continue
            elif key in _IGNORED:
                if key == "deploy" and (lim := ((val or {}).get("resources") or {}).get("limits")):
                    if lim.get("memory"):
                        spec["memory"] = str(lim["memory"])
                    if lim.get("cpus"):
                        spec["cpus"] = float(lim["cpus"])
                if key not in ("networks", "container_name", "deploy"):
                    unsupported.append({"service": svc, "key": key})
            else:
                unsupported.append({"service": svc, "key": key})
        env = _env(c.get("environment"), base, c.get("env_file"), notes, svc)
        if env:
            spec["env"] = env
        services[svc] = spec
    for dep in healthy_deps:
        if dep in services:
            services[dep]["ready"] = "healthy" if services[dep].get("health_cmd") else "probe"
    top_unsupported = sorted(set(data) - {"services", "volumes", "networks", "name", "version"} -
                             {k for k in data if str(k).startswith("x-")})
    return {"stack": {"name": stack_name, **({"volumes": sorted(data["volumes"])} if data.get("volumes") else {}),
                      "services": services},
            "notes": notes, "unsupported": unsupported,
            **({"unsupported_top_level": top_unsupported} if top_unsupported else {})}


def load(path: str | Path, *, name: str | None = None) -> dict[str, Any]:
    p = Path(path).expanduser().resolve()
    try:
        data = yamlish.loads(p.read_text())
    except OSError as e:
        raise ValueError(f"{path}: {e}") from None
    return convert(data, base=p.parent, name=name)
