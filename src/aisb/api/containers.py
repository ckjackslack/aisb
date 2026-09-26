import heapq
import re
import shlex
import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from .. import insights
from ..errors import NotFound, NotModified
from ..models import Container, RunSpec, parse_port, parse_size
from ..ops import Resource, Tier, op
from ..streams import Stream, decode_output, demux, tar_path, untar
from ..util import MANAGED, MANAGED_KEY, clip, compact, docker_time, project, q, split_cp, to_unix
from .images import Images

Ref = Annotated[str, "container name or id"]
Fields = Annotated[str | None, "comma-separated dotted paths to keep, e.g. State.Status,Config.Image"]
MaxBytes = Annotated[int, "cap output size (keeps the tail); 0 = unlimited"]
Cmd = Annotated[str, "command and arguments (put them after --)"]

_KINDS = {0: "modified", 1: "added", 2: "deleted"}


def _pct(used: float, total: float) -> float:
    return round(used / total * 100, 2) if total else 0.0


def summarize_stats(s: dict[str, Any]) -> dict[str, Any]:
    cpu, pre = s.get("cpu_stats") or {}, s.get("precpu_stats") or {}
    cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    mem = s.get("memory_stats") or {}
    cache = (mem.get("stats") or {}).get("inactive_file", (mem.get("stats") or {}).get("cache", 0))
    used, limit = mem.get("usage", 0) - cache, mem.get("limit", 0)
    nets = (s.get("networks") or {}).values()
    blk = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
    return {
        "cpu_percent": round(cpu_delta / sys_delta * ncpu * 100, 2) if sys_delta > 0 else 0.0,
        "memory": {"used": used, "limit": limit, "percent": _pct(used, limit)},
        "net": {"rx": sum(n.get("rx_bytes", 0) for n in nets), "tx": sum(n.get("tx_bytes", 0) for n in nets)},
        "block": {op_: sum(b["value"] for b in blk if b.get("op", "").lower() == op_) for op_ in ("read", "write")},
        "pids": (s.get("pids_stats") or {}).get("current"),
    }


@dataclass(frozen=True, slots=True)
class ExecResult:
    code: int | None
    out: bytes
    err: bytes

    @property
    def ok(self) -> bool:
        return self.code in (0, None)  # None only in dry-run

    @property
    def stdout(self) -> str:
        return self.out.decode(errors="replace")

    @property
    def stderr(self) -> str:
        return self.err.decode(errors="replace")


def compare_specs(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Field-by-field diff of two RunSpec dicts; list fields as added/removed, env by key, secrets masked."""
    from ..transport import SECRET_KEY
    same, different = [], {}
    for key in sorted(a.keys() | b.keys()):
        x, y = a.get(key), b.get(key)
        if x == y:
            same.append(key)
        elif key == "env":
            ex = dict(e.partition("=")[::2] for e in x or [])
            ey = dict(e.partition("=")[::2] for e in y or [])
            mask = lambda k, v: "***" if SECRET_KEY.search(k) and v else v  # noqa: E731
            different["env"] = {
                "only_in_a": {k: mask(k, ex[k]) for k in sorted(ex.keys() - ey.keys())},
                "only_in_b": {k: mask(k, ey[k]) for k in sorted(ey.keys() - ex.keys())},
                "different": {k: {"a": mask(k, ex[k]), "b": mask(k, ey[k])}
                              for k in sorted(ex.keys() & ey.keys()) if ex[k] != ey[k]},
            }
        elif isinstance(x, list) or isinstance(y, list):
            sx, sy = set(map(str, x or [])), set(map(str, y or []))
            different[key] = {"only_in_a": sorted(sx - sy), "only_in_b": sorted(sy - sx)}
        else:
            different[key] = {"a": x, "b": y}
    return {"identical": not different, "different": different, "same": same}


def port_open(spec: str, timeout: float = 1.0) -> bool:
    host, _, port = spec.rpartition(":")
    try:
        with socket.create_connection((host or "127.0.0.1", int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _ports(bindings: dict[str, Any] | None, exposed: dict[str, Any] | None) -> list[str]:
    out = []
    for key, binds in (bindings or {}).items():
        ctr = key.removesuffix("/tcp")
        for b in binds or [{}]:
            out.append(":".join(filter(None, [b.get("HostIp"), b["HostPort"], ctr])) if b.get("HostPort") else ctr)
    return out + [key.removesuffix("/tcp") for key in exposed or {} if key not in (bindings or {})]


def _restart(policy: dict[str, Any]) -> str | None:
    name, retries = policy.get("Name"), policy.get("MaximumRetryCount")
    if name in (None, "", "no"):
        return None
    return f"{name}:{retries}" if retries else name


def runspec_of(d: dict[str, Any]) -> dict[str, Any]:
    """Inverse of RunSpec.to_api for an inspected container; drops empty and default values."""
    cfg, host = d.get("Config") or {}, d.get("HostConfig") or {}
    health = (cfg.get("Healthcheck") or {}).get("Test") or []
    spec = {
        "image": cfg.get("Image"),
        "cmd": cfg.get("Cmd") or [],
        "entrypoint": shlex.join(cfg["Entrypoint"]) if cfg.get("Entrypoint") else None,
        "name": (d.get("Name") or "").lstrip("/") or None,
        "env": cfg.get("Env") or [],
        "ports": _ports(host.get("PortBindings"), cfg.get("ExposedPorts")),
        "volumes": [*(host.get("Binds") or []), *(cfg.get("Volumes") or {})],
        "labels": {k: v for k, v in (cfg.get("Labels") or {}).items() if k != MANAGED_KEY},
        "restart": _restart(host.get("RestartPolicy") or {}),
        "network": host.get("NetworkMode") if host.get("NetworkMode") not in (None, "default", "bridge") else None,
        "workdir": cfg.get("WorkingDir") or None,
        "user": cfg.get("User") or None,
        "memory": str(host["Memory"]) if host.get("Memory") else None,
        "cpus": host["NanoCpus"] / 1e9 if host.get("NanoCpus") else None,
        "tty": bool(cfg.get("Tty")),
        "rm": bool(host.get("AutoRemove")),
        "health_cmd": health[1] if len(health) == 2 and health[0] == "CMD-SHELL" else None,
    }
    return {k: v for k, v in spec.items() if v not in (None, [], {}, False)}


class Containers(Resource, name="containers"):
    @op(Tier.READ, name="list")
    def ls(self, *, all: Annotated[bool, "include stopped containers"] = False,
           label: Annotated[list[str] | None, "filter by label (key or key=value)"] = None,
           managed: Annotated[bool, "only containers created by aisb"] = False) -> list[Container]:
        """List containers (running only unless --all)."""
        labels = [*(label or ()), *([MANAGED] if managed else [])]
        rows = self.t.json("GET", "/containers/json", query={"all": all, "filters": {"label": labels} if labels else None})
        return [Container.from_api(r) for r in rows]

    @op(Tier.READ)
    def inspect(self, ref: Ref, *, fields: Fields = None) -> Any:
        """Low-level container details; narrow with --fields."""
        return project(self.t.json("GET", f"/containers/{q(ref)}/json"), fields)

    @op(Tier.READ)
    def spec(self, ref: Ref) -> dict[str, Any]:
        """Dump an existing container's config as RunSpec JSON (edit, then `run --spec` to recreate)."""
        return runspec_of(self.t.json("GET", f"/containers/{q(ref)}/json"))

    def _text(self, ref: str, *, tail: int = 0, since: str | None = None, until: str | None = None,
              stream: str = "all", timestamps: bool = False, tty: bool | None = None) -> str:
        if tty is None:
            tty = bool((self.t.json("GET", f"/containers/{q(ref)}/json") or {}).get("Config", {}).get("Tty"))
        raw = self.t.raw("GET", f"/containers/{q(ref)}/logs", query={
            "stdout": stream != "stderr", "stderr": stream != "stdout", "tail": tail or "all",
            "since": since and to_unix(since), "until": until and to_unix(until), "timestamps": timestamps,
        })
        return decode_output(raw, tty)

    @op(Tier.READ)
    def logs(self, ref: Ref, *, tail: Annotated[int, "lines from the end; 0 = all"] = 200,
             since: Annotated[str | None, "unix ts, ISO time, or relative like 10m"] = None,
             until: Annotated[str | None, "unix ts, ISO time, or relative like 1m"] = None,
             stream: Literal["all", "stdout", "stderr"] = "all",
             timestamps: bool = False,
             grep: Annotated[str | None, "only lines matching this regex (numbered, like grep -n)"] = None,
             context: Annotated[int, "lines of context around --grep matches"] = 0,
             max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Container logs, stdout and stderr interleaved; --grep filters with context."""
        text = self._text(ref, tail=tail, since=since, until=until, stream=stream, timestamps=timestamps)
        return clip(insights.grep(text.splitlines(), grep, context) if grep else text, max_bytes)

    @op(Tier.READ)
    def patterns(self, ref: Ref, *, tail: Annotated[int, "lines to analyse; 0 = all"] = 5000,
                 since: Annotated[str | None, "unix ts, ISO time, or relative like 1h"] = None,
                 top: Annotated[int, "max templates returned"] = 20,
                 level: Annotated[Literal["other", "debug", "info", "warn", "error"], "minimum level shown"] = "other",
                 ) -> dict[str, Any]:
        """Fingerprint logs into ranked templates (errors first) and flag patterns that only appeared at the end."""
        lines = self._text(ref, tail=tail, since=since).splitlines()
        return insights.fingerprint(lines, top=top, min_level=level)

    @op(Tier.READ, name="wait")
    def wait_for(self, ref: Ref, *, running: Annotated[bool, "running and not restarting"] = False,
                 healthy: Annotated[bool, "healthcheck reports healthy"] = False,
                 exited: Annotated[bool, "container has stopped"] = False,
                 log: Annotated[str | None, "regex a log line (since the last start) must match"] = None,
                 port: Annotated[str | None, "[host:]port accepting TCP connections"] = None,
                 within: Annotated[float, "give up after N seconds"] = 60.0,
                 interval: Annotated[float, "poll interval in seconds"] = 1.0) -> dict[str, Any]:
        """Block until every given condition holds (default: --running). Fails fast if the container dies or turns unhealthy."""
        if not (running or healthy or exited or log or port):
            running = True
        try:
            rx = re.compile(log) if log else None
        except re.error as e:
            raise ValueError(f"invalid --log regex: {e}") from None
        begin = time.monotonic()
        deadline = begin + within
        while True:
            info = self.t.json("GET", f"/containers/{q(ref)}/json")
            st = info.get("State") or {}
            health = (st.get("Health") or {}).get("Status")
            if healthy and health is None:
                raise ValueError(f"{ref} has no healthcheck; wait for --log or --port instead")
            met: dict[str, bool] = {}
            matched = None
            if running:
                met["running"] = bool(st.get("Running")) and not st.get("Restarting")
            if healthy:
                met["healthy"] = health == "healthy"
            if exited:
                met["exited"] = st.get("Status") in ("exited", "dead")
            if rx:
                started = docker_time(st.get("StartedAt"))
                text = self._text(ref, since=str(int(started)) if started else None)
                matched = next((line for line in text.splitlines() if rx.search(line)), None)
                met["log"] = matched is not None
            if port:
                met["port"] = port_open(port)
            elapsed = round(time.monotonic() - begin, 2)
            if all(met.values()):
                return {"ok": True, "elapsed": elapsed, "conditions": met, **({"matched": matched} if matched else {})}
            died = not exited and (st.get("Status") in ("exited", "dead") or st.get("Restarting"))
            reason = ("container stopped (exit code {})".format(st.get("ExitCode")) if died
                      else "healthcheck reports unhealthy" if healthy and health == "unhealthy"
                      else f"timed out after {within}s" if time.monotonic() >= deadline else None)
            if reason:
                last = ((st.get("Health") or {}).get("Log") or [{}])[-1].get("Output")
                return {"ok": False, "reason": reason, "elapsed": elapsed, "conditions": met,
                        "state": st.get("Status"), "exit_code": st.get("ExitCode"),
                        **({"health_output": str(last).strip()[-500:]} if last else {}),
                        "log_tail": clip(self._text(ref, tail=20), 4096)["output"]}
            time.sleep(max(0.0, min(interval, deadline - time.monotonic())))

    @op(Tier.READ)
    def doctor(self, ref: Ref, *, tail: Annotated[int, "log lines to scan"] = 500,
               stats: Annotated[bool, "sample CPU/memory if running (~1s)"] = True) -> dict[str, Any]:
        """One-shot triage: verdict, ranked findings with evidence, and the next commands to run."""
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        lines = tuple(self._text(ref, tail=tail, tty=bool((info.get("Config") or {}).get("Tty"))).splitlines())
        running = (info.get("State") or {}).get("Running")
        facts = insights.Facts(
            name=(info.get("Name") or ref).lstrip("/"), inspect=info, logs=lines,
            image_id=self._image_id((info.get("Config") or {}).get("Image")),
            stats=self.stats(ref) if stats and running else None,
            peers=self.names(),
        )
        report = insights.diagnose(facts)
        report["log_patterns"] = [
            {k: p[k] for k in ("level", "count", "template")}
            for p in insights.fingerprint(lines, top=5, min_level="warn")["top"]
        ]
        return report

    def names(self) -> frozenset[str]:
        rows = self.t.json("GET", "/containers/json", query={"all": True}) or []
        return frozenset(n.lstrip("/") for r in rows for n in r.get("Names") or [])

    def _exists(self, path: str) -> bool:
        try:
            self.t.json("GET", path)
            return True
        except NotFound:
            return False

    def preflight(self, s: RunSpec, *, pull: bool = True) -> list[str]:
        """Read-only checks that predict a create/start failure; run during --dry-run."""
        warnings = []
        if s.name and self._exists(f"/containers/{q(s.name)}/json"):
            warnings.append(f"a container named {s.name!r} already exists: create would fail with 409 (remove or rename it)")
        if s.network and s.network not in ("bridge", "host", "none") and not s.network.startswith("container:") \
                and not self._exists(f"/networks/{q(s.network)}"):
            warnings.append(f"network {s.network!r} does not exist (aisb networks create {s.network})")
        if not self._exists(f"/images/{q(s.image)}/json"):
            warnings.append(f"image {s.image!r} is not local: " + ("it will be pulled" if pull else "and --no-pull is set"))
        for v in s.volumes:
            src = v.split(":")[0]
            if ":" in v and not src.startswith(("/", ".", "~")) and not self._exists(f"/volumes/{q(src)}"):
                warnings.append(f"volume {src!r} does not exist: Docker will create it empty")
        wanted = {b["HostPort"] for p in s.ports if (b := parse_port(p)[1]) and b["HostPort"]}
        if wanted:
            for row in self.t.json("GET", "/containers/json") or []:
                clash = wanted & {str(p.get("PublicPort")) for p in row.get("Ports") or []}
                for port in sorted(clash):
                    name = (row.get("Names") or ["?"])[0].lstrip("/")
                    warnings.append(f"host port {port} is already published by running container {name!r}")
        return warnings

    def _image_id(self, image: str | None) -> str | None:
        if not image or image.startswith("sha256:"):
            return None
        try:
            return (self.t.json("GET", f"/images/{q(image)}/json") or {}).get("Id")
        except NotFound:
            return None

    @op(Tier.READ)
    def top(self, ref: Ref) -> list[dict[str, str]]:
        """Processes running inside the container."""
        r = self.t.json("GET", f"/containers/{q(ref)}/top")
        return [dict(zip(r["Titles"], p)) for p in r.get("Processes") or []]

    @op(Tier.READ)
    def stats(self, ref: Ref) -> dict[str, Any]:
        """One-shot resource usage: CPU %, memory, network, block IO, pids."""
        raw = self.t.json("GET", f"/containers/{q(ref)}/stats", query={"stream": False}) or {}
        if str(raw.get("read", "")).startswith("0001-"):  # the daemon's zero-filled answer for a stopped container
            return {"running": False, "note": "container is not running; no live stats"}
        return summarize_stats(raw)

    @op(Tier.READ)
    def diff(self, ref: Ref) -> list[dict[str, str]]:
        """Filesystem changes relative to the image."""
        return [{"path": c["Path"], "kind": _KINDS.get(c["Kind"], str(c["Kind"]))}
                for c in self.t.json("GET", f"/containers/{q(ref)}/changes") or []]

    @op(Tier.MUTATE)
    def run(self, image: Annotated[str, "image reference"], *cmd: Cmd,
            name: str | None = None,
            env: Annotated[list[str] | None, "KEY=VALUE"] = None,
            port: Annotated[list[str] | None, "[ip:]host:container[/proto]"] = None,
            volume: Annotated[list[str] | None, "host_or_volume:container[:ro] or anonymous path"] = None,
            label: Annotated[dict[str, str] | None, "KEY=VALUE"] = None,
            restart: Annotated[str | None, "no | always | unless-stopped | on-failure[:N]"] = None,
            network: str | None = None, workdir: str | None = None, user: str | None = None,
            memory: Annotated[str | None, "memory limit, e.g. 512m"] = None,
            cpus: Annotated[float | None, "CPU quota, e.g. 1.5"] = None,
            entrypoint: str | None = None, tty: bool = False,
            rm: Annotated[bool, "remove the container after it exits"] = False,
            health_cmd: Annotated[str | None, "shell healthcheck command"] = None,
            spec: Annotated[str | None, "RunSpec JSON file; flags override it"] = None,
            detach: Annotated[bool, "start and return instead of waiting for exit"] = False,
            pull: Annotated[bool, "pull the image if it is missing"] = True,
            max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Create and start a container; waits for exit and returns output unless --detach."""
        base = RunSpec.load(spec).merge(image=image) if spec else RunSpec(image=image)
        s = base.merge(cmd=tuple(cmd), name=name, env=tuple(env or ()), ports=tuple(port or ()),
                       volumes=tuple(volume or ()), labels=label, restart=restart, network=network,
                       workdir=workdir, user=user, memory=memory, cpus=cpus, entrypoint=entrypoint,
                       tty=tty, rm=rm, health_cmd=health_cmd)
        warn = {"warnings": w} if self.t.planning and (w := self.preflight(s, pull=pull)) else {}
        cid = self.create_from(s, pull=pull, auto_remove=s.rm and detach)
        self.t.json("POST", f"/containers/{cid}/start")
        if detach:
            return {"id": cid[:12], "name": s.name, "status": "started", **warn}
        status = self.t.json("POST", f"/containers/{cid}/wait", timeout=None) or {}
        out = self.logs(cid, tail=0, max_bytes=max_bytes)
        if s.rm:
            self.t.json("DELETE", f"/containers/{cid}", query={"force": True})
        return {"id": cid[:12], "exit_code": status.get("StatusCode"), **out, **warn}

    @contextmanager
    def transient(self, image: str, *, volumes: tuple[str, ...] = (), pull: bool = True) -> Iterator[str]:
        """A never-started helper container (net-zero side effect): read an image's filesystem or a volume."""
        cid = self.create_from(RunSpec(image=image, cmd=("aisb-transient",), volumes=volumes,
                                       labels={"aisb.helper": "transient"}), pull=pull)
        try:
            yield cid
        finally:
            self.t.json("DELETE", f"/containers/{cid}", query={"force": True, "v": True})

    def create_from(self, s: RunSpec, *, pull: bool = True, auto_remove: bool = False) -> str:
        """Create (not start) a container from a RunSpec, pulling the image on demand; returns its id."""
        body = s.to_api(auto_remove=auto_remove)
        create = lambda: self.t.json("POST", "/containers/create", query={"name": s.name}, body=body)  # noqa: E731
        try:
            return create()["Id"]
        except NotFound:
            if not pull:
                raise
            Images(self.t).pull(s.image)
            return create()["Id"]

    @op(Tier.READ)
    def secrets(self, ref: Ref, *, path: Annotated[list[str] | None, "also scan files under these paths"] = None,
                max_mb: Annotated[int, "archive budget per path (MiB)"] = 128) -> dict[str, Any]:
        """Find exposed credentials: plain secrets in env, secrets in image history, and (with --path) key files
        and known token formats inside files. Values are masked."""
        from ..insights.audit import dedupe, scan_env, scan_history, scan_text
        from .fs import Fs
        from .images import Images
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        hits = scan_env((info.get("Config") or {}).get("Env") or [])
        try:
            hits += scan_history(Images(self.t).history(info.get("Image", "")))
        except NotFound:
            pass
        risky = re.compile(r"(^|/)(\.env(\..*)?|id_(rsa|ed25519|ecdsa)|.*\.pem|.*\.key|credentials|\.npmrc|\.pypirc|"
                           r"\.git-credentials|\.netrc|\.docker/config\.json|.*\.p12|.*\.pfx)$")
        scanned = 0
        for root in path or []:
            for m, rel, tar in Fs(self.t)._members(ref, root, max_mb):
                if not m.isfile():
                    continue
                where = f"{root.rstrip('/')}/{rel}"
                if risky.search(rel):
                    hits.append({"kind": "sensitive-file", "where": where, "sample": f"{m.size} bytes"})
                if m.size <= 256 * 1024:
                    data = tar.extractfile(m).read()  # type: ignore[union-attr]
                    if b"\0" not in data[:1024]:
                        scanned += 1
                        hits += scan_text(data.decode(errors="ignore"), where)
        hits = dedupe(hits)
        return {"container": ref, "count": len(hits), "files_scanned": scanned, "findings": hits}

    def env_uses(self, ref: str, image_config: dict[str, Any], extra: list[str] | None = None,
                 budget_mib: int = 256) -> tuple[list[Any], list[str]]:
        """Scan app dirs + entrypoint scripts of a container's filesystem for env var reads."""
        from ..insights import envcontract as ec
        from ..rootfs import walk
        wd = image_config.get("WorkingDir") or ""
        dirs = [d for d in dict.fromkeys([*(extra or []), *([wd] if wd not in ("", "/") else []), "/app", "/srv",
                                          "/usr/src/app", "/opt/app", "/code", "/workspace", "/var/www/html"])]
        dirs = [d for d in dirs if not any(d != o and d.startswith(o.rstrip("/") + "/") for o in dirs)]
        files = [e for e in (image_config.get("Entrypoint") or [])[:1] if e.startswith("/")]
        files += ["/docker-entrypoint.sh", "/entrypoint.sh", "/usr/local/bin/docker-entrypoint.sh"]
        uses, scanned = [], []
        for root in [*dirs, *dict.fromkeys(files)]:
            try:
                for m, rel, data in walk(self.t, ref, root, budget_mib=budget_mib,
                                         want=lambda r, mm: mm.size <= 512 * 1024 and (ec.is_source(r) or r == "")):
                    if data is not None and b"\0" not in data[:1024]:
                        path = root.rstrip("/") + ("/" + rel if rel else "")
                        scanned.append(path)
                        uses += ec.extract(path, data.decode(errors="replace"))
            except NotFound:
                continue
        inline = " ".join([*(image_config.get("Entrypoint") or []), *(image_config.get("Cmd") or [])])
        if "$" in inline:  # `sh -c '... ${X:?}'` reads the environment too
            scanned.append("<command>")
            uses += ec.extract("<command>", inline)
        return uses, scanned

    @op(Tier.READ)
    def envcheck(self, ref: Ref, *, path: Annotated[list[str] | None, "extra directories to scan"] = None,
                 ) -> dict[str, Any]:
        """Env contract: variables the code reads vs. what the container provides; flags missing ones and typos.

        Works on running, stopped and created (never-started) containers: create first, check, then start.
        """
        from ..insights import envcontract as ec
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        uses, scanned = self.env_uses(ref, info.get("Config") or {}, path)
        provided = dict(e.partition("=")[::2] for e in (info.get("Config") or {}).get("Env") or [])
        return {"container": ref, "files_scanned": len(scanned), **ec.check(uses, provided)}

    @op(Tier.READ)
    def compare(self, ref: Ref, other: Annotated[str, "second container"]) -> dict[str, Any]:
        """Config drift between two containers: env (secrets masked), ports, mounts, command, image digest, limits."""
        ia, ib = (self.t.json("GET", f"/containers/{q(r)}/json") for r in (ref, other))
        return compare_specs(runspec_of(ia) | {"image_id": ia.get("Image", "")[7:19]},
                             runspec_of(ib) | {"image_id": ib.get("Image", "")[7:19]})

    @op(Tier.READ)
    def timeline(self, *refs: Annotated[str, "containers to interleave"],
                 since: Annotated[str, "unix ts, ISO time, or relative like 10m"] = "10m",
                 tail: Annotated[int, "max lines per container"] = 1000,
                 grep: Annotated[str | None, "only lines matching this regex"] = None,
                 patterns: Annotated[bool, "fingerprint the merged stream instead of printing it"] = False,
                 max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Merge several containers' logs into one timeline by Docker's timestamps, each line tagged with its source."""
        if len(refs) < 1:
            raise ValueError("usage: aisb containers timeline api db cache --since 5m")
        rx = re.compile(grep) if grep else None
        streams = []
        for r in refs:
            text = self._text(r, tail=tail, since=since, timestamps=True)
            entries = []
            for line in text.splitlines():
                ts, _, msg = line.partition(" ")
                if (when := docker_time(ts)) is not None and (not rx or rx.search(msg)):
                    entries.append((when, r, msg))
            streams.append(entries)
        merged = list(heapq.merge(*streams))
        width = max(len(r) for r in refs)
        if patterns:
            fp = insights.fingerprint([f"[{r}] {m}" for _, r, m in merged], top=20)
            return {"containers": list(refs), "since": since, **fp}
        lines = [f"{time.strftime('%H:%M:%S', time.gmtime(t))}.{int(t % 1 * 1000):03d} {r:<{width}} | {m}"
                 for t, r, m in merged]
        return {"containers": list(refs), "since": since, "lines": len(lines),
                **clip("\n".join(lines) + ("\n" if lines else ""), max_bytes)}

    @op(Tier.MUTATE)
    def debug(self, ref: Ref, *cmd: Cmd,
              image: Annotated[str, "toolbox image (e.g. nicolaka/netshoot for tcpdump/dig/curl)"] = "alpine:3.20",
              max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Run a command in a throwaway sidecar sharing REF's network and PID namespaces (for images with no tools).

        localhost is REF's localhost, and REF's processes are visible (`ps`, /proc/1/root/...). The sidecar is
        removed afterwards.
        """
        if not cmd:
            raise ValueError("usage: aisb containers debug NAME -- nc -zv db 5432")
        target = self.t.json("GET", f"/containers/{q(ref)}/json")["Id"]
        spec = RunSpec(image=image, cmd=tuple(cmd), network=f"container:{target}", pid=f"container:{target}",
                       labels={"aisb.debug-of": ref})
        cid = self.create_from(spec)
        try:
            self.t.json("POST", f"/containers/{cid}/start")
            status = self.t.json("POST", f"/containers/{cid}/wait", timeout=None) or {}
            out = self.logs(cid, tail=0, max_bytes=max_bytes)
        finally:
            self.t.json("DELETE", f"/containers/{cid}", query={"force": True})
        return {"target": ref, "image": image, "exit_code": status.get("StatusCode"), **out}

    def _act(self, ref: str, action: str, grace: int | None = None) -> dict[str, Any]:
        try:
            self.t.json("POST", f"/containers/{q(ref)}/{action}", query={"t": grace},
                        timeout=None if grace is None else grace + 30)
        except NotModified:
            return {"ref": ref, "changed": False}
        return {"ref": ref, "changed": True}

    @op(Tier.MUTATE)
    def start(self, ref: Ref) -> dict[str, Any]:
        """Start a stopped container."""
        return self._act(ref, "start")

    @op(Tier.MUTATE)
    def stop(self, ref: Ref, *, grace: Annotated[int, "seconds before SIGKILL"] = 10) -> dict[str, Any]:
        """Stop a running container (SIGTERM, then SIGKILL after --grace)."""
        return self._act(ref, "stop", grace)

    @op(Tier.MUTATE)
    def restart(self, ref: Ref, *, grace: Annotated[int, "seconds before SIGKILL"] = 10) -> dict[str, Any]:
        """Restart a container."""
        return self._act(ref, "restart", grace)

    @op(Tier.MUTATE)
    def limit(self, ref: Ref, *, memory: Annotated[str | None, "e.g. 256m, 1g (0 = unlimited)"] = None,
              cpus: Annotated[float | None, "e.g. 0.5 (0 = unlimited)"] = None,
              pids: Annotated[int | None, "max processes (0 = unlimited)"] = None) -> dict[str, Any]:
        """Change resource limits of a live container in place (no recreate); swap is capped to the new memory."""
        if memory is None and cpus is None and pids is None:
            raise ValueError("give at least one of --memory, --cpus, --pids")
        hc = (self.t.json("GET", f"/containers/{q(ref)}/json") or {}).get("HostConfig") or {}
        body: dict[str, Any] = {}
        if memory is not None:
            mem = parse_size(memory)
            body["Memory"] = mem
            # MemorySwap must be >= Memory when both are set; -1 when unlimiting keeps the daemon consistent.
            body["MemorySwap"] = mem * 2 if mem else -1
        if cpus is not None:
            body["NanoCpus"] = int(cpus * 1e9)
        if pids is not None:
            body["PidsLimit"] = pids or -1
        res = self.t.json("POST", f"/containers/{q(ref)}/update", body=body) or {}
        before = {"memory": hc.get("Memory") or None, "cpus": (hc.get("NanoCpus") or 0) / 1e9 or None,
                  "pids": hc.get("PidsLimit") or None}
        return {"ref": ref, "before": before, "applied": body, "warnings": res.get("Warnings") or []}

    @op(Tier.MUTATE, name="exec")
    def exec_(self, ref: Ref, *cmd: Cmd, workdir: str | None = None, user: str | None = None,
              env: Annotated[list[str] | None, "KEY=VALUE"] = None,
              max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Run a command in a running container; returns exit code and output."""
        if not cmd:
            raise ValueError("exec needs a command, e.g. `aisb containers exec web -- ls /`")
        chunks: list[bytes] = []
        code = self.stream_in(ref, list(cmd), chunks.append, stderr=chunks.append, env=env, user=user, workdir=workdir)
        return {"exit_code": code, **clip(b"".join(chunks).decode(errors="replace"), max_bytes)}

    def stream_in(self, ref: str, argv: list[str], stdout: Callable[[bytes], object], *,
                  stderr: Callable[[bytes], object] | None = None, env: list[str] | None = None,
                  user: str | None = None, workdir: str | None = None) -> int | None:
        """Run argv inside the container, feeding output chunks to callbacks as they arrive; returns the exit code."""
        created = self.t.json("POST", f"/containers/{q(ref)}/exec", body=compact({
            "Cmd": argv, "AttachStdout": True, "AttachStderr": True, "WorkingDir": workdir, "User": user, "Env": env,
        }))
        eid = created["Id"]
        chunks = self.t.stream("POST", f"/exec/{eid}/start", body={"Detach": False, "Tty": False}, timeout=None)
        for kind, data in demux(chunks):
            (stderr or stdout)(data) if kind is Stream.STDERR else stdout(data)
        return (self.t.json("GET", f"/exec/{eid}/json") or {}).get("ExitCode")

    def run_in(self, ref: str, argv: list[str], *, env: list[str] | None = None, user: str | None = None,
               workdir: str | None = None) -> "ExecResult":
        """Run argv inside the container and capture stdout and stderr separately."""
        out, err = bytearray(), bytearray()
        code = self.stream_in(ref, argv, out.extend, stderr=err.extend, env=env, user=user, workdir=workdir)
        return ExecResult(code, bytes(out), bytes(err))

    @op(Tier.MUTATE)
    def cp(self, src: Annotated[str, "CONTAINER:PATH or local path"],
           dest: Annotated[str, "CONTAINER:DIR or local dir"]) -> dict[str, Any]:
        """Copy files between a container and the local filesystem (one side must be CONTAINER:PATH)."""
        (s_ref, s_path), (d_ref, d_path) = split_cp(src), split_cp(dest)
        if (s_ref is None) == (d_ref is None):
            raise ValueError("exactly one of src/dest must be CONTAINER:PATH")
        if s_ref is not None:
            data = self.t.raw("GET", f"/containers/{q(s_ref)}/archive", query={"path": s_path})
            return {"copied": untar(data, d_path) if data else [], "dest": d_path}
        self.t.json("PUT", f"/containers/{q(d_ref)}/archive", query={"path": d_path},
                    data=tar_path(s_path), content_type="application/x-tar")
        return {"copied": [s_path], "dest": dest}

    @op(Tier.DESTROY)
    def rm(self, ref: Ref, *, force: Annotated[bool, "kill if running"] = False,
           volumes: Annotated[bool, "also remove anonymous volumes"] = False) -> dict[str, Any]:
        """Remove a container."""
        self.t.json("DELETE", f"/containers/{q(ref)}", query={"force": force, "v": volumes})
        return {"removed": ref}

