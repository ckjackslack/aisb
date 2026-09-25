import shlex
from typing import Annotated, Any, Literal

from ..errors import NotFound, NotModified
from ..models import Container, RunSpec
from ..ops import Resource, Tier, op
from ..streams import decode_output, tar_path, untar
from ..util import MANAGED, MANAGED_KEY, clip, compact, project, q, split_cp, to_unix
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

    @op(Tier.READ)
    def logs(self, ref: Ref, *, tail: Annotated[int, "lines from the end; 0 = all"] = 200,
             since: Annotated[str | None, "unix ts, ISO time, or relative like 10m"] = None,
             until: Annotated[str | None, "unix ts, ISO time, or relative like 1m"] = None,
             stream: Literal["all", "stdout", "stderr"] = "all",
             timestamps: bool = False, max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Container logs, stdout and stderr interleaved."""
        tty = bool((self.t.json("GET", f"/containers/{q(ref)}/json") or {}).get("Config", {}).get("Tty"))
        raw = self.t.raw("GET", f"/containers/{q(ref)}/logs", query={
            "stdout": stream != "stderr", "stderr": stream != "stdout", "tail": tail or "all",
            "since": since and to_unix(since), "until": until and to_unix(until), "timestamps": timestamps,
        })
        return clip(decode_output(raw, tty), max_bytes)

    @op(Tier.READ)
    def top(self, ref: Ref) -> list[dict[str, str]]:
        """Processes running inside the container."""
        r = self.t.json("GET", f"/containers/{q(ref)}/top")
        return [dict(zip(r["Titles"], p)) for p in r.get("Processes") or []]

    @op(Tier.READ)
    def stats(self, ref: Ref) -> dict[str, Any]:
        """One-shot resource usage: CPU %, memory, network, block IO, pids."""
        return summarize_stats(self.t.json("GET", f"/containers/{q(ref)}/stats", query={"stream": False}))

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
        body = s.to_api(auto_remove=s.rm and detach)
        create = lambda: self.t.json("POST", "/containers/create", query={"name": s.name}, body=body)  # noqa: E731
        try:
            cid = create()["Id"]
        except NotFound:
            if not pull:
                raise
            Images(self.t).pull(s.image)
            cid = create()["Id"]
        self.t.json("POST", f"/containers/{cid}/start")
        if detach:
            return {"id": cid[:12], "name": s.name, "status": "started"}
        status = self.t.json("POST", f"/containers/{cid}/wait", timeout=None) or {}
        out = self.logs(cid, tail=0, max_bytes=max_bytes)
        if s.rm:
            self.t.json("DELETE", f"/containers/{cid}", query={"force": True})
        return {"id": cid[:12], "exit_code": status.get("StatusCode"), **out}

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

    @op(Tier.MUTATE, name="exec")
    def exec_(self, ref: Ref, *cmd: Cmd, workdir: str | None = None, user: str | None = None,
              env: Annotated[list[str] | None, "KEY=VALUE"] = None,
              max_bytes: MaxBytes = 64 * 1024) -> dict[str, Any]:
        """Run a command in a running container; returns exit code and output."""
        if not cmd:
            raise ValueError("exec needs a command, e.g. `aisb containers exec web -- ls /`")
        created = self.t.json("POST", f"/containers/{q(ref)}/exec", body=compact({
            "Cmd": list(cmd), "AttachStdout": True, "AttachStderr": True,
            "WorkingDir": workdir, "User": user, "Env": env,
        }))
        eid = created["Id"]
        raw = self.t.raw("POST", f"/exec/{eid}/start", body={"Detach": False, "Tty": False}, timeout=None)
        code = (self.t.json("GET", f"/exec/{eid}/json") or {}).get("ExitCode")
        return {"exit_code": code, **clip(decode_output(raw, False), max_bytes)}

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

