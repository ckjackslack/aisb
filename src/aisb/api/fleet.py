"""`aisb fleet`: many machines, one CLI. Inventory + selectors, health, and any aisb op fanned out over SSH."""

import json
import shlex
import time
from collections.abc import Sequence
from typing import Annotated, Any, Literal

from ..fleet import health, runner
from ..fleet.inventory import Host, Inventory
from ..ops import Op, Resource, Tier, invoke, jsonable, op
from ..errors import NotFound
from ..streams import iter_jsonl
from ..util import clip, kv, q

Target = Annotated[str, "hosts: all, name, glob, @group, label=value; `,` union, `&` intersect, `!` exclude"]
Inv = Annotated[str | None, "inventory file (default: $AISB_FLEET or ~/.aisb/fleet.json)"]
Parallel = Annotated[int, "hosts worked on concurrently"]
Batch = Annotated[int | None, "rolling: this many hosts at a time"]
FailFast = Annotated[bool, "stop starting new batches once a host failed"]
Retries = Annotated[int, "retry a host whose SSH/tunnel setup failed (nothing ran there yet), with backoff"]
HostTimeout = Annotated[float | None, "per-host wall-clock limit in seconds"]
FailOn = Annotated[Literal["degraded", "failing", "down"] | None, "exit 4 when any host is at this level or worse"]
Command = Annotated[str, "RESOURCE OP [ARGS...] of the aisb op to run on each host (after --)"]
_VIA = {Tier.READ: "query", Tier.MUTATE: "apply", Tier.DESTROY: "destroy"}


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value, default=jsonable))


def _inner(command: Sequence[str], tier: Tier) -> tuple[Op, dict[str, Any]]:
    """Parse `RESOURCE OP ARGS...` with the regular CLI parser and enforce that the op's tier matches."""
    from ..cli import parse
    if len(command) < 2:
        raise ValueError("give the op to run after --, e.g. `-- containers list`")
    try:
        args = parse(list(command))
    except SystemExit:
        raise ValueError(f"invalid op command: {' '.join(command)}") from None
    o: Op | None = args._op
    if o is None or o.resource == "fleet":
        raise ValueError("fleet ops can't be nested")
    if o.tier is not tier:
        raise ValueError(f"{o.qualname} is {o.tier} tier: run it with `aisb fleet {_VIA[o.tier]}`")
    return o, {p.name: getattr(args, p.name) for p in o.params}


class Fleet(Resource, name="fleet"):
    # --- inventory ------------------------------------------------------------------------------

    @op(Tier.READ)
    def hosts(self, target: Target = "all", *, inventory: Inv = None) -> list[dict[str, Any]]:
        """Hosts of the inventory (or of a selection) with transport, groups and labels."""
        inv = Inventory.load(inventory)
        if not inv.hosts:
            raise ValueError(f"no hosts in {inv.path}; add one with `aisb fleet add NAME --ssh user@host`")
        return [{"host": h.name, "transport": h.transport,
                 "address": h.ssh or h.docker or "local", "groups": inv.groups_of(h.name),
                 "labels": dict(h.labels)} for h in inv.select(target)]

    @op(Tier.READ)
    def groups(self, *, inventory: Inv = None) -> list[dict[str, Any]]:
        """Every group with its members; computed groups show the selectors they're defined by."""
        inv = Inventory.load(inventory)
        return [{"group": g, "members": sorted(inv.members(g)),
                 **({"computed_from": inv.groups[g]} if g in inv.groups else {})} for g in inv.group_names()]

    @op(Tier.MUTATE)
    def add(self, name: Annotated[str, "host name used in selectors"], *,
            ssh: Annotated[str | None, "user@host or an ~/.ssh/config alias"] = None,
            port: Annotated[int | None, "ssh port"] = None,
            key: Annotated[str | None, "ssh identity file"] = None,
            docker: Annotated[str | None, "remote socket path (with --ssh), else a direct endpoint (tcp://...)"] = None,
            group: Annotated[list[str] | None, "group to put it in (repeatable)"] = None,
            label: Annotated[dict[str, str] | None, "KEY=VALUE (repeatable)"] = None,
            ssh_option: Annotated[list[str] | None, "extra `ssh -o` option, e.g. ProxyJump=bastion"] = None,
            replace: Annotated[bool, "replace an existing entry instead of merging into it"] = False,
            inventory: Inv = None) -> dict[str, Any]:
        """Add or update a machine. Nothing is contacted; run `fleet ping NAME` next."""
        inv = Inventory.load(inventory)
        host = Host.from_dict(name, {"ssh": ssh, "port": port, "key": key, "docker": docker, "groups": group or [],
                                     "labels": kv(label), "ssh_options": ssh_option or []})
        existed = name in inv.hosts
        host = inv.upsert(host, merge=not replace)
        self._save(inv, action="add" if not existed else "update", host=name)
        return {"host": name, "action": "updated" if existed else "added", "entry": host.to_dict(),
                "inventory": str(inv.path), "next": [f"aisb fleet ping {name}"]}

    @op(Tier.MUTATE)
    def remove(self, name: Annotated[str, "host to forget"], *, inventory: Inv = None) -> dict[str, Any]:
        """Remove a machine from the inventory (the machine itself is not touched)."""
        inv = Inventory.load(inventory)
        if name not in inv.hosts:
            raise ValueError(f"unknown host {name!r}")
        del inv.hosts[name]
        self._save(inv, action="remove", host=name)
        return {"host": name, "action": "removed", "inventory": str(inv.path)}

    @op(Tier.MUTATE)
    def group(self, name: Annotated[str, "group name"], *,
              add: Annotated[str | None, "put these hosts in the group (a selector)"] = None,
              remove: Annotated[str | None, "take these hosts out (a selector)"] = None,
              inventory: Inv = None) -> dict[str, Any]:
        """Change group membership in bulk: `fleet group canary --add 'web*,&region=eu'`."""
        if not add and not remove:
            raise ValueError("give --add and/or --remove")
        inv = Inventory.load(inventory)
        added = [h.name for h in inv.select(add)] if add else []
        removed = [h.name for h in inv.select(remove)] if remove else []
        inv.regroup(name, add=added, remove=removed)
        self._save(inv, action="group", group=name, add=added, remove=removed)
        return {"group": name, "members": sorted(inv.members(name)) if added or name in inv.group_names() else [],
                "added": added, "removed": removed}

    def _save(self, inv: Inventory, **what: Any) -> None:
        if self.t.planning:
            self.t.note(inventory=str(inv.path), **what)
        else:
            inv.save()

    @op(Tier.READ)
    def export(self, target: Target = "all", *,
               format: Annotated[Literal["pyinfra", "ssh-config", "json"], "output format"] = "pyinfra",
               inventory: Inv = None) -> dict[str, Any]:
        """The inventory for other tools: a pyinfra inventory.py (groups kept), an ssh_config, or JSON."""
        inv = Inventory.load(inventory)
        hosts = inv.select(target)
        if format == "json":
            return {"hosts": {h.name: h.to_dict() for h in hosts}}
        text = _pyinfra(inv, hosts) if format == "pyinfra" else _ssh_config(hosts)
        return {"output": text, "hosts": len(hosts), "format": format}

    # --- health ---------------------------------------------------------------------------------

    @op(Tier.READ)
    def ping(self, target: Target = "all", *, parallel: Parallel = 16, retries: Retries = 0, host_timeout: HostTimeout = None, inventory: Inv = None) -> dict[str, Any]:
        """Can each host be reached (SSH, then Docker)? Round-trip time and Docker version per host."""
        def one(h: Host) -> dict[str, Any]:
            t0 = time.monotonic()
            with runner.docker(h, timeout=15) as d:
                v = d.transport.json("GET", "/version") or {}
            return {"docker": v.get("Version"), "api": v.get("ApiVersion"), "os": v.get("Os"),
                    "arch": v.get("Arch"), "rtt_ms": int((time.monotonic() - t0) * 1000)}
        return self._fan(target, one, inventory, parallel=parallel, retries=retries, host_timeout=host_timeout)

    def _status_one(self, h: Host, *, doctor: bool, tail: int) -> dict[str, Any]:
        from .system import System
        vitals = None
        if h.transport != "tcp":
            _, out, _ = runner.shell(h, health.PROBE, timeout=20)
            vitals = health.parse(out)
        with runner.docker(h, timeout=60) as d:
            info = d.transport.json("GET", "/info") or {}
            rep = System(d.transport).doctor(tail=tail) if doctor else None
        vitals = vitals or health.Vitals(cpus=info.get("NCPU"), mem_total=info.get("MemTotal"))
        a = health.assess(vitals, rep)
        return {"verdict": a.verdict, "load": vitals.load1, "cpus": vitals.cpus,
                "mem_free_pct": vitals.mem_available_pct, "disk_pct": vitals.disk_used_pct,
                "containers": f"{info.get('ContainersRunning', 0)}/{info.get('Containers', 0)}",
                "docker": info.get("ServerVersion"), "os": vitals.os or info.get("OperatingSystem"),
                "uptime_h": round(vitals.uptime_s / 3600, 1) if vitals.uptime_s else None, "reasons": a.reasons}

    def _status(self, hosts: list[Host], *, doctor: bool, tail: int, parallel: int, retries: int = 0,
                host_timeout: float | None = None) -> list[dict[str, Any]]:
        results, _ = runner.fan_out(hosts, lambda h: self._status_one(h, doctor=doctor, tail=tail), parallel=parallel,
                                    retries=retries, host_timeout=host_timeout)
        cols = next((list(r.result) for r in results if r.ok), ["verdict", "reasons"])
        rows = [{"host": r.host, **(r.result if r.ok else {**dict.fromkeys(cols), "verdict": "down",
                                                           "reasons": [r.error or "unreachable"]})}
                for r in results]
        return sorted(rows, key=lambda r: (-health.RANK[r["verdict"]], r["host"]))

    @op(Tier.READ)
    def status(self, target: Target = "all", *,
               doctor: Annotated[bool, "include container triage (slower on big hosts)"] = True,
               tail: Annotated[int, "log lines scanned per container by the triage; 0 = state/config only"] = 50,
               fail_on: FailOn = None, parallel: Parallel = 16, retries: Retries = 0,
               host_timeout: HostTimeout = None, inventory: Inv = None) -> dict[str, Any]:
        """Which machines need attention and why: vitals (load, memory, disk) + container verdicts, worst first.
        With --fail-on, exits 4 when any host is at that level or worse (cron/CI gates)."""
        rows = self._status(Inventory.load(inventory).select(target), doctor=doctor, tail=tail, parallel=parallel,
                            retries=retries, host_timeout=host_timeout)
        summary = {v: sum(r["verdict"] == v for r in rows) for v in health.RANK}
        out = {"summary": summary, "hosts": rows,
               "next": [f"aisb fleet doctor {r['host']}" for r in rows if r["verdict"] in ("failing", "degraded")][:5]}
        return {**out, **_gate(fail_on, {r["host"]: r["verdict"] for r in rows})}

    @op(Tier.READ)
    def watch(self, target: Target = "all", *, interval: Annotated[float, "seconds between checks"] = 30.0,
              duration: Annotated[float, "stop after N seconds"] = 300.0,
              until_change: Annotated[bool, "return at the first change"] = False,
              tail: Annotated[int, "log lines scanned per container"] = 50,
              fail_on: FailOn = None, parallel: Parallel = 16, retries: Retries = 0,
              host_timeout: HostTimeout = None, inventory: Inv = None) -> dict[str, Any]:
        """Monitor: re-run status and report only changes: hosts going down/recovering, verdicts, new reasons.
        Connections stay open across polls. With --fail-on, exits 4 if the final state is at that level or worse."""
        with runner.pooled():
            return self._watch(Inventory.load(inventory).select(target), interval=interval, duration=duration,
                               until_change=until_change, tail=tail, fail_on=fail_on, parallel=parallel,
                               retries=retries, host_timeout=host_timeout)

    def _watch(self, hosts: list[Host], *, interval: float, duration: float, until_change: bool, tail: int,
               fail_on: str | None, parallel: int, retries: int, host_timeout: float | None) -> dict[str, Any]:
        snap = lambda: {r["host"]: {"verdict": r["verdict"], "reasons": r["reasons"]}  # noqa: E731
                        for r in self._status(hosts, doctor=True, tail=tail, parallel=parallel, retries=retries,
                                              host_timeout=host_timeout)}
        begin, prev, events, polls = time.monotonic(), snap(), [], 1
        while time.monotonic() - begin + interval <= duration:
            time.sleep(interval)
            cur, polls = snap(), polls + 1
            now = int(time.time())
            events += [{"at": now, **e} for e in health.changes(prev, cur)]
            prev = cur
            if until_change and events:
                break
        now_ = {h: s["verdict"] for h, s in prev.items()}
        return {"polls": polls, "events": events, "now": now_,
                "attention": sorted(h for h, v in now_.items() if v != "healthy"), **_gate(fail_on, now_)}

    @op(Tier.READ)
    def ps(self, target: Target = "all", *, all: Annotated[bool, "include stopped containers"] = False,
           name: Annotated[str | None, "only containers whose name matches this glob"] = None,
           parallel: Parallel = 16, retries: Retries = 0, host_timeout: HostTimeout = None, inventory: Inv = None) -> dict[str, Any]:
        """Containers across machines in one table (host column)."""
        import fnmatch

        def one(h: Host) -> list[dict[str, Any]]:
            with runner.docker(h) as d:
                rows = _plain(d.containers.ls(all=all))
            return [r for r in rows if not name or fnmatch.fnmatch(r["name"], name)]
        return self._fan(Inventory.load(inventory).select(target), one, None, parallel=parallel, flat=True,
                         retries=retries, host_timeout=host_timeout)

    @op(Tier.READ)
    def doctor(self, target: Target = "all", *, tail: Annotated[int, "log lines scanned per container"] = 100,
               parallel: Parallel = 8, retries: Retries = 0, host_timeout: HostTimeout = None, inventory: Inv = None) -> dict[str, Any]:
        """Container problems across machines, worst first, with the host each one is on."""
        from .system import System

        def one(h: Host) -> dict[str, Any]:
            with runner.docker(h) as d:
                return System(d.transport).doctor(tail=tail)
        results, _ = runner.fan_out(Inventory.load(inventory).select(target), one, parallel=parallel, retries=retries,
                                    host_timeout=host_timeout)
        order = {"failing": 0, "degraded": 1}
        problems = sorted(({"host": r.host, **p} for r in results if r.ok for p in r.result["problems"]),
                          key=lambda p: (order.get(p["verdict"], 2), p["host"], p["container"]))
        return {"problems": problems,
                "summary": {r.host: r.result["summary"] for r in results if r.ok},
                "unreachable": {r.host: r.error for r in results if not r.ok},
                "next": [f"aisb fleet query {p['host']} -- containers doctor {p['container']}" for p in problems[:5]]}

    @op(Tier.MUTATE)
    def ship(self, image: Annotated[str, "local image reference"], target: Target, *,
             parallel: Parallel = 4, retries: Retries = 0, host_timeout: HostTimeout = None, batch: Batch = None, fail_fast: FailFast = False,
             inventory: Inv = None) -> dict[str, Any]:
        """Copy an image from this machine to the selected hosts (no registry needed; air-gapped friendly).
        Hosts that already have the same image ID are skipped."""
        import tempfile
        local = self.t.json("GET", f"/images/{q(image)}/json") or {}
        ident, tags = _identity(local), local.get("RepoTags") or []
        hosts = Inventory.load(inventory).select(target)

        def present(d: Any) -> bool:
            # image IDs differ between engines (containerd store vs classic), layer diff IDs don't
            for ref in (image, *tags):
                try:
                    if _identity(d.transport.json("GET", f"/images/{q(ref)}/json") or {}) == ident:
                        return True
                except NotFound:
                    continue
            return False
        if self.t.planning:
            for h in hosts:
                self.t.note(host=h.name, load=image, tags=tags, skip_if_same_layers=True)
            return {"image": image, "planned": len(hosts)}
        with tempfile.NamedTemporaryFile(prefix="aisb-ship-") as spool:
            size = 0
            for chunk in self.t.stream("GET", f"/images/{q(image)}/get", timeout=None):
                spool.write(chunk)
                size += len(chunk)
            spool.flush()

            def one(h: Host) -> dict[str, Any]:
                # each host reads its own handle (independent offsets) of the one spooled export
                with runner.docker(h, timeout=600) as d:
                    if present(d):
                        return {"action": "present"}
                    with open(spool.name, "rb") as body:
                        msgs = [m.get("stream", "").strip() for m in iter_jsonl(d.transport.stream(
                            "POST", "/images/load", data=body, content_type="application/x-tar", timeout=None))]
                    loaded_id = next((m.split(": ", 1)[1] for m in msgs if m.startswith("Loaded image ID:")), None)
                    for t in tags if loaded_id else ():  # exported by ID: re-apply the local tags
                        repo, _, tag = t.rpartition(":")
                        d.transport.json("POST", f"/images/{q(loaded_id)}/tag", query={"repo": repo, "tag": tag})
                    if not present(d):
                        raise ValueError(f"load finished but {image} is not there: {'; '.join(msgs)[-200:]}")
                return {"action": "loaded", "bytes": size}
            out = self._fan(hosts, one, None, parallel=parallel, batch=batch, fail_fast=fail_fast, retries=retries,
                            host_timeout=host_timeout)
        return {"image": image, "tags": tags, "bytes": size, **out}

    # --- run anything, tier-preserving ------------------------------------------------------------

    @op(Tier.READ)
    def query(self, target: Target, *command: Command, parallel: Parallel = 8, retries: Retries = 0, host_timeout: HostTimeout = None, batch: Batch = None,
              fail_fast: FailFast = False, flat: Annotated[bool, "merge list results into one table"] = False,
              inventory: Inv = None) -> dict[str, Any]:
        """Run a read op on every selected host: `fleet query @prod -- containers logs api --tail 50`."""
        return self._run(target, command, Tier.READ, parallel, batch, fail_fast, inventory, retries=retries,
                         host_timeout=host_timeout, flat=flat)

    @op(Tier.MUTATE)
    def apply(self, target: Target, *command: Command, parallel: Parallel = 8, retries: Retries = 0, host_timeout: HostTimeout = None, batch: Batch = None,
              fail_fast: FailFast = False, inventory: Inv = None) -> dict[str, Any]:
        """Run a mutate op on every selected host; `--dry-run` returns each host's planned API calls.
        Rolling: `fleet apply @web --batch 1 --fail-fast -- containers restart api`."""
        return self._run(target, command, Tier.MUTATE, parallel, batch, fail_fast, inventory, retries=retries,
                         host_timeout=host_timeout)

    @op(Tier.DESTROY)
    def destroy(self, target: Target, *command: Command, parallel: Parallel = 8, retries: Retries = 0, host_timeout: HostTimeout = None, batch: Batch = None,
                fail_fast: FailFast = False, inventory: Inv = None) -> dict[str, Any]:
        """Run a destroy op on every selected host. Without --yes: each host's plan, exit 3, nothing changed."""
        return self._run(target, command, Tier.DESTROY, parallel, batch, fail_fast, inventory, retries=retries,
                         host_timeout=host_timeout)

    def _run(self, target: str, command: Sequence[str], tier: Tier, parallel: int, batch: int | None,
             fail_fast: bool, inventory: str | None, *, flat: bool = False, retries: int = 0,
             host_timeout: float | None = None) -> dict[str, Any]:
        o, kwargs = _inner(command, tier)
        planning = self.t.planning and tier is not Tier.READ

        def one(h: Host) -> Any:
            # each host goes through invoke(): policy (with this host's groups/labels), session capture, audit
            with runner.docker(h) as d:
                if planning:
                    res = invoke(d, o, kwargs, dry_run=True)
                    return {"planned": res.planned, **({"warnings": res.warnings} if res.warnings else {})}
                return _plain(invoke(d, o, kwargs, confirm=True).result)
        out = self._fan(Inventory.load(inventory).select(target), one, None, parallel=parallel, batch=batch,
                        fail_fast=fail_fast, flat=flat, retries=retries, host_timeout=host_timeout)
        if planning:
            for r in out["results"]:
                self.t.note(host=r["host"], op=o.qualname, **(r["result"] if r["ok"] else {"error": r["error"]}))
        return {"op": o.qualname, **out}

    @op(Tier.MUTATE)
    def shell(self, target: Target, *cmd: Annotated[str, "shell command for the machines (after --)"],
              sudo: Annotated[bool, "run through `sudo -n`"] = False,
              seconds: Annotated[float, "per-host timeout"] = 60.0,
              parallel: Parallel = 8, retries: Retries = 0, host_timeout: HostTimeout = None, batch: Batch = None, fail_fast: FailFast = False,
              max_bytes: Annotated[int, "output kept per host"] = 16 * 1024, inventory: Inv = None) -> dict[str, Any]:
        """Run a command on the machines themselves over SSH (not in containers): `fleet shell @db -- df -h /var`."""
        if not cmd:
            raise ValueError("give the command after --, e.g. `-- uptime`")
        line = cmd[0] if len(cmd) == 1 else shlex.join(cmd)  # one argument = a shell snippet, several = argv
        line = f"sudo -n sh -c {shlex.quote(line)}" if sudo else line
        hosts = Inventory.load(inventory).select(target)
        if self.t.planning:
            for h in hosts:
                self.t.note(host=h.name, shell=line)
            return {"planned": len(hosts)}

        def one(h: Host) -> dict[str, Any]:
            code, out, err = runner.shell(h, line, timeout=seconds)
            return {"ok": code == 0, "exit_code": code, "stdout": clip(out, max_bytes)["output"],
                    "stderr": clip(err, max_bytes)["output"], "reason": f"exit {code}"}
        return self._fan(hosts, one, None, parallel=parallel, batch=batch, fail_fast=fail_fast, retries=retries,
                         host_timeout=host_timeout)

    # --- plumbing ---------------------------------------------------------------------------------

    def _fan(self, target: str | list[Host], fn: Any, inventory: str | None, *, parallel: int = 8,
             batch: int | None = None, fail_fast: bool = False, flat: bool = False, retries: int = 0,
             host_timeout: float | None = None) -> dict[str, Any]:
        hosts = Inventory.load(inventory).select(target) if isinstance(target, str) else target
        results, skipped = runner.fan_out(hosts, fn, parallel=parallel, batch=batch, fail_fast=fail_fast,
                                          retries=retries, host_timeout=host_timeout)
        out: dict[str, Any] = {"summary": runner.summary(results, skipped)}
        if flat and all(isinstance(r.result, list) for r in results if r.ok):
            out["rows"] = [{"host": r.host, **(row if isinstance(row, dict) else {"value": row})}
                           for r in results if r.ok for row in r.result]
            out["errors"] = {r.host: r.error for r in results if not r.ok}
        else:
            out["results"] = [r.row() for r in results]
        if out["summary"]["failed"]:
            out["ok"] = False
            out["reason"] = f"{len(out['summary']['failed'])} host(s) failed: {', '.join(out['summary']['failed'])}"
        return out


def _gate(fail_on: str | None, verdicts: dict[str, str]) -> dict[str, Any]:
    """`ok: false` (exit 4) when any host is at the --fail-on level or worse."""
    if not fail_on:
        return {}
    bad = sorted(h for h, v in verdicts.items() if health.RANK[v] >= health.RANK[fail_on])
    return {"ok": not bad, **({"reason": f"{len(bad)} host(s) at '{fail_on}' or worse: {', '.join(bad)}"} if bad else {})}


def _identity(inspect: dict[str, Any]) -> tuple[Any, ...]:
    return tuple((inspect.get("RootFS") or {}).get("Layers") or ()), inspect.get("Architecture"), inspect.get("Os")


def _pyinfra(inv: Inventory, hosts: list[Host]) -> str:
    def entry(h: Host) -> str:
        if not h.ssh:
            return f"('@local', {{}})" if h.transport == "local" else ""
        user, _, addr = h.ssh.rpartition("@")
        data = {"ssh_hostname": addr, **({"ssh_user": user} if user else {}), **({"ssh_port": h.port} if h.port else {}),
                **({"ssh_key": h.key} if h.key else {}), **({"aisb_labels": dict(h.labels)} if h.labels else {})}
        return f"({h.name!r}, {data!r})"
    names = {h.name for h in hosts}
    lines = ['"""pyinfra inventory generated by `aisb fleet export --format pyinfra`. Regenerate; don\'t edit."""', ""]
    skipped = [h.name for h in hosts if not entry(h)]
    if skipped:
        lines.append(f"# skipped (no ssh, Docker endpoint only): {', '.join(skipped)}")
    group = lambda hs: "[" + ", ".join(dict.fromkeys(e for h in hs if (e := entry(h)))) + "]"  # noqa: E731
    lines.append(f"fleet = {group(hosts)}")  # hosts on this machine all collapse into one @local
    for g in inv.group_names():
        members = [h for h in hosts if h.name in inv.members(g) and h.name in names and entry(h)]
        if members:
            lines.append(f"{g.replace('-', '_').replace('.', '_')} = {group(members)}")
    return "\n".join(lines) + "\n"


def _ssh_config(hosts: list[Host]) -> str:
    blocks = []
    for h in hosts:
        if not h.ssh:
            continue
        user, _, addr = h.ssh.rpartition("@")
        lines = [f"Host {h.name}", f"  HostName {addr}"] + ([f"  User {user}"] if user else []) + \
            ([f"  Port {h.port}"] if h.port else []) + ([f"  IdentityFile {h.key}"] if h.key else []) + \
            [f"  {o.split('=', 1)[0]} {o.split('=', 1)[1]}" for o in h.ssh_options if "=" in o]
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"
