import collections
import dataclasses
import re
import threading
import time
from typing import Annotated, Any, Literal

from ..errors import DockerError, NotFound

from .. import insights
from ..insights import snapshot as snap
from ..ops import Resource, Tier, op
from ..streams import demux, iter_jsonl
from ..util import MANAGED, docker_time, filters, project, q, to_unix

_EVENT_ATTRS = ("name", "image", "exitCode", "signal", "container")


def summarize_df(d: dict[str, Any]) -> dict[str, Any]:
    images = d.get("Images") or []
    containers = d.get("Containers") or []
    volumes = d.get("Volumes") or []
    cache = d.get("BuildCache") or []
    vsize = lambda v: max((v.get("UsageData") or {}).get("Size", 0), 0)  # noqa: E731
    return {
        "images": {"count": len(images), "active": sum(i.get("Containers", 0) > 0 for i in images),
                   "size": d.get("LayersSize", 0),
                   "reclaimable": sum(i.get("Size", 0) for i in images if i.get("Containers", 0) <= 0)},
        "containers": {"count": len(containers), "running": sum(c.get("State") == "running" for c in containers),
                       "size": sum(c.get("SizeRw", 0) for c in containers),
                       "reclaimable": sum(c.get("SizeRw", 0) for c in containers if c.get("State") != "running")},
        "volumes": {"count": len(volumes),
                    "active": sum((v.get("UsageData") or {}).get("RefCount", 0) > 0 for v in volumes),
                    "size": sum(vsize(v) for v in volumes),
                    "reclaimable": sum(vsize(v) for v in volumes if not (v.get("UsageData") or {}).get("RefCount"))},
        "build_cache": {"count": len(cache), "size": sum(c.get("Size", 0) for c in cache),
                        "reclaimable": sum(c.get("Size", 0) for c in cache if not c.get("InUse"))},
    }


def compact_event(e: dict[str, Any]) -> dict[str, Any]:
    actor = e.get("Actor") or {}
    attrs = actor.get("Attributes") or {}
    return {
        "time": e.get("time"), "type": e.get("Type"), "action": e.get("Action"),
        "id": (actor.get("ID") or "")[:12],
        **{k: attrs[k] for k in _EVENT_ATTRS if k in attrs},
    }


def _reclaimed(r: Any, key: str) -> dict[str, Any]:
    r = r or {}
    return {"deleted": len(r.get(key) or []), "space_reclaimed": r.get("SpaceReclaimed", 0)}


_HOST_REF = re.compile(r"(?:^|[/@=,\s])([a-z0-9][a-z0-9_.-]*):(\d{2,5})\b|//([a-z0-9][a-z0-9_.-]*)(?=[/:?]|$)")


def config_dependencies(t: Any, rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Container -> containers its env points at (by name or network alias), e.g. REDIS_URL=redis://cache:6379."""
    infos = {(r.get("Names") or ["?"])[0].lstrip("/"): t.json("GET", f"/containers/{r['Id']}/json") for r in rows}
    alias: dict[str, str] = {}
    for name, info in infos.items():
        alias[name] = name
        for ep in ((info.get("NetworkSettings") or {}).get("Networks") or {}).values():
            for a in ep.get("Aliases") or []:
                alias.setdefault(a, name)
    out: dict[str, set[str]] = {}
    for name, info in infos.items():
        for entry in (info.get("Config") or {}).get("Env") or []:
            value = entry.partition("=")[2]
            for m in _HOST_REF.finditer(value):
                host = m.group(1) or m.group(3)
                if host in alias and alias[host] != name:
                    out.setdefault(name, set()).add(alias[host])
    return out


class System(Resource, name="system"):
    @op(Tier.READ)
    def ping(self) -> dict[str, Any]:
        """Check the daemon is reachable and report the negotiated API version."""
        return {"ok": True, "endpoint": self.t.endpoint.url, "api_version": self.t.version}

    @op(Tier.READ)
    def version(self) -> Any:
        """Daemon and API versions."""
        return self.t.json("GET", "/version")

    @op(Tier.READ)
    def info(self, *, fields: Annotated[str | None, "comma-separated dotted paths"] = None) -> Any:
        """System-wide information; narrow with --fields."""
        return project(self.t.json("GET", "/info"), fields)

    @op(Tier.READ)
    def df(self) -> dict[str, Any]:
        """Disk usage summary with reclaimable bytes per object type."""
        return summarize_df(self.t.json("GET", "/system/df", timeout=None))

    @op(Tier.READ)
    def events(self, *, since: Annotated[str, "unix ts, ISO time, or relative like 10m"] = "10m",
               until: Annotated[str, "end of window (bounded, never streams forever)"] = "now",
               filter: Annotated[list[str] | None, "KEY=VALUE, e.g. type=container, container=web, event=die"] = None,
               limit: Annotated[int, "max events returned"] = 200) -> list[dict[str, Any]]:
        """Daemon events in a bounded time window."""
        query = {"since": to_unix(since), "until": to_unix(until), "filters": filters(filter)}
        out: list[dict[str, Any]] = []
        for e in iter_jsonl(self.t.stream("GET", "/events", query=query)):
            out.append(compact_event(e))
            if len(out) >= limit:
                break
        return out

    @op(Tier.READ)
    def doctor(self, *, managed: Annotated[bool, "only containers created by aisb"] = False,
               tail: Annotated[int, "log lines scanned per container; 0 = skip logs (faster)"] = 200) -> dict[str, Any]:
        """Fleet triage across every container, worst first: state, config, image, and recent log signatures."""
        from .containers import Containers
        ctr = Containers(self.t)
        rows = self.t.json("GET", "/containers/json", query={"all": True, "filters": {"label": [MANAGED]} if managed else None})
        tags = {t: i["Id"] for i in self.t.json("GET", "/images/json") for t in i.get("RepoTags") or []}
        peers = ctr.names() if managed else frozenset(n.lstrip("/") for r in rows for n in r.get("Names") or [])
        reports = []
        for row in rows:
            info = self.t.json("GET", f"/containers/{row['Id']}/json")
            cfg = info.get("Config") or {}
            name = (info.get("Name") or row["Id"][:12]).lstrip("/")
            logs = tuple(ctr._text(row["Id"], tail=tail, tty=bool(cfg.get("Tty"))).splitlines()) if tail else ()
            reports.append(insights.diagnose(insights.Facts(name, info, logs=logs, image_id=tags.get(cfg.get("Image", "")),
                                                            peers=peers)))
        order = {"failing": 0, "degraded": 1, "healthy": 2}
        reports.sort(key=lambda r: (order[r["verdict"]], r["container"]))
        problems = [{"container": r["container"], "verdict": r["verdict"], "state": r["state"]["status"],
                     "likely_cause": r["likely_cause"],
                     "findings": [f"{f['severity']}:{f['code']}: {f['summary']}" for f in r["findings"]
                                  if f["severity"] != "info"]}
                    for r in reports if r["verdict"] != "healthy"]
        return {
            "scope": f"state, config, image{f', last {tail} log lines' if tail else ''}; no live stats",
            "summary": {v: sum(r["verdict"] == v for r in reports) for v in order},
            "problems": problems,
            "healthy": [r["container"] for r in reports if r["verdict"] == "healthy"],
            "next": [f"aisb containers doctor {p['container']}" for p in problems],
        }

    @op(Tier.READ)
    def audit(self, *, managed: Annotated[bool, "only containers created by aisb"] = False,
              container: Annotated[list[str] | None, "only these containers"] = None,
              min_severity: Annotated[Literal["info", "warning", "critical"], "hide findings below this"] = "warning",
              ) -> dict[str, Any]:
        """Security/config audit of containers: privileges, socket and host mounts, root user, exposed datastores,
        secrets in env, missing limits/healthchecks, unpinned images. Ranked with a 0-100 score per container."""
        from ..insights.audit import audit
        ids = container or [r["Id"] for r in self.t.json("GET", "/containers/json", query={
            "all": True, "filters": {"label": [MANAGED]} if managed else None}) or []]
        images: dict[str, Any] = {}
        order = ["info", "warning", "critical"]
        reports = []
        for cid in ids:
            info = self.t.json("GET", f"/containers/{q(cid)}/json")
            img = info.get("Image", "")
            if img not in images:
                try:
                    images[img] = self.t.json("GET", f"/images/{q(img)}/json")
                except NotFound:
                    images[img] = {}
            rep = audit(info, images[img])
            rep["findings"] = [f for f in rep["findings"] if order.index(f["severity"]) >= order.index(min_severity)]
            reports.append(rep)
        reports.sort(key=lambda r: (r["score"], r["container"]))
        codes: dict[str, int] = {}
        for r in reports:
            for f in r["findings"]:
                codes[f["code"]] = codes.get(f["code"], 0) + 1
        return {"containers": len(reports), "average_score": round(sum(r["score"] for r in reports) / len(reports))
                if reports else None, "most_common": dict(sorted(codes.items(), key=lambda kv: -kv[1])[:8]),
                "reports": reports}

    @op(Tier.READ)
    def watch(self, *, interval: Annotated[float, "seconds between checks"] = 30.0,
              duration: Annotated[float, "stop after N seconds"] = 300.0,
              until_change: Annotated[bool, "return as soon as anything changes"] = False,
              managed: Annotated[bool, "only containers created by aisb"] = False,
              tail: Annotated[int, "log lines scanned per container"] = 100) -> dict[str, Any]:
        """Re-run fleet triage and report only what changed: new problems, recoveries, verdict changes, arrivals."""
        def state() -> dict[str, tuple[str, tuple[str, ...], str]]:
            rep = self.doctor(managed=managed, tail=tail)
            rows = self.t.json("GET", "/containers/json", query={
                "all": True, "filters": {"label": [MANAGED]} if managed else None}) or []
            states = {(r.get("Names") or ["?"])[0].lstrip("/"): r.get("State", "") for r in rows}
            out = {c: ("healthy", (), states.get(c, "")) for c in rep["healthy"]}
            for p in rep["problems"]:
                out[p["container"]] = (p["verdict"], tuple(sorted(f.split(":")[1] for f in p["findings"])),
                                       states.get(p["container"], ""))
            return out
        begin = time.monotonic()
        prev, events, polls = state(), [], 1
        rank = {"healthy": 0, "degraded": 1, "failing": 2}
        while time.monotonic() - begin + interval <= duration:
            time.sleep(interval)
            cur, polls = state(), polls + 1
            now = int(time.time())
            for name in sorted(prev.keys() | cur.keys()):
                old, new = prev.get(name), cur.get(name)
                if old == new:
                    continue
                if old is None or new is None:
                    kind = "appeared" if old is None else "gone"
                else:
                    kind = "worse" if rank[new[0]] > rank[old[0]] else "better" if rank[new[0]] < rank[old[0]] \
                        else f"{old[2]} -> {new[2]}" if old[2] != new[2] else "findings-changed"
                events.append({"at": now, "container": name, "change": kind,
                               "from": old[0] if old else None, "to": new[0] if new else None,
                               "state": new[2] if new else None,
                               "new_findings": sorted(set(new[1]) - set(old[1] if old else ())) if new else [],
                               "resolved": sorted(set(old[1]) - set(new[1] if new else ())) if old else []})
            prev = cur
            if until_change and events:
                break
        worst = [n for n, (v, *_) in prev.items() if v == "failing"]
        return {"polls": polls, "seconds": round(time.monotonic() - begin, 1), "changes": events,
                "failing_now": worst, "next": [f"aisb containers doctor {n}" for n in worst]}

    @op(Tier.READ)
    def incident(self, *, since: Annotated[str, "window start: unix ts, ISO time, or relative like 30m"] = "30m",
                 format: Annotated[Literal["json", "markdown"], "markdown = postmortem draft"] = "json",
                 log_lines: Annotated[int, "log lines scanned per container"] = 2000) -> Any:
        """Causal incident report: correlate events, first error signals and observed dependencies into a
        root cause, blast radius and chain (with a postmortem draft in markdown)."""
        from ..insights import incident as inc
        from ..insights.logs import level_of, template
        from .containers import Containers
        from .net import Net
        ctr = Containers(self.t)
        start, now = to_unix(since), time.time()
        signals: list[inc.Signal] = []
        for e in self.events(since=since, until="now", limit=2000):
            action, name = str(e.get("action", "")), e.get("name") or e.get("id")
            if e.get("type") != "container" or not name:
                continue
            if action == "oom":
                signals.append(inc.Signal(e["time"], name, "event", "critical", "OOM killed"))
            elif action == "die" and e.get("exitCode") not in (None, "0", "143"):
                signals.append(inc.Signal(e["time"], name, "event", "critical", f"died (exit {e.get('exitCode')})"))
            elif action.startswith("health_status: unhealthy"):
                signals.append(inc.Signal(e["time"], name, "health", "critical", "healthcheck unhealthy"))
            elif action in ("kill", "restart"):
                signals.append(inc.Signal(e["time"], name, "event", "info", action))
        rows = self.t.json("GET", "/containers/json", query={"all": True}) or []
        causes: dict[str, str | None] = {}
        for r in rows:
            name = (r.get("Names") or ["?"])[0].lstrip("/")
            seen: set[str] = set()
            try:
                text = ctr._text(r["Id"], tail=log_lines, since=str(int(start)), timestamps=True)
            except Exception:  # noqa: BLE001 - a container vanishing mid-scan must not sink the report
                continue
            for line in text.splitlines():
                ts, _, msg = line.partition(" ")
                when = docker_time(ts)
                lvl = level_of(msg)
                if when is None or lvl not in ("error", "warn"):
                    continue
                key = template(msg)
                if key not in seen and len(seen) < 5:
                    seen.add(key)
                    signals.append(inc.Signal(when, name, "log", "critical" if lvl == "error" else "warning", msg[:200]))
        failing = {s.container for s in signals if s.severity == "critical"}
        for name in failing:
            try:
                causes[name] = ctr.doctor(name, tail=300, stats=False).get("likely_cause")
            except Exception:  # noqa: BLE001
                causes[name] = None
        try:
            from ..insights import graph
            deps = graph.depends_on(graph.build(Net(self.t).observe(samples=1)))
        except Exception:  # noqa: BLE001
            deps = {}
        # A dead dependency has no live connections left, so also use configured targets (env URLs/host:port).
        sources = ["traffic"] if deps else []
        if configured := config_dependencies(self.t, rows):
            sources.append("config")
        for name, targets in configured.items():
            deps.setdefault(name, set()).update(targets)
        report = inc.analyze(signals, deps, likely_causes=causes, evidence="+".join(sources) or "temporal")
        report["window"] = {"from": int(start), "to": int(now)}
        nxt = [f"aisb containers doctor {c}" for c in report.get("chain", [])[:3]] + \
              ([f"aisb containers timeline {' '.join(report['chain'][:4])} --since {since}"] if report.get("chain") else [])
        report["next"] = nxt
        if format == "markdown":
            return {"output": inc.postmortem(report, window=f"last {since}", next_steps=nxt), "summary": report["summary"]}
        return report

    @op(Tier.READ)
    def blackbox(self, *, seconds: Annotated[float, "how long to record"] = 600.0,
                 max_records: Annotated[int, "stop after this many captures"] = 100,
                 log_lines: Annotated[int, "log lines kept per container (ring buffer)"] = 500) -> dict[str, Any]:
        """Flight recorder: keeps a ring buffer of every container's logs from the moment it is *created*, and
        saves config + buffer when it dies/OOMs/is killed. Works even for --rm containers, whose logs Docker
        refuses to serve once they die. Read records back with `system forensics`."""
        from .. import state
        from ..transport import redact_env
        out_dir = state.home("blackbox")
        buffers: dict[str, collections.deque[str]] = {}
        configs: dict[str, dict[str, Any]] = {}

        def follow(cid: str) -> None:
            buf = buffers.setdefault(cid, collections.deque(maxlen=log_lines))
            try:
                info = self.t.json("GET", f"/containers/{cid}/json")
                configs[cid] = info
                chunks = self.t.stream("GET", f"/containers/{cid}/logs", query={
                    "follow": True, "stdout": True, "stderr": True, "timestamps": True}, timeout=None)
                pending = ""
                if (info.get("Config") or {}).get("Tty"):
                    source = (c.decode(errors="replace") for c in chunks)
                else:
                    source = (d.decode(errors="replace") for _, d in demux(chunks))
                for text in source:
                    *lines, pending = (pending + text).split("\n")
                    buf.extend(lines)
                if pending:
                    buf.append(pending)
            except Exception:  # noqa: BLE001 - a follower dying must never take the recorder down
                pass

        def attach(cid: str) -> None:
            if cid not in buffers:
                buffers[cid] = collections.deque(maxlen=log_lines)
                threading.Thread(target=follow, args=(cid,), daemon=True).start()

        for r in self.t.json("GET", "/containers/json") or []:
            attach(r["Id"])
        captured: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        query = {"since": int(time.time()), "until": int(time.time() + seconds),
                 "filters": {"type": ["container"], "event": ["create", "start", "die", "oom", "kill"]}}
        for e in iter_jsonl(self.t.stream("GET", "/events", query=query, timeout=None)):
            cid = (e.get("Actor") or {}).get("ID") or e.get("id") or ""
            attrs = (e.get("Actor") or {}).get("Attributes") or {}
            action = e.get("Action") or e.get("status")
            if action in ("create", "start"):
                attach(cid)  # following a created container attaches before it runs: nothing is missed
                continue
            try:
                info = self.t.json("GET", f"/containers/{cid}/json")
            except DockerError:
                info = configs.get(cid) or {"Name": "/" + attrs.get("name", cid[:12]), "Config": {}, "State": {}}
            info.setdefault("State", {})
            if action == "die" and attrs.get("exitCode") is not None:
                info["State"] = {**info["State"], "Status": "exited", "Running": False,
                                 "ExitCode": int(attrs["exitCode"])}
            if action == "oom":
                info["State"] = {**info["State"], "OOMKilled": True}
            name = attrs.get("name") or (info.get("Name") or "").lstrip("/") or cid[:12]
            key = (name, f"{info['State'].get('StartedAt')}:{action}")
            if key in seen:
                continue
            seen.add(key)
            time.sleep(0.2)  # let the follower drain the last lines
            cfg = info.get("Config") or {}
            info["Config"] = {**cfg, "Env": redact_env(cfg.get("Env") or [])}
            record = {"container": name, "event": action, "at": e.get("time"),
                      "exit_code": info["State"].get("ExitCode"), "inspect": info,
                      "logs": "\n".join(buffers.get(cid) or [])}
            path = state.write_json(out_dir / f"{name}-{int(e.get('time') or time.time())}-{action}.json", record)
            captured.append({"container": name, "event": action, "exit_code": record["exit_code"],
                             "log_lines": len(buffers.get(cid) or []), "record": str(path)})
            if len(captured) >= max_records:
                break
        return {"seconds": seconds, "captured": captured, "stored_in": str(out_dir)}

    @op(Tier.READ)
    def forensics(self, name: Annotated[str | None, "container name (omit to list records)"] = None, *,
                  limit: Annotated[int, "records shown"] = 20) -> Any:
        """Read blackbox records; with a name, run doctor on the last captured state of a container that's gone."""
        from .. import insights, state
        records = sorted(state.home("blackbox").glob(f"{name or '*'}-*.json"), key=lambda p: p.stat().st_mtime,
                         reverse=True)
        if not name:
            out = []
            for p in records[:limit]:
                r = state.read_json(p) or {}
                out.append({"container": r.get("container"), "event": r.get("event"), "at": r.get("at"),
                            "exit_code": r.get("exit_code"), "record": str(p)})
            return out
        if not records:
            raise ValueError(f"no blackbox record for {name!r} (run `aisb system blackbox` while it fails)")
        r = state.read_json(records[0])
        lines = tuple(line.partition(" ")[2] for line in (r.get("logs") or "").splitlines())
        report = insights.diagnose(insights.Facts(name, r["inspect"], logs=lines))
        return {"record": str(records[0]), "captured_event": r.get("event"), "records_for_container": len(records),
                **report, "log_patterns": [
                    {k: p[k] for k in ("level", "count", "template")}
                    for p in insights.fingerprint(list(lines), top=5, min_level="warn")["top"]]}

    @op(Tier.READ)
    def rightsize(self, *, seconds: Annotated[float, "sampling window"] = 60,
                  interval: Annotated[float, "seconds between samples"] = 5,
                  headroom: Annotated[float, "safety margin over observed peak/p95"] = 0.3,
                  container: Annotated[list[str] | None, "only these containers (default: all running)"] = None,
                  ) -> dict[str, Any]:
        """Sample live usage and recommend memory/CPU/pids limits per container, flagging at-risk,
        over-provisioned, unlimited and idle ones, with ready `containers limit` commands."""
        from ..insights import rightsize as rs
        rows = self.t.json("GET", "/containers/json") or []
        names = {(r.get("Names") or ["?"])[0].lstrip("/"): r["Id"] for r in rows}
        wanted = container or sorted(names)
        unknown = [n for n in wanted if n not in names]
        if unknown:
            raise ValueError(f"not running: {', '.join(unknown)}")
        series: dict[str, list[rs.Sample]] = {n: [] for n in wanted}

        def sample(n: str) -> None:
            try:
                raw = self.t.json("GET", f"/containers/{names[n]}/stats", query={"stream": False, "one-shot": True})
                series[n].append(rs.Sample.from_api(raw or {}, time.monotonic()))
            except DockerError:
                pass  # container went away mid-window

        rounds = max(round(seconds / interval), 1) + 1  # samples at 0, interval, ..., seconds
        for i in range(rounds):
            if i:
                time.sleep(interval)
            workers = [threading.Thread(target=sample, args=(n,), daemon=True) for n in wanted]
            for w in workers:
                w.start()
            for w in workers:
                w.join()
        out = []
        for n in wanted:
            if len(series[n]) < 2:
                out.append({"name": n, "error": "not enough samples (stopped during the window?)"})
                continue
            hc = (self.t.json("GET", f"/containers/{names[n]}/json") or {}).get("HostConfig") or {}
            out.append(dataclasses.asdict(rs.recommend(n, series[n], rs.Limits.from_host_config(hc),
                                                       headroom=headroom)))
        flagged = [r for r in out if r.get("command")]
        return {"window_s": seconds, "interval_s": interval, "headroom": headroom, "containers": out,
                "note": "recommendations only reflect this window; sample under representative load",
                "commands": [r["command"] for r in flagged],
                "summary": {f: sum(f in r.get("flags", []) for r in out)
                            for f in ("at-risk", "over-provisioned", "unlimited", "idle")}}

    @op(Tier.READ)
    def snapshot(self) -> dict[str, Any]:
        """Inventory of containers, images, volumes and networks; save it and diff later with `system changes`."""
        return snap.take(
            self.t.json("GET", "/containers/json", query={"all": True}),
            self.t.json("GET", "/images/json"),
            (self.t.json("GET", "/volumes") or {}).get("Volumes") or [],
            self.t.json("GET", "/networks"),
        )

    @op(Tier.READ)
    def changes(self, before: Annotated[str, "snapshot JSON file (from `system snapshot`)"],
                after: Annotated[str | None, "second snapshot file; default: live state now"] = None) -> dict[str, Any]:
        """What was added, removed, recreated or changed between two snapshots, with dry-run cleanup commands."""
        return snap.compare(snap.load(before), snap.load(after) if after else self.snapshot())

    @op(Tier.DESTROY)
    def prune(self, *, containers: Annotated[bool, "stopped containers"] = True,
              images: Annotated[bool, "dangling images"] = True,
              networks: Annotated[bool, "unused networks"] = True,
              volumes: Annotated[bool, "unused anonymous volumes (data loss!)"] = False,
              all_images: Annotated[bool, "all unused images, not just dangling"] = False,
              managed: Annotated[bool, "only objects labelled aisb.managed=true"] = False) -> dict[str, Any]:
        """Remove unused objects. Volumes are opt-in."""
        label = {"label": [MANAGED]} if managed else {}
        out: dict[str, Any] = {}
        if containers:
            out["containers"] = _reclaimed(self.t.json("POST", "/containers/prune", query={"filters": label or None}),
                                           "ContainersDeleted")
        if images:
            f = {"dangling": ["false" if all_images else "true"], **label}
            out["images"] = _reclaimed(self.t.json("POST", "/images/prune", query={"filters": f}, timeout=None),
                                       "ImagesDeleted")
        if networks:
            out["networks"] = _reclaimed(self.t.json("POST", "/networks/prune", query={"filters": label or None}),
                                         "NetworksDeleted")
        if volumes:
            # API >= 1.42 prunes only anonymous volumes unless all=true; aisb-managed named volumes count too.
            f = {**label, "all": ["true"]} if managed else None
            out["volumes"] = _reclaimed(self.t.json("POST", "/volumes/prune", query={"filters": f}),
                                        "VolumesDeleted")
        return out
