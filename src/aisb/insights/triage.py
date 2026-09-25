"""Rule-based container triage: facts in, ranked findings with evidence and next commands out.

Rules are pure functions registered with @rule; add one to teach `doctor` a new failure mode.
"""

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal

from ..util import docker_time
from .logs import fingerprint, level_of

Severity = Literal["critical", "warning", "info"]
_RANK: dict[str, int] = {"critical": 0, "warning": 1, "info": 2}


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    code: str
    summary: str
    evidence: tuple[str, ...] = ()
    next: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Facts:
    name: str
    inspect: Mapping[str, Any]
    logs: tuple[str, ...] = ()
    image_id: str | None = None            # id the container's image tag points to *now*
    stats: Mapping[str, Any] | None = None  # summarize_stats() output, running containers only
    peers: frozenset[str] | None = None     # names of all containers on the host, when known

    @property
    def state(self) -> Mapping[str, Any]:
        return self.inspect.get("State") or {}

    @property
    def config(self) -> Mapping[str, Any]:
        return self.inspect.get("Config") or {}

    @property
    def host(self) -> Mapping[str, Any]:
        return self.inspect.get("HostConfig") or {}

    @property
    def failing(self) -> bool:
        st = self.state
        return bool(st.get("Restarting") or st.get("OOMKilled")
                    or (st.get("Status") in ("exited", "dead") and st.get("ExitCode")))

    @property
    def lifetime(self) -> float | None:
        """Seconds between the last start and finish, for stopped containers."""
        start, end = docker_time(self.state.get("StartedAt")), docker_time(self.state.get("FinishedAt"))
        return round(end - start, 2) if start and end and end >= start else None

    @property
    def env_keys(self) -> set[str]:
        return {e.partition("=")[0] for e in self.config.get("Env") or []}


Rule = Callable[[Facts], Iterable[Finding]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def _recreate(name: str, what: str) -> str:
    return f"aisb containers spec {name} > spec.json  # {what}, then recreate (rm needs approval)"


# --- state -----------------------------------------------------------------------------------

_EXIT_CODES: dict[int, tuple[str, str]] = {
    125: ("docker-run-failure", "the Docker daemon failed to run the container"),
    126: ("not-executable", "the command exists but is not executable"),
    127: ("command-not-found", "the command/entrypoint was not found in the image"),
    139: ("segfault", "the process crashed with SIGSEGV"),
    134: ("aborted", "the process aborted (SIGABRT)"),
}


@rule
def state_rules(f: Facts) -> Iterable[Finding]:
    st, name = f.state, f.name
    code, status = st.get("ExitCode") or 0, st.get("Status", "")
    if st.get("Error"):
        yield Finding("critical", "start-error", f"daemon reported: {st['Error']}", (f"State.Error={st['Error']!r}",),
                      (f"aisb containers inspect {name} --fields HostConfig.PortBindings,HostConfig.Binds",))
    if st.get("OOMKilled"):
        limit, life = f.host.get("Memory") or 0, f.lifetime
        evidence = ["State.OOMKilled=true", f"HostConfig.Memory={limit or 'unlimited'}"]
        if life is not None:
            evidence.append(f"lived {life}s after start")
        runaway = life is not None and life < 10
        if runaway:
            evidence.append("died within seconds: a runaway allocation is more likely than an undersized limit")
        yield Finding("critical", "oom-killed", "killed by the kernel OOM killer", tuple(evidence),
                      (f"aisb containers inspect {name} --fields Config.Cmd,HostConfig.Memory,State.StartedAt,State.FinishedAt",
                       _recreate(name, "fix the allocation first" if runaway else "raise 'memory'")))
    restarts = f.inspect.get("RestartCount") or 0
    looping = bool(st.get("Restarting") or restarts >= 3)
    if looping:
        policy = (f.host.get("RestartPolicy") or {}).get("Name", "no")
        yield Finding("critical", "crash-loop", f"restarted {restarts}x (policy {policy}), last exit code {code}",
                      (f"RestartCount={restarts}", f"State.Status={status}"),
                      (f"aisb containers logs {name} --tail 100", f"aisb containers patterns {name}"))
    # A failed start leaves Status=created with the would-be exit code set, so classify that too.
    if status in ("exited", "dead") or st.get("Restarting") or (status == "created" and code):
        cmd = [*(f.config.get("Entrypoint") or []), *(f.config.get("Cmd") or [])]
        if code in _EXIT_CODES:
            c, why = _EXIT_CODES[code]
            yield Finding("critical", c, f"exit {code}: {why}", (f"command={cmd}",),
                          (f"aisb images inspect {f.config.get('Image')} --fields Config.Entrypoint,Config.Cmd,Architecture",))
        elif code == 137 and not st.get("OOMKilled"):
            yield Finding("warning", "sigkill", "exit 137: SIGKILL (not OOM); external kill or stop timeout exceeded",
                          ("State.OOMKilled=false",), (f"aisb system events --since 1h --filter container={name}",))
        elif code == 143:
            yield Finding("info", "sigterm", "exit 143: stopped by SIGTERM (normal for `stop`)")
        elif code and not looping and not st.get("OOMKilled"):
            yield Finding("warning", "app-error", f"exited with application error code {code}",
                          (f"State.FinishedAt={st.get('FinishedAt')}",), (f"aisb containers logs {name} --tail 100",))
    health = st.get("Health") or {}
    if health.get("Status") == "unhealthy":
        last = (health.get("Log") or [{}])[-1]
        yield Finding("critical", "unhealthy", f"healthcheck failing {health.get('FailingStreak', '?')}x in a row",
                      (f"last check exit={last.get('ExitCode')} output={str(last.get('Output', '')).strip()[:200]!r}",
                       f"test={f.config.get('Healthcheck', {}).get('Test')}"),
                      (f"aisb containers inspect {name} --fields State.Health",))
    if status == "created":
        yield Finding("warning", "never-started", "container was created but never started",
                      (), (f"aisb containers start {name} --dry-run",))
    if status == "paused":
        yield Finding("warning", "paused", "container is paused")


# --- logs ------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Signature:
    code: str
    summary: str
    rx: re.Pattern[str]
    hint: str
    extract: Callable[[re.Match[str], Facts], str | None] | None = None


def _missing_env(m: re.Match[str], f: Facts) -> str | None:
    var = m.group("var") or m.group("var2")
    return f"{var} is {'SET' if var in f.env_keys else 'NOT set'} in the container env"


def _remote(m: re.Match[str], f: Facts) -> str | None:
    return f"target: {m.group('target')}" if m.groupdict().get("target") else None


SIGNATURES: tuple[Signature, ...] = (
    Signature("missing-env", "required environment variable is missing",
              re.compile(r"\b(?P<var>[A-Z][A-Z0-9_]{2,})[\"'`]?\s+(?:(?:environment|env) var(?:iable)?\s+)?"
                         r"(?:is not set|not set|is missing|missing|is required|required|is undefined|undefined|is empty|"
                         r"must be (?:set|defined|provided))\b"
                         r"|(?i:missing|required|undefined|unset)[^\n]{0,30}?(?i:env(?:ironment)?[ _-]?var(?:iable)?s?)"
                         r"[\s:'\"`=]+(?P<var2>[A-Z][A-Z0-9_]{2,})\b"),
              "add the variable to the spec's env", _missing_env),
    Signature("dependency-unreachable", "cannot reach a dependency (DB, cache, API)",
              re.compile(r"(?i)(?:connection refused|ECONNREFUSED|could not connect to|failed to connect to|no route to host|"
                         r"timed? ?out connecting|connect: connection timed out)(?:[^\n]{0,40}?(?P<target>[\w.-]+:\d{2,5}))?"),
              "check the dependency is running and on a shared user-defined network", _remote),
    Signature("dns-failure", "hostname does not resolve",
              re.compile(r"(?i)(?:name or service not known|could not translate host name|getaddrinfo \w+|"
                         r"temporary failure in name resolution|no such host|ENOTFOUND)"),
              "containers resolve each other by name only on user-defined networks"),
    Signature("port-in-use", "address already in use",
              re.compile(r"(?i)(?:address already in use|EADDRINUSE|port is already allocated)"),
              "another process or container holds the port"),
    Signature("permission-denied", "permission denied (file ownership, user, or capability)",
              re.compile(r"(?i)(?:permission denied|EACCES|operation not permitted|read-only file system)"),
              "check the container user vs volume ownership, or a :ro mount"),
    Signature("wrong-arch", "binary built for a different CPU architecture",
              re.compile(r"(?i)exec format error"), "pull or build the image for the host platform"),
    Signature("missing-file", "file, module or binary not found",
              re.compile(r"(?i)(?:no such file or directory|ENOENT|cannot find module|ModuleNotFoundError|"
                         r"ClassNotFoundException|not found in \$PATH)"),
              "check the image contents, the working dir, and the mounts"),
    Signature("memory-exhausted", "the application ran out of memory",
              re.compile(r"(?i)(?:out of memory|OutOfMemoryError|cannot allocate memory|heap out of memory|MemoryError)"),
              "raise the memory limit or fix the leak"),
    Signature("disk-full", "no space left on device",
              re.compile(r"(?i)(?:no space left on device|disk quota exceeded|ENOSPC)"),
              "run `aisb system df` and reclaim space"),
    Signature("tls-error", "TLS or certificate failure",
              re.compile(r"(?i)(?:certificate verify failed|x509:|SSL routines|unknown certificate authority)"),
              "check CA certificates in the image and the endpoint's certificate"),
    Signature("auth-failure", "authentication rejected by a dependency",
              re.compile(r"(?i)(?:password authentication failed|access denied for user|authentication failed|"
                         r"invalid credentials|401 unauthorized)"),
              "check the credentials passed via env or secrets"),
    Signature("app-crash", "unhandled exception or panic",
              re.compile(r"(?:Traceback \(most recent call last\)|^panic: |Exception in thread|Unhandled (?:exception|rejection)|"
                         r"\bFATAL\b|segmentation fault)", re.M),
              "read the first error line and stack frames"),
)


GENERIC = frozenset({"app-crash"})  # only claims lines no specific signature explained


@rule
def log_rules(f: Facts) -> Iterable[Finding]:
    severity: Severity = "critical" if f.failing else "warning"
    explained: set[int] = set()
    for sig in SIGNATURES:
        hits = [(i, line, m) for i, line in enumerate(f.logs, 1)
                if not (sig.code in GENERIC and i in explained) and (m := sig.rx.search(line))]
        if not hits:
            continue
        explained.update(i for i, _, _ in hits)
        evidence = [f"log:{i}: {line.strip()[:200]}" for i, line, _ in hits[:3]]
        extra = sorted({x for _, _, m in hits if sig.extract and (x := sig.extract(m, f))})
        nxt = [_recreate(f.name, sig.hint)] if sig.code == "missing-env" else [f"# {sig.hint}"]
        if sig.code in ("dependency-unreachable", "dns-failure"):
            nxt.append(f"aisb containers inspect {f.name} --fields NetworkSettings.Networks")
            hosts = sorted({m["target"].rsplit(":", 1)[0] for _, _, m in hits if m.groupdict().get("target")})
            for h in (h for h in hosts[:2] if not re.fullmatch(r"[\d.]+|localhost", h)):
                if f.peers is not None and h not in f.peers:
                    extra.append(f"no container named {h!r} exists on this host")
                    nxt.append(f"# start {h!r} (or fix the hostname) on a network shared with {f.name}")
                else:
                    nxt.append(f"aisb containers inspect {h} --fields State.Status,NetworkSettings.Networks")
        # A missing var that is actually set is not the root cause; downgrade it.
        sev: Severity = "info" if sig.code == "missing-env" and extra and all(" is SET" in x for x in extra) else severity
        yield Finding(sev, sig.code, f"{sig.summary} ({len(hits)} matching lines)", (*evidence, *extra[:3]), tuple(nxt))
    leftovers = [line for i, line in enumerate(f.logs, 1) if i not in explained and level_of(line) == "error"]
    if leftovers:
        fp = fingerprint(list(f.logs), top=3, min_level="error")
        tail_note = " (new at the end of the log)" if set(fp["emerging"]) & {p["template"] for p in fp["top"]} else ""
        yield Finding(severity, "log-errors", f"{len(leftovers)} unexplained error lines{tail_note}",
                      tuple(f"{p['count']}x {p['template'][:160]}" for p in fp["top"]),
                      (f"aisb containers patterns {f.name} --level warn",
                       f"aisb containers logs {f.name} --grep 'ERROR|FATAL|Exception' --context 3 --tail 0"))


# --- image & config --------------------------------------------------------------------------

@rule
def image_rules(f: Facts) -> Iterable[Finding]:
    ref, running = f.config.get("Image", ""), f.inspect.get("Image", "")
    if f.image_id and running and f.image_id != running:
        yield Finding("warning", "stale-image", f"running an older build of {ref}; the tag now points to a newer image",
                      (f"container image={running[7:19]}", f"{ref} now={f.image_id[7:19]}"),
                      (_recreate(f.name, "same spec, new image"),))
    if ref and "@" not in ref and (":" not in ref.rsplit("/", 1)[-1] or ref.endswith(":latest")):
        yield Finding("info", "unpinned-image", f"image {ref!r} is not pinned to a version tag or digest")


@rule
def config_rules(f: Facts) -> Iterable[Finding]:
    if f.host.get("Privileged"):
        yield Finding("warning", "privileged", "container runs --privileged (full host device access)")
    binds = [b for b in f.host.get("Binds") or [] if b.split(":")[0] in ("/var/run/docker.sock", "/run/docker.sock")]
    if binds:
        yield Finding("warning", "docker-socket-mounted", "Docker socket mounted: the container controls the host daemon",
                      tuple(binds))
    policy = (f.host.get("RestartPolicy") or {}).get("Name") or "no"
    if f.state.get("Status") == "exited" and f.state.get("ExitCode") and policy == "no":
        yield Finding("info", "no-restart-policy", "a failed container won't be restarted (restart policy 'no')")


@rule
def resource_rules(f: Facts) -> Iterable[Finding]:
    if not f.stats:
        return
    mem = f.stats.get("memory") or {}
    if (mem.get("percent") or 0) >= 90:
        yield Finding("warning", "memory-pressure", f"memory at {mem['percent']}% of limit; an OOM kill is likely",
                      (f"used={mem.get('used')} limit={mem.get('limit')}",), (_recreate(f.name, "raise 'memory'"),))
    if (f.stats.get("cpu_percent") or 0) >= 90:
        yield Finding("info", "cpu-hot", f"CPU at {f.stats['cpu_percent']}%", (), (f"aisb containers top {f.name}",))


# --- entry points ----------------------------------------------------------------------------

SYMPTOMS = frozenset({"crash-loop", "app-error", "sigkill", "sigterm", "app-crash", "log-errors", "unhealthy"})


def verdict(findings: Iterable[Finding]) -> str:
    sev = {x.severity for x in findings}
    return "failing" if "critical" in sev else "degraded" if "warning" in sev else "healthy"


def diagnose(f: Facts) -> dict[str, Any]:
    by_code: dict[str, Finding] = {}
    for r in RULES:
        for x in r(f):
            by_code.setdefault(x.code, x)
    # Causes before symptoms within a severity: 'crash-loop' is what you see, 'missing-env' is why.
    findings = sorted(by_code.values(), key=lambda x: (_RANK[x.severity], x.code in SYMPTOMS))
    cause = next((x.code for x in findings if x.code not in SYMPTOMS and x.severity != "info"), None)
    st = f.state
    return {
        "container": f.name,
        "verdict": verdict(findings),
        "likely_cause": cause,
        "state": {"status": st.get("Status"), "exit_code": st.get("ExitCode"), "restarts": f.inspect.get("RestartCount"),
                  "health": (st.get("Health") or {}).get("Status"), "started_at": st.get("StartedAt")},
        "findings": [asdict(x) for x in findings],
    }
