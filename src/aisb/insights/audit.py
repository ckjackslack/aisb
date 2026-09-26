"""Static analyses: security/config audit, secret detection, and image-bloat hints. Pure functions over API data."""

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .triage import Finding

# --- secret detection ------------------------------------------------------------------------

SECRET_KEY = re.compile(r"PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH", re.I)
TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("url-with-password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s/@]{3,}@[^\s/]+", re.I)),
)
_PLACEHOLDER = re.compile(r"^(|changeme|change_me|password|secret|example|xxx+|\*+|<.*>|\$\{.*\}|\$[A-Z_]+|dev|test)$", re.I)


def mask(value: str) -> str:
    return value[:4] + "***" if len(value) > 8 else "***"


def scan_text(text: str, where: str) -> list[dict[str, str]]:
    """Known credential formats inside arbitrary text."""
    return [{"kind": kind, "where": where, "sample": mask(m.group(0))}
            for kind, rx in TOKEN_PATTERNS for m in rx.finditer(text)]


def scan_env(env: Iterable[str], where: str = "env") -> list[dict[str, str]]:
    hits = []
    for entry in env:
        key, _, value = entry.partition("=")
        if key.endswith("_FILE"):
            continue
        if SECRET_KEY.search(key) and not _PLACEHOLDER.match(value):
            hits.append({"kind": "secret-in-env", "where": f"{where}:{key}", "sample": mask(value),
                         "fix": f"pass it as a file instead: {key}_FILE=/run/secrets/... (Docker/Compose secrets)"})
        hits += [h | {"where": f"{where}:{key}"} for h in scan_text(value, where)]
    return hits


def scan_history(history: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Secrets baked into image layers: ENV/ARG values and build args recorded in `created_by`."""
    hits = []
    for i, layer in enumerate(history):
        cmd = str(layer.get("created_by") or layer.get("CreatedBy") or "")
        where = f"layer {i}"
        m = re.match(r"\|\d+ (.*?) (?:/bin/sh -c|RUN )", cmd)  # "|2 TOKEN=abc X=1 /bin/sh -c ..." = build args
        env_like = re.findall(r"(?:ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)[= ]([^\s]+)", cmd)
        pairs = [f"{k}={v}" for k, v in env_like] + (re.findall(r"[A-Za-z_][A-Za-z0-9_]*=\S+", m.group(1)) if m else [])
        for h in scan_env(pairs, where):
            hits.append(h | {"kind": "secret-in-image-history", "fix": "use BuildKit secrets "
                             "(RUN --mount=type=secret) instead of ARG/ENV; the value is readable by anyone with the image"})
        hits += scan_text(cmd, where)
    return hits


def dedupe(hits: list[dict[str, str]]) -> list[dict[str, str]]:
    seen, out = set(), []
    for h in hits:
        key = (h["where"], h["sample"])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


# --- configuration audit ---------------------------------------------------------------------

DB_PORTS = {5432: "postgres", 3306: "mysql", 6379: "redis", 27017: "mongo", 9200: "elasticsearch",
            5672: "rabbitmq", 9092: "kafka", 11211: "memcached"}
SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/home", "/var/run", "/run", "/proc", "/sys", "/boot", "/var/lib/docker")

AuditRule = Callable[[Mapping[str, Any], Mapping[str, Any]], Iterable[Finding]]
AUDIT_RULES: list[AuditRule] = []


def audit_rule(fn: AuditRule) -> AuditRule:
    AUDIT_RULES.append(fn)
    return fn


@audit_rule
def privileges(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    host = c.get("HostConfig") or {}
    if host.get("Privileged"):
        yield Finding("critical", "privileged", "runs --privileged: full access to host devices and kernel",
                      (), ("drop --privileged; add only the capabilities it needs (--cap-add)",))
    if caps := [cp for cp in host.get("CapAdd") or [] if cp in ("SYS_ADMIN", "ALL", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE")]:
        yield Finding("warning", "dangerous-caps", f"added capabilities: {', '.join(caps)}")
    for mode, what in (("NetworkMode", "network"), ("PidMode", "PID"), ("IpcMode", "IPC")):
        if host.get(mode) == "host":
            yield Finding("warning", f"host-{what.lower()}", f"shares the host {what} namespace")
    if "no-new-privileges" not in " ".join(host.get("SecurityOpt") or []) and not host.get("Privileged"):
        yield Finding("info", "no-new-privileges-unset", "no-new-privileges is not set",
                      (), ("--security-opt no-new-privileges:true",))


@audit_rule
def mounts(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    for m in c.get("Mounts") or []:
        src, rw = m.get("Source") or "", m.get("RW", True)
        if src in ("/var/run/docker.sock", "/run/docker.sock"):
            yield Finding("critical", "docker-socket", "Docker socket mounted: equivalent to root on the host",
                          (f"{src} -> {m.get('Destination')}",), ("use a socket proxy with a read-only allowlist",))
        elif m.get("Type") == "bind" and (src.rstrip("/") or "/") in SENSITIVE_MOUNTS:
            yield Finding("critical" if rw else "warning", "sensitive-mount",
                          f"host path {src or '/'} mounted {'read-write' if rw else 'read-only'}",
                          (f"{src} -> {m.get('Destination')}",))


@audit_rule
def identity(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    user = (c.get("Config") or {}).get("User") or (image.get("Config") or {}).get("User") or ""
    if user in ("", "0", "root", "0:0"):
        yield Finding("warning", "runs-as-root", "the process runs as root inside the container",
                      (), ("set USER in the Dockerfile, or --user 1000:1000",))


@audit_rule
def image_pinning(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    ref = (c.get("Config") or {}).get("Image") or ""
    last = ref.rsplit("/", 1)[-1]
    if not ref.startswith("sha256:") and "@" not in ref and (":" not in last or last.endswith(":latest")):
        yield Finding("warning", "unpinned-image", f"image {ref!r} floats (no version tag or digest)",
                      (), ("pin a version tag, ideally with @sha256:<digest>",))


@audit_rule
def resources(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    host = c.get("HostConfig") or {}
    if not host.get("Memory"):
        yield Finding("warning", "no-memory-limit", "no memory limit: a leak can starve the whole host",
                      (), ("--memory 512m (and consider --memory-swap equal to it)",))
    if not host.get("NanoCpus") and not host.get("CpuQuota") and not host.get("CpuShares"):
        yield Finding("info", "no-cpu-limit", "no CPU limit")
    if not host.get("PidsLimit") or host.get("PidsLimit", 0) <= 0:
        yield Finding("info", "no-pids-limit", "no PIDs limit (fork bombs can exhaust the host)", (), ("--pids-limit 512",))


@audit_rule
def exposure(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    for key, binds in ((c.get("NetworkSettings") or {}).get("Ports") or {}).items():
        port = int(key.split("/")[0])
        for b in binds or []:
            if b.get("HostIp") in ("0.0.0.0", "::", "") and port in DB_PORTS:
                yield Finding("critical", "datastore-exposed",
                              f"{DB_PORTS[port]} port {port} published on all interfaces (host port {b.get('HostPort')})",
                              (), (f"publish on loopback only: 127.0.0.1:{b.get('HostPort')}:{port}",))


@audit_rule
def resilience(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    cfg, host = c.get("Config") or {}, c.get("HostConfig") or {}
    health = cfg.get("Healthcheck") or (image.get("Config") or {}).get("Healthcheck") or {}
    if not health.get("Test") or health.get("Test") == ["NONE"]:
        yield Finding("info", "no-healthcheck", "no healthcheck: orchestration can't tell 'up' from 'working'",
                      (), ("--health-cmd '<cheap check>' (aisb svc ready shows what a real probe looks like)",))
    if (host.get("RestartPolicy") or {}).get("Name") in (None, "", "no") and (c.get("State") or {}).get("Running"):
        yield Finding("info", "no-restart-policy", "a long-running service without a restart policy",
                      (), ("--restart unless-stopped",))


@audit_rule
def secrets(c: Mapping[str, Any], image: Mapping[str, Any]) -> Iterable[Finding]:
    seen: set[str] = set()
    for h in scan_env((c.get("Config") or {}).get("Env") or []):
        if h["where"] in seen:  # one finding per variable, even if several detectors matched it
            continue
        seen.add(h["where"])
        yield Finding("warning", h["kind"], f"{h['where']} holds a secret in plain env ({h['sample']})",
                      (), (h.get("fix", "rotate it and move it out of env"),))


def audit(container: Mapping[str, Any], image: Mapping[str, Any] | None = None) -> dict[str, Any]:
    found: list[Finding] = [x for r in AUDIT_RULES for x in r(container, image or {})]
    rank = {"critical": 0, "warning": 1, "info": 2}
    found.sort(key=lambda x: rank[x.severity])
    score = max(0, 100 - sum({"critical": 30, "warning": 10, "info": 2}[x.severity] for x in found))
    return {"container": (container.get("Name") or "").lstrip("/"), "score": score,
            "findings": [asdict(x) for x in found]}


# --- image slimming --------------------------------------------------------------------------

_SLIM_RULES: tuple[tuple[str, re.Pattern[str], re.Pattern[str] | None, str], ...] = (
    ("apt-lists-kept", re.compile(r"apt-get install"), re.compile(r"rm -rf /var/lib/apt/lists"),
     "end the same RUN with `&& rm -rf /var/lib/apt/lists/*` (and use --no-install-recommends)"),
    ("apt-recommends", re.compile(r"apt-get install(?!.*--no-install-recommends)"), None,
     "add --no-install-recommends"),
    ("apk-cache", re.compile(r"apk add(?!.*--no-cache)"), None, "use `apk add --no-cache`"),
    ("pip-cache", re.compile(r"pip3? install(?!.*--no-cache-dir)"), None,
     "use `pip install --no-cache-dir` (or a cache mount)"),
    ("npm-dev-deps", re.compile(r"npm (install|i)\b(?!.*(--omit=dev|--production|ci))"), None,
     "use `npm ci --omit=dev` in the final stage"),
    ("build-tools-in-final", re.compile(r"(build-essential|gcc|g\+\+|make|cmake|golang|rustc|cargo)\b"), None,
     "compile in a builder stage and COPY --from=builder only the artifacts"),
    ("copy-everything", re.compile(r"COPY (?:--\S+ )*(?:\. |dir:\S+ in /\S*$)"), None,
     "add a .dockerignore (.git, node_modules, build output) or COPY only what the runtime needs"),
)


def slim(history: list[Mapping[str, Any]], size: int) -> dict[str, Any]:
    """Rank layers by size and flag common Dockerfile bloat patterns with concrete fixes."""
    layers = [{"layer": i, "size": int(h.get("size") or h.get("Size") or 0),
               "created_by": re.sub(r"\s+", " ", str(h.get("created_by") or h.get("CreatedBy") or ""))[:200]}
              for i, h in enumerate(reversed(history))]
    hints = []
    for layer in layers:
        cmd = layer["created_by"]
        for code, bad, fixed, fix in _SLIM_RULES:
            if bad.search(cmd) and not (fixed and fixed.search(cmd)):
                hints.append({"code": code, "layer": layer["layer"], "layer_size": layer["size"], "fix": fix})
    big = [lay for lay in layers if lay["size"] >= 50 << 20]
    nonzero = [lay for lay in layers if lay["size"] > 0]
    if len(nonzero) > 25:
        hints.append({"code": "many-layers", "layer": None, "layer_size": None,
                      "fix": f"{len(nonzero)} non-empty layers: merge related RUN steps"})
    return {"size": size, "layers": len(layers), "largest": sorted(layers, key=lambda x: -x["size"])[:5],
            "over_50mb": len(big), "hints": hints,
            "estimated_waste_hint": "layers flagged above are where the bytes are; fix the biggest first" if hints else None}
