"""Remediation rules: doctor findings -> safe actions (executed as ordinary aisb ops) or human suggestions.

Only actions that can't make things worse are automatic; everything that needs a decision (a missing variable,
a bad image, a crash loop) becomes a suggestion with the reason. Pure: input is a doctor report + inspect data.
"""

import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

MIB = 1 << 20
RULES = ("start-exited", "restart-unhealthy", "raise-memory")

# causes where (re)starting the container can't help: a person has to change something first
NEEDS_HUMAN = {
    "missing-env": "set the missing variable (containers spec -> edit -> recreate)",
    "missing-file": "a file the app needs is missing: check mounts and the image contents",
    "disk-full": "free disk space first (fleet status shows disk %; system df / prune)",
    "tls-error": "fix the certificate or CA trust (net tls shows the chain)",
    "auth-failure": "fix the credentials the app uses (secrets / env)",
    "dependency-unreachable": "fix or start the dependency first (net probe SRC DST), then restart",
    "dns-failure": "the name doesn't resolve: check networks and aliases (net map)",
    "start-error": "read the start error: a mount, port or entrypoint is wrong",
    "port-in-use": "free the host port or publish another one",
    "permission-denied": "fix file ownership/permissions on the mount or the image user",
    "wrong-arch": "use an image built for this host's architecture",
    "crash-loop": "the restart policy already retries; restarting again won't help: fix the cause",
    "never-started": "created but never started: start it deliberately if it's meant to run",
    "stale-image": "recreate from the freshly pulled image (containers spec -> run --spec)",
    "paused": "unpause deliberately (`aisb chaos` pauses are reverted automatically)",
}


@dataclass(slots=True)
class Action:
    container: str
    rule: str
    op: str
    kwargs: dict[str, Any]
    why: str

    def row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Plan:
    actions: list[Action] = field(default_factory=list)
    suggestions: list[dict[str, str]] = field(default_factory=list)


def _codes(report: Mapping[str, Any]) -> list[str]:
    """Finding codes in the doctor's order (most important first), without duplicates."""
    return list(dict.fromkeys(f["code"] for f in report.get("findings") or []))


def plan(report: Mapping[str, Any], inspect: Mapping[str, Any], *, rules: tuple[str, ...] = RULES,
         growth: float = 1.25) -> Plan:
    """Actions for one container from its `containers doctor` report and inspect data."""
    name = report["container"]
    codes = _codes(report)
    st = report.get("state") or {}
    host = inspect.get("HostConfig") or {}
    out = Plan()
    blocked = [c for c in codes if c in NEEDS_HUMAN]
    if "oom-killed" in codes or "memory-pressure" in codes:
        limit = host.get("Memory") or 0
        if not limit:
            out.suggestions.append({"container": name, "rule": "raise-memory",
                                    "suggestion": "OOM without a container limit: the host itself is short on memory; "
                                                  "add RAM or set limits on other containers (system rightsize)"})
        elif "raise-memory" in rules:
            new = int(math.ceil(limit * growth / (16 * MIB)) * 16 * MIB)
            out.actions.append(Action(name, "raise-memory", "containers.limit", {"ref": name, "memory": f"{new // MIB}m"},
                                      f"{'OOM-killed' if 'oom-killed' in codes else 'memory at its limit'}: "
                                      f"raise {limit // MIB}m -> {new // MIB}m (live update)"))
            if "oom-killed" in codes and st.get("status") in ("exited", "dead") and "start-exited" in rules:
                out.actions.append(Action(name, "start-exited", "containers.start", {"ref": name},
                                          "start it again with the higher limit"))
                blocked = [c for c in blocked if c != "crash-loop"]
                return out
    for code in blocked:
        out.suggestions.append({"container": name, "rule": code, "suggestion": NEEDS_HUMAN[code]})
    if blocked:
        return out
    if "unhealthy" in codes and st.get("status") == "running" and "restart-unhealthy" in rules:
        out.actions.append(Action(name, "restart-unhealthy", "containers.restart", {"ref": name},
                                  "healthcheck failing and no cause that needs a human was found"))
    elif st.get("status") in ("exited", "dead") and "start-exited" in rules and "oom-killed" not in codes:
        out.actions.append(Action(name, "start-exited", "containers.start", {"ref": name},
                                  f"exited (code {st.get('exit_code')}) and nothing blocks a restart"))
    return out
