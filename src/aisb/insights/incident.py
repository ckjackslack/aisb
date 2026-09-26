"""Causal incident analysis: signals + observed dependencies -> root cause, blast radius, chain, postmortem."""

import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal

Severity = Literal["critical", "warning", "info"]


@dataclass(frozen=True, slots=True)
class Signal:
    t: float
    container: str
    kind: str        # event | log | health | finding
    severity: Severity
    detail: str


def _closure(start: str, edges: Mapping[str, set[str]]) -> set[str]:
    seen, stack = set(), [start]
    while stack:
        for nxt in edges.get(stack.pop(), set()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def analyze(signals: Iterable[Signal], depends: Mapping[str, set[str]], *,
            likely_causes: Mapping[str, str | None] | None = None, evidence: str | None = None) -> dict[str, Any]:
    """Rank root causes: a failing container none of whose (transitive) dependencies failed earlier."""
    sigs = sorted(signals, key=lambda s: s.t)
    first_bad: dict[str, float] = {}
    for s in sigs:
        if s.severity == "critical":
            first_bad.setdefault(s.container, s.t)
    rdeps: dict[str, set[str]] = {}
    for a, bs in depends.items():
        for b in bs:
            rdeps.setdefault(b, set()).add(a)
    evidence = evidence or ("traffic" if depends else "temporal")
    roots = []
    for c, t in sorted(first_bad.items(), key=lambda kv: kv[1]):
        upstream = _closure(c, depends)
        if not any(d in first_bad and first_bad[d] < t for d in upstream):
            roots.append(c)
    if not depends and roots:
        roots = roots[:1]  # without topology only the earliest failure is a defensible candidate
    report: dict[str, Any] = {"failing": sorted(first_bad, key=first_bad.get), "evidence": evidence}
    if not roots:
        degraded = sorted({s.container for s in sigs if s.severity == "warning"})
        report.update(summary="no failure found in the window" + (f"; degraded: {', '.join(degraded)}" if degraded else ""),
                      root_cause=None, chain=[], blast_radius=[])
    else:
        root = roots[0]
        downstream = _closure(root, rdeps) if depends else set(first_bad) - {root}
        blast = sorted((c for c in downstream if c in first_bad and first_bad[c] >= first_bad[root]), key=first_bad.get)
        first = next(s for s in sigs if s.container == root and s.severity == "critical")
        cause = (likely_causes or {}).get(root)
        report.update(
            root_cause={"container": root, "first_signal": first.detail, "at": first.t, "likely_cause": cause},
            chain=[root, *blast], blast_radius=blast, other_roots=roots[1:],
            summary=(f"{root} failed first ({first.detail}"
                     + (f"; likely cause: {cause}" if cause else "") + ")"
                     + (f", then {', '.join(blast)} failed" + (" (they depend on it)" if depends else " (timing only)")
                        if blast else "")),
        )
    report["timeline"] = [asdict(s) | {"at": time.strftime("%H:%M:%S", time.gmtime(s.t))} for s in sigs[:60]]
    return report


def postmortem(report: Mapping[str, Any], *, window: str, next_steps: Iterable[str] = ()) -> str:
    rc = report.get("root_cause")
    lines = [f"# Incident report ({window})", "", "## Summary", "", report["summary"] + ".", ""]
    lines += ["## Impact", ""]
    lines += [f"- `{c}` failed" for c in report.get("failing", [])] or ["- no failing containers"]
    lines += ["", "## Timeline (UTC)", ""]
    lines += [f"- {s['at']} **{s['container']}** [{s['severity']}] {s['detail']}" for s in report["timeline"][:30]]
    if rc:
        lines += ["", "## Root cause", "", f"`{rc['container']}`: {rc['first_signal']}"
                  + (f" (doctor: `{rc['likely_cause']}`)" if rc.get("likely_cause") else ""), ""]
        if report["blast_radius"]:
            lines += ["## Blast radius", "", *[f"- `{c}`" for c in report["blast_radius"]], ""]
        what = {"traffic": "observed connections", "config": "configured endpoints (env URLs)",
                "traffic+config": "observed connections and configured endpoints", "temporal": "ordering only: verify"}
        lines += [f"Evidence for causality: {what.get(report['evidence'], report['evidence'])}", ""]
    lines += ["## Next steps", "", *[f"- `{n}`" for n in next_steps], "",
              "## Open questions", "", "- What changed right before the first signal (deploy, config, traffic)?", ""]
    return "\n".join(lines)
