"""Vulnerability matching against OSV (pure part): queries from an SBOM, CVSS v3 scoring, affected/fixed versions."""

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

SEVERITIES = ("unknown", "low", "medium", "high", "critical")

# OSV ecosystem per aisb package ecosystem; distro ecosystems need the OS version
_ECO = {"pypi": "PyPI", "npm": "npm", "gem": "RubyGems"}


def osv_ecosystem(ecosystem: str, os_release: Mapping[str, str]) -> str | None:
    if ecosystem in _ECO:
        return _ECO[ecosystem]
    distro, version = (os_release.get("id") or "").lower(), os_release.get("version") or ""
    if ecosystem == "apk" and distro == "alpine" and version:
        return "Alpine:v" + ".".join(version.split(".")[:2])
    if ecosystem == "dpkg" and distro == "debian" and version:
        return "Debian:" + version.split(".")[0]
    if ecosystem == "dpkg" and distro == "ubuntu" and version:
        return "Ubuntu:" + version + (":LTS" if version.endswith(".04") and int(version.split(".")[0]) % 2 == 0 else "")
    return None


def queries(components: Sequence[Mapping[str, str]], os_release: Mapping[str, str]
            ) -> tuple[list[dict[str, Any]], list[Mapping[str, str]], list[str]]:
    """(OSV queries, the components they belong to, ecosystems that could not be queried)."""
    out, owners, skipped = [], [], set()
    for c in components:
        eco = osv_ecosystem(c["ecosystem"], os_release)
        if eco is None:
            skipped.add(c["ecosystem"])
            continue
        name = c["name"].lower() if c["ecosystem"] == "pypi" else c["name"]
        out.append({"package": {"name": name, "ecosystem": eco}, "version": c["version"]})
        owners.append(c)
    return out, owners, sorted(skipped)


# --- CVSS v3.x base score (FIRST spec, section 7.1) -----------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3(vector: str) -> float | None:
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p) if vector.startswith("CVSS:3") else {}
    try:
        scope = m["S"]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["C"][m["I"]]) * (1 - _W["C"][m["A"]])
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[scope][m["PR"]] * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(impact + expl, 10) if scope == "U" else min(1.08 * (impact + expl), 10))


def level(score: float | None) -> str:
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "unknown"


def severity(vuln: Mapping[str, Any]) -> tuple[str, float | None]:
    """Best available severity: a CVSS v3 vector, else the database's own label."""
    for s in vuln.get("severity") or []:
        if s.get("type") in ("CVSS_V3", "CVSS_V3_1") or str(s.get("score", "")).startswith("CVSS:3"):
            if (score := cvss3(str(s.get("score")))) is not None:
                return level(score), score
    for src in (vuln.get("database_specific") or {}, *((a.get("database_specific") or {}) for a in vuln.get("affected") or [])):
        label = str(src.get("severity") or "").lower()
        label = {"moderate": "medium", "important": "high"}.get(label, label)
        if label in SEVERITIES:
            return label, None
    return "unknown", None


def fixed_versions(vuln: Mapping[str, Any], name: str, ecosystem: str) -> list[str]:
    out = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("name") not in (name, name.lower()) or not str(pkg.get("ecosystem", "")).startswith(ecosystem.split(":")[0]):
            continue
        for r in a.get("ranges") or []:
            out += [e["fixed"] for e in r.get("events") or [] if "fixed" in e]
    return sorted(set(out))


def report(owners: Sequence[Mapping[str, str]], ids_per_query: Sequence[Iterable[str]],
           details: Mapping[str, Mapping[str, Any]], queries_: Sequence[Mapping[str, Any]], *,
           min_severity: str = "low") -> dict[str, Any]:
    floor = SEVERITIES.index(min_severity)
    findings: list[dict[str, Any]] = []
    for comp, ids, q in zip(owners, ids_per_query, queries_):
        for vid in ids:
            v = details.get(vid) or {"id": vid}
            sev, score = severity(v)
            if SEVERITIES.index(sev) < floor and sev != "unknown":
                continue
            findings.append({"id": vid, "package": comp["name"], "version": comp["version"],
                             "ecosystem": comp["ecosystem"], "severity": sev, "score": score,
                             "fixed": fixed_versions(v, q["package"]["name"], q["package"]["ecosystem"]),
                             "summary": (v.get("summary") or v.get("details") or "")[:160],
                             "aliases": [a for a in v.get("aliases") or [] if a.startswith("CVE-")][:3]})
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (-rank[f["severity"]], -(f["score"] or 0), f["package"]))
    counts = {s: sum(f["severity"] == s for f in findings) for s in reversed(SEVERITIES)}
    return {"vulnerable_packages": len({(f["package"], f["version"]) for f in findings}), "counts": counts,
            "fixable": sum(bool(f["fixed"]) for f in findings), "findings": findings}


