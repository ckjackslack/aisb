"""Index candidates from a Postgres EXPLAIN (ANALYZE, FORMAT JSON) plan; the caller measures each one."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

_COND = re.compile(r"\(?\(?(?:(\w+)\.)?\"?(\w+)\"?\)?(?:::[\w ]+)?\s*(=|<>|<=|>=|<|>|~~\*?|IS NOT|IS)\s")
_JOIN = re.compile(r"\(?(\w+)\.\"?(\w+)\"?\s*=\s*(\w+)\.\"?(\w+)\"?\)?")


@dataclass(frozen=True, slots=True)
class Candidate:
    relation: str
    columns: tuple[str, ...]
    reason: str

    @property
    def ddl(self) -> str:
        cols = ", ".join(f'"{c}"' for c in self.columns)
        return f"CREATE INDEX CONCURRENTLY ON {self.relation} ({cols});"


def nodes(plan: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield plan
    for child in plan.get("Plans") or []:
        yield from nodes(child)


def _rel(node: dict[str, Any]) -> str | None:
    if "Relation Name" not in node:
        return None
    return f"{node.get('Schema', 'public')}.{node['Relation Name']}"


def candidates(plan: dict[str, Any], *, min_removed: int = 100) -> list[Candidate]:
    found: dict[tuple[str, tuple[str, ...]], Candidate] = {}
    scans = [n for n in nodes(plan) if n.get("Node Type") == "Seq Scan"]
    by_alias = {n.get("Alias"): n for n in scans}

    def add(rel: str, cols: tuple[str, ...], reason: str) -> None:
        if cols and (rel, cols) not in found:
            found[(rel, cols)] = Candidate(rel, cols, reason)

    for n in scans:
        rel, filt = _rel(n), n.get("Filter")
        removed = n.get("Rows Removed by Filter", 0)
        if rel and filt and removed >= min_removed:
            conds = [(m.group(2), m.group(3)) for m in _COND.finditer(filt)]
            eq = [c for c, o in conds if o == "="]
            rng = [c for c, o in conds if o != "=" and c not in eq]
            cols = tuple(dict.fromkeys(eq + rng[:1]))
            add(rel, cols, f"seq scan filtering out {removed} rows on {filt}")
    for n in nodes(plan):
        kind = n.get("Node Type", "")
        cond = n.get("Hash Cond") or n.get("Merge Cond") or n.get("Join Filter")
        if kind in ("Hash Join", "Merge Join", "Nested Loop") and cond:
            for m in _JOIN.finditer(cond):
                for alias, col in ((m.group(1), m.group(2)), (m.group(3), m.group(4))):
                    scan = by_alias.get(alias)
                    if scan and _rel(scan) and scan.get("Plan Rows", 0) + scan.get("Actual Rows", 0) > 100:
                        add(_rel(scan), (col,), f"{kind} probes a seq scan of {scan['Relation Name']} on {col}")
        if kind == "Sort" and n.get("Sort Key"):
            child = (n.get("Plans") or [{}])[0]
            if child.get("Node Type") == "Seq Scan" and _rel(child):
                key = n["Sort Key"][0].split(".")[-1].split(" ")[0].strip('"()')
                add(_rel(child), (key,), f"sort over a seq scan by {n['Sort Key'][0]}")
    return list(found.values())


def hot_nodes(plan: dict[str, Any], top: int = 5) -> list[dict[str, Any]]:
    """Most expensive nodes by exclusive time (actual total time minus children), for the report."""
    out = []
    for n in nodes(plan):
        total = n.get("Actual Total Time", 0) * n.get("Actual Loops", 1)
        kids = sum(c.get("Actual Total Time", 0) * c.get("Actual Loops", 1) for c in n.get("Plans") or [])
        out.append({"node": n.get("Node Type"), "relation": _rel(n), "self_ms": round(max(total - kids, 0), 2),
                    "rows": n.get("Actual Rows"), "filter": n.get("Filter") or n.get("Hash Cond") or n.get("Index Cond")})
    return sorted(out, key=lambda x: -x["self_ms"])[:top]
