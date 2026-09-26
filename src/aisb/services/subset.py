"""Referentially complete subsets: sample root tables, then pull in every row their foreign keys need."""

import math
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from .sql import SQL, Relations

CHUNK = 500


def _where(db: SQL, cols: Sequence[str], values: Sequence[tuple[Any, ...]]) -> str:
    """`(a, b) IN ((1, 2), ...)` (or `a IN (...)` for one column)."""
    if len(cols) == 1:
        return f"{db.ident(cols[0])} IN ({', '.join(db.literal(v[0]) for v in values)})"
    tuples = ", ".join("(" + ", ".join(db.literal(x) for x in v) + ")" for v in values)
    return f"({', '.join(db.ident(c) for c in cols)}) IN ({tuples})"


def _chunks(items: Sequence[Any], n: int = CHUNK) -> Iterator[Sequence[Any]]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


@dataclass(slots=True)
class Subset:
    """selection[table][columns] = set of value tuples selecting rows by those columns."""
    selection: dict[str, dict[tuple[str, ...], set[tuple[Any, ...]]]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, table: str, cols: tuple[str, ...], values: Iterable[tuple[Any, ...]]) -> set[tuple[Any, ...]]:
        bucket = self.selection.setdefault(table, {}).setdefault(cols, set())
        new = {v for v in values if all(x is not None for x in v)} - bucket
        bucket |= new
        return new


def plan(db: SQL, rel: Relations, *, ratio: float, roots: list[str] | None = None, max_rows: int = 1000,
         with_children: bool = False, database: str | None = None) -> Subset:
    sub = Subset()
    query = lambda sql: db.query(sql, database=database, seconds=300)  # noqa: E731
    frontier: list[tuple[str, tuple[str, ...], set[tuple[Any, ...]]]] = []
    for t in roots or rel.roots():
        total = int(query(f"select count(*) from {db.ident(t)}").rows[0][0])
        n = min(max_rows, math.ceil(total * ratio)) if total else 0
        key = rel.pk.get(t)
        if not n:
            continue
        if not key:
            sub.notes.append(f"{t}: no primary key; sampled as a whole-row root, its children can't reference it")
            key = tuple(query(f"select * from {db.ident(t)} limit 0").columns)
        r = query(f"select {', '.join(db.ident(c) for c in key)} from {db.ident(t)} order by {db.random_fn} limit {n}")
        frontier.append((t, key, sub.add(t, key, (tuple(row) for row in r.rows))))
    if with_children:  # downward, transitively: orders of sampled customers, then their items, ...
        i = 0
        while i < len(frontier):
            t, key, values = frontier[i]
            i += 1
            for fk in (f for f in rel.fks if f.parent == t and f.child != t and f.ref == key):
                ckey = rel.pk.get(fk.child)
                if not ckey:
                    continue
                for chunk in _chunks(sorted(values, key=str)):
                    r = query(f"select {', '.join(db.ident(c) for c in ckey)} from {db.ident(fk.child)} "
                              f"where {_where(db, fk.columns, chunk)}")
                    if new := sub.add(fk.child, ckey, (tuple(row) for row in r.rows)):
                        frontier.append((fk.child, ckey, new))
    while frontier:  # upward closure to a fixpoint: every referenced parent row is included
        t, cols, values = frontier.pop()
        for fk in (f for f in rel.fks if f.child == t):
            for chunk in _chunks(sorted(values, key=str)):
                r = query(f"select distinct {', '.join(db.ident(c) for c in fk.columns)} from {db.ident(t)} "
                          f"where {_where(db, cols, chunk)}")
                if new := sub.add(fk.parent, fk.ref, (tuple(row) for row in r.rows)):
                    frontier.append((fk.parent, fk.ref, new))
    return sub


def export(db: SQL, rel: Relations, sub: Subset, *, database: str | None = None) -> tuple[list[str], dict[str, int]]:
    """INSERT statements in parent-first order, framed so FK checks don't block the load."""
    out: list[str] = []
    counts: dict[str, int] = {}
    head, foot = {"postgres": ("SET session_replication_role = replica;", "SET session_replication_role = DEFAULT;"),
                  "mysql": ("SET FOREIGN_KEY_CHECKS=0;", "SET FOREIGN_KEY_CHECKS=1;"),
                  "sqlite": ("PRAGMA foreign_keys=OFF;", "PRAGMA foreign_keys=ON;")}[db.dialect]
    out.append(head)
    for t in rel.parents_first():
        if t not in sub.selection:
            continue
        seen: set[tuple[Any, ...]] = set()
        columns: list[str] = []
        rows: list[list[Any]] = []
        for cols, values in sub.selection[t].items():
            for chunk in _chunks(sorted(values, key=str)):
                r = db.query(f"select * from {db.ident(t)} where {_where(db, cols, chunk)}", database=database, seconds=300)
                columns = r.columns
                for row in r.rows:
                    if (key := tuple(row)) not in seen:
                        seen.add(key)
                        rows.append(row)
        counts[t] = len(rows)
        col_sql = ", ".join(db.ident(c) for c in columns)
        for chunk in _chunks(rows, 200):
            values_sql = ",\n  ".join("(" + ", ".join(db.literal(v) for v in row) + ")" for row in chunk)
            out.append(f"INSERT INTO {db.ident(t)} ({col_sql}) VALUES\n  {values_sql};")
    for table, column, seq in db.sequences(database):
        if table in counts:
            out.append(f"SELECT setval({db.literal(seq)}, (SELECT coalesce(max({db.ident(column)}), 1) "
                       f"FROM {db.ident(table)}));")
    out.append(foot)
    return out, counts
