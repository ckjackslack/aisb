"""Synthetic rows that satisfy the schema: types, lengths, precision, enums, simple CHECKs, uniqueness, and FKs."""

import datetime as dt
import random
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from .sql import SQL, Relations

FIRST = ("Ada", "Alan", "Grace", "Linus", "Barbara", "Ken", "Dennis", "Margaret", "Edsger", "Frances", "Donald", "Radia")
LAST = ("Lovelace", "Turing", "Hopper", "Torvalds", "Liskov", "Thompson", "Ritchie", "Hamilton", "Dijkstra", "Allen")
CITIES = ("Lisbon", "Oslo", "Kyoto", "Austin", "Nairobi", "Lima", "Tallinn", "Hanoi", "Perth", "Quebec")
COUNTRIES = (("PT", "Portugal"), ("NO", "Norway"), ("JP", "Japan"), ("US", "United States"), ("KE", "Kenya"),
             ("PE", "Peru"), ("EE", "Estonia"), ("VN", "Vietnam"), ("AU", "Australia"), ("CA", "Canada"))
WORDS = ("amber", "basalt", "cobalt", "delta", "ember", "fjord", "glacier", "harbor", "indigo", "juniper", "kelp",
         "lumen", "meadow", "nebula", "onyx", "prairie", "quartz", "reef", "sierra", "tundra")
NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


@dataclass(slots=True)
class Column:
    name: str
    type: str                # normalized: int smallint bigint numeric float text varchar char bool date timestamp time json uuid bytes other
    nullable: bool
    has_default: bool
    maxlen: int | None = None
    precision: int | None = None
    scale: int | None = None
    choices: tuple[str, ...] = ()
    minimum: float | None = None


@dataclass(slots=True)
class TableMeta:
    columns: dict[str, Column] = field(default_factory=dict)
    unique: list[tuple[str, ...]] = field(default_factory=list)


def normalize(data_type: str, udt: str = "") -> str:
    t = (data_type or "").lower()
    for key, norm in (("smallint", "smallint"), ("tinyint(1)", "bool"), ("bigint", "bigint"), ("int", "int"),
                      ("serial", "int"), ("numeric", "numeric"), ("decimal", "numeric"), ("double", "float"),
                      ("real", "float"), ("float", "float"), ("bool", "bool"), ("timestamp", "timestamp"),
                      ("datetime", "timestamp"), ("date", "date"), ("time", "time"), ("json", "json"), ("uuid", "uuid"),
                      ("bytea", "bytes"), ("blob", "bytes"), ("binary", "bytes"), ("character varying", "varchar"),
                      ("varchar", "varchar"), ("character", "char"), ("char", "char"), ("text", "text"), ("enum", "text")):
        if key in t:
            return norm
    return "text" if udt in ("citext", "name") else "other"


_ANY_ARRAY = re.compile(r"\(?\(?(\w+)\)?(?:::\w+)? = ANY \(\(?ARRAY\[(.*?)\]")
_IN_LIST = re.compile(r"`?(\w+)`?\s+in\s*\((.*?)\)", re.I)
_MIN = re.compile(r"\(?`?(\w+)`?\s*(>=|>)\s*\(?'?(-?\d+(?:\.\d+)?)")


def apply_check(meta: TableMeta, clause: str) -> None:
    """Understand the common CHECK shapes: `col IN (...)` / `col = ANY (ARRAY[...])` and `col >= n`."""
    for rx in (_ANY_ARRAY, _IN_LIST):
        if (m := rx.search(clause)) and m.group(1) in meta.columns:
            meta.columns[m.group(1)].choices = tuple(re.findall(r"'((?:[^']|'')*)'", m.group(2)))
            return
    if (m := _MIN.search(clause)) and m.group(1) in meta.columns:
        meta.columns[m.group(1)].minimum = float(m.group(3)) + (1 if m.group(2) == ">" else 0)


def introspect(db: SQL, database: str | None = None) -> dict[str, TableMeta]:
    metas: dict[str, TableMeta] = {}
    if db.dialect == "postgres":
        user = "not in ('pg_catalog', 'information_schema')"
        cols = db.query(
            "select c.table_schema || '.' || c.table_name, c.column_name, c.data_type, c.udt_name, c.is_nullable, "
            "c.column_default, c.is_identity, c.character_maximum_length, c.numeric_precision, c.numeric_scale "
            "from information_schema.columns c join information_schema.tables t using (table_schema, table_name) "
            f"where t.table_type = 'BASE TABLE' and c.table_schema {user} order by 1, c.ordinal_position",
            database=database).rows
        enums: dict[str, list[str]] = {}
        for typ, label in db.query("select t.typname, e.enumlabel from pg_type t join pg_enum e on e.enumtypid = t.oid "
                                   "order by t.typname, e.enumsortorder", database=database).rows:
            enums.setdefault(typ, []).append(label)
        for t, name, dtype, udt, nullable, default, identity, maxlen, prec, scale in cols:
            m = metas.setdefault(t, TableMeta())
            m.columns[name] = Column(name, "text" if udt in enums else normalize(dtype, udt), nullable == "YES",
                                     default is not None or identity == "YES", _int(maxlen), _int(prec), _int(scale),
                                     tuple(enums.get(udt, ())))
        cons = db.query(
            "select n.nspname || '.' || c.relname, con.contype, pg_get_constraintdef(con.oid), "
            "array_to_string(array(select a.attname from unnest(con.conkey) k join pg_attribute a "
            "on a.attrelid = c.oid and a.attnum = k), ',') from pg_constraint con join pg_class c on c.oid = con.conrelid "
            f"join pg_namespace n on n.oid = c.relnamespace where con.contype in ('u', 'p', 'c') and n.nspname {user}",
            database=database).rows
        for t, kind, definition, cols_csv in cons:
            if t in metas:
                if kind in ("u", "p"):
                    metas[t].unique.append(tuple(cols_csv.split(",")))
                else:
                    apply_check(metas[t], definition)
    else:
        cols = db.query(
            "select c.table_name, c.column_name, c.data_type, c.column_type, c.is_nullable, c.column_default, c.extra, "
            "c.character_maximum_length, c.numeric_precision, c.numeric_scale from information_schema.columns c "
            "join information_schema.tables t on t.table_schema = c.table_schema and t.table_name = c.table_name "
            "where c.table_schema = database() and t.table_type = 'BASE TABLE' order by 1, c.ordinal_position",
            database=database).rows
        for t, name, dtype, ctype, nullable, default, extra, maxlen, prec, scale in cols:
            m = metas.setdefault(t, TableMeta())
            choices = tuple(re.findall(r"'((?:[^']|'')*)'", ctype)) if ctype.startswith(("enum(", "set(")) else ()
            m.columns[name] = Column(name, normalize(ctype if ctype.startswith("tinyint(1)") else dtype),
                                     # MariaDB reports "no default" on nullable columns as the string 'NULL'
                                     nullable == "YES", default not in (None, "NULL") or "auto_increment" in (extra or ""),
                                     _int(maxlen), _int(prec), _int(scale), choices)
        for t, _, cols_csv in db.query(
                "select table_name, index_name, group_concat(column_name order by seq_in_index) from "
                "information_schema.statistics where table_schema = database() and non_unique = 0 "
                "group by table_name, index_name", database=database).rows:
            if t in metas:
                metas[t].unique.append(tuple(cols_csv.split(",")))
        try:
            for t, clause in db.query(
                    "select tc.table_name, cc.check_clause from information_schema.table_constraints tc join "
                    "information_schema.check_constraints cc on cc.constraint_schema = tc.constraint_schema and "
                    "cc.constraint_name = tc.constraint_name where tc.table_schema = database()", database=database).rows:
                if t in metas:
                    apply_check(metas[t], clause)
        except Exception:  # noqa: BLE001 - older servers have no check_constraints view
            pass
    return metas


def _int(v: Any) -> int | None:
    return int(v) if v not in (None, "") else None


class Generator:
    def __init__(self, seed: int | None) -> None:
        self.rng = random.Random(seed)

    def value(self, col: Column, i: int, unique: bool) -> Any:
        r, name, t = self.rng, col.name.lower(), col.type
        if col.choices:
            return col.choices[i % len(col.choices)] if unique else r.choice(col.choices)
        first, last = r.choice(FIRST), r.choice(LAST)
        v: Any = None
        if t in ("text", "varchar", "char", "other"):
            if "email" in name:
                v = f"{first}.{last}.{i}@example.com".lower()
            elif name in ("first_name", "firstname", "given_name"):
                v = first
            elif name in ("last_name", "lastname", "surname", "family_name"):
                v = last
            elif name in ("name", "full_name", "fullname", "display_name"):
                v = f"{first} {last}"
            elif "user" in name and "name" in name or name == "login":
                v = f"{first}{i}".lower()
            elif "phone" in name:
                v = f"+1-555-{i % 10000:04d}"
            elif "city" in name:
                v = r.choice(CITIES)
            elif "country" in name:
                code, full = r.choice(COUNTRIES)
                v = code if (col.maxlen or 99) <= 3 else full
            elif name.endswith("url") or "website" in name:
                v = f"https://{r.choice(WORDS)}.example.com/{i}"
            elif name in ("sku", "code") or name.endswith(("_code", "_sku", "_ref")):
                v = f"{name[:3].upper()}-{i:06d}"
            elif "slug" in name:
                v = f"{r.choice(WORDS)}-{r.choice(WORDS)}-{i}"
            elif "status" in name or "state" in name:
                v = r.choice(("active", "pending", "done"))
            elif name in ("description", "notes", "note", "bio", "comment", "body", "content", "message"):
                v = " ".join(r.choice(WORDS) for _ in range(r.randint(6, 16))).capitalize() + "."
            elif "title" in name or "subject" in name:
                v = " ".join(r.choice(WORDS) for _ in range(3)).title()
            elif "zip" in name or "postal" in name:
                v = f"{r.randint(10000, 99999)}"
            elif "uuid" in name or name.endswith("_guid"):
                v = str(uuid.UUID(int=r.getrandbits(128), version=4))
            else:
                v = f"{r.choice(WORDS)}-{i}" if unique else r.choice(WORDS)
            if col.type == "char" and col.maxlen:
                v = (v * col.maxlen)[:col.maxlen] if len(v) < col.maxlen else v[:col.maxlen]
            elif col.maxlen:
                v = v[:col.maxlen]
            return v
        if t in ("int", "smallint", "bigint"):
            lo = int(col.minimum) if col.minimum is not None else (1 if any(k in name for k in ("qty", "quantity", "count", "age")) else 0)
            hi = 120 if "age" in name else 10 if ("qty" in name or "quantity" in name) else \
                32767 if t == "smallint" else 100000
            return lo + i if unique else r.randint(lo, max(lo, hi))
        if t == "numeric":
            scale = col.scale if col.scale is not None else 2
            top = 10 ** ((col.precision or 10) - scale) - 1
            lo = col.minimum if col.minimum is not None else 0
            hi = min(top, 999 if any(k in name for k in ("price", "amount", "total", "cost", "fee")) else top)
            num = Decimal(str(round(r.uniform(float(lo), float(max(lo, hi))), scale)))
            return str(num.quantize(Decimal(1).scaleb(-scale)))
        if t == "float":
            return round(r.uniform(-90, 90), 6) if "lat" in name else round(r.uniform(-180, 180), 6) if "lng" in name \
                or "lon" in name else round(r.uniform(0, 1000), 3)
        if t == "bool":
            return r.random() < 0.5
        if t in ("date", "timestamp"):
            when = NOW - dt.timedelta(days=r.randint(0, 365), seconds=r.randint(0, 86399))
            return when.date().isoformat() if t == "date" else when.isoformat()
        if t == "time":
            return f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:00"
        if t == "json":
            return "{}"
        if t == "uuid":
            return str(uuid.UUID(int=r.getrandbits(128), version=4))
        return None


def seed(db: SQL, rel: Relations, metas: dict[str, TableMeta], *, rows: int, tables: list[str] | None,
         seed_value: int | None, database: str | None = None, batch: int = 500) -> dict[str, Any]:
    gen = Generator(seed_value)
    wanted = set(tables or metas)
    needed = set(wanted)
    for t in list(wanted):  # empty parents of required FKs must be seeded first
        for fk in (f for f in rel.fks if f.child == t and f.parent != t):
            nullable = all(metas[t].columns[c].nullable for c in fk.columns if c in metas[t].columns)
            count = int(db.query(f"select count(*) from {db.ident(fk.parent)}", database=database).rows[0][0] or 0)
            if not nullable and count == 0:
                needed.add(fk.parent)
    report: dict[str, Any] = {"tables": {}, "sample": {}}
    for t in [x for x in rel.parents_first() if x in needed and x in metas]:
        meta = metas[t]
        n = rows if t in wanted else min(rows, 50)
        fk_cols = {c: fk for fk in rel.fks if fk.child == t for c in fk.columns}
        parents: dict[str, list[tuple[Any, ...]]] = {}
        for fk in {id(f): f for f in fk_cols.values()}.values():
            r = db.query(f"select {', '.join(db.ident(c) for c in fk.ref)} from {db.ident(fk.parent)} "
                         f"order by {db.random_fn} limit 5000", database=database)
            parents[fk.name] = [tuple(row) for row in r.rows]
        cols = [c for c in meta.columns.values() if (not c.has_default or c.name in fk_cols) and c.type != "bytes"]
        uniques = [u for u in meta.unique if all(c in {x.name for x in cols} for c in u)]
        seen: dict[tuple[str, ...], set[tuple[Any, ...]]] = {u: set() for u in uniques}
        base = int(db.query(f"select count(*) from {db.ident(t)}", database=database).rows[0][0] or 0)
        out_rows: list[list[Any]] = []
        for i in range(n):
            for attempt in range(20):
                idx = base + i + 1 + attempt * rows
                row: dict[str, Any] = {}
                for fk in {id(f): f for f in fk_cols.values()}.values():
                    pool = parents.get(fk.name) or []
                    pick = gen.rng.choice(pool) if pool else None  # empty (e.g. self-reference): NULL
                    for pos, c in enumerate(fk.columns):
                        row[c] = pick[pos] if pick else None
                for c in cols:
                    if c.name not in row:
                        in_unique = any(c.name in u for u in uniques)
                        row[c.name] = gen.value(c, idx, in_unique)
                keys = {u: tuple(row.get(c) for c in u) for u in uniques}
                if all(k not in seen[u] for u, k in keys.items()):
                    for u, k in keys.items():
                        seen[u].add(k)
                    out_rows.append([row[c.name] for c in cols])
                    break
        names = [c.name for c in cols]
        for start in range(0, len(out_rows), batch):
            chunk = out_rows[start:start + batch]
            values = ",\n".join("(" + ", ".join(db.literal(v) for v in r) + ")" for r in chunk)
            db.query(f"INSERT INTO {db.ident(t)} ({', '.join(db.ident(c) for c in names)}) VALUES {values}",
                     readonly=False, database=database, seconds=300)
        report["tables"][t] = len(out_rows)
        if out_rows:
            report["sample"][t] = dict(zip(names, out_rows[0]))
    return report
