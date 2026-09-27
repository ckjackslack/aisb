"""Seeding and subsetting against a real engine: aisb's generated SQL runs on sqlite behind a fake psql.

Constraint satisfaction is checked by the engine itself (CHECK / UNIQUE / NOT NULL / FOREIGN KEY with
foreign_keys=ON), not by re-implementing the rules in the test.
"""

import datetime as dt
import gzip
import itertools
import sqlite3
import uuid
from decimal import Decimal
from typing import Any

import pytest

from aisb import Docker
from aisb.cli import EXIT_OK, EXIT_USAGE
from aisb.services import seed, subset
from aisb.services.sql import MySQL, Postgres, Relations
from test_services_more import MARK, PG, Engine, cli_runner, connect, info, make, psql_on, queue, xml

from conftest import Reply, tar_of


@pytest.fixture
def cli(host, capsys):
    return cli_runner(host, capsys)


SCHEMA = """
create table customers (id integer primary key, email varchar(40) not null unique, name text not null,
  age int check (age >= 18), status text not null check (status in ('active', 'it''s', 'a)b')),
  country char(2) not null, parent_id int references customers(id));
create table orders (id integer primary key, customer_id int not null references customers(id),
  qty int not null check (qty > 0), total numeric(8,2) not null check (total >= 0), placed date not null,
  sku varchar(12) not null, note text, unique (customer_id, sku));
create table tags (id integer primary key, order_id int references orders(id), label text not null);
"""
STATUS_CHECK = "CHECK ((status = ANY (ARRAY['active'::text, 'it''s'::text, 'a)b'::text])))"


def col(name: str, type_: str, nullable: bool = False, default: bool = False, **kw: Any) -> seed.Column:
    return seed.Column(name, type_, nullable, default, **kw)


def shop_metas() -> dict[str, seed.TableMeta]:
    customers = seed.TableMeta({c.name: c for c in [
        col("id", "int", default=True), col("email", "varchar", maxlen=40), col("name", "text"),
        col("age", "int", nullable=True), col("status", "text"), col("country", "char", maxlen=2),
        col("parent_id", "int", nullable=True)]}, [("id",), ("email",)])
    seed.apply_check(customers, STATUS_CHECK)
    seed.apply_check(customers, "CHECK ((age >= 18))")
    orders = seed.TableMeta({c.name: c for c in [
        col("id", "int", default=True), col("customer_id", "int"), col("qty", "int"),
        col("total", "numeric", precision=8, scale=2), col("placed", "date"), col("sku", "varchar", maxlen=12),
        col("note", "text", nullable=True)]}, [("id",), ("customer_id", "sku")])
    seed.apply_check(orders, "CHECK ((qty > 0))")
    seed.apply_check(orders, "CHECK ((total >= (0)::numeric))")
    tags = seed.TableMeta({c.name: c for c in [col("id", "int", default=True), col("order_id", "int", nullable=True),
                                               col("label", "text")]}, [("id",)])
    return {"customers": customers, "orders": orders, "tags": tags}


REL = Relations.build(["customers", "orders", "tags"], [["customers", "id"], ["orders", "id"], ["tags", "id"]],
                      [["c_parent", "customers", "parent_id", "customers", "id"],
                       ["o_cust", "orders", "customer_id", "customers", "id"], ["t_ord", "tags", "order_id", "orders", "id"]])


def shop_db() -> sqlite3.Connection:
    conn = connect()
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA foreign_keys = ON")
    counter = itertools.count()
    conn.create_function("random", 0, lambda: (next(counter) * 7919) % 104729)  # a deterministic server
    return conn


def dump(conn: sqlite3.Connection) -> dict[str, list[tuple[Any, ...]]]:
    return {t: conn.execute(f"select * from {t} order by id").fetchall() for t in ("customers", "orders", "tags")}


@pytest.fixture
def pg(client: Docker, daemon: Any) -> tuple[Postgres, sqlite3.Connection, Engine]:
    conn = shop_db()
    eng = Engine(daemon, "pg", PG, psql_on(conn))
    return make(client, Postgres, PG), conn, eng


# --- end to end: the engine accepts every generated row ------------------------------------------

def test_seed_satisfies_every_constraint_and_seeds_required_parents_first(pg):
    db, conn, eng = pg
    report = seed.seed(db, REL, shop_metas(), rows=30, tables=["orders"], seed_value=5)
    assert report["tables"] == {"customers": 30, "orders": 30}  # empty NOT NULL parent seeded first; tags untouched
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    rows = dump(conn)
    assert rows["tags"] == []
    for _, email, name, age, status, country, parent in rows["customers"]:
        assert len(email) <= 40 and "@" in email and " " in name and parent is None
        assert age is None or age >= 18
        assert status in ("active", "it's", "a)b") and len(country) == 2
    for _, _, qty, total, placed, sku, _ in rows["orders"]:
        assert qty >= 1 and total >= 0 and Decimal(str(total)) == Decimal(str(total)).quantize(Decimal("0.01"))
        assert dt.date.fromisoformat(placed) and len(sku) <= 12
    inserts = [s for s in eng.sql() if s.startswith("INSERT")]
    assert [s.split()[2] for s in inserts] == ['"customers"', '"orders"']
    assert report["sample"]["orders"]["qty"] == rows["orders"][0][2]
    writes = [env for cmd, env in eng.calls if cmd[cmd.index("-c") + 1].startswith("INSERT")]
    reads = [env for cmd, env in eng.calls if not cmd[cmd.index("-c") + 1].startswith("INSERT")]
    assert all("read_only" not in e["PGOPTIONS"] for e in writes) and all("read_only=on" in e["PGOPTIONS"] for e in reads)


def test_seed_is_deterministic_for_a_seed_value(client, daemon):
    results = []
    for n, value in enumerate((11, 11, 12)):
        conn = shop_db()
        name = f"pg{n}"
        inspect = info(name, env=("POSTGRES_PASSWORD=pw",))
        Engine(daemon, name, inspect, psql_on(conn))
        seed.seed(make(client, Postgres, inspect), REL, shop_metas(), rows=15, tables=None, seed_value=value)
        results.append(dump(conn))
    assert results[0] == results[1] and results[0] != results[2]
    assert len(results[0]["tags"]) == 15 and all(t[1] is not None for t in results[0]["tags"])


def test_reseeding_appends_without_unique_collisions(pg):
    db, conn, _ = pg
    for _ in range(2):
        seed.seed(db, REL, shop_metas(), rows=20, tables=["customers"], seed_value=1)
    emails = [r[0] for r in conn.execute("select email from customers")]
    assert len(emails) == 40 == len(set(emails))


def test_nullable_fk_to_an_empty_parent_stays_null(pg):
    db, conn, _ = pg
    report = seed.seed(db, REL, shop_metas(), rows=5, tables=["tags"], seed_value=2)
    assert report["tables"] == {"tags": 5}
    assert conn.execute("select count(*), count(order_id) from tags").fetchone() == (5, 0)


def test_seed_batches_inserts(pg):
    db, conn, eng = pg
    seed.seed(db, REL, shop_metas(), rows=12, tables=["customers"], seed_value=3, batch=5)
    assert sum(s.startswith('INSERT INTO "customers"') for s in eng.sql()) == 3
    assert conn.execute("select count(*) from customers").fetchone() == (12,)


def test_seed_stops_at_exhausted_unique_domain(pg):
    db, conn, _ = pg
    conn.execute("create table flags (id integer primary key, kind text not null unique check (kind in ('a', 'b')))")
    meta = seed.TableMeta({"id": col("id", "int", default=True), "kind": col("kind", "text", choices=("a", "b"))},
                          [("id",), ("kind",)])
    report = seed.seed(db, Relations.build(["flags"], [["flags", "id"]], []), {"flags": meta}, rows=6,
                       tables=None, seed_value=0)
    assert report["tables"] == {"flags": 2} and sorted(r[0] for r in conn.execute("select kind from flags")) == ["a", "b"]


# --- the api op: catalog introspection faked, the rest on the real engine ---------------------------

def pg_catalog(conn: sqlite3.Connection) -> Any:
    """Postgres catalog queries answered from canned text; everything else runs on sqlite."""
    sqlite_psql = psql_on(conn)
    canned = {
        "c.udt_name": "t,c,dt,udt,n,d,i,m,p,s\n"
                      "customers,id,integer,int4,NO,\\N,YES,\\N,32,0\n"
                      "customers,email,character varying,varchar,NO,\\N,NO,40,\\N,\\N\n"
                      "customers,name,text,text,NO,\\N,NO,\\N,\\N,\\N\n"
                      "customers,age,integer,int4,YES,\\N,NO,\\N,32,0\n"
                      "customers,status,USER-DEFINED,mood,NO,\\N,NO,\\N,\\N,\\N\n"
                      "customers,country,character,bpchar,NO,\\N,NO,2,\\N,\\N\n"
                      "customers,parent_id,integer,int4,YES,\\N,NO,\\N,32,0\n",
        "pg_enum": "typname,enumlabel\nmood,active\nmood,it's\n",
        "contype in ('u'": "t,k,d,c\ncustomers,p,PRIMARY KEY (id),id\ncustomers,u,UNIQUE (email),email\n"
                           "customers,c,CHECK ((age >= 18)),age\nghost,c,CHECK ((x > 1)),x\n",
        "information_schema.columns": "t,c,dt,n,d\ncustomers,id,integer,NO,\\N\n",
        "pg_indexes": "t,n,d\n",
        "contype = 'p'": "t,c\ncustomers,id\n",
        "contype = 'f'": "n,c,a,p,r\nc_parent,customers,parent_id,customers,id\n",
    }

    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        sql = cmd[cmd.index("-c") + 1] if "-c" in cmd else ""
        for key, text in canned.items():
            if key in sql:
                return f"{text}{MARK} 0\n".encode(), b"", 0
        return sqlite_psql(cmd, env)
    return handle


def test_db_seed_op_end_to_end(cli, daemon):
    conn = shop_db()
    Engine(daemon, "pg", PG, pg_catalog(conn))
    code, out, _ = cli("db", "seed", "pg", "--rows", "8", "--seed", "4", "--table", "customers")
    assert code == EXIT_OK and out["engine"] == "postgres" and out["rows"] == {"customers": 8}
    assert {r[0] for r in conn.execute("select status from customers")} <= {"active", "it's"}
    assert out["sample"]["customers"]["email"] == conn.execute("select email from customers order by id").fetchone()[0]


def test_db_seed_rejects_unknown_tables_before_writing(cli, daemon):
    conn = shop_db()
    eng = Engine(daemon, "pg", PG, pg_catalog(conn))
    code, _, err = cli("db", "seed", "pg", "--table", "nope")
    assert code == EXIT_USAGE and "unknown tables: ['nope']" in err and "schema.table" in err
    assert not any(s.startswith("INSERT") for s in eng.sql())


def test_db_seed_dry_run_executes_nothing(cli, daemon):
    eng = Engine(daemon, "pg", PG, queue())
    code, out, _ = cli("db", "seed", "pg", "--dry-run")
    assert code == EXIT_OK and eng.calls == []
    assert not any(p.endswith("/start") for _, p in daemon.calls("POST"))


# --- introspection --------------------------------------------------------------------------------

def test_introspect_postgres(client, daemon):
    conn = connect()
    Engine(daemon, "pg", PG, pg_catalog(conn))
    metas = seed.introspect(make(client, Postgres, PG))
    c = metas["customers"].columns
    assert c["id"].has_default and not c["email"].has_default and c["email"].maxlen == 40 and c["email"].type == "varchar"
    assert (c["status"].type, c["status"].choices) == ("text", ("active", "it's"))
    assert c["age"].minimum == 18 and c["age"].nullable and c["country"].type == "char"
    assert metas["customers"].unique == [("id",), ("email",)] and "ghost" not in metas


def test_introspect_mysql(client, daemon):
    maria = info("maria", "mariadb:11", ("MARIADB_ROOT_PASSWORD=r", "MARIADB_DATABASE=shop"))
    cols = [
        {"t": "o", "c": "id", "dt": "int", "ct": "int(11)", "n": "NO", "d": None, "e": "auto_increment", "m": None, "p": "10", "s": "0"},
        {"t": "o", "c": "state", "dt": "enum", "ct": "enum('new','it''s')", "n": "NO", "d": None, "e": "", "m": "5", "p": None, "s": None},
        {"t": "o", "c": "paid", "dt": "tinyint", "ct": "tinyint(1)", "n": "NO", "d": "0", "e": "", "m": None, "p": "3", "s": "0"},
        {"t": "o", "c": "memo", "dt": "text", "ct": "text", "n": "YES", "d": "NULL", "e": "", "m": "65535", "p": None, "s": None},
        {"t": "o", "c": "qty", "dt": "int", "ct": "int(11)", "n": "NO", "d": None, "e": "", "m": None, "p": "10", "s": "0"},
    ]
    Engine(daemon, "maria", maria, queue(
        (xml(cols), b"", 0),
        (xml([{"t": "o", "i": "PRIMARY", "c": "id"}, {"t": "o", "i": "u", "c": "state,qty"}, {"t": "x", "i": "PRIMARY", "c": "id"}]), b"", 0),
        (xml([{"t": "o", "c": "(`qty` >= 3)"}, {"t": "x", "c": "(`a` > 1)"}]), b"", 0)))
    metas = seed.introspect(make(client, MySQL, maria))
    c = metas["o"].columns
    assert c["id"].has_default and c["paid"].type == "bool" and c["paid"].has_default
    assert not c["memo"].has_default and c["memo"].nullable  # MariaDB's 'NULL' default string means none
    assert c["state"].choices == ("new", "it's") and c["qty"].minimum == 3
    assert metas["o"].unique == [("id",), ("state", "qty")]


def test_introspect_mysql_without_check_constraints_view(client, daemon):
    maria = info("maria", "mysql:5.7", ("MYSQL_ROOT_PASSWORD=r", "MYSQL_DATABASE=shop"))
    Engine(daemon, "maria", maria, queue(
        (xml([{"t": "o", "c": "id", "dt": "int", "ct": "int", "n": "NO", "d": None, "e": None, "m": None, "p": None, "s": None}]), b"", 0),
        (xml([]), b"", 0),
        (b"", b"ERROR 1109 (42S02): Unknown table 'CHECK_CONSTRAINTS'\n", 1)))
    metas = seed.introspect(make(client, MySQL, maria))
    assert list(metas["o"].columns) == ["id"] and metas["o"].unique == []


# --- pure pieces ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("data_type", "udt", "norm"), [
    ("smallint", "", "smallint"), ("integer", "", "int"), ("mediumint", "", "int"), ("serial", "", "int"),
    ("numeric", "", "numeric"), ("decimal(10,2)", "", "numeric"), ("double precision", "", "float"), ("real", "", "float"),
    ("float", "", "float"), ("boolean", "", "bool"), ("datetime", "", "timestamp"), ("date", "", "date"),
    ("time without time zone", "", "time"), ("interval", "", "time"), ("jsonb", "", "json"), ("uuid", "", "uuid"),
    ("bytea", "", "bytes"), ("longblob", "", "bytes"), ("varbinary", "", "bytes"), ("varchar", "", "varchar"),
    ("char", "", "char"), ("mediumtext", "", "text"), ("enum", "", "text"), ("USER-DEFINED", "citext", "text"),
    ("name", "name", "text"), ("", "", "other"), (None, "", "other"),
])
def test_normalize_more(data_type, udt, norm):
    assert seed.normalize(data_type, udt) == norm


@pytest.mark.parametrize(("clause", "choices", "minimum"), [
    ("CHECK ((status = ANY (ARRAY['it''s'::text, 'x]y'::text])))", ("it's", "x]y"), None),
    ("(`status` in (_utf8mb4'a)b',_utf8mb4'c'))", ("a)b", "c"), None),
    ("CHECK ((qty >= '-5'::integer))", (), -5.0),
    ("CHECK ((qty > 0.5))", (), 1.5),
    ("CHECK ((other >= 3))", (), None),                # unknown column: ignored
    ("CHECK ((other = ANY (ARRAY['x'::text])))", (), None),
    ("CHECK ((qty < 10))", (), None),                  # upper bounds are not understood
    ("CHECK ((char_length(status) > 2))", (), None),
])
def test_apply_check_shapes(clause, choices, minimum):
    meta = seed.TableMeta({"status": col("status", "text"), "qty": col("qty", "int")})
    seed.apply_check(meta, clause)
    assert (meta.columns["status"].choices, meta.columns["qty"].minimum) == (choices, minimum)


GEN = seed.Generator(99)


@pytest.mark.parametrize(("name", "check"), [
    ("email", lambda v: v.endswith("@example.com") and ".7@" in v),
    ("first_name", lambda v: v in seed.FIRST), ("surname", lambda v: v in seed.LAST),
    ("full_name", lambda v: v.split()[0] in seed.FIRST), ("username", lambda v: v.endswith("7") and v.islower()),
    ("login", lambda v: v.endswith("7")), ("phone", lambda v: v == "+1-555-0007"), ("city", lambda v: v in seed.CITIES),
    ("country", lambda v: v in dict(seed.COUNTRIES).values()), ("website", lambda v: v.startswith("https://")),
    ("avatar_url", lambda v: v.endswith(".example.com/7")), ("sku", lambda v: v == "SKU-000007"),
    ("zone_code", lambda v: v == "ZON-000007"), ("slug", lambda v: v.endswith("-7")),
    ("status", lambda v: v in ("active", "pending", "done")), ("state", lambda v: v in ("active", "pending", "done")),
    ("bio", lambda v: v.endswith(".") and v[0].isupper()), ("subject", lambda v: len(v.split()) == 3),
    ("postal", lambda v: len(v) == 5 and v.isdigit()), ("uuid", lambda v: uuid.UUID(v).version == 4),
    ("ext_guid", lambda v: uuid.UUID(v).version == 4), ("misc", lambda v: v in seed.WORDS),
])
def test_generator_text_by_column_name(name, check):
    assert check(GEN.value(col(name, "text"), 7, unique=False))


def test_generator_text_shapes():
    g = seed.Generator(1)
    assert g.value(col("misc", "text"), 3, unique=True).endswith("-3")
    assert len(g.value(col("country", "char", maxlen=2), 1, False)) == 2
    assert len(g.value(col("misc", "char", maxlen=30), 1, False)) == 30  # padded to fixed width
    assert len(g.value(col("misc", "char", maxlen=2), 1, False)) == 2
    assert len(g.value(col("email", "varchar", maxlen=8), 1, True)) == 8
    assert g.value(col("pick", "text", choices=("x", "y")), 3, unique=True) == "y"
    assert g.value(col("pick", "text", choices=("x", "y")), 3, unique=False) in ("x", "y")


@pytest.mark.parametrize(("column", "lo", "hi"), [
    (col("qty", "int"), 1, 10), (col("age", "int"), 1, 120), (col("n", "smallint"), 0, 32767),
    (col("n", "bigint"), 0, 100000), (col("n", "int", minimum=500.0), 500, 100000),
    (col("n", "int", minimum=200000.0), 200000, 200000),
])
def test_generator_integer_ranges(column, lo, hi):
    g = seed.Generator(5)
    values = [g.value(column, i, unique=False) for i in range(200)]
    assert all(lo <= v <= hi for v in values)
    assert g.value(column, 41, unique=True) == lo + 41


@pytest.mark.parametrize(("column", "low", "high", "places"), [
    (col("price", "numeric", precision=10, scale=2), 0, 999, 2),
    (col("ratio", "numeric", precision=3, scale=2), 0, 9.99, 2),
    (col("n", "numeric"), 0, 99999999, 2),
    (col("n", "numeric", precision=6, scale=0, minimum=10.0), 10, 999999, 0),
])
def test_generator_numeric_respects_precision_scale_minimum(column, low, high, places):
    g = seed.Generator(8)
    for i in range(100):
        v = Decimal(g.value(column, i, unique=False))
        assert low <= v <= high and -v.as_tuple().exponent == places


def test_generator_other_types():
    g = seed.Generator(3)
    assert all(-90 <= g.value(col("lat", "float"), i, False) <= 90 for i in range(50))
    assert all(-180 <= g.value(col("lng", "float"), i, False) <= 180 for i in range(50))
    assert all(0 <= g.value(col("score", "float"), i, False) <= 1000 for i in range(50))
    assert {g.value(col("b", "bool"), i, False) for i in range(50)} == {True, False}
    assert dt.date.fromisoformat(g.value(col("d", "date"), 0, False)) <= seed.NOW.date()
    assert dt.datetime.fromisoformat(g.value(col("t", "timestamp"), 0, False)) <= seed.NOW
    assert dt.time.fromisoformat(g.value(col("t", "time"), 0, False))
    assert g.value(col("j", "json"), 0, False) == "{}"
    assert uuid.UUID(g.value(col("u", "uuid"), 0, False)).version == 4
    assert g.value(col("blob", "bytes"), 0, False) is None


# --- subset -----------------------------------------------------------------------------------------

def test_subset_postgres_export_frames_and_resets_sequences(client, daemon):
    conn = connect()
    conn.executescript("""create table a (id integer primary key, v text);
                          create table b (id integer primary key, a_id int references a(id));
                          insert into a values (1, 'it''s'), (2, 'x'); insert into b values (1, 1), (2, 1);""")
    conn.create_function("random", 0, lambda: 0)
    sqlite_psql = psql_on(conn)
    Engine(daemon, "pg", PG, lambda cmd, env: (f"t,c,s\nb,id,public.b_id_seq\nz,id,z_seq\n{MARK} 2\n".encode(), b"", 0)
           if "pg_get_serial_sequence" in cmd[cmd.index("-c") + 1] else sqlite_psql(cmd, env))
    db = make(client, Postgres, PG)
    rel = Relations.build(["a", "b"], [["a", "id"], ["b", "id"]], [["f", "b", "a_id", "a", "id"]])
    sub = subset.plan(db, rel, ratio=1.0)
    stmts, counts = subset.export(db, rel, sub)
    assert counts == {"a": 1, "b": 2} and stmts[0] == "SET session_replication_role = replica;"
    assert stmts[-1] == "SET session_replication_role = DEFAULT;"
    assert "SELECT setval('public.b_id_seq', (SELECT coalesce(max(\"id\"), 1) FROM \"b\"));" in stmts
    assert not any("z_seq" in s for s in stmts)
    assert "('1', 'it''s')" in stmts[1]  # psql hands back text; values are re-quoted as literals


def test_subset_plan_edge_cases(client, daemon):
    conn = connect()
    conn.executescript("""create table empty (id integer primary key);
                          create table log (msg text, n int);
                          insert into log values ('a', 1), ('b', 2), (NULL, 3);
                          create table p (id integer primary key); create table c (p_id int references p(id));
                          insert into p values (1); insert into c values (1);""")
    sqlite_psql = psql_on(conn)
    Engine(daemon, "pg", PG, lambda cmd, env: (f"t,c,s\n{MARK} 0\n".encode(), b"", 0)
           if "pg_get_serial_sequence" in cmd[cmd.index("-c") + 1] else sqlite_psql(cmd, env))
    db = make(client, Postgres, PG)
    rel = Relations.build(["empty", "log", "p", "c"], [["empty", "id"], ["p", "id"]], [["f", "c", "p_id", "p", "id"]])
    sub = subset.plan(db, rel, ratio=1.0, roots=["empty", "log", "p"], with_children=True)
    assert "empty" not in sub.selection  # zero rows: nothing sampled
    assert sub.notes == ["log: no primary key; sampled as a whole-row root, its children can't reference it"]
    assert sub.selection["log"][("msg", "n")] == {("a", "1"), ("b", "2")}  # NULL-bearing keys can't select a row
    assert "c" not in sub.selection  # a child without a primary key is not pulled down
    stmts, counts = subset.export(db, rel, sub)
    assert counts == {"log": 2, "p": 1}


def test_subset_export_heads_per_dialect(client, daemon):
    maria = info("maria", "mariadb:11", ("MARIADB_ROOT_PASSWORD=r",))
    Engine(daemon, "maria", maria, queue())
    rel = Relations.build([], [], [])
    assert subset.export(make(client, MySQL, maria), rel, subset.Subset()) == (
        ["SET FOREIGN_KEY_CHECKS=0;", "SET FOREIGN_KEY_CHECKS=1;"], {})


def test_subset_where_quotes_values_and_names():
    db = Postgres.__new__(Postgres)
    assert subset._where(db, ["na\"me"], [("o'k",), (None,)]) == "\"na\"\"me\" IN ('o''k', NULL)"
    assert subset._where(db, ["a", "b"], [(1, "x")]) == "(\"a\", \"b\") IN ((1, 'x'))"


def test_db_sample_sqlite_writes_loadable_subset(cli, daemon, tmp_path):
    src = tmp_path / "app.db"
    conn = sqlite3.connect(src)
    conn.executescript("""create table a (id integer primary key, v text);
                          create table b (id integer primary key, a_id int references a(id));
                          create index b_a on b(a_id);
                          insert into a values (1, 'x'), (2, 'y'); insert into b values (1, 2);""")
    conn.commit()
    conn.close()
    daemon.on("GET", "/containers/box/json", json=info("box", "alpine"))
    daemon.on("GET", "/containers/box/archive", lambda s: Reply(body=tar_of({"app.db": src.read_bytes()}),
                                                                content_type="application/x-tar")
              if s.query["path"] == "/app.db" else Reply(404, json={"message": "missing"}))
    out_file = tmp_path / "sub.sql.gz"
    code, out, _ = cli("db", "sample", "box", str(out_file), "--path", "/app.db", "--ratio", "1")
    assert code == EXIT_OK and out["rows"] == {"a": 1, "b": 1} and out["roots"] == ["b"]
    loaded = sqlite3.connect(":memory:")
    loaded.executescript(gzip.decompress(out_file.read_bytes()).decode())
    assert loaded.execute("select * from a").fetchall() == [(2, "y")]
    assert loaded.execute("select name from sqlite_master where type = 'index'").fetchall() == [("b_a",)]
    code, out, _ = cli("db", "sample", "box", str(tmp_path / "data.sql"), "--path", "/app.db", "--data-only",
                       "--root", "a", "--ratio", "1")
    assert out["rows"] == {"a": 2} and "create table" not in (tmp_path / "data.sql").read_text().lower()


def test_db_sample_postgres_prepends_schema_dump(cli, daemon, tmp_path):
    conn = connect()
    conn.executescript("create table a (id integer primary key); insert into a values (1);")
    sqlite_psql = psql_on(conn)

    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        if cmd[0] == "pg_dump":
            assert "--schema-only" in cmd
            return b"CREATE TABLE a (id int);\n", b"", 0
        sql = cmd[cmd.index("-c") + 1]
        if "information_schema.columns" in sql:
            return f"t,c,dt,n,d\na,id,integer,NO,\\N\n{MARK} 1\n".encode(), b"", 0
        if "contype = 'p'" in sql:
            return f"t,c\na,id\n{MARK} 1\n".encode(), b"", 0
        if "pg_indexes" in sql or "contype = 'f'" in sql or "pg_get_serial_sequence" in sql:
            return f"x\n{MARK} 0\n".encode(), b"", 0
        return sqlite_psql(cmd, env)
    Engine(daemon, "pg", PG, handle)
    code, out, _ = cli("db", "sample", "pg", str(tmp_path / "s.sql"), "--ratio", "1")
    text = (tmp_path / "s.sql").read_text()
    assert code == EXIT_OK and text.startswith("CREATE TABLE a (id int);") and 'INSERT INTO "a" ("id") VALUES' in text


def test_subset_dedupes_rows_selected_by_several_keys(client, daemon):
    conn = connect()
    conn.executescript("""create table p (id integer primary key, code text unique);
                          create table c (id integer primary key, p_id int references p(id), p_code text references p(code));
                          insert into p values (1, 'a'), (2, 'b'); insert into c values (1, 1, 'a'), (2, 2, 'b');""")
    conn.create_function("random", 0, lambda: 0)
    sqlite_psql = psql_on(conn)
    Engine(daemon, "pg", PG, lambda cmd, env: (f"t,c,s\n{MARK} 0\n".encode(), b"", 0)
           if "pg_get_serial_sequence" in cmd[cmd.index("-c") + 1] else sqlite_psql(cmd, env))
    db = make(client, Postgres, PG)
    rel = Relations.build(["p", "c"], [["p", "id"], ["c", "id"]],
                          [["f1", "c", "p_id", "p", "id"], ["f2", "c", "p_code", "p", "code"]])
    sub = subset.plan(db, rel, ratio=1.0, roots=["p", "c"], with_children=True)
    assert set(sub.selection["p"]) == {("id",), ("code",)}  # the same parents, reached through two keys
    stmts, counts = subset.export(db, rel, sub)
    assert counts == {"p": 2, "c": 2}  # each row exported once


def test_seed_zero_rows_reports_no_sample(pg):
    db, conn, eng = pg
    report = seed.seed(db, REL, shop_metas(), rows=0, tables=["customers"], seed_value=1)
    assert report == {"tables": {"customers": 0}, "sample": {}}
    assert not any(s.startswith("INSERT") for s in eng.sql())
