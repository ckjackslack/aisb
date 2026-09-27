"""SQL adapters through the exec boundary: quoting invariants, read-only guards, tool-output parsing.

`Engine` fakes a container whose exec endpoint is a Python function of (argv, env) -- the process
boundary. `psql_on(conn)` makes that function a tiny psql backed by a real in-process sqlite3, so
aisb's generated SQL really runs and read-only sessions are enforced by the engine (query_only).
"""

import csv
import gzip
import io
import json
import sqlite3
from collections.abc import Callable
from typing import Any

import pytest

from aisb import Docker
from aisb.api.containers import Containers
from aisb.cli import EXIT_OK, EXIT_USAGE, main
from aisb.services import ServiceError, Target
from aisb.services.sql import (
    SQL,
    MySQL,
    Postgres,
    Relations,
    SQLite,
    _schema,
    diff_schema,
    gzip_sink,
    lit,
    mysql_client_command,
)

from conftest import Reply, frame, tar_of

MARK = "__aisb_rows__"
Handler = Callable[[list[str], dict[str, str]], tuple[bytes, bytes, int]]


def info(name: str = "svc", image: str = "postgres:16", env: tuple[str, ...] = (), *, running: bool = True,
         cmd: tuple[str, ...] = (), ports: dict[str, Any] | None = None, exposed: tuple[int, ...] = (),
         ips: tuple[str, ...] = ("172.17.0.9",), tty: bool = False) -> dict[str, Any]:
    return {
        "Name": f"/{name}", "State": {"Running": running, "Status": "running" if running else "exited"},
        "Config": {"Image": image, "Env": list(env), "Cmd": list(cmd), "Tty": tty,
                   "ExposedPorts": {f"{p}/tcp": {} for p in exposed}},
        "NetworkSettings": {"Ports": ports or {}, "Networks": {"bridge": {"IPAddress": ips[-1]}} if ips else {}},
    }


class Engine:
    """A container whose exec endpoint runs `handler(argv, env)`; records every exec."""

    def __init__(self, daemon: Any, name: str, inspect: dict[str, Any], handler: Handler, key: str = "") -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.results: list[tuple[bytes, bytes, int]] = []
        prefix = f"x-{key or name}-"  # `name` is a route regex; pass a plain `key` when it has metacharacters

        def index(seen: Any) -> int:
            return int(seen.path.split("/")[2].removeprefix(prefix))

        def create(seen: Any) -> Reply:
            cmd, env = seen.body["Cmd"], dict(e.split("=", 1) for e in seen.body.get("Env") or [])
            self.calls.append((cmd, env))
            self.results.append(handler(cmd, env))
            return Reply(201, json={"Id": f"{prefix}{len(self.results) - 1}"})

        def start(seen: Any) -> Reply:
            out, err, _ = self.results[index(seen)]
            return Reply(body=(frame(1, out) if out else b"") + (frame(2, err) if err else b""),
                         content_type="application/vnd.docker.multiplexed-stream")

        daemon.on("GET", f"/containers/{name}/json", json=inspect)
        daemon.on("POST", f"/containers/{name}/exec", create)
        daemon.on("POST", rf"/exec/{prefix}\d+/start", start)
        daemon.on("GET", rf"/exec/{prefix}\d+/json", lambda s: Reply(json={"ExitCode": self.results[index(s)][2]}))

    def sql(self) -> list[str]:
        """The SQL of every psql -c / mysql -e exec, in order."""
        return [c[c.index(flag) + 1] for c, _ in self.calls for flag in ("-c", "-e") if flag in c]


def queue(*results: tuple[bytes, bytes, int]) -> Handler:
    items = list(results)
    return lambda cmd, env: items.pop(0) if items else (b"", b"", 0)


def psql_on(conn: sqlite3.Connection) -> Handler:
    """psql whose server is sqlite: honours PGOPTIONS read-only like Postgres does (writes fail)."""
    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        if cmd[0] == "rm":
            return b"", b"", 0
        assert cmd[0] == "psql", cmd
        sql = cmd[cmd.index("-c") + 1]
        conn.execute(f"PRAGMA query_only = {'ON' if 'default_transaction_read_only=on' in env.get('PGOPTIONS', '') else 'OFF'}")
        try:
            cur = conn.execute(sql)
            rows = cur.fetchall()
            conn.commit()
        except sqlite3.Error as e:
            return b"", f"ERROR:  {e}\n".encode(), 1
        buf = io.StringIO()
        if cur.description:
            w = csv.writer(buf, lineterminator="\n")
            w.writerow([d[0] for d in cur.description])
            w.writerows([["\\N" if v is None else v for v in r] for r in rows])
        return (buf.getvalue() + f"{MARK} {len(rows) if cur.description else cur.rowcount}\n").encode(), b"", 0
    return handle


def connect() -> sqlite3.Connection:
    return sqlite3.connect(":memory:", check_same_thread=False)  # the fake daemon answers from its own thread


def make(client: Docker, cls: type, inspect: dict[str, Any], *extra: Any) -> Any:
    return cls(Containers(client.transport), Target.from_inspect(inspect), *extra)


def cli_runner(host: str, capsys: Any) -> Callable[..., tuple[int, Any, str]]:
    """Run the CLI against the fake daemon: (exit code, parsed JSON stdout, stderr)."""
    def run(*argv: str) -> tuple[int, Any, str]:
        head, tail = (argv[:argv.index("--")], argv[argv.index("--"):]) if "--" in argv else (argv, ())
        code = main([*head, "--host", host, "--json", *tail])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


@pytest.fixture
def cli(host, capsys):
    return cli_runner(host, capsys)


PG = info("pg", env=("POSTGRES_USER=app", "POSTGRES_PASSWORD=pw", "POSTGRES_DB=shop"))
MARIA = info("maria", "mariadb:11", env=("MARIADB_ROOT_PASSWORD=rootpw", "MARIADB_DATABASE=shop"))


def xml(*sets: list[dict[str, str | None]], affected: int | None = None) -> bytes:
    """mysql --xml output: one <resultset> per statement, plus the ROW_COUNT() marker set."""
    docs = []
    for rows in [*sets, *([[{MARK: str(affected)}]] if affected is not None else [])]:
        body = "".join("<row>" + "".join(
            f'<field name="{k}" xsi:nil="true" />' if v is None else f'<field name="{k}">{v}</field>'
            for k, v in r.items()) + "</row>" for r in rows)
        docs.append('<?xml version="1.0"?>\n<resultset statement="s" '
                    f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{body}</resultset>\n')
    return "".join(docs).encode()


# --- quoting invariants ---------------------------------------------------------------------

NASTY = ["plain", "it's", "''", 'dq"name', "semi;colon; drop table t; --", "back\\slash\\", "a' OR '1'='1",
         "ünïcødé ß 😀 中文", "new\nline\ttab", "x`y``z", "", "  spaced  ", "\\'", "$$dollar$$", "/* c */"]


def mysql_unquote(token: str) -> tuple[str, str]:
    """Lex one MySQL string literal (backslash escapes on) from the start of token; returns (value, rest)."""
    assert token[0] == "'"
    out, i = [], 1
    while True:
        c = token[i]
        if c == "\\":
            out.append({"n": "\n", "t": "\t", "0": "\0"}.get(token[i + 1], token[i + 1]))
            i += 2
        elif c == "'" and token[i + 1:i + 2] == "'":
            out.append("'")
            i += 2
        elif c == "'":
            return "".join(out), token[i + 1:]
        else:
            out.append(c)
            i += 1


@pytest.mark.parametrize("value", NASTY)
def test_postgres_literal_round_trips_through_a_real_lexer(value):
    conn = sqlite3.connect(":memory:")  # standard SQL strings: '' doubles, backslash is literal (like Postgres)
    literal = Postgres.literal(Postgres.__new__(Postgres), value)
    assert conn.execute(f"select {literal}, 1").fetchone() == (value, 1)


@pytest.mark.parametrize("value", NASTY)
def test_mysql_literal_round_trips_and_never_terminates_early(value):
    literal = MySQL.literal(MySQL.__new__(MySQL), value)
    assert mysql_unquote(literal + " tail") == (value, " tail")


@pytest.mark.parametrize("value", [None, True, False, 0, -7, 2**40, 1.5, b"\x00\xffA'", "x"])
def test_literal_types_round_trip(value):
    conn = sqlite3.connect(":memory:")
    got = conn.execute(f"select {Postgres.literal(Postgres.__new__(Postgres), value)}").fetchone()[0]
    assert got == (int(value) if isinstance(value, bool) else value)


@pytest.mark.parametrize("name", [n for n in NASTY if n and "." not in n and "\0" not in n])
@pytest.mark.parametrize("cls", [Postgres, MySQL])
def test_identifiers_round_trip(cls, name):
    conn = sqlite3.connect(":memory:")  # sqlite accepts both "..." and `...` quoting with doubled delimiters
    q = cls.ident(cls.__new__(cls), name)
    conn.execute(f"create table {q} ({q} int)")
    conn.execute(f"insert into {q} ({q}) values (1)")
    assert conn.execute("select name from sqlite_master").fetchone()[0] == name
    assert conn.execute(f"select {q} from {q}").fetchone() == (1,)


def test_dotted_identifiers_are_schema_qualified():
    assert Postgres.ident(Postgres.__new__(Postgres), 'public.or"ders') == '"public"."or""ders"'
    assert MySQL.ident(MySQL.__new__(MySQL), "shop.t`x") == "`shop`.`t``x`"


def test_lit_backslash_modes():
    assert lit("a\\'b") == "'a\\''b'"
    assert lit("a\\'b", backslash=True) == "'a\\\\''b'"


# --- mysql client commands inside SQL (a READ query must not reach a shell) -----------------------

@pytest.mark.parametrize("sql", [
    "\\! id", "select 1; \\! touch /tmp/x", "select 1;\nsystem id", "select 1;\n  SOURCE /etc/x.sql",
    "select 1;\ntee /tmp/out", "\\T /tmp/out", "select 1\\G", "select 1 -- it's\n\\! id",
    "select 1--1 '\n' \\! id",           # `--1` is arithmetic, so the quote opens a string for the client
    "/*!50000 '*/\n' \\! id",            # a versioned comment is SQL to the client, quotes inside count
    "select 'a\\' \\! id'",              # NO_BACKSLASH_ESCAPES splits this string differently
    "/* \\! id */ select 1", "# \\! id\nselect 1", "select 1;\nconnect other", "select 1;\nresetconnection",
    "delimiter //\nselect 1//",
    "select 1; system id", "select 1;system id", "select 1;  tee /tmp/o",  # mysql 8.4 runs these (same line)
])
def test_mysql_client_commands_are_found(sql):
    assert mysql_client_command(sql) is not None


@pytest.mark.parametrize("sql", [
    "select 1", "select 'a\\!b', \"q\\\\\"", "select \\N", "select 1 -- it's fine", "select a,\n source from t",
    "select `system` from t", "select 'x;\nsystem id'", "select id from t where note like '%\\_%'",
    "select 1 # comment", "select /* note */ 1", "select 1;\nselect 2", "",
])
def test_mysql_plain_sql_passes(sql):
    assert mysql_client_command(sql) is None


def test_mysql_readonly_query_rejects_client_commands_before_any_exec(cli, daemon):
    eng = Engine(daemon, "maria", MARIA, queue())
    code, _, err = cli("db", "query", "maria", "select 1;\nsystem touch /tmp/pwned")
    assert code == EXIT_USAGE and "client commands" in err
    assert eng.calls == []


def test_postgres_readonly_query_rejects_meta_commands_before_any_exec(cli, daemon):
    eng = Engine(daemon, "pg", PG, queue())
    code, _, err = cli("db", "query", "pg", "\\! touch /tmp/pwned")
    assert code == EXIT_USAGE and "meta-commands" in err and eng.calls == []
    code, _, _ = cli("db", "query", "pg", "  \\copy t to '/tmp/x'")
    assert code == EXIT_USAGE and eng.calls == []


@pytest.mark.parametrize("database", ["dbname=shop options=-cdefault_transaction_read_only=off",
                                      "host=evil.example dbname=shop", "postgresql://evil/shop", "postgres://x"])
def test_postgres_connection_strings_as_database_are_refused(cli, daemon, database, tmp_path):
    eng = Engine(daemon, "pg", PG, queue())
    assert cli("db", "query", "pg", "select 1", "--database", database)[0] == EXIT_USAGE
    assert cli("db", "dump", "pg", str(tmp_path / "d.sql"), "--database", database)[0] == EXIT_USAGE
    assert eng.calls == [] and not (tmp_path / "d.sql").exists()


def test_mysql_option_like_database_and_tables_are_refused(cli, daemon, tmp_path):
    eng = Engine(daemon, "maria", MARIA, queue())
    assert cli("db", "query", "maria", "select 1", "--database=--host=evil.example")[0] == EXIT_USAGE
    assert cli("db", "dump", "maria", str(tmp_path / "d.sql"), "--table=--result-file=/x")[0] == EXIT_USAGE
    assert eng.calls == []


def test_readonly_query_against_a_real_engine_cannot_write(client, daemon):
    conn = connect()
    conn.execute("create table t (id int)")
    eng = Engine(daemon, "pg", PG, psql_on(conn))
    pg = make(client, Postgres, PG)
    with pytest.raises(ServiceError, match="readonly"):
        pg.query("insert into t values (1)")
    assert conn.execute("select count(*) from t").fetchone() == (0,)
    assert pg.query("insert into t values (1)", readonly=False).affected == 1
    env = eng.calls[0][1]
    assert "default_transaction_read_only=on" in env["PGOPTIONS"] and "statement_timeout=30000" in env["PGOPTIONS"]
    assert "read_only" not in eng.calls[1][1]["PGOPTIONS"]


# --- postgres output parsing ---------------------------------------------------------------

@pytest.mark.parametrize(("out", "columns", "rows", "affected"), [
    (b"", [], [], None),
    (f"{MARK} 5\n".encode(), [], [], 5),
    (f"a,b\n{MARK} 0\n".encode(), ["a", "b"], [], 0),
    (f'a,b\n"x,y","multi\nline"\n\\N,""\n{MARK} 2\n'.encode(), ["a", "b"], [["x,y", "multi\nline"], [None, ""]], 2),
    (b"a\n1\n", ["a"], [["1"]], None),                       # marker missing: all output is the result
    (f"a\n1\n{MARK} abc\n".encode(), ["a"], [["1"]], None),  # malformed count
    (f"{MARK} -1\n".encode(), [], [], -1),
    (f'a\n"{MARK} 9"\n{MARK} 1\n'.encode(), ["a"], [[f"{MARK} 9"]], 1),  # marker text in data: last one wins
])
def test_postgres_query_parsing(client, daemon, out, columns, rows, affected):
    Engine(daemon, "pg", PG, queue((out, b"", 0)))
    r = make(client, Postgres, PG).query("select")
    assert (r.columns, r.rows, r.affected) == (columns, rows, affected)
    assert r.elapsed_ms >= 0


def test_postgres_connection_env_and_socket_fallback(client, daemon):
    nopw = info("pg", env=("POSTGRES_USER=u",))
    eng = Engine(daemon, "pg", nopw, queue((f"ok\n1\n{MARK} 1\n".encode(), b"", 0)))
    pg = make(client, Postgres, nopw)
    assert pg.probe() == "select 1"
    cmd, env = eng.calls[0]
    assert "-h" not in cmd and cmd[cmd.index("-d") + 1] == "u" and "PGPASSWORD" not in env
    assert (pg.user(), pg.database(), pg.password()) == ("u", "u", None)


def test_postgres_probe_rejects_unexpected_result(client, daemon):
    Engine(daemon, "pg", PG, queue((f"ok\n2\n{MARK} 1\n".encode(), b"", 0)))
    with pytest.raises(ServiceError, match="unexpected probe"):
        make(client, Postgres, PG).probe()


def test_postgres_describe(client, daemon):
    eng = Engine(daemon, "pg", PG, queue(
        (f"name,type,nullable,default\nid,integer,f,\\N\nnote,text,t,\\N\n{MARK} 2\n".encode(), b"", 0),
        (f"name,kind,definition\nt_pkey,primary key,PRIMARY KEY (id)\n{MARK} 1\n".encode(), b"", 0),
        (f"name,definition\nt_pkey,CREATE UNIQUE INDEX\n{MARK} 1\n".encode(), b"", 0)))
    d = make(client, Postgres, PG).describe("sales.or'ders")
    assert [(c["name"], c["nullable"]) for c in d["columns"]] == [("id", False), ("note", True)]
    assert d["constraints"][0]["kind"] == "primary key" and d["indexes"][0]["name"] == "t_pkey"
    first = eng.sql()[0]
    assert "table_schema = 'sales' and table_name = 'or''ders'" in first  # names travel as literals, escaped
    assert all(env["PGOPTIONS"].startswith("-c default_transaction_read_only=on") for _, env in eng.calls)


def test_postgres_describe_missing_table(client, daemon):
    eng = Engine(daemon, "pg", PG, queue((f"name,type,nullable,default\n{MARK} 0\n".encode(), b"", 0)))
    with pytest.raises(ServiceError, match="no table 'nope'"):
        make(client, Postgres, PG).describe("nope")
    assert "table_schema = current_schema()" in eng.sql()[0]


def test_postgres_catalog_reads(client, daemon):
    cols = f"t,c,dt,n,d\npublic.a,id,integer,NO,\\N\npublic.b,id,integer,NO,\\N\npublic.b,a_id,integer,YES,\\N\n{MARK} 3\n"
    idx = f"t,n,d\npublic.a,a_pkey,CREATE UNIQUE INDEX a_pkey\nother.z,z_idx,x\n{MARK} 2\n"
    Engine(daemon, "pg", PG, queue(
        (cols.encode(), b"", 0), (idx.encode(), b"", 0),
        (f"t,a\npublic.a,id\npublic.b,id\n{MARK} 2\n".encode(), b"", 0),
        (f"n,c,a,p,r\nfk,public.b,a_id,public.a,id\n{MARK} 1\n".encode(), b"", 0),
        (f"t,c,s\npublic.a,id,public.a_id_seq\n{MARK} 1\n".encode(), b"", 0),
        (f"t\n{MARK} 0\n".encode(), b"", 0)))
    pg = make(client, Postgres, PG)
    rel = pg.relations()
    assert rel.tables == ["public.a", "public.b"] and rel.pk == {"public.a": ("id",), "public.b": ("id",)}
    assert rel.parents_first() == ["public.a", "public.b"] and rel.roots() == ["public.b"]
    assert pg.sequences() == [("public.a", "id", "public.a_id_seq")]
    assert pg.tables().columns == ["t"]


def test_postgres_activity_check_reload_kill(client, daemon):
    eng = Engine(daemon, "pg", PG, queue(
        (b'{"connections": {"active": 1}, "active": []}\n', b"", 0), (b"\n", b"", 0),
        (f"sourcefile,sourceline,name,error\n/pg.conf,3,work_mem,bad\n{MARK} 1\n".encode(), b"", 0),
        (f"pg_reload_conf\nt\n{MARK} 1\n".encode(), b"", 0),
        (f"ok\nt\n{MARK} 1\n".encode(), b"", 0), (f"ok\nf\n{MARK} 1\n".encode(), b"", 0)))
    pg = make(client, Postgres, PG)
    assert pg.activity() == {"connections": {"active": 1}, "active": []}
    assert pg.activity() is None  # empty scalar output
    assert pg.check() == {"ok": False, "errors": [{"sourcefile": "/pg.conf", "sourceline": "3", "name": "work_mem",
                                                   "error": "bad"}]}
    assert pg.reload() == {"reloaded": True, "via": "pg_reload_conf()"}
    assert pg.kill(42) == {"pid": 42, "action": "cancel", "ok": True}
    assert pg.kill(43, terminate=True) == {"pid": 43, "action": "terminate", "ok": False}
    sqls = eng.sql()
    assert sqls[-2:] == ["select pg_cancel_backend(42) as ok", "select pg_terminate_backend(43) as ok"]
    assert eng.calls[0][0][:6] == ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1"]
    assert all("read_only" not in env["PGOPTIONS"] for _, env in eng.calls[3:])  # reload/kill need write sessions


def test_postgres_kill_coerces_pid(client, daemon):
    Engine(daemon, "pg", PG, queue())
    with pytest.raises(ValueError):
        make(client, Postgres, PG).kill("1); drop table t; --")  # type: ignore[arg-type]


@pytest.mark.parametrize(("kw", "flags"), [
    ({}, []), ({"clean": True}, ["--clean", "--if-exists"]), ({"schema_only": True}, ["--schema-only"]),
    ({"tables": ["a", "s.b"]}, ["-t", "a", "-t", "s.b"]),
])
def test_postgres_dump_argv_and_streaming(client, daemon, kw, flags):
    eng = Engine(daemon, "pg", PG, queue((b"-- dump\n", b"warn\n", 0)))
    buf = bytearray()
    make(client, Postgres, PG).dump(buf.extend, database="other", **kw)
    cmd, env = eng.calls[0]
    assert cmd == ["pg_dump", "-h", "127.0.0.1", "-U", "app", "-d", "other", "--no-owner", "--no-privileges", *flags]
    assert bytes(buf) == b"-- dump\n" and env["PGPASSWORD"] == "pw"


def test_postgres_dump_failure_raises(client, daemon):
    Engine(daemon, "pg", PG, queue((b"partial", b"pg_dump: error: permission denied\n", 1)))
    with pytest.raises(ServiceError, match="pg_dump exited 1: pg_dump: error: permission denied"):
        make(client, Postgres, PG).dump(bytearray().extend)


def test_postgres_script_uploads_runs_and_always_cleans_up(client, daemon):
    uploads = []
    daemon.on("PUT", "/containers/pg/archive", lambda s: uploads.append(s) or Reply(200, body=b""))
    eng = Engine(daemon, "pg", PG, queue((b"", b"ERROR: boom\n", 3), (b"", b"", 0), (b"CREATE\n", b"NOTICE\n", 0),
                                         (b"", b"", 0)))
    pg = make(client, Postgres, PG)
    with pytest.raises(ServiceError, match="boom"):
        pg.script(b"bad sql", single_transaction=True)
    assert pg.script(b"create table t()") == "CREATE\nNOTICE"
    path = eng.calls[0][0][eng.calls[0][0].index("-f") + 1]
    assert "--single-transaction" in eng.calls[0][0] and "--single-transaction" not in eng.calls[2][0]
    assert eng.calls[1][0] == ["rm", "-f", path] and eng.calls[3][0][:2] == ["rm", "-f"]
    assert uploads[0].query["path"] == "/tmp" and path.startswith("/tmp/aisb-") and path.endswith(".sql")


# --- mysql -----------------------------------------------------------------------------------

@pytest.mark.parametrize(("out", "columns", "rows", "affected"), [
    (b"", [], [], None),
    (xml(affected=3), [], [], 3),
    (xml(affected=-1), [], [], None),
    (xml([{"a": "1", "b": None}], affected=-1), ["a", "b"], [["1", None]], 1),
    (xml([{"a": "1"}], [{"x": "", "y": "&lt;t&gt;"}, {"x": "2", "y": None}], affected=-1),
     ["x", "y"], [["", "<t>"], ["2", None]], 2),       # several result sets: the last one is the answer
    (xml([], affected=-1), [], [], 0),                  # an empty result set
    (xml([{"a": "1"}]), ["a"], [["1"]], 1),             # no marker (e.g. the statement ended the session)
])
def test_mysql_xml_parsing(client, daemon, out, columns, rows, affected):
    Engine(daemon, "maria", MARIA, queue((out, b"", 0)))
    r = make(client, MySQL, MARIA).query("select 1")
    assert (r.columns, r.rows, r.affected) == (columns, rows, affected)


@pytest.mark.parametrize(("env", "user", "password", "database"), [
    (("MYSQL_ROOT_PASSWORD=r", "MYSQL_USER=app", "MYSQL_PASSWORD=p"), "root", "r", None),
    (("MYSQL_ALLOW_EMPTY_PASSWORD=yes", "MYSQL_DATABASE=d"), "root", None, "d"),
    (("MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1", "MARIADB_USER=app"), "root", None, None),
    (("MYSQL_USER=app", "MYSQL_PASSWORD=p", "MYSQL_DATABASE=d"), "app", "p", "d"),
    ((), "root", None, None),
])
def test_mysql_credentials(env, user, password, database):
    my = MySQL(None, Target.from_inspect(info("m", "mysql:8", env)))  # type: ignore[arg-type]
    assert (my.user(), my.password(), my.database()) == (user, password, database)


def test_mysql_query_modes_and_errors(client, daemon):
    eng = Engine(daemon, "maria", MARIA, queue(
        (xml(affected=2), b"", 0),
        (b"", b"ERROR 1064 (42000): You have an error\n", 1),
        (b"", b"some failure without an error line\n", 1)))
    my = make(client, MySQL, MARIA)
    assert my.query("update t set a = 1;;", readonly=False, database="other").affected == 2
    cmd = eng.calls[0][0]
    assert cmd[:5] == ["mariadb", "-u", "root", "--default-character-set=utf8mb4", "other"]
    assert cmd[-1] == f"update t set a = 1;\nSELECT ROW_COUNT() AS {MARK};"  # no READ ONLY prefix for writes
    with pytest.raises(ServiceError, match=r"^mysql: ERROR 1064 \(42000\): You have an error$"):
        my.query("selec 1")
    with pytest.raises(ServiceError, match="some failure without an error line"):
        my.query("select 1")


def test_mysql_no_client_binary(client, daemon):
    missing = (b"", b'exec: "x": executable file not found in $PATH', 127)
    eng = Engine(daemon, "maria", MARIA, queue(missing, missing))
    with pytest.raises(ServiceError, match=r"no client binary in container \(mariadb, mysql\)"):
        make(client, MySQL, MARIA).query("select 1")
    assert [c[0] for c, _ in eng.calls] == ["mariadb", "mysql"]


def test_mysql_catalog_reads(client, daemon):
    eng = Engine(daemon, "maria", MARIA, queue(
        (xml([{"name": "id", "type": "int", "nullable": "0", "default": None, "key": "PRI", "extra": ""},
              {"name": "n", "type": "text", "nullable": "1", "default": None, "key": "", "extra": ""}]), b"", 0),
        (xml([{"name": "PRIMARY", "unique": "1", "columns": "id"}]), b"", 0),
        (xml([{"name": "fk", "column": "c_id", "references": "c.id"}]), b"", 0),
        (xml([]), b"", 0),
        (xml([{"table_name": "c", "column_name": "id", "t": "int", "n": "NO", "d": None},
              {"table_name": "o", "column_name": "c_id", "t": "int", "n": "YES", "d": None}]), b"", 0),
        (xml([{"t": "c", "i": "PRIMARY", "d": "UNIQUE id"}]), b"", 0),
        (xml([{"t": "c", "c": "id"}]), b"", 0),
        (xml([{"n": "fk", "t": "o", "c": "c_id", "p": "c", "r": "id"}]), b"", 0),
        (xml([{"schema": "shop", "name": "c"}]), b"", 0)))
    my = make(client, MySQL, MARIA)
    d = my.describe("shop.o'x")
    assert [c["nullable"] for c in d["columns"]] == [False, True] and d["foreign_keys"][0]["references"] == "c.id"
    assert "table_schema = 'shop' and table_name = 'o''x'" in eng.sql()[0]
    with pytest.raises(ServiceError, match="no table 'gone'"):
        my.describe("gone")
    assert "table_schema = database()" in eng.sql()[3]
    rel = my.relations()
    assert rel.tables == ["c", "o"] and rel.fks[0].parent == "c" and rel.parents_first() == ["c", "o"]
    assert my.tables().rows == [["shop", "c"]]
    assert all(s.startswith("SET SESSION TRANSACTION READ ONLY; ") for s in eng.sql())


def test_mysql_activity_and_kill(client, daemon):
    eng = Engine(daemon, "maria", MARIA, queue(
        (xml([{"pid": "7", "user": "app", "query": "select sleep(9)"}]), b"", 0),
        (xml([{"name": "THREADS_CONNECTED", "value": "3"}, {"name": "UPTIME", "value": "x1"}]), b"", 0),
        (xml([{"max_connections": "151", "version": "11.4"}]), b"", 0),
        (xml(affected=0), b"", 0), (xml(affected=0), b"", 0)))
    my = make(client, MySQL, MARIA)
    a = my.activity()
    assert a["status"] == {"threads_connected": 3, "uptime": "x1"} and a["max_connections"] == "151"
    assert a["active"][0]["pid"] == "7"
    assert my.kill(7)["action"] == "cancel" and my.kill(8, terminate=True)["action"] == "terminate"
    assert eng.sql()[-2:] == [f"KILL QUERY 7;\nSELECT ROW_COUNT() AS {MARK};", f"KILL 8;\nSELECT ROW_COUNT() AS {MARK};"]


def test_mysql_activity_without_limits_row(client, daemon):
    Engine(daemon, "maria", MARIA, queue((xml([]), b"", 0), (xml([]), b"", 0), (xml([]), b"", 0)))
    assert make(client, MySQL, MARIA).activity() == {"status": {}, "active": []}


def test_mysql_dump_falls_back_between_binaries(client, daemon):
    eng = Engine(daemon, "maria", MARIA | {"Config": {**MARIA["Config"], "Image": "mysql:8"}},
                 queue((b"", b"not found", 127), (b"-- dump", b"", 0)))
    buf = bytearray()
    make(client, MySQL, info("maria", "mysql:8", ("MYSQL_ROOT_PASSWORD=r", "MYSQL_DATABASE=shop"))).dump(
        buf.extend, schema_only=True, tables=["a", "b"])
    assert [c[0] for c, _ in eng.calls] == ["mysqldump", "mariadb-dump"] and bytes(buf) == b"-- dump"
    assert eng.calls[1][0][-4:] == ["--no-data", "shop", "a", "b"] and eng.calls[1][1] == {"MYSQL_PWD": "r"}


def test_mysql_dump_errors(client, daemon):
    Engine(daemon, "maria", MARIA, queue((b"", b"Access denied", 2), (b"", b"", 127), (b"", b"", 127)))
    my = make(client, MySQL, MARIA)
    with pytest.raises(ServiceError, match="mariadb-dump exited 2: Access denied"):
        my.dump(bytearray().extend)
    with pytest.raises(ServiceError, match="no dump binary"):
        my.dump(bytearray().extend)
    nodb = make(client, MySQL, info("maria", "mariadb:11", ("MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1",)))
    with pytest.raises(ValueError, match="needs --database"):
        nodb.dump(bytearray().extend)


def test_mysql_script_passes_names_via_env_not_shell_text(client, daemon):
    daemon.on("PUT", "/containers/maria/archive", Reply(200, body=b""))
    eng = Engine(daemon, "maria", MARIA, queue((b"ok\n", b"", 0), (b"", b"", 0), (b"", b"", 0), (b"", b"", 0)))
    my = make(client, MySQL, MARIA)
    assert my.script(b"select 1", database="we'ird; rm -rf /") == "ok"
    cmd, env = eng.calls[0]
    assert cmd[:2] == ["sh", "-c"] and "rm -rf" not in cmd[2] and '"$AISB_DB"' not in cmd[2]
    assert env["AISB_DB"] == "we'ird; rm -rf /" and env["AISB_USER"] == "root" and env["MYSQL_PWD"] == "rootpw"
    assert eng.calls[1][0][:2] == ["rm", "-f"]
    nodb = make(client, MySQL, info("maria", "mariadb:11", ("MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1",)))
    nodb.script(b"select 1")
    assert "$AISB_DB" not in eng.calls[2][0][2] and "AISB_DB" not in eng.calls[2][1] and "MYSQL_PWD" not in eng.calls[2][1]
    with pytest.raises(ValueError, match="invalid database name"):
        my.script(b"select 1", database="--tee=/etc/cron.d/x")  # a positional name must not become an option
    assert eng.calls[-1][0][:2] == ["rm", "-f"] and len(eng.calls) == 5  # only the cleanup ran


# --- sqlite (copied out through the archive API) ------------------------------------------------

@pytest.fixture
def sqlite_box(daemon, tmp_path):
    path = tmp_path / "app.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        create table a (id integer primary key, name text not null default 'x');
        create table b (id integer primary key, a_id int references a, note text);
        create unique index b_note on b(note);
        insert into a values (1, 'one'); insert into b values (1, 1, 'n');
    """)
    conn.commit()
    conn.close()
    daemon.on("GET", "/containers/box/json", json=info("box", "alpine"))
    daemon.on("GET", "/containers/box/archive", lambda s: Reply(body=tar_of({"app.db": path.read_bytes()}),
                                                                content_type="application/x-tar")
              if s.query["path"] == "/data/app.db" else Reply(404, json={"message": "no such file"}))
    return path


def test_sqlite_adapter_catalog(client, sqlite_box):
    lite = make(client, SQLite, info("box", "alpine"), "/data/app.db")
    rel = lite.relations()
    assert rel.pk == {"a": ("id",), "b": ("id",)} and rel.fks[0].ref == ("id",)  # implicit ref -> parent's PK
    assert rel.parents_first() == ["a", "b"]
    s = lite.schema()
    assert s["a"]["columns"]["name"] == {"type": "TEXT", "nullable": False, "default": "'x'"}
    assert s["b"]["indexes"]["b_note"].startswith("CREATE UNIQUE INDEX")
    assert ["index", "b_note", "b"] in lite.tables().rows
    d = lite.describe("b")
    assert d["foreign_keys"] == [{"column": "a_id", "references": None}]  # implicit target column: NULL
    assert [c["nullable"] for c in d["columns"]] == [True, True, True]
    assert lite.count("a") == 1


def test_sqlite_adapter_errors(client, sqlite_box):
    lite = make(client, SQLite, info("box", "alpine"), "/data/app.db")
    with pytest.raises(ServiceError, match="no table \"x'; drop table a; --\""):
        lite.describe("x'; drop table a; --")
    with pytest.raises(ServiceError, match="sqlite: .*readonly|sqlite: attempt to write"):
        lite.query("delete from a")
    with pytest.raises(ServiceError, match="sqlite: no such table"):
        lite.query("select * from nope")
    missing = make(client, SQLite, info("box", "alpine"), "/nope.db")
    with pytest.raises(ServiceError, match="no file '/nope.db' in box"):
        missing.query("select 1")


# --- pure helpers ------------------------------------------------------------------------------

def test_relations_cycles_and_self_references():
    rel = Relations.build(["a", "b", "c"], [["a", "id"]], [["f1", "a", "b_id", "b", "id"], ["f2", "b", "a_id", "a", "id"],
                                                          ["f3", "c", "parent", "c", "id"], ["f4", "c", "x", "gone", "id"]])
    assert rel.parents_first() == ["a", "b", "c"]  # cycle: any order (FK checks are off during load)
    assert rel.roots() == ["c"]
    rel2 = Relations.build(["p", "k"], [["p", "id"]], [["k#0", "k", "p_id", "p", ""]])
    assert rel2.fks[0].ref == ("id",) and rel2.parents_first() == ["p", "k"]


def test_schema_and_diff():
    a = _schema([["t", "id", "int", "NO", None], ["t", "x", "text", "YES", "'d'"], ["u", "id", "int", 1, None]],
                [["t", "t_pkey", "pk"], ["gone", "i", "d"]])
    assert a["t"]["columns"]["x"] == {"type": "text", "nullable": True, "default": "'d'"} and "gone" not in a
    assert a["u"]["columns"]["id"]["nullable"] is True
    b = json.loads(json.dumps(a))
    assert diff_schema(a, b) == {"tables_only_in_a": [], "tables_only_in_b": [], "changed": {}, "identical": True}
    b["t"]["columns"]["x"]["type"] = "varchar"
    b["t"]["indexes"]["t_new"] = "idx"
    del b["u"]
    b["v"] = {"columns": {}, "indexes": {}}
    d = diff_schema(a, b)
    assert d["tables_only_in_a"] == ["u"] and d["tables_only_in_b"] == ["v"] and not d["identical"]
    assert d["changed"]["t"] == {"columns": {"different": {"x": {"a": a["t"]["columns"]["x"], "b": b["t"]["columns"]["x"]}}},
                                 "indexes": {"only_in_b": ["t_new"]}}


@pytest.mark.parametrize("name", ["d.sql", "d.sql.gz"])
def test_gzip_sink(tmp_path, name):
    write, close = gzip_sink(tmp_path / name)
    write(b"abc")
    write(b"def")
    assert close() == 6
    data = (tmp_path / name).read_bytes()
    assert (gzip.decompress(data) if name.endswith(".gz") else data) == b"abcdef"


def test_base_sql_surface_is_abstract():
    s = SQL(None, Target.from_inspect(info()))  # type: ignore[arg-type]
    for call in (lambda: s.query("x"), lambda: s.script(b""), lambda: s.tables(), lambda: s.describe("t"),
                 lambda: s.dump(print), lambda: s.activity(), lambda: s.schema(), lambda: s.relations(),
                 lambda: s.kill(1)):
        with pytest.raises(NotImplementedError):
            call()
    assert s.sequences() == []


def test_query_cli_formats_and_out_file(cli, daemon, tmp_path):
    conn = connect()
    conn.executescript("create table t (id int, name text); insert into t values (1, 'a,b'), (2, NULL);")
    Engine(daemon, "pg", PG, psql_on(conn))
    code, out, _ = cli("db", "query", "pg", "select id, name from t order by id", "--format", "csv")
    assert code == EXIT_OK and out["output"].splitlines() == ["id,name", '1,"a,b"', "2,"]
    code, out, _ = cli("db", "query", "pg", "select id from t order by id", "--limit", "1")
    assert out["rows"] == [{"id": 1}] and out["engine"] == "postgres"
    target = tmp_path / "rows.json"
    code, out, _ = cli("db", "query", "pg", "select id from t", "--out", str(target))
    assert code == EXIT_OK and out["written"] == str(target) and target.exists()
