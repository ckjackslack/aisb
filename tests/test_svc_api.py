"""The svc/db/redis/mongo/kafka/rabbit/es ops through the CLI: tiers (read ops open only read-only sessions,
mutating ops under --dry-run execute nothing, destroy needs --yes), argument checks, and each op's wiring."""

import csv
import gzip
import io
import json
import re
import sqlite3
import tarfile
from typing import Any

import pytest

from aisb.cli import EXIT_CONFIRM, EXIT_DOCKER, EXIT_OK, EXIT_UNMET, EXIT_USAGE
from test_services_more import MARIA, MARK, PG, Engine, cli_runner, info, psql_on, queue, xml
from test_svc_adapters import Api, published

from conftest import Reply, tar_of


@pytest.fixture
def cli(host, capsys):
    return cli_runner(host, capsys)


@pytest.fixture
def api():
    servers: list[Api] = []
    yield lambda routes: servers.append(Api(routes)) or servers[-1]
    for srv in servers:
        srv.close()


PLAN: dict[str, Any] = {"Node Type": "Hash Join", "Hash Cond": "(o.customer_id = c.id)", "Actual Total Time": 80, "Plans": [
    {"Node Type": "Seq Scan", "Relation Name": "orders", "Schema": "public", "Alias": "o", "Actual Total Time": 60,
     "Filter": "((status)::text = 'paid'::text)", "Rows Removed by Filter": 150000, "Plan Rows": 5000},
    {"Node Type": "Seq Scan", "Relation Name": "customers", "Schema": "public", "Alias": "c", "Actual Total Time": 5,
     "Plan Rows": 10}]}


def generic_psql(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
    """Any psql/pg_dump call: an empty but well-formed answer."""
    if cmd[0] == "pg_dump":
        return b"-- schema\n", b"", 0
    if "-A" in cmd:
        return b"{}\n", b"", 0
    return f"x\n{MARK} 0\n".encode(), b"", 0


def csv_cell(value: str) -> bytes:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows([["QUERY PLAN"], [value]])
    return (buf.getvalue() + f"{MARK} 1\n").encode()


def starts(daemon: Any) -> list[str]:
    return [p for m, p in daemon.calls("POST") if p.endswith("/start")]


# --- tier invariants -------------------------------------------------------------------------------

READ_OPS = [
    ("db", "query", "{ref}", "select 1"), ("db", "tables", "{ref}"), ("db", "describe", "{ref}", "t"),
    ("db", "activity", "{ref}"), ("db", "diff", "{ref}", "--other-database", "b"),
    ("db", "diff", "{ref}", "--other-database", "b", "--counts"), ("db", "sample", "{ref}", "{out}"),
    ("db", "dump", "{ref}", "{out}"), ("svc", "stats", "{ref}"), ("svc", "check", "{ref}"), ("svc", "url", "{ref}"),
]


@pytest.mark.parametrize("argv", READ_OPS, ids=lambda a: " ".join(a[:2] + a[3:4]))
def test_read_ops_on_postgres_only_open_read_only_sessions(cli, daemon, tmp_path, argv):
    uploads = []
    daemon.on("PUT", "/containers/pg/archive", lambda s: uploads.append(s) or Reply(200, body=b""))
    eng = Engine(daemon, "pg", PG, generic_psql)
    cli(*[a.format(ref="pg", out=tmp_path / "o.sql") for a in argv])
    assert eng.calls or argv[1] == "url"
    for cmd, env in eng.calls:
        assert cmd[0] in ("psql", "pg_dump"), cmd
        if cmd[0] == "psql":
            assert "-c default_transaction_read_only=on" in env["PGOPTIONS"], cmd
            assert "-f" not in cmd
    assert uploads == []


@pytest.mark.parametrize("argv", [a for a in READ_OPS if a[1] not in ("check",)], ids=lambda a: " ".join(a[:2] + a[3:4]))
def test_read_ops_on_mysql_only_run_read_only_statements(cli, daemon, tmp_path, argv):
    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        return (b"-- dump", b"", 0) if cmd[0] in ("mariadb-dump", "mysqldump") else (xml([]), b"", 0)
    eng = Engine(daemon, "maria", MARIA, handle)
    cli(*[a.format(ref="maria", out=tmp_path / "o.sql") for a in argv])
    for cmd, _ in eng.calls:
        assert cmd[0] in ("mariadb", "mariadb-dump"), cmd
        if cmd[0] == "mariadb":
            assert cmd[-1].startswith("SET SESSION TRANSACTION READ ONLY; "), cmd[-1]


MUTATING = [
    (("db", "exec", "pg", "delete from t"), EXIT_OK),
    (("db", "kill", "pg", "7"), EXIT_OK),
    (("db", "kill", "pg", "7", "--terminate"), EXIT_OK),
    (("db", "seed", "pg"), EXIT_OK),
    (("db", "clone", "pg", "pg-copy"), EXIT_OK),
    (("db", "advise", "pg", "select * from t"), EXIT_OK),
    (("svc", "reload", "web"), EXIT_OK),
    (("redis", "cmd", "cache", "--", "FLUSHALL"), EXIT_OK),
    (("mongo", "eval", "mdb", "return db.users.drop()"), EXIT_OK),
]


@pytest.mark.parametrize(("argv", "code"), MUTATING, ids=lambda a: " ".join(a[:2]) if isinstance(a, tuple) else "")
def test_mutating_ops_under_dry_run_execute_nothing(cli, daemon, argv, code):
    daemon.on("GET", "/containers/pg/json", json=PG)
    daemon.on("GET", "/containers/web/json", json=info("web", "nginx:1"))
    daemon.on("GET", "/containers/cache/json", json=info("cache", "redis:7"))
    daemon.on("GET", "/containers/mdb/json", json=info("mdb", "mongo:7"))
    cut = argv.index("--") if "--" in argv else len(argv)
    got, out, err = cli(*argv[:cut], "--dry-run", *argv[cut:])
    assert got == code, err
    assert out["status"] == "dry-run"
    assert starts(daemon) == [] and not any(m in ("PUT", "DELETE") for m, _ in daemon.calls())
    assert all(p.startswith("/containers/") and p.endswith("/json") for _, p in daemon.calls())


def test_rabbit_peek_dry_run_does_not_touch_the_queue(cli, daemon, api):
    srv = api({("POST", "/api/queues/%2F/q/get"): (200, [])})
    daemon.on("GET", "/containers/r/json", json=info("r", "rabbitmq:3-management", ports=published(15672, srv.port)))
    code, out, _ = cli("rabbit", "peek", "r", "q", "--dry-run")
    assert code == EXIT_OK and srv.seen == []  # a management "get" requeues: it is the mutation itself
    assert out["planned"] == [{"request": f"POST http://127.0.0.1:{srv.port}/api/queues/%2F/q/get",
                               "ackmode": "ack_requeue_true", "count": 5}]


def test_restore_is_destroy_tier(cli, daemon, tmp_path):
    dump = tmp_path / "d.sql.gz"
    dump.write_bytes(gzip.compress(b"create table t (x int);"))
    puts = []
    daemon.on("PUT", "/containers/pg/archive", lambda s: puts.append(s) or Reply(200, body=b""))
    eng = Engine(daemon, "pg", PG, queue((b"CREATE TABLE\n", b"", 0)))
    code, out, _ = cli("db", "restore", "pg", str(dump))
    assert code == EXIT_CONFIRM and eng.calls == [] and puts == []
    code, out, _ = cli("db", "restore", "pg", str(dump), "--yes")
    assert (code, out["output"]) == (EXIT_OK, "CREATE TABLE")
    assert "--single-transaction" in eng.calls[0][0] and eng.calls[1][0][:2] == ["rm", "-f"]
    with tarfile.open(fileobj=io.BytesIO(puts[0].body)) as tar:
        assert tar.extractfile(tar.getmembers()[0]).read() == b"create table t (x int);"  # type: ignore[union-attr]


# --- adapter resolution ------------------------------------------------------------------------------

def test_adapter_resolution_errors(cli, daemon):
    daemon.on("GET", "/containers/off/json", json=PG | {"State": {"Running": False}, "Name": "/off"})
    daemon.on("GET", "/containers/box/json", json=info("box", "busybox"))
    daemon.on("GET", "/containers/cache/json", json=info("cache", "redis:7"))
    code, _, err = cli("db", "query", "off", "select 1")
    assert code == EXIT_DOCKER and "is not running; start it first" in err
    code, _, err = cli("db", "query", "box", "select 1")
    assert code == EXIT_USAGE and "can't tell which service runs in 'box'" in err
    code, _, err = cli("db", "query", "cache", "select 1")
    assert code == EXIT_USAGE and "runs redis, which this command does not support" in err
    code, _, err = cli("db", "query", "box", "select 1", "--engine", "sqlite")
    assert code == EXIT_USAGE and "sqlite needs --path" in err


def test_engine_override(cli, daemon):
    eng = Engine(daemon, "box", info("box", "acme/db:1", ("MYSQL_ROOT_PASSWORD=r",)), queue((xml([{"a": "1"}]), b"", 0)))
    code, out, _ = cli("db", "query", "box", "select 1 as a", "--engine", "mysql")
    assert (code, out["rows"], out["engine"]) == (EXIT_OK, [{"a": 1}], "mysql") and eng.calls[0][0][0] == "mysql"


# --- db ops --------------------------------------------------------------------------------------------

def test_db_exec_arguments_and_file(cli, daemon, tmp_path):
    daemon.on("PUT", "/containers/pg/archive", Reply(200, body=b""))
    eng = Engine(daemon, "pg", PG, queue((b"INSERT 0 1\n", b"", 0), (b"", b"", 0), (b"UPDATE 1\n", b"", 0), (b"", b"", 0)))
    assert cli("db", "exec", "pg")[0] == EXIT_USAGE
    script = tmp_path / "m.sql"
    script.write_text("insert into t values (1);")
    assert cli("db", "exec", "pg", "select 1", "--file", str(script))[0] == EXIT_USAGE
    code, out, _ = cli("db", "exec", "pg", "--file", str(script), "--single-transaction")
    assert (code, out) == (EXIT_OK, {"engine": "postgres", "file": str(script), "output": "INSERT 0 1"})
    assert "--single-transaction" in eng.calls[0][0]
    code, out, _ = cli("db", "exec", "pg", "--file", str(script))
    assert "--single-transaction" not in eng.calls[2][0]


def test_db_dump_writes_gzip_and_cleans_up_on_failure(cli, daemon, tmp_path):
    eng = Engine(daemon, "pg", PG, queue((b"-- dump\nCREATE TABLE t();\n", b"", 0), (b"-- part", b"pg_dump: error: lost\n", 1)))
    target = tmp_path / "d.sql.gz"
    code, out, _ = cli("db", "dump", "pg", str(target), "--schema-only", "--table", "t")
    assert code == EXIT_OK and gzip.decompress(target.read_bytes()) == b"-- dump\nCREATE TABLE t();\n"
    assert out["dump_bytes"] == 26 and out["file_bytes"] == target.stat().st_size
    assert eng.calls[0][0][-3:] == ["--schema-only", "-t", "t"]
    bad = tmp_path / "bad.sql"
    code, _, err = cli("db", "dump", "pg", str(bad))
    assert code == EXIT_DOCKER and "lost" in err and not bad.exists()


def test_db_tables_describe_diff_on_sqlite_files(cli, daemon, tmp_path):
    files = {}
    for name, ddl in (("a.db", "create table t (id int primary key, x text); create table only_a (i int);"
                                "insert into t values (1, 'a'), (2, 'b');"),
                      ("b.db", "create table t (id int primary key, x int, y text); insert into t values (1, 1, 'q');")):
        conn = sqlite3.connect(tmp_path / name)
        conn.executescript(ddl)
        conn.commit()
        conn.close()
        files[f"/data/{name}"] = (tmp_path / name).read_bytes()
    daemon.on("GET", "/containers/box/json", json=info("box", "alpine"))
    daemon.on("GET", "/containers/box/archive", lambda s: Reply(body=tar_of({"f": files[s.query["path"]]}),
                                                                content_type="application/x-tar")
              if s.query["path"] in files else Reply(404, json={"message": "missing"}))
    code, out, _ = cli("db", "tables", "box", "--path", "/data/a.db", "--format", "csv")
    assert code == EXIT_OK and "table,only_a,only_a" in out["output"]
    code, out, _ = cli("db", "describe", "box", "t", "--path", "/data/a.db")
    assert [c["name"] for c in out["columns"]] == ["id", "x"] and out["engine"] == "sqlite"
    assert cli("db", "diff", "box")[0] == EXIT_USAGE
    code, out, _ = cli("db", "diff", "box", "--path", "/data/a.db", "--other-path", "/data/b.db", "--counts")
    assert code == EXIT_OK and out["tables_only_in_a"] == ["only_a"] and not out["identical"]
    assert out["changed"]["t"]["columns"]["only_in_b"] == ["y"] and out["row_counts"] == {"t": {"a": 2, "b": 1}}
    assert (out["a"], out["b"]) == ("box//data/a.db", "box//data/b.db")


def test_db_diff_across_postgres_containers_counts(cli, daemon):
    conn_a, conn_b = sqlite3.connect(":memory:", check_same_thread=False), sqlite3.connect(":memory:", check_same_thread=False)
    for conn, n in ((conn_a, 3), (conn_b, 3)):
        conn.execute("create table t (id int)")
        conn.executemany("insert into t values (?)", [(i,) for i in range(n)])

    def catalog(conn: sqlite3.Connection) -> Any:
        base = psql_on(conn)

        def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
            sql = cmd[cmd.index("-c") + 1]
            if "information_schema.columns" in sql:
                return f"t,c,dt,n,d\nt,id,integer,YES,\\N\n{MARK} 1\n".encode(), b"", 0
            if "pg_indexes" in sql:
                return f"t,n,d\n{MARK} 0\n".encode(), b"", 0
            return base(cmd, env)
        return handle
    Engine(daemon, "pg", PG, catalog(conn_a))
    other = info("pg2", env=("POSTGRES_PASSWORD=x",))
    Engine(daemon, "pg2", other, catalog(conn_b))
    code, out, _ = cli("db", "diff", "pg", "pg2", "--counts")
    assert code == EXIT_OK and out["identical"] and out["row_counts"] == {} and out["a"] == "pg/shop" and out["b"] == "pg2/postgres"


def test_db_activity_and_kill(cli, daemon):
    eng = Engine(daemon, "pg", PG, queue((b'{"active": [{"pid": 9}]}', b"", 0), (f"ok\nt\n{MARK} 1\n".encode(), b"", 0)))
    code, out, _ = cli("db", "activity", "pg")
    assert (code, out) == (EXIT_OK, {"engine": "postgres", "active": [{"pid": 9}]})
    code, out, _ = cli("db", "kill", "pg", "9", "--terminate")
    assert (code, out) == (EXIT_OK, {"pid": 9, "action": "terminate", "ok": True})
    assert eng.sql()[-1] == "select pg_terminate_backend(9) as ok"


def clone_env(daemon: Any, *, running: bool = True) -> dict[str, Any]:
    """A source postgres with a *_FILE secret and a clone container that becomes ready."""
    src = info("pg", env=("POSTGRES_PASSWORD_FILE=/run/secrets/pw", "POSTGRES_DB=shop"))
    daemon.on("GET", "/containers/pg/archive", Reply(body=tar_of({"pw": b"hunter2\n"}), content_type="application/x-tar"))
    created: dict[str, Any] = {}
    daemon.on("POST", "/containers/create", lambda s: created.update(s.query, body=s.body) or Reply(201, json={"Id": "c1"}))
    daemon.on("POST", r"/containers/[\w-]+/start", Reply(204, body=b""))
    daemon.on("PUT", r"/containers/[\w-]+/archive", Reply(200, body=b""))
    daemon.on("GET", r"/containers/[\w-]+/logs", Reply(body=b"", content_type="application/vnd.docker.raw-stream"))
    daemon.on("DELETE", r"/containers/[\w-]+", lambda s: created.update(deleted=s.path) or Reply(204, body=b""))
    Engine(daemon, "pg", src, lambda cmd, env: (b"-- full dump\n", b"", 0) if cmd[0] == "pg_dump" else (b"", b"", 0))
    created["src"] = src
    created["clone_info"] = info("x", env=("POSTGRES_PASSWORD=hunter2", "POSTGRES_DB=shop"), running=running) | (
        {} if running else {"State": {"Running": False, "Status": "exited", "ExitCode": 3}})
    return created


def test_db_clone_resolves_file_secrets_and_loads_dump(cli, daemon):
    created = clone_env(daemon)
    eng = Engine(daemon, "pg-copy", created["clone_info"] | {"Name": "/pg-copy"},
                 lambda cmd, env: (f"ok\n1\n{MARK} 1\n".encode() if "-c" in cmd else b"", b"", 0))
    code, out, _ = cli("db", "clone", "pg", "pg-copy", "--port", "15432", "--within", "20")
    assert code == EXIT_OK and out["ok"] and out["dump_bytes"] == len(b"-- full dump\n") and out["engine"] == "postgres"
    body = created["body"]
    assert created["name"] == "pg-copy" and "POSTGRES_PASSWORD=hunter2" in body["Env"]
    assert not any(e.startswith("POSTGRES_PASSWORD_FILE") for e in body["Env"])
    assert body["Labels"]["aisb.clone-of"] == "pg" and "15432" in json.dumps(body["HostConfig"])
    assert any("-f" in cmd for cmd, _ in eng.calls)  # the dump was loaded into the clone


def test_db_clone_reports_unready_clone(cli, daemon):
    created = clone_env(daemon, running=False)
    daemon.on("GET", "/containers/pg-copy/json", json=created["clone_info"])
    code, out, _ = cli("db", "clone", "pg", "pg-copy", "--within", "5")
    assert code == EXIT_UNMET and out["reason"] == "clone did not become ready"
    assert out["ready"]["reason"] == "container stopped (exit code 3)"


def test_db_advise_argument_checks_and_index_report(cli, daemon):
    Engine(daemon, "maria", MARIA, queue())
    assert "supports Postgres" in cli("db", "advise", "maria")[2]
    eng = Engine(daemon, "pg", PG, queue(
        (f"table,columns,references\norders,customer_id,customers\n{MARK} 1\n".encode(), b"", 0),
        (f"table,index,bytes\norders,o_old,8192\n{MARK} 1\n".encode(), b"", 0)))
    code, _, err = cli("db", "advise", "pg", "delete from orders")
    assert code == EXIT_USAGE and "read queries only" in err and eng.calls == []
    code, out, _ = cli("db", "advise", "pg")
    assert out["unindexed_foreign_keys"] == [{"table": "orders", "columns": "customer_id", "references": "customers",
                                              "ddl": "CREATE INDEX CONCURRENTLY ON orders (customer_id);"}]
    assert out["unused_indexes"] == [{"table": "orders", "index": "o_old", "bytes": 8192}]


def advise_psql(timing: dict[int, float], existing: str) -> Any:
    """psql on the advise clone: EXPLAIN timings depend on how many candidate indexes currently exist."""
    state = {"indexes": 0}

    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        if "-c" not in cmd:
            return b"", b"", 0
        sql = cmd[cmd.index("-c") + 1]
        if sql.startswith("CREATE INDEX"):
            state["indexes"] += 1
        elif sql.startswith("DROP INDEX"):
            state["indexes"] -= 1
        if sql.startswith("EXPLAIN"):
            return csv_cell(json.dumps([{"Execution Time": timing[state["indexes"]], "Plan": PLAN}])), b"", 0
        if "pg_indexes" in sql:
            return f"indexdef\n{existing}\n{MARK} 1\n".encode(), b"", 0
        return f"ok\n1\n{MARK} 1\n".encode(), b"", 0
    return handle


ADVISE_SQL = "select * from orders o join customers c on o.customer_id = c.id where status = 'paid'"


def test_db_advise_measures_candidates_on_a_disposable_clone(cli, daemon):
    created = clone_env(daemon)
    clone_psql = advise_psql({0: 100.0, 1: 10.0, 2: 5.0}, "CREATE INDEX x ON public.customers USING btree (id)")
    eng = Engine(daemon, r"pg-advise-\d+", created["clone_info"] | {"Name": "/pg-advise-1"}, clone_psql, key="adv")
    code, out, _ = cli("db", "advise", "pg", ADVISE_SQL, "--runs", "1")
    assert code == EXIT_OK and out["baseline_ms"] == 100.0
    assert [(c["speedup"], c["ms"]) for c in out["candidates"]] == [(10.0, 10.0), (10.0, 10.0)]
    assert out["recommended"] == ['CREATE INDEX CONCURRENTLY ON public.orders ("status");',
                                  'CREATE INDEX CONCURRENTLY ON public.orders ("customer_id");']
    assert out["combined"] == {"ms": 5.0, "speedup": 20.0} and out["verdict"].startswith("2 index(es) measured faster")
    assert out["clone"] is None and re.fullmatch(r"/containers/pg-advise-\d+", created["deleted"])
    assert all("read_only" not in env.get("PGOPTIONS", "") for cmd, env in eng.calls
               if "-c" in cmd and cmd[cmd.index("-c") + 1].startswith(("CREATE", "DROP", "ANALYZE")))


def test_db_advise_skips_existing_indexes_and_reports_no_winner(cli, daemon):
    created = clone_env(daemon)
    Engine(daemon, r"pg-advise-\d+", created["clone_info"] | {"Name": "/pg-advise-1"},
           advise_psql({0: 100.0, 1: 95.0}, "CREATE INDEX o_s ON public.orders USING btree (status)"), key="adv")
    code, out, _ = cli("db", "advise", "pg", ADVISE_SQL, "--runs", "3", "--keep-clone")
    assert code == EXIT_OK and [c["index"] for c in out["candidates"]] == [
        'CREATE INDEX CONCURRENTLY ON public.orders ("customer_id");']  # (status) already exists: not re-tried
    assert out["recommended"] == [] and out["combined"] is None
    assert out["verdict"] == "no candidate index made this query meaningfully faster"
    assert re.fullmatch(r"pg-advise-\d+", out["clone"]) and "deleted" not in created


# --- svc ------------------------------------------------------------------------------------------------

def test_svc_list_survives_unreadable_secret_file(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "a1"}])
    daemon.on("GET", "/containers/a1/json", json=info("pg", env=("POSTGRES_PASSWORD_FILE=/run/secrets/gone",),
                                                      ports=published(5432, 5432)))
    daemon.on("GET", "/containers/pg/archive", Reply(404, json={"message": "no such file"}))
    code, out, _ = cli("svc", "list")
    assert code == EXIT_OK and out[0]["kind"] == "postgres" and out[0]["url"].startswith("<unavailable: ")
    assert "note" not in out[0]


def test_svc_url_reveal_and_hostname(cli, daemon):
    daemon.on("GET", "/containers/pg/json", json=info("pg", env=("POSTGRES_PASSWORD=p@ss",), ports=published(5432, 6543)))
    code, out, _ = cli("svc", "url", "pg", "--reveal", "--hostname", "db.internal")
    assert out["url"] == "postgresql://postgres:p%40ss@db.internal:6543/postgres" and out["password"] == "p@ss"
    code, out, _ = cli("svc", "url", "pg")
    assert out["password"] == "***" and "p%40ss" not in json.dumps(out)


def test_svc_stats_check_reload_capabilities(cli, daemon):
    eng = Engine(daemon, "cache", info("cache", "redis:7"), queue((b"# Server\r\nredis_version:7.2.4\r\n", b"", 0)))
    code, out, _ = cli("svc", "stats", "cache")
    assert code == EXIT_OK and (out["kind"], out["version"]) == ("redis", "7.2.4")
    assert "has no config check" in cli("svc", "check", "cache")[2]
    assert "has no graceful reload" in cli("svc", "reload", "cache")[2]
    assert len(eng.calls) == 1
    Engine(daemon, "web", info("web", "nginx:1"), queue((b"", b"nginx: configuration file ok\n", 0), (b"", b"", 0),
                                                         (b"", b"", 0)))
    assert "has no stats support" in cli("svc", "stats", "web")[2]
    code, out, _ = cli("svc", "check", "web")
    assert (code, out["ok"], out["output"]) == (EXIT_OK, True, "nginx: configuration file ok")
    code, out, _ = cli("svc", "reload", "web", "--force")  # skips the check
    assert (code, out) == (EXIT_OK, {"ok": True, "kind": "nginx", "reloaded": True, "via": "nginx -s reload"})


def test_svc_reload_runs_check_then_reload(cli, daemon):
    eng = Engine(daemon, "web", info("web", "httpd:2.4"), queue((b"Syntax OK\n", b"", 0), (b"", b"", 0)))
    code, out, _ = cli("svc", "reload", "web")
    assert code == EXIT_OK and out["via"] == "httpd -k graceful"
    assert [c for c, _ in eng.calls] == [["httpd", "-t"], ["httpd", "-k", "graceful"]]


def test_svc_ready_without_probe_and_timeout(cli, daemon):
    daemon.on("GET", "/containers/box/json", json=info("box", "busybox"))
    daemon.on("GET", r"/containers/\w+/logs", Reply(body=b"", content_type="application/vnd.docker.raw-stream"))
    code, _, err = cli("svc", "ready", "box", "--within", "1")
    assert code == EXIT_USAGE and "no readiness probe" in err
    Engine(daemon, "pg", PG, lambda cmd, env: (b"", b"psql: error: connection refused\n", 2))
    code, out, _ = cli("svc", "ready", "pg", "--within", "0.05", "--interval", "0.01")
    assert code == EXIT_UNMET and out["reason"] == "not ready after 0.05s" and "connection refused" in out["last_error"]


# --- redis / mongo / kafka / rabbit / es ops -----------------------------------------------------------------

def test_redis_ops(cli, daemon):
    eng = Engine(daemon, "cache", info("cache", "redis:7"), queue(
        (b"# Memory\r\nused_memory:10\r\n", b"", 0), (b"# Server\r\nredis_version:7.2.4\r\n", b"", 0),
        (b'{"key": "k", "type": "string", "value": "v"}', b"", 0)))
    assert cli("redis", "info", "cache", "--section", "memory")[1] == {"memory": {"used_memory": 10}}
    assert cli("redis", "info", "cache", "--raw")[1] == {"server": {"redis_version": "7.2.4"}}
    assert cli("redis", "get", "cache", "k", "--limit", "3")[1]["value"] == "v"
    assert eng.calls[0][0][-2:] == ["INFO", "memory"] and eng.calls[2][0][-2:] == ["k", "3"]
    assert "usage: aisb redis cmd" in cli("redis", "cmd", "cache")[2]


def test_mongo_ops(cli, daemon):
    eng = Engine(daemon, "mdb", info("mdb", "mongo:7"), queue(
        (b'__AISB__[{"name": "u", "type": "collection", "count": 1}]', b"", 0),
        (b'__AISB__[{"_id": 1, "a": "x"}, {"_id": 2, "b": true}]', b"", 0),
        (b"__AISB__3", b"", 0)))
    assert cli("mongo", "collections", "mdb", "--database", "shop")[1] == [{"name": "u", "type": "collection", "count": 1}]
    assert eng.calls[0][1]["AISB_DB"] == "shop"
    code, out, _ = cli("mongo", "find", "mdb", "users", "--format", "csv")
    assert out == {"count": 2, "output": "_id,a,b\n1,x,\n2,,true\n"}
    assert cli("mongo", "eval", "mdb", "return 3")[1] == {"result": 3}
    assert "return 3" in eng.calls[2][0][-1]


def test_kafka_and_rabbit_ops(cli, daemon, api):
    Engine(daemon, "k", info("k", "apache/kafka:3.8.0"), queue(
        (b"Topic: t\tTopicId: x\tPartitionCount: 1\tReplicationFactor: 1\tConfigs: \n", b"", 0),
        (b"GROUP TOPIC PARTITION LAG CONSUMER-ID\ng t 0 7 -\n", b"", 0)))
    assert cli("kafka", "topics", "k", "--all")[1] == [{"topic": "t", "partitions": 1, "replication": 1, "under_replicated": 0}]
    assert cli("kafka", "groups", "k")[1][0] | {"topics": None} == {
        "group": "g", "lag": 7, "topics": None, "members": 0, "partitions": 1, "idle": True}
    srv = api({("POST", "/api/queues/v%2Fh/q/get"): (200, [{"payload": "p", "payload_encoding": "string"}])})
    rabbit = info("r", "rabbitmq:3-management", ports=published(15672, srv.port))
    Engine(daemon, "r", rabbit, queue((b'[{"name": "amq.direct", "type": "direct", "durable": true}]', b"", 0)))
    assert cli("rabbit", "exchanges", "r", "--vhost", "v/h")[1] == [{"name": "amq.direct", "type": "direct", "durable": True}]
    code, out, _ = cli("rabbit", "peek", "r", "q", "--vhost", "v/h", "--limit", "1")
    assert code == EXIT_OK and out["count"] == 1 and out["messages"][0]["payload"] == "p"


def test_es_ops(cli, daemon, api):
    srv = api({("GET", "/_cat/indices"): (200, [{"index": "books", "health": "green", "docs.count": "2",
                                                  "store.size": "10", "pri": "1", "rep": "0"}])})
    daemon.on("GET", "/containers/es/json", json=info("es", "elasticsearch:8", ports=published(9200, srv.port)))
    code, out, _ = cli("es", "indices", "es", "--format", "markdown")
    assert code == EXIT_OK and "| books | green | 2 | 10 | 1 | 0 |" in out["output"]
    code, _, err = cli("es", "search", "es", "books", "{not json")
    assert code == EXIT_USAGE and "query must be JSON" in err and len(srv.seen) == 1
