"""SQL engines: Postgres and MySQL/MariaDB via their CLIs inside the container, SQLite via a host-side copy."""

import csv
import gzip
import io
import json
import re
import shutil
import sqlite3
import tarfile
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import NotFound
from ..util import q
from .base import Adapter, ServiceError, Target, register
from .fmt import infer

_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"
_MARK = "__aisb_rows__"


def lit(s: str, *, backslash: bool = False) -> str:
    """SQL string literal; MySQL (backslash=True) also treats backslash as an escape character."""
    if backslash:
        s = s.replace("\\", "\\\\")
    return "'" + s.replace("'", "''") + "'"


@dataclass(slots=True)
class Result:
    columns: list[str]
    rows: list[list[Any]]
    affected: int | None = None
    elapsed_ms: int = 0


class SQL(Adapter):
    """Common surface for SQL engines."""
    dialect: str = ""

    def query(self, sql: str, *, readonly: bool = True, database: str | None = None, seconds: int = 30) -> Result:
        raise NotImplementedError

    def script(self, data: bytes, *, database: str | None = None, single_transaction: bool = False) -> str:
        raise NotImplementedError

    def tables(self, database: str | None = None) -> Result:
        raise NotImplementedError

    def describe(self, table: str, database: str | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def dump(self, sink: Callable[[bytes], object], *, database: str | None = None, schema_only: bool = False,
             tables: list[str] | None = None) -> None:
        raise NotImplementedError

    def activity(self) -> dict[str, Any]:
        raise NotImplementedError

    def schema(self, database: str | None = None) -> dict[str, dict[str, Any]]:
        """{table: {"columns": {name: {type, nullable, default}}, "indexes": {name: definition}}} in bulk."""
        raise NotImplementedError

    def ident(self, name: str) -> str:
        return ".".join('"' + part.replace('"', '""') + '"' for part in name.split("."))

    def count(self, table: str, database: str | None = None) -> int:
        r = self.query(f"select count(*) as n from {self.ident(table)}", database=database, seconds=120)
        return int(r.rows[0][0])

    def kill(self, pid: int, *, terminate: bool = False) -> dict[str, Any]:
        raise NotImplementedError

    def probe(self) -> str:
        r = self.query("select 1 as ok", seconds=5)
        if r.rows != [["1"]] and r.rows != [[1]]:
            raise ServiceError(f"{self.kind}: unexpected probe result {r.rows}")
        return "select 1"

    # --- shared helpers ----------------------------------------------------------------------
    def upload(self, data: bytes, suffix: str = ".sql") -> str:
        """Put bytes into /tmp in the container through the archive API; returns the path."""
        name = f"aisb-{uuid.uuid4().hex[:12]}{suffix}"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
        self.ctr.t.json("PUT", f"/containers/{q(self.t.name)}/archive", query={"path": "/tmp"},
                        data=buf.getvalue(), content_type="application/x-tar")
        return f"/tmp/{name}"

    def _describe_rows(self, sql: str, database: str | None) -> list[dict[str, Any]]:
        r = self.query(sql, database=database)
        return [dict(zip(r.columns, row)) for row in infer(r.columns, r.rows)]


def _timed(fn: Callable[[], Result]) -> Result:
    start = time.monotonic()
    r = fn()
    r.elapsed_ms = int((time.monotonic() - start) * 1000)
    return r


@register
class Postgres(SQL):
    kind = "postgres"
    dialect = "postgres"
    image_rx = re.compile(r"postgres|postgis|timescale|pgvector|supabase")
    env_hints = ("POSTGRES_", "POSTGRESQL_")
    ports = (5432,)
    scheme = "postgresql"

    def user(self) -> str:
        return self.secret("POSTGRES_USER", "POSTGRESQL_USERNAME", "POSTGRESQL_USER") or "postgres"

    def password(self) -> str | None:
        return self.secret("POSTGRES_PASSWORD", "POSTGRESQL_PASSWORD")

    def database(self) -> str:
        return self.secret("POSTGRES_DB", "POSTGRESQL_DATABASE") or self.user()

    def _conn(self, database: str | None) -> list[str]:
        # With a known password use TCP (works for official and bitnami images); otherwise the trusted local socket.
        host = ["-h", "127.0.0.1"] if self.password() else []
        return [*host, "-U", self.user(), "-d", database or self.database()]

    def _env(self, *, readonly: bool = False, seconds: int = 0) -> dict[str, str | None]:
        opts = [*(["-c default_transaction_read_only=on"] if readonly else []),
                *([f"-c statement_timeout={seconds * 1000}"] if seconds else [])]
        return {"PGPASSWORD": self.password(), "PGAPPNAME": "aisb", "PGCONNECT_TIMEOUT": "10",
                "PGOPTIONS": " ".join(opts) or None}

    def query(self, sql: str, *, readonly: bool = True, database: str | None = None, seconds: int = 30) -> Result:
        def go() -> Result:
            argv = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", *self._conn(database), "--csv", "-P", "null=\\N",
                    "-c", sql, "-c", f"\\echo {_MARK} :ROW_COUNT"]
            out = self.run(argv, env=self._env(readonly=readonly, seconds=seconds)).stdout
            body, found, tail = out.rpartition(f"{_MARK} ")
            if not found:
                body, tail = out, ""
            rows = list(csv.reader(io.StringIO(body)))
            columns = rows[0] if rows else []
            data = [[None if v == "\\N" else v for v in r] for r in rows[1:]]
            count = tail.strip()
            return Result(columns, data, int(count) if count.lstrip("-").isdigit() else None)
        return _timed(go)

    def scalar_json(self, sql: str, database: str | None = None) -> Any:
        out = self.run(["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", *self._conn(database), "-c", sql],
                       env=self._env(readonly=True, seconds=30)).stdout.strip()
        return json.loads(out) if out else None

    def script(self, data: bytes, *, database: str | None = None, single_transaction: bool = False) -> str:
        path = self.upload(data)
        try:
            argv = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", *self._conn(database), "-f", path,
                    *(["--single-transaction"] if single_transaction else [])]
            res = self.run(argv, env=self._env())
            return (res.stdout + res.stderr).strip()
        finally:
            self.run(["rm", "-f", path], check=False)

    def tables(self, database: str | None = None) -> Result:
        return self.query(
            "select n.nspname as schema, c.relname as name, case c.relkind when 'r' then 'table' when 'v' then 'view' "
            "when 'm' then 'matview' when 'p' then 'partitioned' when 'f' then 'foreign' end as kind, "
            "case when c.reltuples < 0 then null else c.reltuples::bigint end as est_rows, pg_total_relation_size(c.oid) as bytes "
            "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where c.relkind in ('r','v','m','p','f') and n.nspname not in ('pg_catalog','information_schema') "
            "and n.nspname not like 'pg_toast%' order by 1, 2", database=database)

    def describe(self, table: str, database: str | None = None) -> dict[str, Any]:
        schema, _, name = table.rpartition(".")
        s = lit(schema) if schema else "current_schema()"
        cols = self._describe_rows(
            "select column_name as name, data_type as type, is_nullable = 'YES' as nullable, column_default as default "
            f"from information_schema.columns where table_schema = {s} and table_name = {lit(name)} "
            "order by ordinal_position", database)
        if not cols:
            raise ServiceError(f"postgres: no table {table!r} (use `db tables` to list)")
        for c in cols:
            c["nullable"] = c["nullable"] == "t"
        constraints = self._describe_rows(
            "select c.conname as name, case c.contype when 'p' then 'primary key' when 'f' then 'foreign key' "
            "when 'u' then 'unique' when 'c' then 'check' else c.contype::text end as kind, "
            "pg_get_constraintdef(c.oid) as definition from pg_constraint c "
            "join pg_class r on r.oid = c.conrelid join pg_namespace n on n.oid = r.relnamespace "
            f"where n.nspname = {s} and r.relname = {lit(name)} order by 2, 1", database)
        indexes = self._describe_rows(
            f"select indexname as name, indexdef as definition from pg_indexes where schemaname = {s} "
            f"and tablename = {lit(name)} order by 1", database)
        return {"table": table, "columns": cols, "constraints": constraints, "indexes": indexes}

    def dump(self, sink: Callable[[bytes], object], *, database: str | None = None, schema_only: bool = False,
             tables: list[str] | None = None) -> None:
        argv = ["pg_dump", *self._conn(database), "--no-owner", "--no-privileges",
                *(["--schema-only"] if schema_only else []), *[a for t in tables or [] for a in ("-t", t)]]
        self._stream(argv, sink, self._env())

    def _stream(self, argv: list[str], sink: Callable[[bytes], object], env: dict[str, str | None]) -> None:
        err = bytearray()
        code = self.ctr.stream_in(self.t.name, argv, sink, stderr=err.extend,
                                  env=[f"{k}={v}" for k, v in env.items() if v is not None])
        if code not in (0, None):
            raise ServiceError(f"{self.kind}: {argv[0]} exited {code}: {err.decode(errors='replace').strip()[-2000:]}")

    def activity(self) -> dict[str, Any]:
        return self.scalar_json("""
            select json_build_object(
              'connections', (select json_object_agg(coalesce(state, 'background'), n)
                              from (select state, count(*) n from pg_stat_activity group by 1) s),
              'max_connections', current_setting('max_connections')::int,
              'database_bytes', pg_database_size(current_database()),
              'cache_hit_percent', (select round(sum(blks_hit) * 100.0 / nullif(sum(blks_hit) + sum(blks_read), 0), 2)
                                    from pg_stat_database),
              'locks_waiting', (select count(*) from pg_locks where not granted),
              'active', (select coalesce(json_agg(a order by a.seconds desc), '[]'::json) from (
                  select pid, usename as user, datname as db, state, wait_event_type as waiting_on,
                         extract(epoch from now() - query_start)::int as seconds,
                         pg_blocking_pids(pid) as blocked_by, left(query, 300) as query
                  from pg_stat_activity
                  where state <> 'idle' and pid <> pg_backend_pid() and backend_type = 'client backend') a))""")

    _USER_SCHEMAS = "not in ('pg_catalog', 'information_schema') and {col} not like 'pg_toast%'"

    def schema(self, database: str | None = None) -> dict[str, dict[str, Any]]:
        cols = self.query(
            "select c.table_schema || '.' || c.table_name, c.column_name, c.data_type, c.is_nullable, c.column_default "
            "from information_schema.columns c join information_schema.tables t using (table_schema, table_name) "
            f"where t.table_type = 'BASE TABLE' and c.table_schema {self._USER_SCHEMAS.format(col='c.table_schema')} "
            "order by 1, c.ordinal_position", database=database)
        idx = self.query(f"select schemaname || '.' || tablename, indexname, indexdef from pg_indexes "
                         f"where schemaname {self._USER_SCHEMAS.format(col='schemaname')}", database=database)
        return _schema(cols.rows, idx.rows)

    def kill(self, pid: int, *, terminate: bool = False) -> dict[str, Any]:
        fn = "pg_terminate_backend" if terminate else "pg_cancel_backend"
        r = self.query(f"select {fn}({int(pid)}) as ok", readonly=False)
        return {"pid": pid, "action": "terminate" if terminate else "cancel", "ok": bool(r.rows) and r.rows[0][0] == "t"}

    def check(self) -> dict[str, Any]:
        r = self.query("select sourcefile, sourceline, name, error from pg_file_settings where error is not null")
        return {"ok": not r.rows, "errors": [dict(zip(r.columns, row)) for row in r.rows]}

    def reload(self) -> dict[str, Any]:
        self.query("select pg_reload_conf()", readonly=False)
        return {"reloaded": True, "via": "pg_reload_conf()"}


@register
class MySQL(SQL):
    kind = "mysql"
    dialect = "mysql"
    image_rx = re.compile(r"^(mysql|mariadb|percona|mysql-server)")
    env_hints = ("MYSQL_", "MARIADB_")
    ports = (3306,)
    scheme = "mysql"
    _bin: str | None = None

    @property
    def mariadb(self) -> bool:
        return "mariadb" in self.t.image

    def _root_pw(self) -> str | None:
        return self.secret("MARIADB_ROOT_PASSWORD", "MYSQL_ROOT_PASSWORD")

    def _root_ok(self) -> bool:
        return self._root_pw() is not None or any(
            self.t.env.get(k, "").lower() in ("yes", "1", "true")
            for k in ("MYSQL_ALLOW_EMPTY_PASSWORD", "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD"))

    def user(self) -> str:
        return "root" if self._root_ok() else (self.secret("MARIADB_USER", "MYSQL_USER") or "root")

    def password(self) -> str | None:
        return self._root_pw() if self.user() == "root" else self.secret("MARIADB_PASSWORD", "MYSQL_PASSWORD")

    def database(self) -> str | None:
        return self.secret("MARIADB_DATABASE", "MYSQL_DATABASE")

    def _client(self, tool: str = "client") -> list[str]:
        names = {"client": ("mariadb", "mysql"), "dump": ("mariadb-dump", "mysqldump")}[tool]
        return list(names if self.mariadb else names[::-1])

    def _run(self, tool: str, args: list[str]) -> Any:
        """Run the first client binary that exists (mariadb 11 dropped the mysql names)."""
        last = None
        for binary in self._client(tool):
            res = self.run([binary, *args], env={"MYSQL_PWD": self.password()}, check=False)
            if res.code in (126, 127) or "executable file not found" in res.stdout + res.stderr:
                last = res
                continue
            if not res.ok:
                text = (res.stderr or res.stdout).strip()
                errors = [line for line in text.splitlines() if line.startswith("ERROR")]  # drop the echoed statement
                raise ServiceError(f"{self.kind}: {' '.join(errors) or text[-2000:]}")
            return res
        raise ServiceError(f"{self.kind}: no client binary in container ({', '.join(self._client(tool))}): "
                           f"{(last.stderr or last.stdout).strip() if last else ''}")

    def _auth(self, database: str | None) -> list[str]:
        db = database or self.database()
        return ["-u", self.user(), "--default-character-set=utf8mb4", *([db] if db else [])]

    def query(self, sql: str, *, readonly: bool = True, database: str | None = None, seconds: int = 30) -> Result:
        def go() -> Result:
            pre = "SET SESSION TRANSACTION READ ONLY; " if readonly else ""
            body = f"{pre}{sql.strip().rstrip(';')};\nSELECT ROW_COUNT() AS {_MARK};"
            out = self._run("client", [*self._auth(database), "--xml", "-e", body]).stdout
            sets = [ET.fromstring(doc) for doc in ("<?xml" + d for d in out.split("<?xml")[1:])]
            marker = sets.pop() if sets and sets[-1].find(f"row/field[@name='{_MARK}']") is not None else None
            affected = None
            if marker is not None and (f := marker.find(f"row/field[@name='{_MARK}']")) is not None and f.text:
                affected = int(f.text)
            if not sets:
                return Result([], [], affected if affected is not None and affected >= 0 else None)
            last = sets[-1]
            rows_el = last.findall("row")
            columns = [f.get("name", "") for f in rows_el[0].findall("field")] if rows_el else []
            rows = [[None if f.get(_NIL) == "true" else (f.text or "") for f in r.findall("field")] for r in rows_el]
            return Result(columns, rows, len(rows))
        return _timed(go)

    def script(self, data: bytes, *, database: str | None = None, single_transaction: bool = False) -> str:
        path = self.upload(data)
        try:
            client = " ".join(self._client("client"))
            db = database or self.database() or ""
            sh = (f'for b in {client}; do command -v $b >/dev/null && exec $b -u "$AISB_USER" '
                  f'--default-character-set=utf8mb4 {"$AISB_DB" if db else ""} < "$AISB_FILE"; done; exit 127')
            res = self.run(["sh", "-c", sh], env={"MYSQL_PWD": self.password(), "AISB_USER": self.user(),
                                                  "AISB_DB": db or None, "AISB_FILE": path})
            return (res.stdout + res.stderr).strip()
        finally:
            self.run(["rm", "-f", path], check=False)

    _SYSTEM = "('mysql','information_schema','performance_schema','sys')"

    def tables(self, database: str | None = None) -> Result:
        return self.query(
            "select table_schema as `schema`, table_name as name, lower(table_type) as kind, "
            "table_rows as est_rows, data_length + index_length as bytes from information_schema.tables "
            f"where table_schema not in {self._SYSTEM} order by 1, 2", database=database)

    def describe(self, table: str, database: str | None = None) -> dict[str, Any]:
        schema, _, name = table.rpartition(".")
        s = lit(schema, backslash=True) if schema else "database()"
        cols = self._describe_rows(
            "select column_name as name, column_type as type, is_nullable = 'YES' as nullable, "
            "column_default as `default`, column_key as `key`, extra from information_schema.columns "
            f"where table_schema = {s} and table_name = {lit(name, backslash=True)} order by ordinal_position", database)
        if not cols:
            raise ServiceError(f"mysql: no table {table!r} (use `db tables` to list)")
        for c in cols:
            c["nullable"] = c["nullable"] == "1"
        indexes = self._describe_rows(
            "select index_name as name, non_unique = 0 as `unique`, "
            "group_concat(column_name order by seq_in_index) as columns from information_schema.statistics "
            f"where table_schema = {s} and table_name = {lit(name, backslash=True)} group by index_name, non_unique order by 1", database)
        fks = self._describe_rows(
            "select constraint_name as name, column_name as `column`, "
            "concat(referenced_table_name, '.', referenced_column_name) as `references` "
            "from information_schema.key_column_usage where referenced_table_name is not null "
            f"and table_schema = {s} and table_name = {lit(name, backslash=True)} order by 1", database)
        return {"table": table, "columns": cols, "indexes": indexes, "foreign_keys": fks}

    def dump(self, sink: Callable[[bytes], object], *, database: str | None = None, schema_only: bool = False,
             tables: list[str] | None = None) -> None:
        db = database or self.database()
        if not db:
            raise ValueError("mysql dump needs --database (no MYSQL_DATABASE in the container env)")
        args = ["-u", self.user(), "--single-transaction", "--routines", "--triggers", "--no-tablespaces",
                *(["--no-data"] if schema_only else []), db, *(tables or [])]
        err = bytearray()
        for binary in self._client("dump"):
            err.clear()
            code = self.ctr.stream_in(self.t.name, [binary, *args], sink, stderr=err.extend,
                                      env=[f"MYSQL_PWD={self.password()}"] if self.password() else None)
            if code in (126, 127):
                continue
            if code not in (0, None):
                raise ServiceError(f"mysql: {binary} exited {code}: {err.decode(errors='replace').strip()[-2000:]}")
            return
        raise ServiceError("mysql: no dump binary in container (mariadb-dump / mysqldump)")

    def activity(self) -> dict[str, Any]:
        active = self.query(
            "select id as pid, user, db, command, time as seconds, state, left(info, 300) as query "
            "from information_schema.processlist where command <> 'Sleep' and id <> connection_id() order by time desc")
        status = self.query(
            "select variable_name as name, variable_value as value from information_schema.global_status "
            "where variable_name in ('THREADS_CONNECTED','THREADS_RUNNING','MAX_USED_CONNECTIONS','SLOW_QUERIES',"
            "'UPTIME','QUESTIONS','ABORTED_CONNECTS','INNODB_ROW_LOCK_CURRENT_WAITS')")
        limits = self.query("select @@max_connections as max_connections, @@version as version")
        return {
            **dict(zip(limits.columns, limits.rows[0] if limits.rows else [])),
            "status": {str(n).lower(): int(v) if str(v).isdigit() else v for n, v in status.rows},
            "active": [dict(zip(active.columns, r)) for r in active.rows],
        }

    def ident(self, name: str) -> str:
        return ".".join("`" + part.replace("`", "``") + "`" for part in name.split("."))

    def schema(self, database: str | None = None) -> dict[str, dict[str, Any]]:
        cols = self.query(
            "select c.table_name, c.column_name, c.column_type, c.is_nullable, c.column_default "
            "from information_schema.columns c join information_schema.tables t "
            "on t.table_schema = c.table_schema and t.table_name = c.table_name "
            "where c.table_schema = database() and t.table_type = 'BASE TABLE' order by 1, c.ordinal_position",
            database=database)
        idx = self.query(
            "select table_name, index_name, concat(if(non_unique = 0, 'UNIQUE ', ''), "
            "group_concat(column_name order by seq_in_index)) from information_schema.statistics "
            "where table_schema = database() group by table_name, index_name, non_unique", database=database)
        return _schema(cols.rows, idx.rows)

    def kill(self, pid: int, *, terminate: bool = False) -> dict[str, Any]:
        self.query(f"KILL {'' if terminate else 'QUERY '}{int(pid)}", readonly=False)
        return {"pid": pid, "action": "terminate" if terminate else "cancel", "ok": True}


class SQLite(SQL):
    """Query an SQLite file in the container without sqlite3 installed there: copy it out, open the copy."""
    kind = "sqlite"
    dialect = "sqlite"
    image_rx = re.compile(r"(?!)")

    def __init__(self, ctr: Any, target: Target, path: str) -> None:
        super().__init__(ctr, target)
        self.path = path

    def _copy(self) -> tuple[Path, sqlite3.Connection]:
        tmp = Path(tempfile.mkdtemp(prefix="aisb-sqlite-"))
        for suffix in ("", "-wal", "-shm"):  # WAL files hold committed data not yet checkpointed
            try:
                data = self.ctr.t.raw("GET", f"/containers/{q(self.t.name)}/archive", query={"path": self.path + suffix})
            except NotFound:
                if not suffix:
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise ServiceError(f"sqlite: no file {self.path!r} in {self.t.name}") from None
                continue
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                member = next(m for m in tar if m.isfile())
                (tmp / f"db{suffix}").write_bytes(tar.extractfile(member).read())  # type: ignore[union-attr]
        conn = sqlite3.connect(tmp / "db")
        conn.execute("PRAGMA query_only = ON")
        return tmp, conn

    def query(self, sql: str, *, readonly: bool = True, database: str | None = None, seconds: int = 30) -> Result:
        def go() -> Result:
            tmp, conn = self._copy()
            try:
                cur = conn.execute(sql)
                columns = [d[0] for d in cur.description or []]
                return Result(columns, [list(r) for r in cur.fetchall()], cur.rowcount if cur.rowcount >= 0 else None)
            except sqlite3.Error as e:
                raise ServiceError(f"sqlite: {e}") from None
            finally:
                conn.close()
                shutil.rmtree(tmp, ignore_errors=True)
        return _timed(go)

    def schema(self, database: str | None = None) -> dict[str, dict[str, Any]]:
        tmp, conn = self._copy()  # one copy for the whole catalog, not one per query
        try:
            return _sqlite_schema(conn)
        finally:
            conn.close()
            shutil.rmtree(tmp, ignore_errors=True)

    def tables(self, database: str | None = None) -> Result:
        return self.query("select type as kind, name, tbl_name as 'table' from sqlite_master "
                          "where name not like 'sqlite_%' order by type, name")

    def describe(self, table: str, database: str | None = None) -> dict[str, Any]:
        cols = self.query(f"select name, type, \"notnull\" = 0 as nullable, dflt_value as 'default', pk "
                          f"from pragma_table_info({lit(table)})")
        if not cols.rows:
            raise ServiceError(f"sqlite: no table {table!r}")
        idx = self.query(f"select name, \"unique\", origin from pragma_index_list({lit(table)})")
        fks = self.query(f"select \"from\" as 'column', \"table\" || '.' || \"to\" as 'references' "
                         f"from pragma_foreign_key_list({lit(table)})")
        rec = lambda r: [dict(zip(r.columns, row)) for row in r.rows]  # noqa: E731
        columns = rec(cols)
        for c in columns:
            c["nullable"] = bool(c["nullable"])
        return {"table": table, "columns": columns, "indexes": rec(idx), "foreign_keys": rec(fks)}


def _sqlite_schema(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    tables = conn.execute("select name from sqlite_master where type = 'table' and name not like 'sqlite_%'").fetchall()
    for (t,) in tables:
        cols = conn.execute('select name, type, "notnull" = 0, dflt_value from pragma_table_info(?)', (t,)).fetchall()
        idx = conn.execute("select name, sql from sqlite_master where type = 'index' and tbl_name = ?", (t,)).fetchall()
        out[t] = {"columns": {c: {"type": ty, "nullable": bool(n), "default": d} for c, ty, n, d in cols},
                  "indexes": {n: sql or "(auto)" for n, sql in idx}}
    return out


def _schema(col_rows: list[list[Any]], idx_rows: list[list[Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for table, col, type_, nullable, default in col_rows:
        out.setdefault(table, {"columns": {}, "indexes": {}})["columns"][col] = {
            "type": type_, "nullable": nullable in ("YES", "1", 1, True), "default": default}
    for table, name, definition in idx_rows:
        if table in out:
            out[table]["indexes"][name] = definition
    return out


def diff_schema(a: dict[str, dict[str, Any]], b: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Tables/columns/indexes only in A, only in B, or different. Pure, engine-agnostic."""
    changed: dict[str, Any] = {}
    for t in sorted(a.keys() & b.keys()):
        entry: dict[str, Any] = {}
        for part in ("columns", "indexes"):
            x, y = a[t][part], b[t][part]
            d = {"only_in_a": sorted(x.keys() - y.keys()), "only_in_b": sorted(y.keys() - x.keys()),
                 "different": {k: {"a": x[k], "b": y[k]} for k in sorted(x.keys() & y.keys()) if x[k] != y[k]}}
            if any(d.values()):
                entry[part] = {k: v for k, v in d.items() if v}
        if entry:
            changed[t] = entry
    return {"tables_only_in_a": sorted(a.keys() - b.keys()), "tables_only_in_b": sorted(b.keys() - a.keys()),
            "changed": changed, "identical": not changed and a.keys() == b.keys()}


def gzip_sink(path: Path) -> tuple[Callable[[bytes], object], Callable[[], int]]:
    """A sink writing (gzipped if *.gz) to path, plus a closer returning the byte count written."""
    fh = gzip.open(path, "wb") if path.suffix == ".gz" else open(path, "wb")
    total = 0

    def write(chunk: bytes) -> None:
        nonlocal total
        total += len(chunk)
        fh.write(chunk)

    def close() -> int:
        fh.close()
        return total
    return write, close
