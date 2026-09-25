"""Operate the software inside containers: SQL databases, Redis, MongoDB, web servers."""

import gzip
import re
import time
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from ..ops import Resource, Tier, op
from ..services import REGISTRY, SQL, Adapter, ServiceError, SQLite, Target
from ..services.fmt import infer, render, shape
from ..services.mongo import Mongo
from ..services.redis import Redis
from ..services.sql import gzip_sink
from ..util import q
from .containers import Containers

Ref = Annotated[str, "container name or id"]
Engine = Annotated[Literal["postgres", "mysql", "sqlite"] | None, "override auto-detection"]
DbPath = Annotated[str | None, "SQLite: path of the database file inside the container"]
Database = Annotated[str | None, "database name (default: from the container env)"]
Fmt = Annotated[Literal["json", "table", "markdown", "csv"], "result format"]
Out = Annotated[str | None, "write rows to this host file instead (.csv/.json/.md by extension)"]

A = TypeVar("A", bound=Adapter)
_INIT_START = re.compile(r"docker-entrypoint-initdb\.d|Starting temporary server|^initdb:", re.M)
_INIT_DONE = re.compile(r"init process (?:complete|done)", re.I)


def _target(res: Resource, ref: str) -> tuple[Containers, Target]:
    ctr = Containers(res.t)
    return ctr, Target.from_inspect(res.t.json("GET", f"/containers/{q(ref)}/json"))


def adapter(res: Resource, ref: str, want: type[A] = Adapter, *, engine: str | None = None) -> A:  # type: ignore[assignment]
    ctr, t = _target(res, ref)
    cls = REGISTRY.adapters.get(engine) if engine else REGISTRY.detect(t)[0]
    if cls is None:
        raise ValueError(f"can't tell which service runs in {ref!r} (image {t.image}); pass --engine")
    if not issubclass(cls, want):
        raise ValueError(f"{ref!r} runs {cls.kind}, which this command does not support")
    if not t.running:
        raise ServiceError(f"{ref!r} is not running; start it first (aisb containers start {ref})")
    return cls(ctr, t)  # type: ignore[return-value]


def sql_adapter(res: Resource, ref: str, engine: str | None, path: str | None) -> SQL:
    if engine == "sqlite" or path:
        if not path:
            raise ValueError("sqlite needs --path to the database file inside the container")
        ctr, t = _target(res, ref)
        return SQLite(ctr, t, path)
    return adapter(res, ref, SQL, engine=engine)


class Svc(Resource, name="svc"):
    @op(Tier.READ, name="list")
    def ls(self, *, reveal: Annotated[bool, "show passwords in URLs"] = False) -> list[dict[str, Any]]:
        """Detect services in running containers, with host-usable connection URLs (secrets masked)."""
        ctr = Containers(self.t)
        out = []
        for row in self.t.json("GET", "/containers/json") or []:
            t = Target.from_inspect(self.t.json("GET", f"/containers/{row['Id']}/json"))
            cls, why = REGISTRY.detect(t)
            entry: dict[str, Any] = {"container": t.name, "image": t.image, "kind": cls.kind if cls else None,
                                     "detected_by": why or None}
            if cls:
                a = cls(ctr, t)
                try:
                    entry["url"] = a.url(reveal=reveal)
                except Exception as e:  # a *_FILE secret we can't read shouldn't hide the service
                    entry["url"] = f"<unavailable: {e}>"
                if note := a.reachability():
                    entry["note"] = note
            out.append(entry)
        return out

    @op(Tier.READ)
    def url(self, ref: Ref, *, reveal: Annotated[bool, "include the password (it is printed!)"] = False,
            hostname: Annotated[str, "host name to use in the URL"] = "127.0.0.1") -> dict[str, Any]:
        """Connection URL for host tools (psql, redis-cli, DBeaver, app config) via the published port."""
        a = adapter(self, ref)
        return {**a.connection_info(reveal=reveal), "url": a.url(reveal=reveal, host=hostname)}

    @op(Tier.READ)
    def ready(self, ref: Ref, *, within: Annotated[float, "give up after N seconds"] = 120.0,
              stable: Annotated[float, "probe must keep passing for N seconds"] = 2.0,
              interval: Annotated[float, "poll interval"] = 0.5) -> dict[str, Any]:
        """Wait until the service really answers (SELECT 1 / PING / ping / TCP), not just until a log line appears.

        Official DB images run a temporary server during first-time init, then restart it; a log-line wait
        fires too early. This requires the entrypoint's "init process complete/done" line when an init ran,
        and a probe that keeps succeeding for --stable seconds. Fails fast if the container dies.
        """
        ctr = Containers(self.t)
        begin = time.monotonic()
        green_since: float | None = None
        last_error = ""
        while True:
            info = self.t.json("GET", f"/containers/{q(ref)}/json")
            st, tty = info.get("State") or {}, bool((info.get("Config") or {}).get("Tty"))
            if st.get("Status") in ("exited", "dead") or st.get("Restarting"):
                return {"ok": False, "reason": f"container stopped (exit code {st.get('ExitCode')})",
                        "elapsed": round(time.monotonic() - begin, 2), "log_tail": ctr._text(ref, tail=20, tty=tty)}
            logs = ctr._text(ref, tail=0, tty=tty)
            init_pending = bool(_INIT_START.search(logs)) and not _INIT_DONE.search(logs)
            probe = None
            try:
                if init_pending:
                    raise ServiceError("first-time init still running")
                cls = REGISTRY.detect(Target.from_inspect(info))[0]
                if cls is None or not hasattr(cls, "probe"):
                    raise ValueError(f"no readiness probe for {ref!r}; use `containers wait`")
                probe = cls(ctr, Target.from_inspect(info)).probe()  # type: ignore[attr-defined]
                green_since = green_since or time.monotonic()
            except ServiceError as e:
                green_since, last_error = None, str(e)
            now = time.monotonic()
            if green_since and now - green_since >= stable:
                return {"ok": True, "elapsed": round(now - begin, 2), "probe": probe}
            if now - begin >= within:
                return {"ok": False, "reason": f"not ready after {within}s", "last_error": last_error[-500:],
                        "elapsed": round(now - begin, 2)}
            time.sleep(interval)

    @op(Tier.READ)
    def stats(self, ref: Ref) -> Any:
        """Service vitals: running queries/blockers (SQL), memory/hit rate (Redis), ops/connections (Mongo)."""
        a = adapter(self, ref)
        fn = getattr(a, "activity", None) or getattr(a, "stats", None)
        if fn is None:
            raise ValueError(f"{a.kind} has no stats support")
        return {"kind": a.kind, **fn()}

    @op(Tier.READ)
    def check(self, ref: Ref) -> dict[str, Any]:
        """Validate the service configuration (nginx -t, httpd -t, caddy validate, haproxy -c, pg_file_settings)."""
        a = adapter(self, ref)
        if not hasattr(a, "check"):
            raise ValueError(f"{a.kind} has no config check")
        return {"kind": a.kind, **a.check()}  # type: ignore[attr-defined]

    @op(Tier.MUTATE)
    def reload(self, ref: Ref, *, force: Annotated[bool, "skip the config check"] = False) -> dict[str, Any]:
        """Validate the config, then reload gracefully. A failing check aborts the reload."""
        a = adapter(self, ref)
        if not hasattr(a, "reload"):
            raise ValueError(f"{a.kind} has no graceful reload")
        if not force and hasattr(a, "check"):
            result = a.check()  # type: ignore[attr-defined]
            if not result["ok"] and not self.t.planning:
                return {"ok": False, "reloaded": False, "reason": "config check failed", "check": result}
        return {"ok": True, "kind": a.kind, **a.reload()}  # type: ignore[attr-defined]


class Db(Resource, name="db"):
    @op(Tier.READ)
    def query(self, ref: Ref, sql: Annotated[str, "SQL to run (read-only, enforced by the server)"], *,
              database: Database = None, format: Fmt = "json", limit: Annotated[int, "max rows; 0 = all"] = 1000,
              out: Out = None, seconds: Annotated[int, "statement timeout"] = 30,
              engine: Engine = None, path: DbPath = None) -> dict[str, Any]:
        """Run a read-only SQL query in a Postgres/MySQL/MariaDB/SQLite container; returns typed rows."""
        db = sql_adapter(self, ref, engine, path)
        r = db.query(sql, readonly=True, database=database, seconds=seconds)
        # Type inference only for JSON; rendered formats keep the server's exact text (e.g. numeric scale).
        rows = infer(r.columns, r.rows) if format == "json" and db.kind != "sqlite" else r.rows
        return shape(r.columns, rows, fmt=format, limit=limit, out=out,
                     meta={"engine": db.kind, "elapsed_ms": r.elapsed_ms})

    @op(Tier.MUTATE, name="exec")
    def exec_(self, ref: Ref, sql: Annotated[str | None, "SQL statement(s) to run with write access"] = None, *,
              file: Annotated[str | None, "host .sql file (optionally .gz) to run as a script"] = None,
              database: Database = None, single_transaction: Annotated[bool, "wrap --file in one transaction"] = False,
              format: Fmt = "json", seconds: Annotated[int, "statement timeout (inline SQL)"] = 300,
              engine: Annotated[Literal["postgres", "mysql"] | None, "override auto-detection"] = None) -> dict[str, Any]:
        """Run SQL with write access (DML/DDL/migrations). Preview with --dry-run."""
        if bool(sql) == bool(file):
            raise ValueError("pass either SQL or --file")
        db = adapter(self, ref, SQL, engine=engine)
        if file:
            data = Path(file).expanduser().read_bytes()
            data = gzip.decompress(data) if file.endswith(".gz") else data
            return {"engine": db.kind, "file": file, "output": db.script(data, database=database,
                                                                           single_transaction=single_transaction)}
        r = db.query(sql or "", readonly=False, database=database, seconds=seconds)
        return shape(r.columns, infer(r.columns, r.rows), fmt=format, limit=1000, out=None,
                     meta={"engine": db.kind, "affected": r.affected, "elapsed_ms": r.elapsed_ms})

    @op(Tier.READ)
    def tables(self, ref: Ref, *, database: Database = None, format: Fmt = "json",
               engine: Engine = None, path: DbPath = None) -> dict[str, Any]:
        """Tables and views with estimated rows and on-disk size."""
        db = sql_adapter(self, ref, engine, path)
        r = db.tables(database)
        return shape(r.columns, infer(r.columns, r.rows), fmt=format, limit=0, out=None, meta={"engine": db.kind})

    @op(Tier.READ)
    def describe(self, ref: Ref, table: Annotated[str, "table or schema.table"], *, database: Database = None,
                 engine: Engine = None, path: DbPath = None) -> dict[str, Any]:
        """Columns, keys, indexes and constraints of one table."""
        db = sql_adapter(self, ref, engine, path)
        return {"engine": db.kind, **db.describe(table, database)}

    @op(Tier.READ)
    def dump(self, ref: Ref, out: Annotated[str, "host file; gzipped when it ends in .gz"], *,
             database: Database = None, schema_only: bool = False,
             table: Annotated[list[str] | None, "only these tables"] = None,
             engine: Annotated[Literal["postgres", "mysql"] | None, "override auto-detection"] = None) -> dict[str, Any]:
        """Stream a SQL dump (pg_dump / mysqldump) straight to a host file, gzipping on the fly."""
        db = adapter(self, ref, SQL, engine=engine)
        path = Path(out).expanduser()
        write, close = gzip_sink(path)
        start = time.monotonic()
        try:
            db.dump(write, database=database, schema_only=schema_only, tables=table)
        except BaseException:
            close()
            path.unlink(missing_ok=True)
            raise
        raw = close()
        return {"engine": db.kind, "written": str(path), "dump_bytes": raw, "file_bytes": path.stat().st_size,
                "seconds": round(time.monotonic() - start, 2)}

    @op(Tier.DESTROY)
    def restore(self, ref: Ref, file: Annotated[str, "host .sql or .sql.gz file"], *, database: Database = None,
                single_transaction: Annotated[bool, "all-or-nothing"] = True,
                engine: Annotated[Literal["postgres", "mysql"] | None, "override auto-detection"] = None) -> dict[str, Any]:
        """Run a SQL dump into the database. Overwrites data, so it needs confirmation."""
        return self.exec_(ref, file=file, database=database, single_transaction=single_transaction, engine=engine)

    @op(Tier.READ)
    def activity(self, ref: Ref) -> dict[str, Any]:
        """What the database is doing now: running queries (longest first), blockers, connections, cache hit ratio."""
        db = adapter(self, ref, SQL)
        return {"engine": db.kind, **db.activity()}

    @op(Tier.MUTATE)
    def kill(self, ref: Ref, pid: Annotated[int, "backend pid / connection id from `db activity`"], *,
             terminate: Annotated[bool, "drop the whole connection, not just cancel the query"] = False) -> dict[str, Any]:
        """Cancel a running query (or terminate its connection)."""
        return adapter(self, ref, SQL).kill(pid, terminate=terminate)


class RedisOps(Resource, name="redis"):
    @op(Tier.READ)
    def info(self, ref: Ref, *, section: Annotated[str | None, "e.g. memory, clients, keyspace"] = None,
             raw: Annotated[bool, "full parsed INFO instead of the summary"] = False) -> dict[str, Any]:
        """Server summary: memory, clients, hit rate, ops/sec, keyspace, persistence."""
        r = adapter(self, ref, Redis)
        return r.info(section) if raw or section else r.stats()

    @op(Tier.READ)
    def scan(self, ref: Ref, pattern: Annotated[str, "glob, e.g. 'session:*'"] = "*", *,
             limit: Annotated[int, "max keys returned"] = 100,
             type: Annotated[Literal["string", "hash", "list", "set", "zset", "stream"] | None, "only this type"] = None,
             ) -> dict[str, Any]:
        """Find keys with SCAN (never KEYS); each with type, TTL and memory, fetched in one Lua call per 200 keys."""
        return adapter(self, ref, Redis).scan(pattern, limit=limit, type_=type)

    @op(Tier.READ)
    def get(self, ref: Ref, key: str, *, limit: Annotated[int, "max elements for collections"] = 100) -> dict[str, Any]:
        """Read any key by its type (string/hash/list/set/zset/stream) with TTL and size."""
        return adapter(self, ref, Redis).get(key, limit=limit)

    @op(Tier.MUTATE)
    def cmd(self, ref: Ref, *args: Annotated[str, "command and arguments (after --)"]) -> Any:
        """Run any Redis command; structured reply when scriptable, raw output otherwise."""
        if not args:
            raise ValueError("usage: aisb redis cmd NAME -- SET key value")
        return adapter(self, ref, Redis).command(list(args))


class MongoOps(Resource, name="mongo"):
    @op(Tier.READ)
    def collections(self, ref: Ref, *, database: Database = None) -> list[dict[str, Any]]:
        """Collections and views with estimated document counts."""
        return adapter(self, ref, Mongo).collections(database)

    @op(Tier.READ)
    def find(self, ref: Ref, collection: str, filter: Annotated[str, "JSON / Extended JSON filter"] = "{}", *,
             projection: Annotated[str, "JSON projection"] = "{}", sort: Annotated[str, "JSON sort"] = "{}",
             limit: int = 50, database: Database = None, format: Fmt = "json") -> Any:
        """Query a collection; documents as relaxed Extended JSON, or a flattened table."""
        docs = adapter(self, ref, Mongo).find(collection, filter_=filter, projection=projection, sort=sort,
                                              limit=limit, database=database)
        if format == "json":
            return {"count": len(docs), "documents": docs}
        columns = list(dict.fromkeys(k for d in docs for k in d))
        return {"count": len(docs), "output": render(columns, [[d.get(c) for c in columns] for d in docs], format)}

    @op(Tier.MUTATE, name="eval")
    def eval_(self, ref: Ref, script: Annotated[str, "JS function body; `return` a value (cursors are materialized)"], *,
              database: Database = None) -> Any:
        """Run mongosh JavaScript against a database and return the result as JSON."""
        return {"result": adapter(self, ref, Mongo).js(script, database=database)}

