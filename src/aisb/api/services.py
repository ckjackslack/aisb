"""Operate the software inside containers: SQL databases, Redis, MongoDB, web servers."""

import gzip
import json
import re
import time
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from ..ops import Resource, Tier, op
from ..services import REGISTRY, SQL, Adapter, ServiceError, SQLite, Target
from ..services.fmt import infer, render, shape
from ..services.mongo import Mongo
from ..services.queues import Kafka, RabbitMQ, Search
from ..services.redis import Redis
from ..models import RunSpec
from ..services.sql import diff_schema, gzip_sink
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
    def diff(self, ref: Ref, other: Annotated[str | None, "second container (default: the same one)"] = None, *,
             database: Database = None, other_database: Annotated[str | None, "database in the second container"] = None,
             counts: Annotated[bool, "also compare exact row counts of common tables (slower)"] = False,
             engine: Engine = None, path: DbPath = None,
             other_path: Annotated[str | None, "SQLite path in the second container"] = None) -> dict[str, Any]:
        """Schema drift between two databases (tables, columns, indexes), optionally row counts too."""
        if other is None and other_database is None and other_path is None:
            raise ValueError("compare against another container, --other-database, or --other-path")
        a = sql_adapter(self, ref, engine, path)
        b = sql_adapter(self, other or ref, engine, other_path)
        sa, sb = a.schema(database), b.schema(other_database or (database if other else None))
        out = {"a": f"{ref}/{database or a.database() or path or ''}".rstrip("/"),
               "b": f"{other or ref}/{other_database or b.database() or other_path or ''}".rstrip("/"),
               **diff_schema(sa, sb)}
        if counts:
            common = sorted(sa.keys() & sb.keys())[:200]
            rows = {t: (a.count(t, database), b.count(t, other_database)) for t in common}
            out["row_counts"] = {t: {"a": x, "b": y} for t, (x, y) in rows.items() if x != y}
            out["identical"] = out["identical"] and not out["row_counts"]
        return out

    @op(Tier.MUTATE)
    def clone(self, ref: Ref, name: Annotated[str, "name of the new container"], *, database: Database = None,
              port: Annotated[int | None, "publish the clone on 127.0.0.1:PORT"] = None,
              within: Annotated[float, "readiness timeout (seconds)"] = 180.0) -> dict[str, Any]:
        """Disposable copy of a database container with its data: rehearse migrations or risky writes, then drop it.

        Same image, command and credentials (*_FILE secrets resolved), no volumes or published ports of the
        original. The clone is labelled aisb.clone-of=REF; remove it with `containers rm NAME --force`.
        """
        src = adapter(self, ref, SQL)
        ctr = Containers(self.t)
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        env = {}
        for k, _, v in (e.partition("=") for e in (info.get("Config") or {}).get("Env") or []):
            if k.endswith("_FILE") and v.startswith("/"):
                env[k[:-5]] = src.read_file(v).rstrip("\n")  # the secret mount doesn't come along
            else:
                env[k] = v
        cfg = info.get("Config") or {}
        spec = RunSpec(image=cfg.get("Image") or src.t.image, cmd=tuple(cfg.get("Cmd") or ()), name=name,
                       env=tuple(f"{k}={v}" for k, v in env.items()),
                       ports=(f"127.0.0.1:{port}:{src.default_port()}",) if port else (),
                       labels={"aisb.clone-of": src.t.name})
        ctr.create_from(spec)
        self.t.json("POST", f"/containers/{q(name)}/start")
        if self.t.planning:
            return {"clone": name, "source": ref}
        started = time.monotonic()
        ready = Svc(self.t).ready(name, within=within, stable=1.0)
        if not ready["ok"]:
            return {"ok": False, "clone": name, "reason": "clone did not become ready", "ready": ready}
        buf = bytearray()
        src.dump(buf.extend, database=database)
        dst = adapter(self, name, SQL)
        dst.script(bytes(buf), database=database)
        return {"ok": True, "clone": name, "source": ref, "engine": src.kind, "dump_bytes": len(buf),
                "seconds": round(time.monotonic() - started, 2), "url": dst.url(),
                "next": [f"aisb db query {name} \"...\"", f"aisb db diff {ref} {name}",
                         f"aisb containers rm {name} --force --dry-run"]}

    @op(Tier.READ)
    def sample(self, ref: Ref, out: Annotated[str, "host .sql / .sql.gz file"], *,
               ratio: Annotated[float, "fraction of each root table to take"] = 0.01,
               root: Annotated[list[str] | None, "root tables (default: tables nothing references)"] = None,
               max_rows: Annotated[int, "cap per root table"] = 1000,
               with_children: Annotated[bool, "also take the roots' direct child rows"] = False,
               data_only: Annotated[bool, "omit the schema"] = False,
               database: Database = None, engine: Engine = None, path: DbPath = None) -> dict[str, Any]:
        """Referentially complete subset: sample root tables, pull in every parent row their FKs need (to a
        fixpoint), and write schema + INSERTs in load order. Load it with `db restore` or into a clone."""
        from ..services import subset
        db = sql_adapter(self, ref, engine, path)
        rel = db.relations(database)
        started = time.monotonic()
        sub = subset.plan(db, rel, ratio=ratio, roots=root, max_rows=max_rows, with_children=with_children,
                          database=database)
        statements, counts = subset.export(db, rel, sub, database=database)
        schema = b""
        if not data_only:
            if isinstance(db, SQLite):
                schema = "\n".join(f"{s};" for (s,) in db.query(
                    "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' "
                    "order by type = 'index', rowid").rows).encode()
            else:
                buf = bytearray()
                db.dump(buf.extend, database=database, schema_only=True)
                schema = bytes(buf)
        body = schema + b"\n" + "\n".join(statements).encode() + b"\n"
        target = Path(out).expanduser()
        target.write_bytes(gzip.compress(body) if target.suffix == ".gz" else body)
        return {"engine": db.kind, "written": str(target), "bytes": target.stat().st_size,
                "roots": root or rel.roots(), "rows": counts, "total_rows": sum(counts.values()),
                "seconds": round(time.monotonic() - started, 2), "notes": sub.notes,
                "next": [f"aisb db restore NEWDB {out} --dry-run  (or load into a fresh container)"]}

    @op(Tier.MUTATE)
    def seed(self, ref: Ref, *, rows: Annotated[int, "rows per table"] = 100,
             table: Annotated[list[str] | None, "only these tables (their empty required parents are seeded too)"] = None,
             seed: Annotated[int | None, "random seed for reproducible data"] = None,
             database: Database = None,
             engine: Annotated[Literal["postgres", "mysql"] | None, "override auto-detection"] = None) -> dict[str, Any]:
        """Insert synthetic rows that satisfy the schema: types, lengths, precision, enums, simple CHECKs,
        uniqueness and foreign keys (parents first). Preview with --dry-run."""
        from ..services import seed as seeding
        db = adapter(self, ref, SQL, engine=engine)
        rel = db.relations(database)
        metas = seeding.introspect(db, database)
        if table and (unknown := set(table) - set(metas)):
            raise ValueError(f"unknown tables: {sorted(unknown)} "
                             f"(names are {'schema.table' if db.dialect == 'postgres' else 'table'})")
        started = time.monotonic()
        report = seeding.seed(db, rel, metas, rows=rows, tables=table, seed_value=seed, database=database)
        return {"engine": db.kind, "rows": report["tables"], "sample": report["sample"],
                "seconds": round(time.monotonic() - started, 2)}

    @op(Tier.MUTATE)
    def advise(self, ref: Ref, sql: Annotated[str | None, "a slow SELECT (omit for a schema index report)"] = None, *,
               runs: Annotated[int, "timed runs per variant (median)"] = 3, database: Database = None,
               keep_clone: Annotated[bool, "keep the temporary clone for further experiments"] = False) -> dict[str, Any]:
        """Postgres index advisor that proves itself: on a disposable clone, EXPLAIN ANALYZE the query, derive index
        candidates from the plan, create each one, re-measure, and report the measured speedups + production DDL.
        Without SQL: unindexed foreign keys and never-used indexes."""
        from ..services import advise as adv
        from ..services.sql import Postgres
        db = adapter(self, ref, SQL)
        if not isinstance(db, Postgres):
            raise ValueError("db advise supports Postgres (EXPLAIN ANALYZE JSON plans)")
        if sql is None:
            return {"engine": db.kind, **self._index_report(db, database)}
        if not re.match(r"\s*(select|with)\b", sql, re.I):
            raise ValueError("advise measures read queries only (SELECT / WITH)")
        clone = f"{ref}-advise-{int(time.time()) % 100000}"
        self.clone(ref, clone, database=database)
        if self.t.planning:
            return {"clone": clone}
        try:
            cdb = adapter(self, clone, SQL)

            def measure() -> tuple[float, dict[str, Any]]:
                times, plan = [], {}
                for _ in range(max(1, runs)):
                    raw = cdb.query(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}", database=database, seconds=600)
                    doc = json.loads(raw.rows[0][0])[0]
                    times.append(doc["Execution Time"])
                    plan = doc["Plan"]
                return sorted(times)[len(times) // 2], plan

            cdb.query("ANALYZE", readonly=False, database=database, seconds=600)
            base_ms, base_plan = measure()
            existing = {row[0] for row in cdb.query("select indexdef from pg_indexes", database=database).rows}
            tried = []
            for i, cand in enumerate(adv.candidates(base_plan)[:5]):
                lead = f"({', '.join(cand.columns)})"
                if any(f"USING btree {lead}" in d for d in existing):
                    continue
                name = f"aisb_advise_{i}"
                cdb.query(f"CREATE INDEX {name} ON {cand.relation} ({', '.join(chr(34) + c + chr(34) for c in cand.columns)})",
                          readonly=False, database=database, seconds=600)
                cdb.query(f"ANALYZE {cand.relation}", readonly=False, database=database, seconds=600)
                ms, _ = measure()
                cdb.query(f"DROP INDEX {name}", readonly=False, database=database)
                tried.append({"index": cand.ddl, "reason": cand.reason, "ms": round(ms, 2),
                              "speedup": round(base_ms / ms, 2) if ms else None})
            winners = [t for t in tried if (t["speedup"] or 0) >= 1.2]
            combined = None
            if len(winners) > 1:
                for i, w in enumerate(winners):
                    cdb.query(w["index"].replace("CONCURRENTLY ", "").replace("CREATE INDEX", f"CREATE INDEX aisb_w{i}", 1),
                              readonly=False, database=database, seconds=600)
                cdb.query("ANALYZE", readonly=False, database=database, seconds=600)
                ms, _ = measure()
                combined = {"ms": round(ms, 2), "speedup": round(base_ms / ms, 2) if ms else None}
            return {"engine": db.kind, "baseline_ms": round(base_ms, 2), "hot_nodes": adv.hot_nodes(base_plan),
                    "candidates": tried, "recommended": [w["index"] for w in winners], "combined": combined,
                    "verdict": (f"{len(winners)} index(es) measured faster; best {max(w['speedup'] for w in winners)}x"
                                if winners else "no candidate index made this query meaningfully faster"),
                    "clone": clone if keep_clone else None}
        finally:
            if not keep_clone:
                Containers(self.t).t.json("DELETE", f"/containers/{q(clone)}", query={"force": True, "v": True})

    def _index_report(self, db: SQL, database: str | None) -> dict[str, Any]:
        unindexed = db.query(
            "select c.conrelid::regclass::text as table, string_agg(a.attname, ', ' order by k.ord) as columns, "
            "c.confrelid::regclass::text as references from pg_constraint c "
            "cross join lateral unnest(c.conkey) with ordinality k(attnum, ord) "
            "join pg_attribute a on a.attrelid = c.conrelid and a.attnum = k.attnum where c.contype = 'f' "
            "and not exists (select 1 from pg_index i where i.indrelid = c.conrelid "
            "and (i.indkey::int2[])[0:cardinality(c.conkey) - 1] @> c.conkey) group by c.oid, c.conrelid, c.confrelid",
            database=database)
        unused = db.query(
            "select s.relname as table, s.indexrelname as index, pg_relation_size(s.indexrelid) as bytes "
            "from pg_stat_user_indexes s join pg_index i on i.indexrelid = s.indexrelid "
            "where s.idx_scan = 0 and not i.indisunique order by 3 desc limit 20", database=database)
        rec = lambda r: [dict(zip(r.columns, row)) for row in infer(r.columns, r.rows)]  # noqa: E731
        fks = rec(unindexed)
        for f in fks:
            f["ddl"] = f"CREATE INDEX CONCURRENTLY ON {f['table']} ({f['columns']});"
        return {"unindexed_foreign_keys": fks, "unused_indexes": rec(unused),
                "note": "unused = never scanned since stats reset; check replicas before dropping"}

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



class KafkaOps(Resource, name="kafka"):
    @op(Tier.READ)
    def topics(self, ref: Ref, *, all: Annotated[bool, "include internal topics (__consumer_offsets, ...)"] = False,
               ) -> list[dict[str, Any]]:
        """Topics with partition count, replication factor and under-replicated partitions."""
        return adapter(self, ref, Kafka).topics(internal=all)

    @op(Tier.READ)
    def groups(self, ref: Ref) -> list[dict[str, Any]]:
        """Consumer groups by total lag (worst first), with members; idle groups with lag mean stalled consumers."""
        return adapter(self, ref, Kafka).groups()

    @op(Tier.READ)
    def peek(self, ref: Ref, topic: str, *, limit: Annotated[int, "max messages"] = 10,
             seconds: Annotated[int, "stop waiting after N seconds"] = 5) -> dict[str, Any]:
        """Read messages from the beginning without a consumer group (commits nothing, disturbs no one)."""
        msgs = adapter(self, ref, Kafka).peek(topic, limit=limit, seconds=seconds)
        return {"topic": topic, "count": len(msgs), "messages": msgs}


class RabbitOps(Resource, name="rabbit"):
    @op(Tier.READ)
    def queues(self, ref: Ref, *, vhost: Annotated[str, "virtual host"] = "/") -> list[dict[str, Any]]:
        """Queues by depth: ready/unacked messages, consumers, state."""
        return adapter(self, ref, RabbitMQ).queues(vhost)

    @op(Tier.READ)
    def exchanges(self, ref: Ref, *, vhost: Annotated[str, "virtual host"] = "/") -> list[dict[str, Any]]:
        """Exchanges with type and durability."""
        return adapter(self, ref, RabbitMQ).exchanges(vhost)

    @op(Tier.MUTATE)
    def peek(self, ref: Ref, queue: str, *, vhost: str = "/", limit: int = 5) -> dict[str, Any]:
        """Look at messages and requeue them (management API). They come back flagged redelivered, so mutate tier."""
        msgs = adapter(self, ref, RabbitMQ).peek(queue, vhost=vhost, limit=limit)
        return {"queue": queue, "count": len(msgs), "messages": msgs}


class SearchOps(Resource, name="es"):
    @op(Tier.READ)
    def health(self, ref: Ref) -> dict[str, Any]:
        """Cluster health: status, nodes, active and unassigned shards."""
        return adapter(self, ref, Search).stats()

    @op(Tier.READ)
    def indices(self, ref: Ref, *, format: Fmt = "json") -> Any:
        """Indices (system ones hidden) with health, doc count, size, shards."""
        rows = adapter(self, ref, Search).indices()
        if format == "json":
            return rows
        cols = list(rows[0]) if rows else ["index"]
        return {"output": render(cols, [[r[c] for c in cols] for r in rows], format)}

    @op(Tier.READ)
    def search(self, ref: Ref, index: Annotated[str, "index name or pattern"],
               query: Annotated[str, "query DSL JSON, e.g. '{\"query\":{\"match\":{\"title\":\"x\"}}}'"] = "{}",
               *, limit: int = 10) -> dict[str, Any]:
        """Search with query DSL; hits flattened with _index/_id/_score."""
        try:
            body = json.loads(query)
        except ValueError as e:
            raise ValueError(f"query must be JSON: {e}") from None
        return adapter(self, ref, Search).search(index, body, limit=limit)
