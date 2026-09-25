import base64
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_UNMET, EXIT_USAGE, main
from aisb.services import REGISTRY, Target
from aisb.services.fmt import infer, render, shape
from aisb.services.redis import parse_info
from aisb.services.sql import lit
from conftest import Reply, frame, tar_of


def inspect(name="svc", image="postgres:16", env=(), ports=None, exposed=(), running=True, cmd=(), ips=("172.17.0.9",)):
    return {
        "Name": f"/{name}", "State": {"Running": running, "Status": "running" if running else "exited"},
        "Config": {"Image": image, "Env": list(env), "Cmd": list(cmd), "Tty": False,
                   "ExposedPorts": {f"{p}/tcp": {} for p in exposed}},
        "NetworkSettings": {"Ports": ports or {}, "Networks": {"bridge": {"IPAddress": ip} for ip in ips}},
    }


@pytest.fixture
def cli(host, capsys):
    def run(*argv: str):
        code = main([*argv, "--host", host, "--json"] if "--" not in argv else
                    [*argv[:argv.index("--")], "--host", host, "--json", *argv[argv.index("--"):]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


# --- detection & connection info ---------------------------------------------------------

@pytest.mark.parametrize(("image", "env", "exposed", "kind", "why"), [
    ("postgres:16-alpine", (), (), "postgres", "image"),
    ("docker.io/bitnami/redis:7.2", (), (), "redis", "image"),
    ("ghcr.io/acme/db:1", ("POSTGRES_PASSWORD=x",), (), "postgres", "env"),
    ("mariadb:11", (), (), "mysql", "image"),
    ("valkey/valkey:8", (), (), "redis", "image"),
    ("acme/custom:1", (), (27017,), "mongo", "port"),
    ("nginxinc/nginx-unprivileged:1", (), (), "nginx", "image"),
    ("busybox", (), (), None, None),
])
def test_detection(image, env, exposed, kind, why):
    cls, reason = REGISTRY.detect(Target.from_inspect(inspect(image=image, env=env, exposed=exposed)))
    assert (cls.kind if cls else None) == kind
    assert (reason.split()[0] if reason else None) == why


def test_target_parses_ports_ips_and_args():
    t = Target.from_inspect(inspect(ports={"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "15432"}], "9/tcp": None},
                                    cmd=("redis-server", "--requirepass", "s3", "--port=7000")))
    assert t.published == {5432: ("0.0.0.0", 15432)}
    assert (t.arg("--requirepass"), t.arg("--port"), t.arg("--nope")) == ("s3", "7000", None)


def adapter_for(info, ctr=None):
    t = Target.from_inspect(info)
    return REGISTRY.detect(t)[0](ctr, t)


def test_url_published_masked_and_revealed():
    a = adapter_for(inspect(env=("POSTGRES_USER=app", "POSTGRES_PASSWORD=p@ss w/rd", "POSTGRES_DB=shop"),
                            ports={"5432/tcp": [{"HostIp": "", "HostPort": "15432"}]}, exposed=(5432,)))
    assert a.url() == "postgresql://app:***@127.0.0.1:15432/shop"
    assert a.url(reveal=True) == "postgresql://app:p%40ss%20w%2Frd@127.0.0.1:15432/shop"


def test_url_unpublished_uses_container_ip_and_defaults():
    a = adapter_for(inspect(image="postgres:16", exposed=(5432,)))
    assert a.url() == "postgresql://postgres@172.17.0.9:5432/postgres"
    assert "not published" in a.reachability()


def test_redis_password_from_command_line():
    a = adapter_for(inspect(image="redis:7", cmd=("redis-server", "--requirepass", "r3dis pass"),
                            ports={"6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": "16379"}]}))
    assert a.url(reveal=True) == "redis://:r3dis%20pass@127.0.0.1:16379"


def test_secret_from_file_via_archive(client, daemon):
    from aisb.api.containers import Containers
    daemon.on("GET", "/containers/pg/archive", body=tar_of({"pgpass": b"from-file\n"}), content_type="application/x-tar")
    a = adapter_for(inspect(name="pg", env=("POSTGRES_PASSWORD_FILE=/run/secrets/pgpass",)), Containers(client.transport))
    assert a.password() == "from-file"
    assert daemon.seen[0].query == {"path": "/run/secrets/pgpass"}


# --- formatting ----------------------------------------------------------------------------

def test_infer_only_canonical_integers():
    rows = infer(["n", "zip", "price", "ver", "mixed"],
                 [["1", "007", "2998.20", "16.10", "3"], ["-5", "010", "1.00", "16.2", "x"], [None, None, None, None, None]])
    assert rows == [[1, "007", "2998.20", "16.10", "3"], [-5, "010", "1.00", "16.2", "x"], [None] * 5]


def test_render_formats():
    cols, rows = ["name", "n"], [["a|b", 5], ["tab\there", None], ["x\ny", 12]]
    assert render(cols, rows, "table") == (
        "+-----------+------+\n| name      | n    |\n+-----------+------+\n| a|b       |    5 |\n"
        "| tab\\there |  NULL |\n| x\\ny      |   12 |\n+-----------+------+\n").replace("|  NULL |", "| NULL |")
    assert render(cols, rows, "markdown").splitlines()[2] == "| a\\|b | 5 |"
    assert render(cols, rows, "csv") == 'name,n\na|b,5\ntab\there,\n"x\ny",12\n'


def test_shape_limit_and_host_file(tmp_path):
    cols, rows = ["a"], [[1], [2], [3]]
    assert shape(cols, rows, fmt="json", limit=2, out=None, meta={})["rows"] == [{"a": 1}, {"a": 2}]
    res = shape(cols, rows, fmt="json", limit=0, out=str(tmp_path / "r.csv"), meta={"engine": "x"})
    assert (res["format"], res["row_count"], (tmp_path / "r.csv").read_text()) == ("csv", 3, "a\n1\n2\n3\n")
    shape(cols, rows, fmt="json", limit=0, out=str(tmp_path / "r.json"), meta={})
    assert json.loads((tmp_path / "r.json").read_text()) == [{"a": 1}, {"a": 2}, {"a": 3}]


def test_sql_literals():
    assert lit("o'k\\") == "'o''k\\'"
    assert lit("o'k\\", backslash=True) == "'o''k\\\\'"


# --- SQL through the exec boundary ----------------------------------------------------------

PG = inspect(name="pg", env=("POSTGRES_USER=app", "POSTGRES_PASSWORD=pw", "POSTGRES_DB=shop"))


def test_postgres_query_is_readonly_and_parses_nulls(cli, daemon):
    daemon.on("GET", "/containers/pg/json", json=PG)
    created = daemon.execs("pg", [(b'id,note,price\n1,\\N,2.50\n2,"",1.00\n__aisb_rows__ 2\n', b"", 0)])
    code, out, _ = cli("db", "query", "pg", "select id, note, price from t")
    assert code == EXIT_OK
    assert out["rows"] == [{"id": 1, "note": None, "price": "2.50"}, {"id": 2, "note": "", "price": "1.00"}]
    body = created[0].body
    assert body["Cmd"][body["Cmd"].index("-c") + 1] == "select id, note, price from t"
    assert "-h" in body["Cmd"] and "PGPASSWORD=pw" in body["Env"]
    assert any(e.startswith("PGOPTIONS=") and "default_transaction_read_only=on" in e for e in body["Env"])


def test_postgres_exec_reports_affected_and_error(cli, daemon):
    daemon.on("GET", "/containers/pg/json", json=PG)
    daemon.execs("pg", [(b"__aisb_rows__ 7\n", b"", 0), (b"", b"ERROR:  relation \"nope\" does not exist\n", 1)])
    code, out, _ = cli("db", "exec", "pg", "update t set x = 1")
    assert (code, out["affected"]) == (EXIT_OK, 7)
    code, _, err = cli("db", "exec", "pg", "update nope set x = 1")
    assert code == 1 and 'relation \\"nope\\" does not exist' in err


def test_db_exec_dry_run_redacts_secrets(cli, daemon):
    daemon.on("GET", "/containers/pg/json", json=PG)
    code, out, _ = cli("db", "exec", "pg", "delete from t", "--dry-run")
    create = out["planned"][0]["body"]
    assert code == EXIT_OK and "PGPASSWORD=***" in create["Env"] and "delete from t" in create["Cmd"]
    assert [m for m, _ in daemon.calls()] == ["GET"]


def test_restore_needs_confirmation(cli, daemon, tmp_path):
    dump = tmp_path / "d.sql"
    dump.write_text("create table t (x int);")
    daemon.on("GET", "/containers/pg/json", json=PG)
    code, out, _ = cli("db", "restore", "pg", str(dump))
    assert code == EXIT_CONFIRM and out["planned"][0]["path"] == "/containers/pg/archive"
    assert [m for m, _ in daemon.calls()] == ["GET"]


MARIA = inspect(name="maria", image="mariadb:11", env=("MARIADB_ROOT_PASSWORD=rootpw", "MARIADB_DATABASE=shop"))
XML = b"""<?xml version="1.0"?>
<resultset statement="select" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <row><field name="sku">A-1</field><field name="gone" xsi:nil="true" /><field name="qty">3</field></row>
  <row><field name="sku">NULL</field><field name="gone">2024-01-01</field><field name="qty">10</field></row>
</resultset>
<?xml version="1.0"?>
<resultset statement="SELECT ROW_COUNT()" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <row><field name="__aisb_rows__">-1</field></row>
</resultset>
"""


def test_mariadb_xml_parsing_and_binary_fallback(cli, daemon):
    daemon.on("GET", "/containers/maria/json", json=MARIA)
    created = daemon.execs("maria", [(XML, b"", 0)])
    code, out, _ = cli("db", "query", "maria", "select sku, gone, qty from p")
    assert code == EXIT_OK
    assert out["rows"] == [{"sku": "A-1", "gone": None, "qty": 3}, {"sku": "NULL", "gone": "2024-01-01", "qty": 10}]
    cmd = created[0].body["Cmd"]
    assert cmd[0] == "mariadb" and cmd[-1].startswith("SET SESSION TRANSACTION READ ONLY; select sku")
    assert "MYSQL_PWD=rootpw" in created[0].body["Env"]


def test_mysql_image_falls_back_to_other_client_and_cleans_errors(cli, daemon):
    daemon.on("GET", "/containers/maria/json", json=MARIA | {"Config": {**MARIA["Config"], "Image": "mysql:8"}})
    created = daemon.execs("maria", [
        (b"", b'OCI runtime exec failed: exec: "mysql": executable file not found in $PATH', 127),
        (b"", b"--------------\nupdate p\n--------------\n\nERROR 1792 (25006) at line 1: READ ONLY\n", 1),
    ])
    code, _, err = cli("db", "query", "maria", "update p set x=1")
    assert [c.body["Cmd"][0] for c in created] == ["mysql", "mariadb"]
    assert code == 1 and json.loads(err)["message"] == "mysql: ERROR 1792 (25006) at line 1: READ ONLY"


def test_sqlite_copy_out_sees_uncheckpointed_wal(cli, daemon, tmp_path):
    db = tmp_path / "app.db"
    conn = sqlite3.connect(db)
    conn.execute("pragma journal_mode=wal")
    conn.execute("pragma wal_autocheckpoint=0")
    conn.execute("create table u (id integer primary key, email text)")
    conn.execute("insert into u (email) values ('in-wal@x.io')")
    conn.commit()  # committed, but only in app.db-wal while this connection stays open
    files = {"": db.read_bytes(), "-wal": (tmp_path / "app.db-wal").read_bytes()}
    daemon.on("GET", "/containers/box/json", json=inspect(name="box", image="alpine"))
    daemon.on("GET", "/containers/box/archive", lambda s: Reply(
        body=tar_of({"app.db": files[s.query["path"].removeprefix("/data/app.db")]}), content_type="application/x-tar")
        if s.query["path"].removeprefix("/data/app.db") in files else Reply(404, json={"message": "not found"}))
    code, out, _ = cli("db", "query", "box", "select email from u", "--path", "/data/app.db")
    conn.close()
    assert (code, out["rows"]) == (EXIT_OK, [{"email": "in-wal@x.io"}])
    assert cli("db", "query", "box", "delete from u", "--path", "/data/app.db")[0] == 1


# --- redis & mongo ------------------------------------------------------------------------

REDIS = inspect(name="cache", image="redis:7", cmd=("redis-server", "--requirepass", "pw"))


def test_parse_info():
    info = parse_info("# Server\r\nredis_version:7.4.1\r\n\r\n# Stats\r\nkeyspace_hits:9\r\nratio:0.5\r\n"
                      "# Keyspace\r\ndb0:keys=3,expires=1,avg_ttl=10\r\n")
    assert info == {"server": {"redis_version": "7.4.1"}, "stats": {"keyspace_hits": 9, "ratio": 0.5},
                    "keyspace": {"db0": {"keys": 3, "expires": 1, "avg_ttl": 10}}}


def test_redis_scan_uses_scan_and_one_lua_call(cli, daemon):
    daemon.on("GET", "/containers/cache/json", json=REDIS)
    details = [{"key": "u:1", "type": "hash", "ttl": -1, "bytes": 80}, {"key": "u:2", "type": "string", "ttl": 5, "bytes": 56}]
    created = daemon.execs("cache", [(b"u:1\nu:2\nu:3\n", b"", 0), (json.dumps(details).encode(), b"", 0)])
    code, out, _ = cli("redis", "scan", "cache", "u:*", "--limit", "2")
    assert code == EXIT_OK and (out["count"], out["truncated"], out["keys"]) == (2, True, details)
    assert created[0].body["Cmd"][:4] == ["redis-cli", "--scan", "--pattern", "u:*"]
    assert created[1].body["Cmd"][1] == "EVAL" and created[1].body["Cmd"][-2:] == ["u:1", "u:2"]
    assert "REDISCLI_AUTH=pw" in created[0].body["Env"]


def test_redis_cmd_falls_back_for_unscriptable_commands(cli, daemon):
    daemon.on("GET", "/containers/cache/json", json=REDIS)
    daemon.execs("cache", [(b"(error) ERR This Redis command is not allowed from script\n", b"", 0),
                           (b"maxmemory\n0\n", b"", 0)])
    code, out, _ = cli("redis", "cmd", "cache", "--", "CONFIG", "GET", "maxmemory")
    assert (code, out) == (EXIT_OK, {"reply": ["maxmemory", 0], "via": "redis-cli"})


MONGO = inspect(name="mdb", image="mongo:7", env=("MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=p w"))


def test_mongo_find_passes_inputs_via_env(cli, daemon):
    daemon.on("GET", "/containers/mdb/json", json=MONGO)
    created = daemon.execs("mdb", [(b'noise\n__AISB__[{"name":"Ann","joined":{"$date":"2024-02-01T00:00:00Z"}}]\n', b"", 0)])
    code, out, _ = cli("mongo", "find", "mdb", "users", '{"age": {"$gt": 30}}', "--limit", "5")
    assert (code, out["count"]) == (EXIT_OK, 1)
    env = dict(e.split("=", 1) for e in created[0].body["Env"])
    assert (env["AISB_C"], env["AISB_F"], env["AISB_N"], env["AISB_P"]) == ("users", '{"age": {"$gt": 30}}', "5", "p w")
    assert "users" not in created[0].body["Cmd"][-1]  # never interpolated into the script


def test_mongo_rejects_non_json_filter(cli, daemon):
    daemon.on("GET", "/containers/mdb/json", json=MONGO)
    assert cli("mongo", "find", "mdb", "users", "{age: 3}")[0] == EXIT_USAGE


# --- svc ----------------------------------------------------------------------------------

def test_svc_reload_refuses_broken_config(cli, daemon):
    daemon.on("GET", "/containers/web/json", json=inspect(name="web", image="nginx:alpine"))
    created = daemon.execs("web", [(b"", b'nginx: [emerg] unknown directive "retrun"\n', 1)])
    code, out, _ = cli("svc", "reload", "web")
    assert (code, out["reloaded"], out["check"]["ok"]) == (EXIT_UNMET, False, False)
    assert [c.body["Cmd"] for c in created] == [["nginx", "-t"]]


def test_svc_ready_waits_for_init_to_finish(cli, daemon):
    logs = iter([b"initdb: warning\n", b"initdb: warning\nPostgreSQL init process complete; ready for start up.\n"])
    current = {"v": b""}

    def serve_logs(_):
        current["v"] = next(logs, current["v"])
        return Reply(body=current["v"], content_type="text/plain")
    daemon.on("GET", "/containers/pg/json", json=PG | {"Config": {**PG["Config"], "Tty": True}})
    daemon.on("GET", "/containers/pg/logs", serve_logs)
    created = daemon.execs("pg", [(b"ok\n1\n__aisb_rows__ 1\n", b"", 0)] * 10)
    code, out, _ = cli("svc", "ready", "pg", "--stable", "0", "--interval", "0.01")
    assert (code, out["ok"], out["probe"]) == (EXIT_OK, True, "select 1")
    assert len(created) == 1  # no probe while init was pending


def test_svc_ready_fails_fast_on_dead_container(cli, daemon):
    daemon.on("GET", "/containers/pg/json", json=PG | {"State": {"Status": "exited", "ExitCode": 1}})
    daemon.on("GET", "/containers/pg/logs", Reply(body=frame(2, b"FATAL: bad config\n")))
    code, out, _ = cli("svc", "ready", "pg", "--within", "30")
    assert (code, out["ok"], out["reason"]) == (EXIT_UNMET, False, "container stopped (exit code 1)")


def test_svc_list(cli, daemon):
    daemon.on("GET", "/containers/json", json=[{"Id": "a" * 64}, {"Id": "b" * 64}])
    daemon.on("GET", "/containers/a+/json", json=inspect(name="pg", env=("POSTGRES_PASSWORD=x",)))
    daemon.on("GET", "/containers/b+/json", json=inspect(name="box", image="busybox"))
    code, out, _ = cli("svc", "list")
    assert out == [
        {"container": "pg", "image": "postgres:16", "kind": "postgres", "detected_by": "image postgres:16",
         "url": "postgresql://postgres:***@172.17.0.9:5432/postgres",
         "note": "port 5432 is not published: the container IP works only from a Linux Docker host "
                 "(publish it, e.g. --port 127.0.0.1:5432:5432, or use `aisb` commands, which run inside)"},
        {"container": "box", "image": "busybox", "kind": None, "detected_by": None},
    ]


# --- http & fs ----------------------------------------------------------------------------

@pytest.fixture
def web_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            status, body, ctype = (200, b'{"ok": true}', "application/json") if self.path == "/health" else \
                (500, b"boom", "text/plain")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_http_get_resolves_published_port(cli, daemon, web_server):
    daemon.on("GET", "/containers/web/json", json=inspect(
        name="web", image="nginx", ports={"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": str(web_server)}]}))
    code, out, _ = cli("http", "get", "web", "/health")
    assert (code, out["status"], out["body"], out["via"]) == (EXIT_OK, 200, {"ok": True}, f"published 127.0.0.1:{web_server} -> 80")
    code, out, _ = cli("http", "get", "web", "/fail")
    assert (code, out["status"], out["body"]) == (EXIT_UNMET, 500, "boom")


def test_fs_ls_cat_stat_without_exec(cli, daemon):
    tar = tar_of({"config/app.toml": b"port = 8080\n", "config/blob.bin": b"\0\1\2" * 10}, dirs=("config",))
    daemon.on("GET", "/containers/nosh/archive", lambda s: Reply(
        body=tar_of({"app.toml": b"port = 8080\n"}) if s.query["path"].endswith(".toml") else
        tar_of({"blob.bin": b"\0\1\2" * 10}) if s.query["path"].endswith(".bin") else tar,
        content_type="application/x-tar"))
    stat = base64.b64encode(json.dumps({"name": "config", "size": 4096, "mode": 2147484141,
                                        "mtime": "2026-01-01T00:00:00Z", "linkTarget": ""}).encode()).decode()
    daemon.on("HEAD", "/containers/nosh/archive", Reply(headers={"X-Docker-Container-Path-Stat": stat}))
    code, out, _ = cli("fs", "ls", "nosh", "/app/config")
    assert code == EXIT_OK and [(e["path"], e["type"], e["size"]) for e in out["entries"]] == [
        ("app.toml", "file", 12), ("blob.bin", "file", 30)]
    assert cli("fs", "cat", "nosh", "/app/config/app.toml")[1]["output"] == "port = 8080\n"
    binary = cli("fs", "cat", "nosh", "/app/config/blob.bin")[1]
    assert (binary["binary"], binary["size"]) == (True, 30)
    assert cli("fs", "stat", "nosh", "/app/config")[1] | {"mtime": None} == {
        "path": "/app/config", "name": "config", "type": "dir", "size": 4096, "mode": "0o755", "mtime": None, "target": None}
    assert not any(s.path.endswith("/exec") for s in daemon.seen)


def test_fs_find_filters(cli, daemon):
    tar = tar_of({"etc/nginx/nginx.conf": b"x" * 50, "etc/nginx/mime.types": b"y", "etc/app.conf": b"z" * 5}, dirs=("etc",))
    daemon.on("GET", "/containers/web/archive", body=tar, content_type="application/x-tar")
    code, out, _ = cli("fs", "find", "web", "/etc", "--name", "*.conf", "--min-size", "10")
    assert (code, [e["path"] for e in out["entries"]]) == (EXIT_OK, ["nginx/nginx.conf"])
