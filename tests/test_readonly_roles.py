"""Least-privilege read-only roles: SQL builders, credential storage and scoping, and the db ops end to end
against a fake psql/mysql (exec boundary). The live server-side proof is in test_integration.py."""

import json
import os
import stat
from typing import Any

import pytest

from aisb import config, context
from aisb.cli import EXIT_CONFIRM, EXIT_OK, EXIT_USAGE
from aisb.fleet.inventory import Host
from aisb.services import roles
from test_services_more import MARIA, MARK, PG, Engine, cli_runner

# --- pure SQL builders -------------------------------------------------------------------------------------

def test_postgres_grant_modern_uses_pg_read_all_data():
    out = roles.postgres_grant("aisb_ro", "s3'cret", exists=False, version=16, schemas={"shop": ["public"]})
    assert list(out) == [""]
    create, readonly, grant = out[""]
    assert create.startswith('CREATE ROLE "aisb_ro" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
                             "NOBYPASSRLS CONNECTION LIMIT 10 PASSWORD 's3''cret'")
    assert readonly == 'ALTER ROLE "aisb_ro" SET default_transaction_read_only = on'
    assert grant == 'GRANT pg_read_all_data TO "aisb_ro"'


def test_postgres_grant_legacy_is_per_schema_and_rotates_existing_roles():
    out = roles.postgres_grant('we"ird', "pw", exists=True, version=13, schemas={"shop": ["public", "sales"]})
    assert out[""][0].startswith('ALTER ROLE "we""ird" WITH LOGIN')
    assert out["shop"][0] == 'GRANT CONNECT ON DATABASE "shop" TO "we""ird"'
    assert 'GRANT SELECT ON ALL TABLES IN SCHEMA "sales" TO "we""ird"' in out["shop"]
    assert 'ALTER DEFAULT PRIVILEGES IN SCHEMA "public" GRANT SELECT ON TABLES TO "we""ird"' in out["shop"]
    assert not any("pg_read_all_data" in s for stmts in out.values() for s in stmts)


def test_postgres_revoke_drops_owned_per_database_then_the_role():
    out = roles.postgres_revoke("aisb_ro", ["shop", "crm"])
    assert out == {"shop": ['DROP OWNED BY "aisb_ro"'], "crm": ['DROP OWNED BY "aisb_ro"'],
                   "": ['DROP ROLE IF EXISTS "aisb_ro"']}


@pytest.mark.parametrize(("dbs", "grants"), [
    (["shop"], ["GRANT SELECT, SHOW VIEW ON `shop`.* TO 'aisb_ro'@'localhost'"]),
    (["we`ird", "b"], ["GRANT SELECT, SHOW VIEW ON `we``ird`.* TO 'aisb_ro'@'localhost'",
                       "GRANT SELECT, SHOW VIEW ON `b`.* TO 'aisb_ro'@'localhost'"]),
])
def test_mysql_grant_is_scoped_to_named_databases(dbs, grants):
    stmts = roles.mysql_grant("aisb_ro", "p'w\\x", dbs)
    assert stmts[0] == ("CREATE USER IF NOT EXISTS 'aisb_ro'@'localhost' IDENTIFIED BY 'p''w\\\\x' "
                        "WITH MAX_USER_CONNECTIONS 10")
    assert stmts[2] == "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'aisb_ro'@'localhost'"  # re-grant can narrow
    assert stmts[3:] == grants
    assert not any("mysql`.*" in s or "*.*" in s for s in stmts)
    assert roles.mysql_revoke("aisb_ro") == ["DROP USER IF EXISTS 'aisb_ro'@'localhost'"]


# --- credential storage, mode, scoping ---------------------------------------------------------------------

def test_credentials_are_private_and_never_shown():
    cred = roles.Credential("aisb_ro", "secret", "postgres", ["shop"], 1.0)
    roles.save("local:x/pg", cred)
    path = roles._path()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    assert roles.load("local:x/pg") == cred and roles.load("local:x/other") is None
    assert "password" not in cred.public() and cred.public()["databases"] == ["shop"]
    assert roles.forget("local:x/pg") is True and roles.forget("local:x/pg") is False
    assert roles.load("local:x/pg") is None


@pytest.mark.parametrize(("toml", "expected"), [
    ("", "auto"), ('[db]\nreadonly_role = "required"\n', "required"), ('[db]\nreadonly_role = "never"\n', None),
])
def test_mode_from_config(toml, expected):
    from pathlib import Path
    Path(os.environ["AISB_CONFIG"]).write_text(toml)
    config.reset()
    if expected is None:
        with pytest.raises(ValueError, match="readonly_role must be one of"):
            roles.mode()
    else:
        assert roles.mode() == expected


def test_role_key_is_per_endpoint_and_fleet_host(host):
    from aisb import Docker
    db = Docker(host).resource("db")
    assert db._role_key("pg") == f"local:{host}/pg"
    with context.use(host=Host("web1")):
        assert db._role_key("pg") == "web1/pg"  # same container name on another host: another credential


# --- the ops end to end, fake psql / mysql ------------------------------------------------------------------

def csv_out(header: str, *rows: str) -> tuple[bytes, bytes, int]:
    return ("\n".join([header, *rows]) + f"\n{MARK} {len(rows)}\n").encode(), b"", 0


def fake_psql(state: dict[str, Any]) -> Any:
    """Answers what grant/query/revoke ask; `state` controls role existence and login success."""
    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        if cmd[0] == "rm":
            return b"", b"", 0
        if "-f" in cmd:
            state["scripts"].append((cmd[cmd.index("-U") + 1], cmd[cmd.index("-d") + 1]))
            state["role"] = not state.get("dropping")
            return b"", b"", 0
        sql = cmd[cmd.index("-c") + 1]
        if sql == "show server_version_num":
            return csv_out("server_version_num", "160004")
        if "from pg_roles" in sql:
            return csv_out("?column?", *(["1"] if state.get("role") else []))
        if cmd[cmd.index("-U") + 1] == "aisb_ro" and not state.get("login", True):
            return b"", b"psql: error: FATAL:  password authentication failed\n", 2
        if "has_schema_privilege" in sql:
            return csv_out("has_schema_privilege", "t" if state.get("public_create") else "f")
        state["queries"].append((cmd, env))
        return csv_out("ro", "on")
    return handle


@pytest.fixture
def pg(daemon, capsys, host):
    state: dict[str, Any] = {"scripts": [], "queries": []}
    daemon.on("PUT", "/containers/pg/archive", status=200)
    Engine(daemon, "pg", PG, fake_psql(state))
    return cli_runner(host, capsys), state, host


def test_grant_then_query_connects_as_the_role(pg):
    run, state, host = pg
    code, out, _ = run("db", "grant-readonly", "pg")
    assert code == EXIT_OK and out["user"] == "aisb_ro" and out["stored"] and out["warnings"] == []
    assert "every database" in out["scope"] and "password" not in json.dumps(out).lower().replace("pg_read", "")
    assert state["scripts"] == [("app", "shop")]  # granted by the admin user, as one transaction
    cred = roles.load(f"local:{host}/pg")
    assert cred is not None and cred.user == "aisb_ro" and len(cred.password) >= 24 and cred.password != "pw"

    state["queries"].clear()
    code, out, _ = run("db", "query", "pg", "select 1")
    assert code == EXIT_OK and out["access"] == "role aisb_ro"
    cmd, env = state["queries"][0]
    assert cmd[cmd.index("-U") + 1] == "aisb_ro" and cmd[cmd.index("-h") + 1] == "127.0.0.1"
    assert env["PGPASSWORD"] == cred.password
    assert "default_transaction_read_only=on" in env["PGOPTIONS"]  # the session guard stays as a second layer


def test_writes_keep_the_admin_login(pg):
    run, state, _ = pg
    run("db", "grant-readonly", "pg")
    state["queries"].clear()
    assert run("db", "exec", "pg", "update t set x = 1")[0] == EXIT_OK
    cmd, env = state["queries"][0]
    assert cmd[cmd.index("-U") + 1] == "app" and env["PGPASSWORD"] == "pw"


def test_grant_dry_run_stores_nothing_and_plans_no_real_password(pg):
    run, state, host = pg
    code, out, _ = run("db", "grant-readonly", "pg", "--dry-run")
    assert code == EXIT_OK and roles.load(f"local:{host}/pg") is None and state["scripts"] == []


def test_role_that_cannot_log_in_is_not_stored(pg):
    run, state, host = pg
    state["login"] = False
    code, _, err = run("db", "grant-readonly", "pg")
    assert code != EXIT_OK and "cannot log in" in err and "pg_hba" in err
    assert roles.load(f"local:{host}/pg") is None


def test_public_create_is_reported(pg):
    run, state, _ = pg
    state["public_create"] = True
    out = run("db", "grant-readonly", "pg")[1]
    assert "REVOKE CREATE ON SCHEMA public FROM PUBLIC" in out["warnings"][0]


def test_without_a_role_query_says_it_is_only_a_session_guard(pg):
    run, _, _ = pg
    assert run("db", "query", "pg", "select 1")[1]["access"] == "read-only session"


def test_required_mode_refuses_without_a_role_before_any_exec(pg, daemon):
    run, state, _ = pg
    from pathlib import Path
    Path(os.environ["AISB_CONFIG"]).write_text('[db]\nreadonly_role = "required"\n')
    config.reset()
    code, _, err = run("db", "query", "pg", "select 1")
    assert code == EXIT_USAGE and "grant-readonly pg" in err
    assert not any(s.path.endswith("/exec") for s in daemon.seen)
    run("db", "grant-readonly", "pg")
    assert run("db", "query", "pg", "select 1")[1]["access"] == "role aisb_ro"


def test_revoke_is_destroy_tier_drops_and_forgets(pg):
    run, state, host = pg
    run("db", "grant-readonly", "pg")
    state["scripts"].clear()
    code, _, _ = run("db", "revoke-readonly", "pg")
    assert code == EXIT_CONFIRM and roles.load(f"local:{host}/pg") is not None and state["scripts"] == []
    state["dropping"] = True
    code, out, _ = run("db", "revoke-readonly", "pg", "--yes")
    assert code == EXIT_OK and out == {"engine": "postgres", "user": "aisb_ro", "dropped": True, "forgotten": True}
    assert state["scripts"] == [("app", "shop"), ("app", "shop")]  # DROP OWNED in shop, then DROP ROLE
    assert roles.load(f"local:{host}/pg") is None


def test_revoke_of_a_missing_role_only_forgets(pg):
    run, state, _ = pg
    out = run("db", "revoke-readonly", "pg", "--yes")[1]
    assert out["dropped"] is False and out["forgotten"] is False and state["scripts"] == []


def test_mysql_grant_and_query_as_the_role(daemon, capsys, host):
    calls: list[tuple[list[str], dict[str, str]]] = []

    def handle(cmd: list[str], env: dict[str, str]) -> tuple[bytes, bytes, int]:
        calls.append((cmd, env))
        return b"", b"", 0
    daemon.on("PUT", "/containers/maria/archive", status=200)
    Engine(daemon, "maria", MARIA, handle)
    run = cli_runner(host, capsys)
    code, out, _ = run("db", "grant-readonly", "maria")
    assert code == EXIT_OK and out["scope"] == "databases ['shop']"
    script = next(env for cmd, env in calls if cmd[0] == "sh")
    assert script["AISB_USER"] == "root" and script["MYSQL_PWD"] == "rootpw"
    cred = roles.load(f"local:{host}/maria")
    assert cred is not None and cred.databases == ["shop"]
    calls.clear()
    assert run("db", "query", "maria", "select 1")[1]["access"] == "role aisb_ro"
    cmd, env = calls[0]
    assert cmd[cmd.index("-u") + 1] == "aisb_ro" and env["MYSQL_PWD"] == cred.password


def test_roles_are_refused_for_other_engines(daemon, capsys, host):
    from test_services_more import info
    Engine(daemon, "r", info("r", "redis:7"), lambda c, e: (b"", b"", 0))
    code, _, err = cli_runner(host, capsys)("db", "grant-readonly", "r")
    assert code != EXIT_OK and "redis" in err
