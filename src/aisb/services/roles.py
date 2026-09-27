"""Least-privilege read-only database roles: the server-enforced boundary behind `db query`.

`db grant-readonly` creates a login role that can read but never write, and stores its credential locally
($AISB_HOME/credentials/db-roles.json, 0600, never printed). `db query` then connects as that role, so no SQL
can write, whatever it does to its session. Without a role, `db query` falls back to a read-only *session*,
which guards against accidents only; `[db] readonly_role = "required"` in config.toml refuses that fallback.

Pure SQL builders here; execution lives in `aisb.api.services`.
"""

import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .. import state
from .sql import lit

DEFAULT_USER = "aisb_ro"
MODES = ("auto", "required")


@dataclass(frozen=True, slots=True)
class Credential:
    user: str
    password: str
    engine: str
    databases: list[str] = field(default_factory=list)
    created: float = 0.0

    def public(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if k != "password"}


def new_password() -> str:
    return secrets.token_urlsafe(24)


def _path() -> Any:
    return state.home("credentials") / "db-roles.json"


def load(key: str) -> Credential | None:
    raw = (state.read_json(_path(), {}) or {}).get(key)
    return Credential(**raw) if raw else None


def save(key: str, cred: Credential) -> None:
    data = state.read_json(_path(), {}) or {}
    data[key] = asdict(cred)
    state.write_json(_path(), data)


def forget(key: str) -> bool:
    data = state.read_json(_path(), {}) or {}
    if data.pop(key, None) is None:
        return False
    state.write_json(_path(), data)
    return True


def stamp(cred: Credential) -> Credential:
    return Credential(cred.user, cred.password, cred.engine, cred.databases, time.time())


def mode() -> str:
    from .. import config
    value = str(config.load().db.get("readonly_role", "auto"))
    if value not in MODES:
        raise ValueError(f"config [db] readonly_role must be one of {MODES}, not {value!r}")
    return value


# --- postgres ------------------------------------------------------------------------------------

def pg_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def postgres_grant(user: str, password: str, *, exists: bool, version: int,
                   schemas: dict[str, list[str]]) -> dict[str, list[str]]:
    """Statements per database ("" = any database) that make `user` a read-only login role.

    PostgreSQL 14+: the built-in pg_read_all_data role (every table, current and future, in every database).
    Older servers: CONNECT + USAGE + SELECT per schema of the given databases, and default privileges so tables
    created later by the granting user stay readable.
    """
    role = pg_ident(user)
    head = [f"{'ALTER' if exists else 'CREATE'} ROLE {role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            f"NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10 PASSWORD {lit(password)}",
            f"ALTER ROLE {role} SET default_transaction_read_only = on"]
    if version >= 14:
        return {"": [*head, f"GRANT pg_read_all_data TO {role}"]}
    out: dict[str, list[str]] = {"": head}
    for db, names in schemas.items():
        stmts = [f"GRANT CONNECT ON DATABASE {pg_ident(db)} TO {role}"]
        for s in names:
            stmts += [f"GRANT USAGE ON SCHEMA {pg_ident(s)} TO {role}",
                      f"GRANT SELECT ON ALL TABLES IN SCHEMA {pg_ident(s)} TO {role}",
                      f"GRANT SELECT ON ALL SEQUENCES IN SCHEMA {pg_ident(s)} TO {role}",
                      f"ALTER DEFAULT PRIVILEGES IN SCHEMA {pg_ident(s)} GRANT SELECT ON TABLES TO {role}"]
        out[db] = stmts
    return out


def postgres_revoke(user: str, databases: list[str]) -> dict[str, list[str]]:
    """Drop the role: first whatever it owns or was granted in each database, then the role itself."""
    role = pg_ident(user)
    out = {db: [f"DROP OWNED BY {role}"] for db in databases}
    out[""] = [*out.get("", []), f"DROP ROLE IF EXISTS {role}"]
    return out


# --- mysql / mariadb ------------------------------------------------------------------------------

def my_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def mysql_account(user: str) -> str:
    return f"{lit(user, backslash=True)}@'localhost'"  # the client inside the container uses the local socket


def mysql_grant(user: str, password: str, databases: list[str]) -> list[str]:
    """A local account with SELECT and SHOW VIEW on the given databases only (never mysql.*)."""
    acct, pw = mysql_account(user), lit(password, backslash=True)
    return [f"CREATE USER IF NOT EXISTS {acct} IDENTIFIED BY {pw} WITH MAX_USER_CONNECTIONS 10",
            f"ALTER USER {acct} IDENTIFIED BY {pw}",
            f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {acct}",
            *(f"GRANT SELECT, SHOW VIEW ON {my_ident(db)}.* TO {acct}" for db in databases)]


def mysql_revoke(user: str) -> list[str]:
    return [f"DROP USER IF EXISTS {mysql_account(user)}"]


MYSQL_SYSTEM = frozenset({"mysql", "information_schema", "performance_schema", "sys"})
