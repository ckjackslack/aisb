# Changelog

All notable changes to aisb. The release workflow publishes the section for a version as its GitHub release notes.

## [0.3.0] - 2026-09-28

### Security
- **Server-enforced read-only SQL.** `db grant-readonly` creates a least-privilege login role and keeps its
  password only in `$AISB_HOME/credentials` (mode 0600). The role gets:
  - PostgreSQL 14+: `pg_read_all_data`;
  - older PostgreSQL: per-schema `SELECT` grants;
  - MySQL/MariaDB: `SELECT, SHOW VIEW` on the named databases only.

  `db query` then connects as that role, so the server refuses every write. Before this, a read-only session
  could be reset from inside the SQL (`SET ... READ WRITE; COMMIT; INSERT ...`).
  - Each result reports its `access` (`role aisb_ro` or `read-only session`).
  - `[db] readonly_role = "required"` refuses to fall back to the session guard.
  - `db revoke-readonly` drops the role and forgets its credential.
- **MySQL 8.4 bypass fixed.** MySQL 8.4 runs client commands placed after `;` on the same line
  (`SELECT 1; system id`). The guard now checks every statement start. This was found by a new differential
  test against the real `mysql`, `mariadb` and `psql` binaries.
- **Capsule secrets.** Capsules now redact secrets outside env too: command-line arguments, entrypoints,
  health checks, labels, URL passwords and known token formats. Named placeholders are filled back in with
  `capsule load --env arg:--requirepass=...`. `load` refuses to create anything until command secrets are
  supplied.

### Fixed
- Rollback: removed volumes come back with their driver, options and labels.
- Rollback: containers created during the session no longer produce spurious start/stop or volume-removal
  failures.
- Rollback: recreated containers keep the DNS aliases on their extra networks and their `bridge` connection.
- Policy: `hosts = "all,!local"` no longer applies to the local endpoint.
- Policy: read-only governance commands (`policy rules/check`, `audit log/verify`, `config show`) are exempt from
  blanket rules that don't name them.
- Runbooks: the failure reason is the step that stopped the run, not an earlier `continue_on_error` step.
- Compose import (yamlish), found by property tests against PyYAML:
  - nested block sequences;
  - YAML double-quote escapes;
  - a flow collection as the whole document;
  - values wrapped over several lines;
  - quotes and apostrophes inside `[...]`/`{...}`;
  - `\x85`/` ` treated as line breaks;
  - non-breaking spaces treated as whitespace;
  - non-ASCII digits read as numbers.
- Seeding: CHECK upper bounds and `BETWEEN` are respected.
- Output: CSV and table output print `true`/`false`, and Redis versions stay text.
- The audit syslog mirror uses one logger per target and never inherits a stale handler.

### Changed
- Fleet selectors accept `&` and `!` without commas (`@prod&region=eu!web2`). Computed groups accept
  exclusions.

### Testing
- 2311 tests, 99.8% branch coverage (the CI floor is 98%).
- Property-based tests (Hypothesis).
- Differential tests against the real SQL clients (MariaDB 11, MySQL 8.4, PostgreSQL 16).
- Mutation testing (mutmut) of the safety core: 95–99% per module, rerun weekly with a 90% floor.
  `docs/testing.md` describes every layer.

## [0.2.0] - 2026-09-27

First release: the stdlib-only Docker client and CLI, services inside containers, fleet management over SSH,
the platform layer (policy, audit, runbooks, monitoring, desired state, supply chain, remediation), the MCP
server and portal, and the Claude Code skill.
