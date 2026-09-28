# How aisb is tested

aisb changes containers, volumes, databases and remote machines, so its tests pin down *behaviour*, and several
layers check the tests themselves.

| Layer | Where | What it proves |
|---|---|---|
| Unit and CLI tests against a fake daemon | most of `tests/` | every op's requests, tiers, previews and errors, at the socket boundary |
| Live tests against a real daemon | `tests/test_integration.py` (`-m docker`) | round trips on real Docker, Postgres, MariaDB, MySQL, Redis, nginx |
| Branch coverage | `pytest --cov` (CI floor: 98%) | no untested code paths |
| Property-based tests | `tests/test_properties.py` (Hypothesis) | parsers and matchers hold for thousands of generated inputs |
| Differential tests against real clients | `test_*_guard_is_sound_against_the_real_client` | the SQL guards match what `psql` / `mysql` / `mariadb` actually execute |
| Mutation testing | `mutmut` (weekly workflow) | the tests fail when the safety code is changed |

## Running

```bash
pip install -e ".[dev,pyinfra]"
pytest -q -m "not docker"                        # fast: fake daemon only
pytest -q                                        # everything, if a Docker daemon is reachable
pytest -q --cov                                  # with branch coverage (fails under 98%)
AISB_PROPERTY_EXAMPLES=5000 pytest -q tests/test_properties.py   # a deeper property run
mutmut run "aisb.policy*" && mutmut results      # mutation testing of one module (see below)
```

## The fake daemon

`tests/conftest.py` runs a Docker Engine API stand-in on a unix socket. Tests register canned replies or
handlers per route and then assert on the requests aisb actually sent: for example, "a destroy without `--yes`
sends no DELETE". Nothing internal is mocked. Services inside containers are faked at the exec endpoint: a
handler receives the argv and environment of `psql`, `mysql` or `redis-cli`, and sometimes answers from a real
in-process sqlite engine so that constraints are enforced for real.

## Property-based tests

Each property compares aisb against an independent model or a round trip:

- **Fleet selectors** against a set-algebra model over random inventories and expressions.
- **Policy time windows:**
  - a window and its complement partition the day;
  - a window contains exactly its hours;
  - a day list selects only those days.
- **SQL literals:**
  - round trips through sqlite for standard quoting, and through a MySQL lexer for MySQL quoting;
  - a literal never looks like a client command;
  - a client command after a statement is always found.
- **yamlish** reads whatever PyYAML writes, in block and flow style. The comparison skips the few YAML 1.1-only
  readings, such as `\x85` as a line break and `1e5` as a string, because yamlish follows YAML 1.2 like compose.
- **The audit chain** detects every edit, deletion and reordering except dropping the newest records, which is
  a documented limit.
- **Redaction** always replaces a secret flag's value, and `fill` restores it exactly.
- **CVSS 3.x** scores stay between 0 and 10, are rounded, and never drop when an impact metric rises.

These tests found 9 real bugs in yamlish:
- nested block sequences;
- YAML escapes (`\x80`, `\N`);
- a flow collection as the whole document;
- flow collections and quoted strings that span lines;
- `\"` and apostrophes inside flow collections;
- Python's `splitlines()` breaking lines at `\x85` and ` `;
- `strip()` and `\s` treating non-breaking spaces as YAML whitespace;
- non-ASCII digits read as numbers.

## Differential tests against the real SQL clients

`db query` refuses SQL that would make the database client act outside the server. For `psql` that is a
leading backslash meta-command such as `\!` (a shell). For `mysql` it is a client command such as `\! sh`,
`system`, `tee` or `connect`.

The guards are models of how each client parses its input, so a live test checks them against the real
binaries. A corpus of SQL puts a `touch /tmp/sentinel` payload in strings, comments, escaped quotes and
statement positions. Each string runs through the real client as admin, with no guard. The test fails if a
sentinel appears for SQL the guard would have let through.

The first run found a real bypass: MySQL 8.4 runs `SELECT 1; system id` (a command after `;` on the same line),
while the guard, modelled on the documentation, only looked at line starts. MariaDB does not run it. The
guard now checks every statement start.

## Mutation testing

`mutmut` changes the code one small step at a time, for example `<` to `<=`, `and` to `or`, a string, or
`continue` to `break`. It then runs the tests that cover that code. A mutant that survives means no test noticed
the change.

Configuration is `[tool.mutmut]` in `pyproject.toml`:
- the whole package is copied;
- `contrib/` is not mutated, because pyinfra inspects the fact signatures that mutmut wraps;
- live Docker tests are excluded for speed.

The weekly `mutation` workflow covers the safety core and fails a module whose score drops below 90%.

Latest full run of the safety core (timeouts count as killed; the survivors that remain are equivalent mutants):

| Module | Killed | Survived | Score |
|---|---|---|---|
| `policy` | 419 | 10 | 97.7% |
| `audit` | 296 | 14 | 95.5% |
| `ops.invoke` | 195 | 7 | 96.5% |
| `api/session` | 1154 | 16 | 98.6% |
| `api/chaos` | 163 | 1 | 99.4% |
| `redact` | 165 | 6 | 96.5% |
| MySQL client-command guard | 64 | 1 | 98.5% |

The first runs scored 85–94%. The tests written for their survivors found these real bugs:
- A policy with `hosts = "all,!local"` still applied to the local endpoint, because exclusions were ignored there.
- Rollback reported a spurious failure for a container created during the session with an anonymous volume:
  the volume was already gone with the container.
- Containers recreated by rollback lost the DNS aliases on their extra networks, and lost the default `bridge`
  when they also had a user network.

(The MySQL same-line bypass was found by the differential test above, not by mutation testing.)

Some mutants cannot be killed because they don't change behaviour (equivalent mutants). Examples: `24` vs `25`
as the open end of an hour window, or `split("/", 1)` vs `rsplit("/", 1)` where only the last segment can
contain a colon. They are left alone rather than contorting the code.
