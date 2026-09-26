---
name: docker
description: Inspect, diagnose, and manage Docker containers, images, networks, and volumes, and operate the services inside them (Postgres, MySQL/MariaDB, SQLite, Redis, MongoDB, nginx and other web servers), through the stdlib-only `aisb` CLI (JSON output, tiered safety). Use when the user asks about running containers, docker logs, why a container is crashing / restarting / unhealthy / OOM-killed, port or network problems, disk usage and cleanup, building or running images, executing a command in a container, querying or dumping a database in a container, inspecting Redis keys, checking what queries are running or blocked, reloading nginx, calling a container's HTTP endpoint, reading files from a container, bringing up a multi-service dev stack, rehearsing a migration on a copy of a database, comparing schemas or container configs, debugging why one container can't reach another, security-auditing containers or finding leaked secrets in images, backing up volumes, slimming images, watching a deploy, or inspecting Kafka topics/consumer lag, RabbitMQ queues or Elasticsearch indices.
---

# Docker via `aisb`

`aisb` talks to the Docker Engine API directly (no docker CLI needed) and prints **one JSON document on stdout** when piped.

## Invoke

```bash
aisb RESOURCE OP [ARGS] [-- CMD...]          # if installed (pip install -e .)
PYTHONPATH=src python3 -m aisb RESOURCE OP   # from the repo root without installing
```

Resources: `containers`, `images`, `networks`, `volumes`, `system`. The full op table is in [references/commands.md](references/commands.md); per-flag help is `aisb RESOURCE OP --help`.

Commands for `run` / `exec` always go **after `--`**:
`aisb containers exec web -- sh -c 'ls -la /app'`.

## Output and exit codes

| exit | meaning | what you do |
|---|---|---|
| 0 | success; result JSON on stdout | continue |
| 1 | Docker error; `{"error","message","status"}` on stderr | read `message`; 404 = wrong name, 409 = conflict/state |
| 2 | usage error | fix the arguments |
| 3 | **confirmation required**; planned requests on stdout | show the plan to the user, then stop and ask |
| 4 | condition not met (`"ok": false`, e.g. `wait`) | read `reason` and `log_tail`, then run `doctor` |

Endpoint comes from `--host` or `$DOCKER_HOST`, falling back to the local socket. Run `aisb system ping` first if unsure.

## Power tools: reach for these first

| Instead of | Use | Why |
|---|---|---|
| inspect + logs + events + stats by hand | `aisb containers doctor NAME` | One call returns a verdict, ranked findings with evidence, and the exact next commands. |
| checking containers one by one | `aisb system doctor` | Triages every container, worst first. The start of any "what's wrong with my Docker?" |
| reading hundreds of log lines | `aisb containers patterns NAME` | Clusters lines into templates, errors first. `emerging` shows what first appeared at the end, right before a crash. |
| `logs` and scanning by eye | `aisb containers logs NAME --grep REGEX --context 2` | Numbered matches only. It searches the `--tail` window, 200 lines by default; use `--tail 0` for the whole log. |
| `sleep 10` and hoping | `aisb containers wait NAME --healthy / --log REGEX / --port 8080 / --exited --within 60` | All given conditions must hold. It returns early if the container dies or turns unhealthy, with the reason and log tail. **Exit 4** means the condition was not met. |
| guessing what you changed | `aisb system snapshot > before.json`, then `aisb system changes before.json` | Before/after diff of containers, images, volumes and networks, plus dry-run cleanup commands for exactly what was added. |

Doctor findings are **leads, not proof**. `likely_cause` is the top cause-type finding; symptoms like `crash-loop` rank below causes. Quote the evidence, and confirm a surprising finding with a targeted read before acting on it.
`patterns` also reports `numbers` (per-slot first/last/min/max with `trend`: a latency climb) and `repeated_ids` (the same UUID or IP recurring: retries or one hot key).
Every `--dry-run` of `run` includes preflight `warnings` (name in use, missing network or volume, image not local, host port taken). Read them before executing.
Before a session that will create or change things, take a snapshot so you can report and clean up precisely.

## Services inside containers: no host clients, no credential hunting

`aisb` detects the service (`svc list`), reads credentials from the container env (including `*_FILE` secrets), and runs the service's own CLI **inside** the container. Output comes back as typed JSON, or `--format table|markdown|csv`, or `--out file.csv`.

| Task | Command | Notes |
|---|---|---|
| What runs where, and how to connect | `svc list`, `svc url NAME` | Host URLs with secrets masked. `--reveal` prints the password, so use it only if the user asks. A `note` explains unpublished ports. |
| Wait until it *really* works | `svc ready NAME --within 120` | Real probe (`SELECT 1`, `PING`, TCP) plus the init-phase check. Use this before the first query on a new DB, **not** `containers wait --log`. |
| Read data | `db query NAME "SELECT ..."` | **Read-only enforced by the server.** Decimals stay exact strings, integers become numbers, NULL stays null. `--limit` defaults to 1000. |
| Change data or schema | `db exec NAME "UPDATE ..."`, `db exec NAME --file m.sql` | Mutate tier: preview with `--dry-run`, which redacts secrets. Returns `affected`. |
| Explore schema | `db tables NAME`, `db describe NAME TABLE` | Postgres, MySQL/MariaDB, SQLite (`--path /file.db` inside the container; no sqlite3 needed there). |
| Backup / restore | `db dump NAME out.sql.gz`; `db restore NAME f.sql.gz` | Dump streams gzipped to the host. **Restore is destroy tier.** |
| Stuck or slow DB | `db activity NAME`, then `db kill NAME PID [--terminate]` | Longest-running first, with `blocked_by` pids and waiting locks. Kill the *blocker*, after approval. |
| Redis | `redis info`, `redis scan 'p:*'`, `redis get KEY`, `redis cmd -- ARGS` | Uses SCAN, never KEYS. `cmd` is mutate tier. |
| MongoDB | `mongo collections`, `mongo find COLL '{"a":1}' --sort '{"t":-1}'`, `mongo eval 'return ...'` | Filters are JSON/Extended JSON. `eval` is mutate tier. |
| Vitals | `svc stats NAME` | Per engine: activity, memory and hit rate, opcounters. |
| Web server config | `svc check NAME`; `svc reload NAME` | `reload` validates first and **refuses** a broken config (exit 4, with the error and line). |
| HTTP | `http get NAME /health`, `http send NAME /x --json-data '{}'` | Resolves the published port or container IP. Exit 4 on status >= 400. `send` is mutate tier. |
| Files, even in distroless or stopped containers | `fs ls / cat / find / stat NAME PATH` | Archive API: no shell or coreutils needed in the image. |

Rules: prefer `db query` over `db exec` for anything read-only. Put `LIMIT` in exploratory SQL. Never `--reveal` or print credentials unless the user asked. Treat `db exec`, `db kill`, `redis cmd`, `mongo eval` and `http send` as changes that need clear intent.

## Workflows and safety nets

| Need | Command | Notes |
|---|---|---|
| A dev stack without Compose | `stack up FILE.json`, `stack ps`, `stack down NAME` | Dependency order, each service gated on a real readiness probe. Services reach each other by service name. Changed config is reported as `drift`, never silently recreated. `down` is destroy tier. File format: `stack.py` docstring. |
| Rehearse a risky DB change | `db clone NAME COPY`, then `db exec COPY ...`, then `db diff NAME COPY --counts` | Real data, disposable container. **Default to this before any destructive migration on data you can't recreate.** |
| Schema / config drift | `db diff A B [--counts]`, `containers compare A B` | Tables, columns, indexes, row counts; env (secrets masked), ports, mounts, image digest. |
| "A can't reach B" | `net probe A B --port P`, `net map` | Checks shared network, B listening (and on which address), DNS, TCP; `broken_at` names the failing layer. |
| No tools in the image | `containers debug NAME -- CMD` | Throwaway alpine (or `--image nicolaka/netshoot`) sidecar sharing NAME's network and PID namespaces. |
| Cross-service story | `containers timeline A B C --since 5m [--patterns]` | One stream ordered by Docker timestamps. |
| Security review | `system audit`, `containers secrets NAME [--path /app]`, `images secrets IMG` | Scored findings with fixes. Secrets are masked; **never print unmasked values**. Report rotation for anything found in image history. |
| Backups | `volumes backup VOL out.tar.gz`; `volumes restore VOL f.tar.gz` | Restore is destroy tier. A live database volume copy is crash-consistent; prefer `db dump` for databases. |
| Image size | `images slim IMG` | Largest layers plus Dockerfile fixes. |
| Babysit a deploy | `system watch --interval 10 --duration 600 --until-change` | Returns on the first change (new failure, stop, recovery). Exit 0 with `changes: []` means it stayed quiet. |
| Brokers / search | `kafka topics / groups / peek`, `rabbit queues / exchanges / peek`, `es health / indices / search` | `kafka groups`: an idle group with lag is a stalled consumer. `rabbit peek` requeues but marks messages redelivered (mutate tier). |

MCP: `aisb mcp` serves every op as a tool (`--max-tier read` for a read-only toolset). Destroy tools need `confirm=true`, and the same approval rules apply.

## Safety rules (non-negotiable)

Every op has a tier, listed in the `tier` column of [references/commands.md](references/commands.md), which is the source of truth.

1. **read**: always fine to run.
2. **mutate**: changes state. When the user's intent is not explicit, run it with `--dry-run` first (exit 0, prints the planned API calls), show the plan, then run it without the flag.
3. **destroy**: deletes state. **Preview with an explicit `--dry-run`** so the command visibly can't delete anything.
   - A bare destroy command without `--yes` also refuses (exit 3 with the plan). That is a safety net, not the way to preview.
   - **Never add `--yes` unless the user explicitly approved that specific action in this conversation.** Approval does not carry over to other objects.
4. Everything aisb creates is labelled `aisb.managed=true`. Prefer `--managed` when listing or pruning, so cleanup touches only what you created.
5. Volume data is unrecoverable. `system prune --volumes`, `volumes rm`, and `containers rm --volumes` each need the user to approve *volumes* by name or scope.
6. Removing a running or restarting container needs `--force`. Include it in the preview so the user approves the command that will actually run.

## Keep context small

- `inspect` returns hundreds of lines, so always narrow it: `--fields State,RestartCount,Config.Image,HostConfig.RestartPolicy`.
- `logs` defaults to `--tail 200` and caps at 64 KiB, keeping the tail. Add `--since 10m` and `--stream stderr` to focus.
- `events` is always bounded. The defaults are `--since 10m --until now --limit 200`; widen `--since` for slow crash loops. Filter with `--filter container=web --filter event=die`.
- `--fields` returns flat keys named by the path you asked for: `--fields State,Config.Image` gives `{"State": {...}, "Config.Image": "..."}`.

## Playbooks

For multi-step tasks, read [references/playbooks.md](references/playbooks.md) and follow the matching recipe:

- Diagnose an unhealthy, crashing or restarting container.
- Fix a config error by recreating the container (`containers spec` → edit → `rm` → `run --spec`).
- Check whether the process is OOM-killed.
- Debug container-to-container networking.
- Reclaim disk space safely.
- Run a reproducible service from a RunSpec JSON file.
- Build an image and smoke-test it.
- Investigate a slow or stuck database.
- Safely change data in a database container.
- Rehearse a migration on a clone.
- Debug connectivity between containers.
- Security review of a host.
- Bring up, check and tear down a dev stack.

End every diagnosis with: **evidence** (quoted fields and log lines), **root-cause hypothesis**, and **proposed fix**, including the exact command. Mark it destroy-tier if it is one.
