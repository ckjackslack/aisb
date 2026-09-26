# aisb

A Docker Engine API client built on the **Python stdlib alone** (3.11+): no `docker` SDK, no `requests`, and no shelling out to the docker CLI. On top of it sit an agent-friendly CLI and a Claude Code skill.

```bash
pip install -e .            # or: export PYTHONPATH=src
aisb system ping
aisb containers run alpine --rm -- sh -c 'echo hi'
aisb containers logs web --since 10m --tail 100
aisb containers inspect web --fields State.Status,RestartCount
aisb system prune --managed          # exits 3 with a preview; add --yes to execute
```

```python
from aisb import Docker

d = Docker()  # $DOCKER_HOST or the local socket
d.containers.run("alpine", "echo", "hi", rm=True)  # {'id': ..., 'exit_code': 0, 'output': 'hi\n', ...}
```

## Power tools

| Command | What it does |
|---|---|
| `aisb containers doctor web` | One-shot triage: verdict plus ranked findings with evidence and next commands. Pluggable `@rule`s cover exit codes, OOM, crash loops, healthchecks, start errors, log signatures (missing env var, refused dependency, DNS, port in use, permissions, wrong architecture, TLS, auth), stale image, and risky config. |
| `aisb system doctor` | Fleet triage across every container, worst first. |
| `aisb containers patterns web` | Log fingerprinting: masks timestamps, UUIDs, IPs and numbers, clusters lines into templates ranked by severity and count, and flags patterns that emerged at the end. |
| `aisb containers logs web --grep ERR --context 2` | Numbered `grep -C` over the log window. |
| `aisb containers wait web --healthy --log ready --port 8080` | Waits until every condition holds. Fails fast on death or unhealthy; exit 4 when not met. |
| `aisb system snapshot` / `system changes before.json` | Before/after inventory diff with dry-run cleanup commands. |

The analysis lives in the pure `aisb.insights` package (`fingerprint`, `diagnose`, `compare`), so it can be tested and reused without a daemon.

## Services inside containers

No host clients and no credential hunting: `aisb` detects the service, reads credentials from the container env (`*_FILE` secrets included), and runs the service's own CLI inside the container.

```bash
aisb svc list                                   # what runs where + host connection URLs (secrets masked)
aisb svc ready pg                               # SELECT 1 succeeds and init is finished, not just "a log line appeared"
aisb db query pg "select * from orders limit 5" --format table   # read-only, enforced by the server
aisb db exec pg --file migration.sql --dry-run  # write path, previewable, secrets redacted
aisb db activity pg                             # running queries, blockers, locks, cache hit ratio
aisb db dump pg backup.sql.gz                   # streamed and gzipped on the host
aisb db query app "select * from users" --path /data/app.db    # SQLite, no sqlite3 needed in the image
aisb redis scan cache 'session:*'               # SCAN + type/TTL/memory in one Lua round trip
aisb mongo find mdb users '{"age": {"$gt": 30}}' --format table
aisb svc reload web                             # nginx -t first; refuses to reload a broken config
aisb http get api /health                       # published port or container IP resolved for you
aisb fs cat distroless-app /app/config.yaml     # works without a shell in the image
```

Adapters (`aisb.services`) register with `@register`, so a new engine is a class with `image_rx`, credentials, and the methods it supports.

## Workflows

```bash
aisb stack up stack.json                  # services in dependency order, each gated on real readiness; stack down NAME
aisb db clone pg pg-rehearsal             # disposable copy with real data, for rehearsing migrations
aisb db diff pg pg-rehearsal --counts     # schema + row-count drift
aisb containers compare api-blue api-green  # env (secrets masked), ports, mounts, image digest
aisb net probe api db --port 5432         # shared network -> listening (which address?) -> DNS -> TCP
aisb containers debug distroless -- nc -zv db 5432    # toolbox sidecar in the target's namespaces
aisb containers timeline api db cache --since 5m      # interleaved logs by timestamp
aisb system audit                         # scored security/config audit
aisb images secrets app:1                 # credentials leaked into image history
aisb volumes backup pgdata pg.tar.gz      # via a never-started helper; restore is destroy tier
aisb images slim app:1                    # largest layers + Dockerfile fixes
aisb system watch --until-change          # returns on the first change in fleet health
aisb kafka groups kfk; aisb rabbit queues rmq; aisb es search es books '{"query":{...}}'
aisb mcp [--max-tier read]                # every op as an MCP tool over stdio
```

## Killer features

Designs, algorithms and trade-offs are in [docs/design/killer-features.md](docs/design/killer-features.md).

```bash
aisb session begin; ...; aisb session rollback --yes   # undo for Docker: journaled inverses + automatic backups
aisb system incident --since 15m --format markdown     # causal root cause, blast radius, postmortem draft
aisb system blackbox --seconds 600; aisb system forensics api   # flight recorder, even for --rm containers
aisb capsule create api bug.tar.gz --db-sample 0.02    # bug-in-a-file; `capsule load` recreates it anywhere
aisb net graph --stack stack.json --format mermaid     # who really talks to whom, from socket tables
aisb containers envcheck api                           # env contract: missing vars and typos, before start
aisb images sbom app:2 --format cyclonedx; aisb images diff app:1 app:2
aisb db sample pg small.sql.gz --ratio 0.05            # FK-complete subset, sequences advanced
aisb db seed pg --rows 500 --seed 1                    # fake data that satisfies CHECKs, enums, uniques, FKs
aisb db advise pg "select ... "                        # candidate indexes measured on a disposable clone
aisb chaos run stack.json                              # game day: inject, observe, revert, report card
aisb http record api --out t.jsonl; aisb http replay t.jsonl --to api-v2
aisb system rightsize --seconds 120; aisb containers limit api --memory 256m --cpus 0.5
aisb portal [--allow mutate]                           # local, token-protected web dashboard
```

## Design

```
transport.py   http.client over AF_UNIX / TCP+TLS; API version negotiation; typed errors; dry-run recorder
streams.py     multiplexed stdout/stderr demux, JSON-stream decoder, tar contexts (.dockerignore)
models.py      compact dataclass views + RunSpec (declarative container config -> API body)
ops.py         @op(Tier) registry: CLI flags, JSON schemas, docs and safety policy come from one declaration
api/*.py       containers, images, networks, volumes, system, session, capsule, chaos, http, net, ...
insights/      pure analysis: log fingerprinting, rule-based triage, snapshot diffs, dependency graph,
               incident ranking, env contracts, package inventories, pcap/HTTP parsing, rightsizing
services/      adapters for software inside containers: postgres, mysql/mariadb, sqlite, redis, mongo, kafka,
               rabbitmq, elasticsearch/opensearch, web servers
rootfs.py      streaming walks over a container's filesystem via the archive API
state.py       $AISB_HOME (0700): sessions, blackbox records
portal.py      stdlib web UI over the registry (token, Host allowlist, no destroy)
stack.py       stack files: validation, naming, dependency order (graphlib), config hashes
mcp.py         MCP server (stdio JSON-RPC) generated from the registry
cli.py         argparse generated from the registry; JSON on stdout; exit codes 0/1/2/3/4
```

Every operation carries a **tier**:
- **read** always runs.
- **mutate** supports `--dry-run`, which records the exact API calls instead of sending them.
- **destroy** degrades to a preview and exits 3 unless `--yes` is passed.

Objects that aisb creates are labelled `aisb.managed=true`, so cleanup can be scoped to them.

The Claude Code skill lives in `.claude/skills/docker/`. Its `references/commands.md` is generated by `aisb docs`, and a test keeps it in sync with the code.

## Tests

```bash
pip install pytest && pytest -q    # unit + CLI tests against a fake daemon on a unix socket
pytest -m docker                   # live round-trips; auto-skipped without a daemon
```
