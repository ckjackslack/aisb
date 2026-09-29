# aisb

A Docker Engine API client built on the **Python stdlib alone** (3.11+): no `docker` SDK, no `requests`, and no shelling out to the docker CLI. On top of it sit an agent-friendly CLI and a Claude Code skill.

> **Use at your own risk.** aisb can stop, delete and modify containers, images, volumes, databases and remote
> machines. It is provided "as is", without warranty; you are responsible for how you use it and for what you approve.
> See [License and disclaimer](#license-and-disclaimer).

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
aisb db query pg "select * from orders limit 5" --format table   # read-only; `access` says what enforces it
aisb db grant-readonly pg                       # least-privilege role: the server refuses every write from db query
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

## Fleet: many machines, one CLI

> Hands-on recipes for sysadmins and DevOps (monitoring, rolling deploys, backups, security sweeps, cron/CI): **[docs/ops-guide.md](docs/ops-guide.md)**.

`aisb fleet` works one level up, on an inventory of machines grouped and labelled, which you monitor and act on one host or many at a time.
It stays stdlib-only. Transport is your OpenSSH client (`~/.ssh/config`, agent, ProxyJump all apply), and each remote Docker socket is
forwarded to a private local socket, so **remote machines need only sshd and Docker**: no Python, no agent, no docker CLI.
Design: [docs/design/fleet.md](docs/design/fleet.md).

```bash
aisb fleet add web1 --ssh deploy@10.0.0.5 --group web --group prod --label region=eu
aisb fleet add db1 --ssh db1.internal --port 2222 --key ~/.ssh/ops --group db --group prod
aisb fleet ping all                                     # SSH + Docker round trip, versions
aisb fleet status @prod                                 # worst first: vitals (load, mem, disk) + container verdicts, with reasons
aisb fleet watch all --interval 30 --until-change       # monitor: host down/recovered, verdict changes, new reasons
aisb fleet ps 'region=eu' ; aisb fleet doctor @prod     # containers / problems across hosts, one table
aisb fleet query @web -- containers logs api --tail 50  # ANY read op on each host
aisb fleet apply @web --batch 1 --fail-fast -- containers restart api   # rolling; --dry-run = per-host plan
aisb fleet destroy '@web,!web1' -- containers rm old    # exit 3 with each host's plan until --yes
aisb fleet ship app:2 @prod                             # copy an image over SSH, no registry; skips hosts that have it
aisb fleet shell @db -- 'df -h /var/lib/docker'         # on the machines themselves
aisb fleet group canary --add '@web,&region=eu'         # bulk membership by selector
aisb fleet export --format pyinfra > inventory.py       # the same groups for pyinfra deploys (or ssh-config)
```

Selectors: `all`, `name`, `web*`, `@group`, `label=value`, joined with `,` (union), `&` (intersect), `!` (exclude).
Fleet ops keep the inner op's safety tier, and the MCP server exposes them like every other op.

## Fleet deploys: `aisb bundle` + pyinfra

Being stdlib-only, aisb ships as **one deterministic `.pyz`** (~160 KB) that runs on any host with Python >= 3.11:
no pip, no venv, no docker CLI. `aisb bundle aisb.pyz`, copy it anywhere, `python3 aisb.pyz system doctor`.

[pyinfra](https://pyinfra.com) is the natural carrier: agentless over SSH, and the optional integration
(`pip install -e '.[pyinfra]'`, `aisb.contrib.pyinfra`, never imported by the core) plugs in both directions.

```python
# deploy.py: pyinfra -> hosts, aisb -> Docker on each host
from pyinfra import host
from aisb.contrib.pyinfra import operations as aisb
from aisb.contrib.pyinfra.facts import AisbDoctor

aisb.install()                                             # uploads the bundle; skipped while unchanged
aisb.stack(src="stacks/shop.json", recreate_drifted=True)  # converge: noop when running with the same config
aisb.ready(container="shop-db", within=120)                # gate: the service really answers, or the deploy fails
aisb.limits(container="shop-api", memory="256m", cpus=0.5) # live update, only when the limits differ
aisb.call("session", "begin")                              # any op; destroy tier needs confirm=True
if host.get_fact(AisbDoctor)["summary"]["failing"]: ...    # read-only ops as facts (mutate/destroy refused)
```

```bash
pyinfra @aisb/web exec -- nginx -t            # connector: pyinfra operations *inside* containers,
pyinfra @aisb/stack:shop deploy_in.py         # via Engine API exec + archive (no docker CLI, no image commits)
```

Idempotency is real: a second run of the deploy above reports "No change" for everything except the
readiness gate. Stack drift (a changed service config) is reported and left running unless
`recreate_drifted=True`, which is the explicit approval to replace those containers (volumes are kept).

## Platform: guardrails, automation, operations at scale

Everything below is one layer over the same op registry, so it applies equally to the CLI, the MCP server, the portal,
runbooks and fleet fan-outs. Design: [docs/design/platform.md](docs/design/platform.md).

**Guardrails.** `~/.aisb/config.toml` (or `$AISB_CONFIG`) holds per-op flag defaults, aliases, profiles, notify
sinks, plugins and **policy rules**. Denied changes exit **5** (previews say "would be DENIED"). Every mutate/destroy
lands in a **hash-chained audit log** with user, source, host, ticket and a `run_id` shared by a whole fan-out.

```toml
[aliases]
restart-api = "fleet apply @web --batch 1 --fail-fast -- containers restart api"

[profiles.prod]
env = { AISB_FLEET = "~/infra/prod.json" }

[[policy.rules]]
name = "prod destroy needs a ticket, in office hours"
match = { tier = "destroy", hosts = "@prod" }
require = { ticket = true }
window = { days = ["mon", "tue", "wed", "thu", "fri"], hours = "09-17", tz = "Europe/Warsaw" }

[[policy.rules]]
name = "no privileged or :latest"
match = { op = "containers.run" }
deny_if = { privileged = true, image_tag = ["latest"] }
```

```bash
aisb --profile prod fleet destroy @web --ticket OPS-42 -- containers rm old --yes
aisb policy check --on web1 -- containers rm api --force     # explain a decision, run nothing
aisb audit log --since 1d --action 'fleet.*' --failed -o table ; aisb audit verify
aisb containers list -o csv --pick name,state,image          # also: ndjson, table, yaml, raw
```

**Runbooks.** TOML procedures whose steps are aisb commands (tiers, policy and audit apply), with `approve` gates,
`retry`, `when = "on_failure"` cleanups, and persisted state you can resume.

```bash
aisb runbook plan rollout-api --var image=shop-api:1.5   # every step's per-host plan + approvals needed
aisb runbook run rollout-api --yes                        # pauses at `approve` steps (exit 4, status waiting)
aisb runbook pending ; aisb runbook approve RUN --note "canary ok" --resume   # or from the portal's Approvals tab
```

**Monitoring.** Samples go to a local sqlite history; trends forecast when disks fill; alerts go to webhook, Slack,
ntfy or email sinks; `aisb exporter` serves Prometheus metrics.

```bash
aisb fleet status @prod --record --notify ops --fail-on failing    # cron-friendly: exit 4 on failing hosts
aisb fleet trends @prod --since 7d ; aisb fleet report all --since 30d --slo 99.9
aisb exporter --port 9469 --inventory ~/.aisb/fleet.json --record
```

**Desired state and migration.** Map selectors to stack files; `diff` shows drift, `converge` fixes it rolling.
Compose files and existing inventories import directly.

```bash
aisb stack import docker-compose.yml --out stacks/shop.json
aisb fleet diff desired.json all ; aisb fleet converge desired.json @web --batch 1 --fail-fast
aisb fleet import ~/.ssh/config --match 'prod-*' --group prod ; aisb fleet import hosts.json --source aws --user ec2-user
```

**Supply chain, self-healing, canaries.**

```bash
aisb images vulns shop-api:1.5 --min-severity high      # OSV.dev lookup of the image's packages
aisb images updates                                      # running images whose tag moved in the registry
aisb net tls web --port 443 --server-name shop.example   # certificate expiry, chain, SANs
aisb system remediate --dry-run                          # start-exited / restart-unhealthy / raise-memory plan
aisb fleet canary @canary '@web,!@canary' --container api --http /healthz --port 8080   # go / no-go
aisb fleet logs @web api --since 10m --patterns          # merged across hosts, fingerprinted
```

**Agents and UI.** The MCP server also exposes resources (`aisb://fleet/status`, `aisb://runbooks/pending`,
`aisb://audit/recent`, `aisb://policy/rules`, `aisb://runbooks/{name}`) and prompts (`investigate-incident`, `rollout`,
`daily-check`, one per runbook). The portal adds Fleet and Approvals tabs. **Plugins** (`aisb.plugins` entry points,
`$AISB_PLUGINS`, `[plugins] modules`) add resources that get CLI, MCP, docs, man pages, completion, policy and audit
for free; [`examples/aisb-owners`](examples/aisb-owners) is a complete one to copy.

**Tamper evidence.** With `[audit] key` set (`aisb audit keygen PATH`), each audit record is HMAC-signed, so
rewriting the log needs the key. `aisb audit anchor` prints a signed checkpoint to keep elsewhere, and
`aisb audit verify --anchors FILE` proves no records were dropped or rewritten since.

**Shell and man.** `aisb completion bash|zsh|fish` and `aisb docs --man DIR` generate completion scripts and man
pages from the registry. Releases ship both in `aisb-X.Y.Z-share.tar.gz`.

## Design

```text
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
bundle.py      deterministic single-file .pyz of aisb (stdlib zipfile)
fleet/         inventory + selectors, OpenSSH transport (exec, socket tunnels), vitals/health, fan-out
contrib/       optional third-party integrations (pyinfra facts, operations, @aisb connector)
context.py     who/where/why of a call (user, source, host, ticket, run_id), propagated into fleet workers
config.py      config.toml: defaults, aliases, profiles, notify sinks, plugins, policy
policy.py      rule matching and effects (deny, ticket, windows, deny_if) evaluated in invoke()
audit.py       hash-chained JSONL audit log (flock, redaction, optional syslog, HMAC signing, anchors)
plugins.py     entry-point / env / config plugin loading
completion.py  bash / zsh / fish completion generated from the argparse tree
manpages.py    roff man pages: aisb(1), one per resource and special command
render.py      output formats: json, ndjson, table, csv, yaml, raw; --pick projection
runbooks.py    runbook parsing, rendering, persisted run state
notify.py      alert sinks: webhook, slack, ntfy, email
exporter.py    Prometheus exposition for the fleet or the local daemon
yamlish.py     strict YAML subset parser; compose.py: compose -> stack translation
supply.py      OSV client, registry digest lookup (token auth)
fleet/         (+ metrics.py sqlite history and forecasts, desired.py, sources.py inventory importers)
portal.py      stdlib web UI over the registry (token, Host allowlist, no destroy)
stack.py       stack files: validation, naming, dependency order (graphlib), config hashes
mcp.py         MCP server (stdio JSON-RPC) generated from the registry
cli.py         argparse generated from the registry; JSON on stdout; exit codes 0 ok, 1 docker, 2 usage, 3 confirm, 4 unmet, 5 policy
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
pip install pyinfra                # enables tests/test_pyinfra.py (otherwise skipped)
pytest -m docker                   # live round-trips; auto-skipped without a daemon
ruff check src tests && mypy       # lint + types (config in pyproject.toml); CI runs both on 3.11-3.13
aisb docs --site site/             # static per-resource command reference
```

Releases are cut from tags (GitHub release with sdist, wheel and `aisb.pyz`, optional PyPI trusted
publishing): see [docs/RELEASING.md](docs/RELEASING.md).

## License and disclaimer

Licensed under the [Apache License, Version 2.0](LICENSE): free to use, modify and redistribute, including
commercially, provided that:

- you keep the [LICENSE](LICENSE) and [NOTICE](NOTICE) files (or their text) with any copy or derivative work,
  including the `aisb bundle` `.pyz`, which embeds both;
- you credit the project: *"Includes aisb (https://github.com/ckjackslack/aisb), Copyright 2026 ckjackslack,
  licensed under Apache-2.0"*, in your documentation or about/credits screen;
- modified files carry a notice that you changed them.

**No warranty, no liability.** The software is provided "AS IS", without warranties or conditions of any kind. aisb
automates powerful and sometimes irreversible operations (deleting containers and volumes, changing databases,
running commands on remote hosts, acting on behalf of AI agents). Safety tiers, previews, policy rules and undo
sessions reduce risk but do not remove it. **You alone are responsible** for how you use it, for reviewing plans
before approving them, for backups, and for any consequences, including data loss, downtime, security incidents or
costs. To the extent permitted by law, the authors and contributors are not liable for any damage arising from its
use or misuse (Sections 7 and 8 of the License).
