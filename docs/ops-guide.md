# aisb for sysadmins and DevOps: a field guide

Practical recipes for running Docker hosts with `aisb`, from one box to a fleet of them. Every command
here is copy-pasteable; replace names in `CAPS` or the example names (`web1`, `@prod`, `shop`).

- [1. Mental model](#1-mental-model)
- [2. Setup](#2-setup)
- [3. Scripting contract: JSON, exit codes, safety tiers](#3-scripting-contract-json-exit-codes-safety-tiers)
- [4. Guardrails: config, profiles, policy, audit](#4-guardrails-config-profiles-policy-audit)
- [5. Inventory: hosts, groups, labels, selectors](#5-inventory-hosts-groups-labels-selectors)
- [6. Daily operations across the fleet](#6-daily-operations-across-the-fleet)
- [7. Monitoring and alerting](#7-monitoring-and-alerting)
- [8. Deployments and rolling changes](#8-deployments-and-rolling-changes)
- [9. Runbooks: repeatable procedures with approvals](#9-runbooks-repeatable-procedures-with-approvals)
- [10. Incidents](#10-incidents)
- [11. Capacity, disk and cleanup](#11-capacity-disk-and-cleanup)
- [12. Backups and disaster-recovery drills](#12-backups-and-disaster-recovery-drills)
- [13. Security and compliance sweeps](#13-security-and-compliance-sweeps)
- [14. Host (OS) level tasks](#14-host-os-level-tasks)
- [15. Single-host power tools](#15-single-host-power-tools)
- [16. Automation: cron, systemd, CI, pyinfra, AI agents](#16-automation-cron-systemd-ci-pyinfra-ai-agents)
- [17. Troubleshooting](#17-troubleshooting)
- [18. Limits and gotchas](#18-limits-and-gotchas)

---

## 1. Mental model

| Layer | Command | Scope |
|---|---|---|
| **One Docker host** | `aisb RESOURCE OP ...` | the daemon you point at (`--host`, `$DOCKER_HOST`, or the local socket) |
| **Many hosts** | `aisb fleet ...` | an inventory of machines; any single-host op fanned out over SSH |
| **Converging deploys** | pyinfra + `aisb.contrib.pyinfra` | idempotent, file-based deploys (optional) |

How `fleet` reaches a machine:

```text
admin box ── ssh (your ~/.ssh/config, agent, ProxyJump) ──▶ host: sshd ──▶ /var/run/docker.sock
   aisb  ◀── forwarded unix socket (private, per call) ──┘
```

- Remote hosts need **only sshd and Docker**: no Python, no agent, no docker CLI.
- Everything runs on the admin box. Paths in arguments (`--file`, `OUT`, stack files, `--spec`) are **admin-box paths**.
  That is a feature: backups land centrally, and stack files live in one git repo.

---

## 2. Setup

### Admin machine (Python >= 3.11, no dependencies)

```bash
pip install 'git+https://github.com/ckjackslack/aisb'      # or, from a checkout: pip install -e .
# or ship a single file to any box with Python >= 3.11 (no pip, no venv):
aisb bundle aisb.pyz && sudo install -m 755 aisb.pyz /usr/local/bin/aisb
aisb system ping                          # local Docker, if any (not required for fleet work)
```

Tab-friendly habits:
- `aisb RESOURCE OP --help` shows every flag.
- `aisb docs` prints the full command table.
- Output is a **table on a terminal** and **JSON when piped**. Force either with `--json` / `--no-json`.

### Each managed host

1. Docker Engine running.
2. An SSH user allowed to use the Docker socket: `sudo usermod -aG docker deploy` (log in again afterwards), or root.
3. sshd with stream-local forwarding. This is the default; check it isn't disabled:
   `sshd -T | grep -Ei 'allowstreamlocalforwarding|disableforwarding'` should say `yes` / `no`.
4. The host key known on the admin box (the first contact is non-interactive):
   `ssh-keyscan -p 22 10.0.0.5 >> ~/.ssh/known_hosts`, or add `--ssh-option StrictHostKeyChecking=accept-new`.

> Rootless Docker? Point at its socket: `--docker /run/user/1000/docker.sock`.

---

## 3. Scripting contract: JSON, exit codes, safety tiers

| Exit | Meaning | Typical reaction in scripts |
|---|---|---|
| 0 | success | continue |
| 1 | Docker/daemon error (JSON on stderr) | alert, read `.message` |
| 2 | usage error | fix the command |
| 3 | confirmation required: destroy op without `--yes`; the plan is on stdout | show the plan to a human |
| 4 | condition not met (`"ok": false`): e.g. a fleet op failed on some hosts, or `wait`/`svc ready` timed out | alert, read `.reason` / `.summary.failed` |
| 5 | denied by a policy rule (JSON on stderr names the rule and reason) | get the ticket/window/approval the rule asks for; never work around it |

**Safety tiers** (every op has one; see `aisb docs`):

- **read**: runs freely.
- **mutate**: changes state. `--dry-run` prints the exact API calls, per host for fleet ops.
- **destroy**: deletes state. Without `--yes` it exits 3 and prints the plan, and changes nothing.

Fleet ops keep the tier of what they run:

| Tier | Fleet op | Example |
|---|---|---|
| read | `fleet query` | `fleet query @prod -- containers logs api` |
| mutate | `fleet apply` | `fleet apply @web -- containers restart api` |
| destroy | `fleet destroy` | `fleet destroy @web -- containers rm old`; needs `--yes` |

**Argument order for fleet ops:** fleet options first, then `--`, then the aisb command exactly as you'd run it on one host:

```bash
aisb fleet apply @web --batch 1 --fail-fast --dry-run -- containers restart api --grace 30
#                ^target  ^fleet options (before --)      ^the op, with its own options
aisb fleet apply @web -- containers exec api -- nginx -s reload     # an op that itself takes -- works too
```

**jq patterns you'll reuse:**

```bash
# every host's result, one line each
aisb fleet query @prod -- system df | jq -c '.results[] | {host, ok, result: .result.images}'
# only failures
aisb fleet apply @web -- containers restart api | jq -r '.results[] | select(.ok|not) | "\(.host): \(.error)"'
# list results merged into one table with a host column
aisb fleet query all --flat -- containers list | jq -r '.rows[] | [.host, .name, .image, .state] | @tsv'
# host names of a selection, for loops
aisb fleet hosts @db | jq -r '.[].host'
```

---

## 4. Guardrails: config, profiles, policy, audit

One file, `~/.aisb/config.toml` (or `$AISB_CONFIG`), makes a shared admin box safe and pleasant. See
[docs/design/platform.md](design/platform.md) for every key.

### Defaults, aliases, profiles

```toml
[defaults]                                # flag defaults per op: "*" < "resource.*" < globs < exact
"fleet.*" = { parallel = 16, retries = 2, host_timeout = 120 }
"containers.logs" = { tail = 500 }

[aliases]                                 # `aisb restart-api` (extra args are appended)
restart-api = "fleet apply @web --batch 1 --fail-fast -- containers restart api"
morning = "fleet status all --record --fail-on failing"

[profiles.prod]                           # `aisb --profile prod ...` or AISB_PROFILE=prod
env = { AISB_FLEET = "~/infra/fleets/prod.json" }
defaults = { "fleet.*" = { parallel = 4 } }

[profiles.staging]
env = { AISB_FLEET = "~/infra/fleets/staging.json" }
```

```bash
aisb config show                                  # the effective config: profile, defaults, aliases, rules
aisb --profile prod morning                       # alias under a profile
aisb --profile staging fleet status all -o table
```

### Policy rules

Rules are checked on every real run *and* every preview, whatever the entry point (CLI, runbook, MCP agent, portal,
fleet fan-out). A denial exits **5**; `mode = "warn"` only reports.

```toml
[[policy.rules]]
name = "prod changes need a ticket"
match = { tier = ["mutate", "destroy"], hosts = "@prod" }
require = { ticket = true, ticket_pattern = "^(OPS|INC)-[0-9]+$" }

[[policy.rules]]
name = "prod destroy only in office hours"
match = { tier = "destroy", hosts = "@prod" }
window = { days = ["mon", "tue", "wed", "thu"], hours = "09-16", tz = "Europe/Warsaw" }

[[policy.rules]]
name = "no risky containers"
match = { op = ["containers.run", "stack.up"] }
deny_if = { privileged = true, host_network = true, docker_socket = true, image_tag = ["latest"] }

[[policy.rules]]
name = "agents are read-only on prod"
match = { source = "mcp", hosts = "@prod", tier = ["mutate", "destroy"] }
deny = true

[[policy.rules]]
name = "volume deletion is suspicious"
match = { tier = "destroy" }
deny_if = { volumes = true }
mode = "warn"
```

The read-only governance commands (`policy rules`, `policy check`, `audit log`, `audit verify`,
`config show`) are exempt from rules that don't name them in `match.op`, so a blanket rule never hides why
something is denied.

```bash
aisb policy rules -o table
aisb policy check --on web1 -- containers rm api --force        # would this be allowed? why not?
aisb policy check --source mcp --on db1 -- containers restart pg
aisb --ticket OPS-812 fleet apply @prod -- containers restart api   # or export AISB_TICKET=OPS-812
```

### Audit log

Every change (and reads with `[audit] reads = true`) becomes a JSONL record: user, source, host, op, args
(secrets redacted), ticket, `run_id`, result and duration, SHA-256 chained so edits and deletions are detectable.

```toml
[audit]
path = "/var/log/aisb/audit.jsonl"      # default ~/.aisb/audit.jsonl
syslog = "udp://logs.internal:514"      # optional mirror (also /dev/log)
```

```bash
aisb audit log --since 1d -o table                         # what changed today, by whom
aisb audit log --action 'fleet.*' --on 'web*' --failed     # failed or denied fleet changes on web hosts
aisb audit log --run 3f2a9c1d7e0b                          # everything one rollout/runbook did, every host
aisb audit verify                                          # exit 4 if the chain is broken
```

### Output formats

Every command takes `-o json|ndjson|table|csv|yaml|raw` and `--pick a,b.c` (dotted fields per row):

```bash
aisb fleet ps @web -o table --pick host,name,state,image
aisb containers list -o csv --pick name,image,state > containers.csv
aisb fleet status all -o ndjson | grep failing
```

---

## 5. Inventory: hosts, groups, labels, selectors

The inventory lives in `$AISB_FLEET`, else `~/.aisb/fleet.json` (mode 0600). Every fleet op also takes `--inventory FILE`.

### Adding machines: variations

```bash
# plain user@host
aisb fleet add web1 --ssh deploy@10.0.0.11 --group web --group prod --label region=eu --label role=frontend
# an alias from ~/.ssh/config (keeps User/Port/IdentityFile/ProxyJump there)
aisb fleet add db1 --ssh db1.prod --group db --group prod --label region=eu
# non-default port and key
aisb fleet add edge3 --ssh ops@203.0.113.7 --port 2222 --key ~/.ssh/edge_ed25519 --group edge
# behind a bastion, without touching ~/.ssh/config
aisb fleet add app7 --ssh deploy@10.20.0.7 --ssh-option ProxyJump=bastion.example.com --group app
# rootless Docker on the remote
aisb fleet add ci2 --ssh runner@ci2 --docker /run/user/1001/docker.sock --group ci
# Docker's TCP+TLS API directly (no SSH: no shell and no host vitals for this host)
aisb fleet add build --docker tcp://build.internal:2376 --group ci      # uses DOCKER_TLS_VERIFY/DOCKER_CERT_PATH
# this machine
aisb fleet add localhost --group lab

aisb fleet add web1 --group canary        # adding again MERGES (groups/labels added); --replace overwrites
aisb fleet remove edge3                   # forgets the entry; the machine is not touched
aisb fleet ping all                       # verify: SSH + Docker round trip, Docker versions
```

Bulk onboarding from a list:

```bash
while read -r name addr role region; do
  aisb fleet add "$name" --ssh "deploy@$addr" --group "$role" --group prod --label "region=$region"
done <<'EOF'
web1 10.0.0.11 web eu
web2 10.0.0.12 web us
db1  10.0.0.21 db  eu
EOF
aisb fleet ping @prod
```

### Groups

Groups come in two kinds:
- **Assigned groups** are stored on hosts, set with `--group` or by bulk regrouping.
- **Computed groups** are defined by selectors and always up to date. You edit them in the JSON file, e.g.
  `"groups": {"stable": ["@web", "!web2"]}`: their terms combine exactly like a command-line selector.

```bash
aisb fleet group canary --add 'web*,&region=eu'      # bulk assign by selector
aisb fleet group canary --remove web1
aisb fleet groups                                    # every group with its members
aisb fleet hosts @canary                             # resolve before you act
```

Computed groups in `fleet.json`:

```json
{"hosts": {"...": {}},
 "groups": {"frontends": ["@web", "@edge"],
            "eu-prod":   ["@prod", "&region=eu"],
            "not-db":    ["all", "!@db"]}}
```

### Selector cheat sheet

| Selector | Selects |
|---|---|
| `all` | every host |
| `web1` | one host (unknown names are an error, never "nothing") |
| `web*`, `db[12]` | glob |
| `@prod` | a group |
| `region=eu`, `role=front*` | labels (value globs allowed) |
| `web1,db1` | union |
| `@prod,&region=eu` | intersection |
| `@web,!web2` | exclusion |
| `!@db` | everything except @db |
| `@web,&@canary,!web3` | combined: web canaries except web3 |
| `@prod&region=eu!web2` | the same operators without commas (`&!x` = and-not) |

Always check a selection first: `aisb fleet hosts '@prod,&region=eu'`.

### Several environments

```bash
export AISB_FLEET=~/infra/fleets/staging.json   # per shell
aisb fleet status --inventory ~/infra/fleets/prod.json all
```

Keep the inventory files in git. They contain no secrets: keys stay in your SSH agent or `~/.ssh`.

### Importing existing inventories

```bash
aisb fleet import ~/.ssh/config --match 'prod-*' --group prod --dry-run   # preview
aisb fleet import ~/.ssh/config --match 'prod-*' --group prod
aisb fleet import instances.json --source aws --user ec2-user --label env=prod   # `aws ec2 describe-instances` output
aisb fleet import hosts.csv --source csv --group dc1        # header: name,ssh[,port,key,docker,groups,labels]; a;b and k=v;k2=v2
aisb fleet import hosts.json --source json --replace        # {"hosts": {...}} from another aisb, overwriting entries
```

Only running AWS instances are imported: named by their `Name` tag, with every tag plus `instance_id` and `az` as
labels, reached on private IPs unless `--public` is passed.

### Export to other tools

```bash
aisb fleet export --format ssh-config | jq -r .output > ~/.ssh/config.d/aisb   # `ssh web1` just works
aisb fleet export @prod --format pyinfra | jq -r .output > inventory.py         # groups become pyinfra groups
aisb fleet export --format json                                                  # raw
```

---

## 6. Daily operations across the fleet

### Morning check (30 seconds)

```bash
aisb fleet status all          # worst first: verdict + reasons (disk, memory, load, failing containers)
aisb fleet doctor @prod        # the container problems behind those verdicts, with host names
```

`status` verdicts:

| Verdict | Means |
|---|---|
| `down` | unreachable |
| `failing` | a failing container, disk at least 90%, or available memory under 5% |
| `degraded` | a degraded container, disk at least 80%, available memory under 10%, or load/CPU at least 2 |
| `healthy` | none of the above |

### What runs where

```bash
aisb fleet ps all                                   # running containers, one table, host column
aisb fleet ps @prod --all --name 'api*'             # include stopped; name glob
aisb fleet query all --flat -- images list | jq -r '.rows[] | [.host, (.tags|join(","))] | @tsv' | sort
aisb fleet query all --flat -- svc list             # databases/caches/web servers detected on every host
aisb fleet ping all | jq -r '.results[] | [.host, .result.docker] | @tsv'   # Docker version drift
```

Which hosts run an old image?

```bash
aisb fleet ps all | jq -r '.rows[] | select(.image == "shop-api:1.4") | .host' | sort -u
```

### Logs across hosts

```bash
aisb fleet query @web -- containers logs api --since 15m --grep 'ERROR|panic' --context 2
aisb fleet query @web -- containers patterns api --since 1h      # clustered templates, errors first, "emerging" ones
aisb fleet query web2 -- containers logs api --tail 500 | jq -r '.results[0].result.output'   # raw text
```

### Inspect one thing on many hosts

```bash
aisb fleet query @web -- containers inspect api --fields State.Status,RestartCount,Config.Image
aisb fleet query @db  -- db activity pg                          # running queries, blockers, cache hit ratio
aisb fleet query @db  -- db query pg "select count(*) from orders where created_at > now() - interval '1 day'"
aisb fleet query @cache -- redis info cache --section memory
aisb fleet query @web -- http get api /healthz                   # from each host's point of view
```

### Compare two hosts' configs

```bash
diff <(aisb fleet query web1 -- containers spec api | jq -S '.results[0].result') \
     <(aisb fleet query web2 -- containers spec api | jq -S '.results[0].result')
```

---

## 7. Monitoring and alerting

### Interactive watch

```bash
aisb fleet watch @prod --interval 30 --duration 3600                 # report every change for an hour
aisb fleet watch @prod --interval 15 --duration 900 --until-change   # return on the first change (good after a deploy)
```

Events: `went down`, `recovered`, `worse`, `better`, `changed`, each with `new` and `resolved` reasons.

### Alert sinks

```toml
[notify.ops]
type = "slack"
url_env = "SLACK_WEBHOOK_URL"        # secrets come from the environment, never the file

[notify.pager]
type = "ntfy"
url = "https://ntfy.sh/acme-ops"
min_level = "failing"

[notify.mail]
type = "email"
smtp = "smtp.example.com:587"
from = "aisb@example.com"
to = ["oncall@example.com"]
user = "aisb"
password_env = "SMTP_PASSWORD"
```

```bash
aisb notify list
aisb notify test ops                                            # sends a test message
aisb notify send pager --title "maintenance" --text "db1 reboot at 22:00" --level degraded
```

### Cron alert (no monitoring stack needed)

`/etc/cron.d/aisb-fleet` (runs every 5 min as the ops user):

```cron
*/5 * * * * ops AISB_FLEET=/etc/aisb/prod.json aisb fleet status @prod --tail 50 --record --notify ops --fail-on failing >> /var/log/fleet-alert.log 2>&1
```

`--record` stores each host's vitals and verdict in the metrics history (`$AISB_HOME/metrics.db`), `--notify`
sends a message only for hosts at `degraded` or worse (honouring each sink's `min_level`), and `--fail-on` makes
the exit code 4 when a host is at that level, so cron mail or a systemd `OnFailure=` fires too.

Variations:
- **Only on change** (no repeat alerts): `aisb fleet watch @prod --interval 60 --duration 290 --until-change --notify ops`
  sends only transitions (`went down`, `recovered`, `worse`...).
- **Degraded too**: `--fail-on degraded`.
- **Container-level**: `aisb fleet doctor @prod -o table`.
- **Reachability only, cheap**: `aisb fleet ping @prod || alert`. It exits 4 if any host is unreachable.
- **Your own formatting**: the JSON is stable, so `jq` works as before:

  ```bash
  aisb fleet status @prod | jq -r '.hosts[] | select(.verdict != "healthy") | "\(.host) \(.verdict): \(.reasons | join("; "))"'
  ```

### History, trends and capacity forecasts

```bash
aisb fleet trends @prod --since 7d              # per host: uptime/health %, load, memory, disk forecast, top reasons
aisb fleet report all --since 30d --slo 99.9    # uptime % per host (from recorded samples), hosts below the SLO
```

`trends` fits a least-squares line through the recorded disk samples (at least 3 spanning an hour) and lists hosts
expected to fill `/` within two weeks under `disk_full_within_14d`, with `days_left`. Put `--record` on your cron
check and you get this for free. Samples are kept 30 days.

### Prometheus

```bash
aisb exporter --port 9469 --inventory /etc/aisb/prod.json --interval 60 --record   # fleet: aisb_host_up, load, mem, disk, verdict...
aisb exporter --port 9470 --local                                                   # this host: per-container state and health
```

`/metrics` serves the last collection (collected in the background every `--interval`), `/healthz` answers 200.
Scrape it from Prometheus and alert on `aisb_host_up == 0` or `aisb_host_verdict{verdict="failing"} == 1`
(the verdict is one-hot); `aisb_host_disk_used_ratio` and `aisb_container_problem` are there for dashboards.

### Right-size limits before they bite

```bash
aisb fleet query @web -- system rightsize --seconds 120 --interval 5 \
  | jq -r '.results[] | .host as $h | .result.containers[] | select(.flags|length>0) | [$h, .name, (.flags|join(",")), .command] | @tsv'
# apply one recommendation (live, no restart):
aisb fleet apply web1 -- containers limit api --memory 384m --cpus 1
```

---

## 8. Deployments and rolling changes

### Rolling restart (one host at a time, stop on first failure)

```bash
aisb fleet apply @web --dry-run -- containers restart api        # per-host plan
aisb fleet apply @web --batch 1 --fail-fast -- containers restart api --grace 30
aisb fleet apply @web --batch 2 -- containers restart api        # two at a time
aisb fleet watch @web --interval 10 --duration 300 --until-change
```

If a host fails, the rest are listed in `summary.skipped` and nothing more is touched. The exit code is 4.

### Get images onto hosts

```bash
aisb fleet apply @web -- images pull registry.example.com/shop-api:1.5     # hosts pull from your registry
aisb fleet ship shop-api:1.5 @web                                          # or copy from the admin box over SSH:
                                                                           # no registry, air-gapped friendly, skips hosts that have it
aisb fleet ship shop-api:1.5 @web --batch 2 --parallel 2                   # gentle on a thin uplink
```

### Deploy with stack files (recommended)

A stack file is plain JSON kept on the admin box (in git). `stack up` is idempotent, starts services in
dependency order, and gates each on real readiness (`SELECT 1`, `PING`, a log line or a port).

`stacks/shop.json`:

```json
{"name": "shop",
 "volumes": ["pgdata"],
 "services": {
   "db":  {"image": "postgres:16-alpine", "env": {"POSTGRES_PASSWORD_FILE": "/run/secrets/pg"},
           "volumes": ["pgdata:/var/lib/postgresql/data", "/etc/shop/pg.secret:/run/secrets/pg:ro"],
           "restart": "unless-stopped"},
   "api": {"image": "shop-api:1.5", "depends_on": ["db"], "ports": ["8080:80"],
           "restart": "unless-stopped", "memory": "512m", "ready": {"log": "listening on"}}}}
```

Containers are named `shop-db` and `shop-api`, and the volume is `shop_pgdata`.

```bash
aisb fleet apply @web --batch 1 --fail-fast -- stack up stacks/shop.json      # first deploy / converge
aisb fleet query @web -- stack ps stacks/shop.json                             # state + drift vs the file
```

**Rolling out a changed service** (e.g. bumped `api` image tag). Changed config shows up as `drift`, and aisb never
silently recreates. You replace the drifted service explicitly:

```bash
# 1. canary first
aisb fleet destroy @canary -- stack down shop --service api            # plan (exit 3)
aisb fleet destroy @canary --yes -- stack down shop --service api      # after approval (volumes untouched)
aisb fleet apply  @canary -- stack up stacks/shop.json
aisb fleet watch  @canary --interval 15 --duration 600 --until-change
# 2. the rest, one by one
aisb fleet destroy '@web,!@canary' --yes --batch 1 --fail-fast -- stack down shop --service api
aisb fleet apply   '@web,!@canary' --batch 1 --fail-fast -- stack up stacks/shop.json
```

Variation: to keep downtime per host to seconds, run both steps per host in a loop:

```bash
for h in $(aisb fleet hosts '@web,!@canary' | jq -r '.[].host'); do
  aisb fleet destroy "$h" --yes -- stack down shop --service api &&
  aisb fleet apply "$h" -- stack up stacks/shop.json || { echo "stopped at $h"; break; }
done
```

### Canary gate: go / no-go from data

```bash
aisb fleet canary @canary '@web,!@canary' --container api --since 15m
aisb fleet canary @canary '@web,!@canary' --container api --http /healthz --port 8080 --probes 20 \
  --max-error-ratio 1.5 --max-latency-ratio 1.3
```

It compares the canary hosts with the baseline hosts: error lines per minute (log fingerprinting), restarts, container
verdicts and (with `--http`) failed probes and p50 latency. The result has `"go": true|false` with the reasons; no-go
exits 4, so it gates scripts and runbooks directly.

### Verify a new version with recorded traffic (before switching)

```bash
aisb fleet ship nicolaka/netshoot:v0.13 web1                                    # capture sidecar image, once
aisb fleet query web1 -- http record api --via tcpdump --seconds 120 --out /tmp/api.jsonl   # real traffic, passively
aisb fleet apply web1 -- http replay /tmp/api.jsonl --to api-next --ignore 'meta.*'
```

### Desired state (GitOps)

Which stacks belong on which hosts, in one file next to the stacks:

`infra/desired.json`:

```json
{"assign": {"@web": ["stacks/shop.json"], "@db": ["stacks/db.json"], "edge*": ["stacks/proxy.json"]}}
```

```bash
aisb fleet diff infra/desired.json all                                # per host+stack: missing / stopped / drift / ok services
aisb fleet converge infra/desired.json all --dry-run                  # per-host plan
aisb fleet converge infra/desired.json @web --batch 1 --fail-fast     # create what's missing, start what's stopped
aisb fleet replace-drifted infra/desired.json @web                    # plan: which containers get replaced (exit 3)
aisb fleet replace-drifted infra/desired.json @web --yes --batch 1    # after approval; volumes are kept
```

`converge` never replaces a running container; drift is only fixed by `replace-drifted`, which is destroy tier.
In CI, run `fleet diff` on pull requests and `fleet converge` on merge (§16).

### Migrating from docker compose

```bash
aisb stack import docker-compose.yml --out stacks/shop.json      # warnings list anything not translated
aisb stack up stacks/shop.json --dry-run
```

Carried over: image, command/entrypoint, environment (list or map) and `env_file`, ports, volumes (named, bind,
`:ro`), depends_on, restart, healthcheck, labels, user, hostname, working_dir, mem_limit/cpus (and
`deploy.resources.limits`), cap_add, privileged. Compose networks are replaced by the stack's own network. Every
key that isn't carried over is listed under `unsupported`, and `notes` explain the rest: e.g. a `build:` without
`image` (build it first), or `environment: [VAR]` taking its value from the admin box's environment at import time.

### Rollback

- **Image-level:** put the previous tag back in the stack file and repeat the rollout.
- **Anything done on one host in a session:**

  ```bash
  aisb session begin
  # ...changes...
  aisb session rollback --yes
  ```

  A session also covers fleet changes made while it is open: `session rollback` reconnects to every host the
  session touched and undoes its steps there, newest first (`--dry-run` shows the per-host plan).

---

## 9. Runbooks: repeatable procedures with approvals

A runbook is a TOML (or JSON) file of steps; each step is an aisb command, so tiers, policy, audit and `--ticket`
apply to every step. Keep them in git; `aisb runbook run NAME` finds `NAME.toml` in `$AISB_RUNBOOKS`
(default `./runbooks:~/.aisb/runbooks`).

`runbooks/rollout-api.toml`:

```toml
name = "rollout-api"
description = "ship a new api image, canary, gate, then the rest"
vars = { image = "shop-api:1.5", stack = "stacks/shop.json" }

[[steps]]
name = "ship"
run = "fleet ship {image} @web"

[[steps]]
name = "canary-replace"
run = "fleet destroy @canary -- stack down shop --service api"

[[steps]]
name = "canary-up"
run = "fleet apply @canary -- stack up {stack}"

[[steps]]
name = "settle"
sleep = 120

[[steps]]
name = "gate"
run = "fleet canary @canary '@web,!@canary' --container api --since 2m"
retry = { times = 3, delay = 60 }

[[steps]]
name = "go"
approve = "Canary {image} is healthy. Roll out to the remaining web hosts?"

[[steps]]
name = "rest"
run = "fleet destroy '@web,!@canary' --batch 1 --fail-fast -- stack down shop --service api"

[[steps]]
name = "rest-up"
run = "fleet apply '@web,!@canary' --batch 1 --fail-fast -- stack up {stack}"

[[steps]]
name = "tell"
when = "always"
run = "notify send ops --title 'rollout-api {image}' --text 'finished (see runbook show)'"
continue_on_error = true
```

```bash
aisb runbook list
aisb runbook plan rollout-api --var image=shop-api:1.6        # every step's per-host plan, policy denials, approvals
aisb runbook run rollout-api --var image=shop-api:1.6         # exit 3: the plan; nothing changes
aisb --ticket OPS-901 runbook run rollout-api --var image=shop-api:1.6 --yes
# ... pauses at "go" with status waiting (exit 4); anyone with access answers it:
aisb runbook pending -o table
aisb runbook approve RUN --note "canary graphs look fine" --resume
aisb runbook approve RUN --deny --note "error rate up"         # then `resume --yes` runs the on_failure/always steps
aisb runbook show RUN -o yaml ; aisb runbook runs --limit 10
aisb runbook resume RUN --yes                                  # after fixing a failed step: continues where it stopped
```

Step options: `when` (`success` default, `always`, `on_failure`, `STEP.ok`, `STEP.failed`), `retry = {times, delay}`,
`continue_on_error`. Completed steps are never re-run on resume, and `resume` refuses a runbook file that changed
since the run started unless you pass `--allow-changed`. Approvals can also be answered in the portal's Approvals tab.

---

## 10. Incidents

```bash
aisb fleet status all                                   # 1. which hosts?
aisb fleet doctor @prod --tail 200                      # 2. which containers, likely cause per container
aisb fleet query web2 -- containers doctor api          # 3. one container: verdict, ranked evidence, next commands
aisb fleet query web2 -- system incident --since 30m --format markdown | jq -r '.results[0].result.output'
                                                        # 4. causal root cause + blast radius + postmortem draft
aisb fleet query web2 -- containers timeline api db cache --since 10m      # 5. interleaved logs by timestamp
```

Common follow-ups:

| Symptom | Command |
|---|---|
| "A can't reach B" | `fleet query web2 -- net probe api db --port 5432` (walks shared network → listening → DNS → TCP) |
| Who talks to whom right now | `fleet query web2 -- net graph --format mermaid` |
| DB stuck | `fleet query db1 -- db activity pg`, then `fleet apply db1 -- db kill pg PID` |
| Crash you keep missing | on the host: `aisb system blackbox --seconds 3600`, later `aisb system forensics api` |
| Container without a shell | `fleet apply web2 -- containers debug api -- sh -c 'ss -tlpn; nslookup db'` |
| Grab evidence for devs | `fleet query web2 -- capsule create api /tmp/api-bug.tar.gz --db-sample 0.02` |

### Self-healing, with a human in the loop

```bash
aisb system remediate --dry-run                                # the plan: which rule, which container, why
aisb fleet apply @web --dry-run -- system remediate            # the same per host
aisb fleet apply @web -- system remediate --rule start-exited --rule restart-unhealthy --max-actions 3
```

Rules: `start-exited` (a service container that exited and has a restart policy), `restart-unhealthy`,
`raise-memory` (OOM-killed or at its memory limit: new limit = 1.25x, rounded up to 16 MiB, live). Causes a restart
can't fix (missing env or files, auth/TLS/DNS errors, a full disk, crash loops...) become `suggestions` with the
next step instead of actions.

End every incident note with the evidence (quoted reasons, findings, log lines), the hypothesis, and the fix command.

---

## 11. Capacity, disk and cleanup

```bash
aisb fleet status all | jq -r '.hosts[] | [.host, .disk_pct, .mem_free_pct, .load, .cpus] | @tsv' | sort -k2 -nr
aisb fleet query @web -- system df                               # reclaimable bytes per object type
aisb fleet shell @web -- 'du -sh /var/lib/docker/* 2>/dev/null | sort -h | tail'
```

Cleaning up is destroy tier. Look at the plan first:

```bash
aisb fleet destroy @web -- system prune                           # plan per host (exit 3): containers, images, networks
aisb fleet destroy @web --yes -- system prune                     # dangling images, stopped containers, unused networks
aisb fleet destroy @web --yes -- system prune --all-images        # also unused tagged images
aisb fleet destroy @web --yes -- system prune --managed           # only what aisb created
```

`--volumes` deletes data. Only use it on hosts and with scope you have confirmed.

Oversized images:

```bash
aisb images slim shop-api:1.5          # biggest layers + the Dockerfile habit that caused each
```

---

## 12. Backups and disaster-recovery drills

Outputs are written **on the admin box**, so backups are central by default. Use one file per host:

```bash
# nightly SQL dumps from every DB host (read tier: dump streams pg_dump / mysqldump, gzipped)
for h in $(aisb fleet hosts @db | jq -r '.[].host'); do
  mkdir -p "/backups/$h"
  aisb fleet query "$h" -- db dump shop-db "/backups/$h/shop-$(date +%F).sql.gz" || echo "FAILED $h" >&2
done

# volume tarballs (e.g. uploads)
for h in $(aisb fleet hosts @web | jq -r '.[].host'); do
  mkdir -p "/backups/$h"
  aisb fleet apply "$h" -- volumes backup shop_uploads "/backups/$h/uploads-$(date +%F).tar.gz"
done
```

> Don't fan one output path out to several hosts in a single `fleet` call. They would all write the same file.
> Loop per host as above.

**DR drill:** restore last night's dump into a scratch database on a spare host:

```bash
aisb fleet apply spare1 -- stack up stacks/shop-db-only.json
aisb fleet destroy spare1 --yes -- db restore shop-db /backups/db1/shop-2026-09-26.sql.gz
aisb fleet query spare1,db1 -- db query shop-db "select count(*) from orders" \
  | jq -r '.results[] | [.host, .result.rows[0].count] | @tsv'          # restored vs production row counts
```

**Before a risky migration, rehearse on a clone** (same host, real data, disposable):

```bash
aisb fleet apply db1 -- db clone shop-db shop-db-rehearsal
aisb fleet apply db1 -- db exec shop-db-rehearsal --file migrations/042.sql --single-transaction
aisb fleet query db1 -- db diff shop-db shop-db-rehearsal --counts
aisb fleet destroy db1 --yes -- containers rm shop-db-rehearsal --force --volumes
```

Test data for staging: `db sample` (a FK-complete subset) and `db seed` (fake rows that satisfy the constraints):

```bash
aisb fleet query db1 -- db sample shop-db /tmp/shop-5pct.sql.gz --ratio 0.05 --data-only   # FK-complete, sequences advanced
aisb fleet apply staging-db -- db exec shop-db --file /tmp/shop-5pct.sql.gz                # into a DB that already has the schema
```

---

## 13. Security and compliance sweeps

```bash
aisb fleet query all -- system audit --min-severity critical # privileged, docker.sock mounts, root, exposed datastores...
aisb fleet query @web -- containers secrets api              # secrets in env / image history (values masked)
aisb images secrets shop-api:1.5                             # before you ship it
```

Make read-only database access server-enforced before agents or scripts query production data. Without a role,
`db query` runs in a read-only *session*, which guards against accidents but not against SQL that resets the session:

```bash
aisb db grant-readonly shop-db                     # least-privilege login; `db query` uses it from now on
aisb db query shop-db "select count(*) from orders" | jq .access   # "role aisb_ro"
aisb fleet apply @db -- db grant-readonly shop-db  # every database host (credentials are kept per host)
aisb db revoke-readonly shop-db --yes              # drop the role, forget the credential
```

The role gets `pg_read_all_data` on PostgreSQL 14+ (per-schema `SELECT` grants on older versions), and
`SELECT, SHOW VIEW` on the named databases only for MySQL/MariaDB, never on `mysql.*`. Its password is generated
and kept only in `$AISB_HOME/credentials/db-roles.json` (0600). To refuse queries that would fall back to a
session guard, set this in config.toml, e.g. on the box your MCP agents use:

```toml
[db]
readonly_role = "required"
```

SBOM per host, for CVE matching in your scanner of choice:

```bash
for h in $(aisb fleet hosts @prod | jq -r '.[].host'); do
  aisb fleet query "$h" -- images sbom shop-api:1.5 --format cyclonedx | jq '.results[0].result' > "sbom-$h.json"
done
aisb images diff shop-api:1.4 shop-api:1.5        # what changed: files, package up/downgrades, config
```

Vulnerabilities, stale images, certificates:

```bash
aisb images vulns shop-api:1.5 --min-severity high -o table     # packages -> OSV.dev: ids, severity (CVSS), fixed versions
aisb fleet query @prod -- images vulns shop-api:1.5 --no-details --limit 0   # counts per host, fast
aisb images updates                                             # images of running containers whose registry tag moved
aisb fleet query all -- images updates --all -o table
aisb net tls web --port 443 --server-name shop.example.com      # days left, issuer, SANs, hostname match
aisb fleet query @edge -- net tls proxy --port 443 | jq -r '.results[] | "\(.host) \(.result.days_left)"'
```

`images vulns` needs outbound HTTPS to `api.osv.dev` (or `AISB_OSV_URL` pointing at a mirror). `images updates`
uses Docker Hub/GHCR/any v2 registry, with credentials from `~/.docker/config.json`. `net tls` sets
`"ok": false` (exit 4) when fewer than 14 days are left, so it drops straight into cron.

Env contract before starting a new version (catches missing vars and typos such as `DATABSE_URL`):

```bash
aisb images envcheck shop-api:1.5 --env-file prod.env
```

---

## 14. Host (OS) level tasks

`fleet shell` runs on the machines themselves over SSH. It's mutate tier, so `--dry-run` shows the exact command per host.

```bash
aisb fleet shell all -- uptime
aisb fleet shell @prod -- 'uname -r; cat /etc/os-release | head -1'
aisb fleet shell @db -- 'df -h /var/lib/docker; free -m'
aisb fleet shell @web -- 'apt list --upgradable 2>/dev/null | tail -n +2 | wc -l'   # pending updates (Debian/Ubuntu)
aisb fleet shell @web --sudo --batch 1 --fail-fast -- 'systemctl restart docker && sleep 5 && docker info >/dev/null'
aisb fleet shell all -- 'journalctl -u docker --since -1h -p warning --no-pager | tail -20'
aisb fleet shell all --seconds 300 -- 'long-running-script.sh'              # per-host timeout
```

The results carry `exit_code`, `stdout` and `stderr` per host, and a non-zero exit marks the host failed:

```bash
aisb fleet shell all -- 'test -f /var/run/reboot-required' | jq -r '.results[] | select(.ok) | .host'   # hosts needing reboot
```

For real configuration management (packages, users, files, templates), use pyinfra with the same groups (§16).

---

## 15. Single-host power tools

Hands-on work on one host: run aisb on the host itself (`aisb bundle` → copy one file), or drive it from the
admin box with `aisb fleet query|apply|destroy HOST -- ...`.

| Need | Command |
|---|---|
| Triage everything | `aisb system doctor` |
| One container, fully | `aisb containers doctor api` |
| Wait properly (not `sleep`) | `aisb containers wait api --healthy --port 8080 --within 60`; `aisb svc ready db` |
| Undo a risky session | `aisb session begin` → work → `aisb session rollback --dry-run` / `--yes` |
| What did I change? | `aisb system snapshot > before.json` … `aisb system changes before.json` |
| Watch a deploy | `aisb system watch --interval 10 --duration 600 --until-change` |
| Outage root cause | `aisb system incident --since 15m --format markdown` |
| Crash recorder | `aisb system blackbox --seconds 3600`; `aisb system forensics NAME` |
| Chaos drill (dev only) | `aisb chaos run stacks/shop.json` |
| Local dashboard | `aisb portal` (loopback, token-protected, read-only unless `--allow mutate`) |

---

## 16. Automation: cron, systemd, CI, pyinfra, AI agents

### systemd timer instead of cron

`/etc/systemd/system/fleet-alert.service` and `.timer`:

```ini
[Unit]
Description=aisb fleet health alert
[Service]
Type=oneshot
User=ops
Environment=AISB_FLEET=/etc/aisb/prod.json
ExecStart=/usr/local/bin/aisb fleet status @prod --record --notify ops --fail-on failing
```

```ini
[Unit]
Description=Run fleet-alert every 5 minutes
[Timer]
OnCalendar=*:0/5
Persistent=true
[Install]
WantedBy=timers.target
```

`systemctl enable --now fleet-alert.timer`

### CI/CD (GitHub Actions example)

```yaml
deploy:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: {python-version: "3.12"}
    - run: pip install 'git+https://github.com/ckjackslack/aisb'
    - name: SSH key + known hosts
      run: |
        install -m 700 -d ~/.ssh
        echo "${{ secrets.DEPLOY_KEY }}" > ~/.ssh/id_ed25519 && chmod 600 ~/.ssh/id_ed25519
        echo "${{ secrets.KNOWN_HOSTS }}" > ~/.ssh/known_hosts
    - name: Plan
      run: aisb fleet apply @web --inventory infra/prod.json --dry-run -- stack up stacks/shop.json
    - name: Roll out
      run: aisb fleet apply @web --inventory infra/prod.json --batch 1 --fail-fast -- stack up stacks/shop.json
    - name: Verify
      run: aisb fleet status @web --inventory infra/prod.json --fail-on failing
```

Exit codes do the gating: a partial failure (4), an unhealthy verify (4) or a policy denial (5) fails the job.

GitOps variant: `aisb fleet diff infra/desired.json all --inventory infra/prod.json` on pull requests (the drift
report as the job output), `aisb fleet converge infra/desired.json all --batch 1 --fail-fast` on merge, with
`AISB_TICKET` set from the PR number so the audit log links every change to it.

### pyinfra for convergent deploys

```bash
pip install 'aisb[pyinfra] @ git+https://github.com/ckjackslack/aisb'     # or: pip install -e '.[pyinfra]'
aisb fleet export @prod --format pyinfra | jq -r .output > inventory.py
pyinfra inventory.py deploy.py --dry       # plan
pyinfra inventory.py deploy.py             # apply
```

`deploy.py`:

```python
from aisb.contrib.pyinfra import operations as aisb
from pyinfra.operations import apt, files

apt.packages(name="base tools", packages=["jq", "htop"], _sudo=True)
files.put(name="app secret", src="secrets/pg.secret", dest="/etc/shop/pg.secret", mode="600", _sudo=True)
aisb.install()                                            # bundles aisb onto the host (needs python3 >= 3.11 there)
aisb.stack(src="stacks/shop.json", recreate_drifted=True) # no-op when converged; recreate is your explicit approval
aisb.ready(container="shop-db", within=120)               # deploy fails unless the DB really answers
aisb.limits(container="shop-api", memory="512m", cpus=1)  # live, only when different
```

Run pyinfra operations *inside* containers without a docker CLI: `pyinfra @aisb/shop-api exec -- nginx -t`.

### AI agents (MCP)

```bash
claude mcp add aisb-ro -- aisb mcp --max-tier read     # read-only: status, doctor, query, logs...
claude mcp add aisb -- aisb mcp                        # everything; destroy tools still need confirm=true
```

The inventory is picked up from `$AISB_FLEET`, so the agent sees the same hosts and groups you do.
Policy rules with `source = "mcp"` restrict what agents may do, and every agent change is audited with
`source: mcp`. Give agents server-enforced read-only SQL with `db grant-readonly` (§13) and `[db] readonly_role = "required"`. The server also offers resources (`aisb://fleet/status`, `aisb://runbooks/pending`,
`aisb://audit/recent`, `aisb://policy/rules`, `aisb://runbooks/NAME`) and prompts (`investigate-incident`,
`rollout`, `daily-check`, and one per runbook).

---

## 17. Troubleshooting

| Symptom (host `down` reason, or error) | Cause | Fix |
|---|---|---|
| `Host key verification failed` | first contact; BatchMode can't prompt | `ssh-keyscan HOST >> ~/.ssh/known_hosts`, or `--ssh-option StrictHostKeyChecking=accept-new` |
| `Permission denied (publickey)` | key not offered or not authorized | `ssh -v user@host`; add `--key`, load the agent (`ssh-add`), or check `authorized_keys` |
| `... may USER open /var/run/docker.sock? docker group` | SSH works, the socket doesn't | `usermod -aG docker USER`, then re-login; or the socket path is different (`--docker`) |
| `Connection reset by peer` right after connecting | Docker isn't running, or forwarding is disabled | `systemctl status docker`; `sshd -T \| grep -i forwarding` |
| `tunnel ... did not come up` | slow link / MFA / ProxyJump prompt | make the jump non-interactive; test `ssh -o BatchMode=yes HOST true` |
| `sudo: a password is required` (shell --sudo) | sudo needs a TTY/password | `NOPASSWD` rule for the specific commands, or run as a privileged user |
| `unknown host 'wbe1'` / `unknown group @x` | selector typo | `aisb fleet hosts`, `aisb fleet groups` |
| `X is mutate tier: run it with aisb fleet apply` | wrong fleet verb | use query/apply/destroy to match the op's tier |
| exit 3 | destroy without `--yes` | read the plan; add `--yes` once approved |
| exit 4 | some hosts failed | `jq '.summary, (.results[] | select(.ok|not))'` |
| exit 5, `denied by policy rule ...` | a `[[policy.rules]]` entry matched | `aisb policy check -- CMD` explains it; add `--ticket`, wait for the window, or ask the rule's owner |
| `config: ...` error at startup | invalid config.toml | `aisb config show`; unknown keys and bad rules are named |
| `resume refuses: runbook changed since the run started` | the file was edited mid-run | review the diff; `--allow-changed` if intended |
| `images vulns`: HTTP 403 / timeout | no egress to api.osv.dev | allow it, or set `AISB_OSV_URL` to a mirror |
| TCP host shows no load/disk | TCP-only hosts have no shell | add SSH access, or accept Docker-only data |

Debugging a single host by hand, the same way aisb does it:

```bash
ssh -o BatchMode=yes deploy@web1 'id; ls -l /var/run/docker.sock'        # can this user reach the socket?
ssh -N -o ExitOnForwardFailure=yes -L /tmp/w1.sock:/var/run/docker.sock deploy@web1 &
aisb system ping --host unix:///tmp/w1.sock                              # the exact path fleet uses
kill %1; rm -f /tmp/w1.sock
```

---

## 18. Limits and gotchas

- **Paths are admin-box paths.** Files you pass (`--file`, `OUT`, stack files, `--spec`, `--env-file`) are read or written where aisb runs. Loop per host for per-host outputs.
- **Container addresses are the host's view.** `http get/send/replay`, `containers wait --port` and the
  broker adapters dial published ports and container IPs *through SSH* (an on-demand `ssh -L`), so they work
  across NAT and bastions. URLs printed by `svc list/url` are likewise as seen *from that host* (e.g. `127.0.0.1:5432`).
- **`http record` over a fleet: use `--via tcpdump`.** Proxy mode listens on the admin box, so it would only
  see traffic you send through the admin box.
- **One SSH tunnel per host per call.** Commands are multiplexed (ControlMaster, 120 s persist). Docker tunnels are fresh connections. Fine for hundreds of hosts at `--parallel 16`. Lower `--parallel` over slow links.
- **Vitals need Linux + a POSIX shell** (`/proc`, `df`). Other hosts still get Docker-level health.
- **Sessions (undo) are best-effort, not transactions.** A session opened on the admin box also journals fleet changes and rolls them back per host; data written by containers in between is not undone. For big changes, still rely on `--dry-run`, canaries, `--batch 1 --fail-fast`, and stack files in git.
- **Runbook steps have no timeout of their own.** Bound fleet steps with `--host-timeout`.
- **Metrics history is local sqlite.** One admin box records; for team-wide dashboards use the Prometheus exporter.
- **`fleet watch` is a foreground loop.** Run it in tmux, or use cron/systemd with `--until-change` for alerts.
- **`stack up` never recreates drifted services by itself.** Replacing a container is an explicit `stack down --service` (destroy tier) or pyinfra's `recreate_drifted=True`.
- **Volumes are never deleted implicitly.** `--volumes` is always opt-in, and destroy-tier ops always show a plan first.
