# aisb for sysadmins and DevOps: a field guide

Practical recipes for running Docker hosts with `aisb`, from one box to a fleet of them. Every command
here is copy-pasteable; replace names in `CAPS` or the example names (`web1`, `@prod`, `shop`).

- [1. Mental model](#1-mental-model)
- [2. Setup](#2-setup)
- [3. Scripting contract: JSON, exit codes, safety tiers](#3-scripting-contract-json-exit-codes-safety-tiers)
- [4. Inventory: hosts, groups, labels, selectors](#4-inventory-hosts-groups-labels-selectors)
- [5. Daily operations across the fleet](#5-daily-operations-across-the-fleet)
- [6. Monitoring and alerting](#6-monitoring-and-alerting)
- [7. Deployments and rolling changes](#7-deployments-and-rolling-changes)
- [8. Incidents](#8-incidents)
- [9. Capacity, disk and cleanup](#9-capacity-disk-and-cleanup)
- [10. Backups and disaster-recovery drills](#10-backups-and-disaster-recovery-drills)
- [11. Security and compliance sweeps](#11-security-and-compliance-sweeps)
- [12. Host (OS) level tasks](#12-host-os-level-tasks)
- [13. Single-host power tools](#13-single-host-power-tools)
- [14. Automation: cron, systemd, CI, pyinfra, AI agents](#14-automation-cron-systemd-ci-pyinfra-ai-agents)
- [15. Troubleshooting](#15-troubleshooting)
- [16. Limits and gotchas](#16-limits-and-gotchas)

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

## 4. Inventory: hosts, groups, labels, selectors

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
- **Computed groups** are defined by selectors and always up to date. You edit them in the JSON file.

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

Always check a selection first: `aisb fleet hosts '@prod,&region=eu'`.

### Several environments

```bash
export AISB_FLEET=~/infra/fleets/staging.json   # per shell
aisb fleet status --inventory ~/infra/fleets/prod.json all
```

Keep the inventory files in git. They contain no secrets: keys stay in your SSH agent or `~/.ssh`.

### Export to other tools

```bash
aisb fleet export --format ssh-config | jq -r .output > ~/.ssh/config.d/aisb   # `ssh web1` just works
aisb fleet export @prod --format pyinfra | jq -r .output > inventory.py         # groups become pyinfra groups
aisb fleet export --format json                                                  # raw
```

---

## 5. Daily operations across the fleet

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

## 6. Monitoring and alerting

### Interactive watch

```bash
aisb fleet watch @prod --interval 30 --duration 3600                 # report every change for an hour
aisb fleet watch @prod --interval 15 --duration 900 --until-change   # return on the first change (good after a deploy)
```

Events: `went down`, `recovered`, `worse`, `better`, `changed`, each with `new` and `resolved` reasons.

### Cron alert (no monitoring stack needed)

`/etc/cron.d/aisb-fleet` (runs every 5 min as the ops user):

```cron
*/5 * * * * ops /usr/local/bin/fleet-alert.sh >> /var/log/fleet-alert.log 2>&1
```

`/usr/local/bin/fleet-alert.sh`:

```bash
#!/bin/sh
set -eu
export AISB_FLEET=/etc/aisb/prod.json
out=$(aisb fleet status @prod --tail 50)
bad=$(echo "$out" | jq '[.hosts[] | select(.verdict == "down" or .verdict == "failing")] | length')
[ "$bad" -eq 0 ] && exit 0
msg=$(echo "$out" | jq -r '.hosts[] | select(.verdict == "down" or .verdict == "failing")
        | "\(.host) \(.verdict): \(.reasons | join("; "))"')
# any webhook works; Slack-compatible example:
curl -fsS -X POST -H 'Content-Type: application/json' \
     -d "$(jq -n --arg t "$msg" '{text: ("fleet alert\n" + $t)}')" "$SLACK_WEBHOOK_URL"
```

Variations:
- **Only on change** (no repeat alerts): run `aisb fleet watch @prod --interval 60 --duration 290 --until-change` from cron, and alert when `.events | length > 0`.
- **Degraded too**: select `.verdict != "healthy"`.
- **Container-level**: use `aisb fleet doctor @prod | jq '.problems'`.
- **Reachability only, cheap**: `aisb fleet ping @prod || alert`. It exits 4 if any host is unreachable.

### Right-size limits before they bite

```bash
aisb fleet query @web -- system rightsize --seconds 120 --interval 5 \
  | jq -r '.results[] | .host as $h | .result.containers[] | select(.flags|length>0) | [$h, .name, (.flags|join(",")), .command] | @tsv'
# apply one recommendation (live, no restart):
aisb fleet apply web1 -- containers limit api --memory 384m --cpus 1
```

---

## 7. Deployments and rolling changes

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

### Verify a new version with recorded traffic (before switching)

```bash
aisb fleet ship nicolaka/netshoot:v0.13 web1                                    # capture sidecar image, once
aisb fleet query web1 -- http record api --via tcpdump --seconds 120 --out /tmp/api.jsonl   # real traffic, passively
aisb fleet apply web1 -- http replay /tmp/api.jsonl --to api-next --ignore 'meta.*'
```

### Rollback

- **Image-level:** put the previous tag back in the stack file and repeat the rollout.
- **Anything done on one host in a session:**

  ```bash
  aisb session begin
  # ...changes...
  aisb session rollback --yes
  ```

  Sessions are per Docker endpoint on the admin box. Use them for hands-on work on one host (see §13).

---

## 8. Incidents

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

End every incident note with the evidence (quoted reasons, findings, log lines), the hypothesis, and the fix command.

---

## 9. Capacity, disk and cleanup

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

## 10. Backups and disaster-recovery drills

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

## 11. Security and compliance sweeps

```bash
aisb fleet query all -- system audit --min-severity critical # privileged, docker.sock mounts, root, exposed datastores...
aisb fleet query @web -- containers secrets api              # secrets in env / image history (values masked)
aisb images secrets shop-api:1.5                             # before you ship it
```

SBOM per host, for CVE matching in your scanner of choice:

```bash
for h in $(aisb fleet hosts @prod | jq -r '.[].host'); do
  aisb fleet query "$h" -- images sbom shop-api:1.5 --format cyclonedx | jq '.results[0].result' > "sbom-$h.json"
done
aisb images diff shop-api:1.4 shop-api:1.5        # what changed: files, package up/downgrades, config
```

Env contract before starting a new version (catches missing vars and typos such as `DATABSE_URL`):

```bash
aisb images envcheck shop-api:1.5 --env-file prod.env
```

---

## 12. Host (OS) level tasks

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

For real configuration management (packages, users, files, templates), use pyinfra with the same groups (§14).

---

## 13. Single-host power tools

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

## 14. Automation: cron, systemd, CI, pyinfra, AI agents

### systemd timer instead of cron

`/etc/systemd/system/fleet-alert.service` and `.timer`:

```ini
[Unit]
Description=aisb fleet health alert
[Service]
Type=oneshot
User=ops
Environment=AISB_FLEET=/etc/aisb/prod.json
ExecStart=/usr/local/bin/fleet-alert.sh
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
      run: |
        aisb fleet status @web --inventory infra/prod.json \
          | jq -e '[.hosts[] | select(.verdict=="down" or .verdict=="failing")] | length == 0'
```

Exit codes do the gating: a partial failure (4) or an unhealthy verify fails the job.

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

---

## 15. Troubleshooting

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
| TCP host shows no load/disk | TCP-only hosts have no shell | add SSH access, or accept Docker-only data |

Debugging a single host by hand, the same way aisb does it:

```bash
ssh -o BatchMode=yes deploy@web1 'id; ls -l /var/run/docker.sock'        # can this user reach the socket?
ssh -N -o ExitOnForwardFailure=yes -L /tmp/w1.sock:/var/run/docker.sock deploy@web1 &
aisb system ping --host unix:///tmp/w1.sock                              # the exact path fleet uses
kill %1; rm -f /tmp/w1.sock
```

---

## 16. Limits and gotchas

- **Paths are admin-box paths.** Files you pass (`--file`, `OUT`, stack files, `--spec`, `--env-file`) are read or written where aisb runs. Loop per host for per-host outputs.
- **Container addresses are the host's view.** `http get/send/replay`, `containers wait --port` and the
  broker adapters dial published ports and container IPs *through SSH* (an on-demand `ssh -L`), so they work
  across NAT and bastions. URLs printed by `svc list/url` are likewise as seen *from that host* (e.g. `127.0.0.1:5432`).
- **`http record` over a fleet: use `--via tcpdump`.** Proxy mode listens on the admin box, so it would only
  see traffic you send through the admin box.
- **One SSH tunnel per host per call.** Commands are multiplexed (ControlMaster, 120 s persist). Docker tunnels are fresh connections. Fine for hundreds of hosts at `--parallel 16`. Lower `--parallel` over slow links.
- **Vitals need Linux + a POSIX shell** (`/proc`, `df`). Other hosts still get Docker-level health.
- **Sessions (undo) are per Docker endpoint on the admin box**, not fleet-wide transactions. For fleet changes, rely on `--dry-run`, canaries, `--batch 1 --fail-fast`, and stack files in git.
- **`fleet watch` is a foreground loop.** Run it in tmux, or use cron/systemd with `--until-change` for alerts.
- **`stack up` never recreates drifted services by itself.** Replacing a container is an explicit `stack down --service` (destroy tier) or pyinfra's `recreate_drifted=True`.
- **Volumes are never deleted implicitly.** `--volumes` is always opt-in, and destroy-tier ops always show a plan first.
