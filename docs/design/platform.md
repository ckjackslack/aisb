# Platform layer: guardrails, automation and operations at scale

Everything here extends the three existing foundations: the **op registry** (one declaration → CLI, MCP,
docs, tiers), **`invoke()`** (the single choke point every op passes through), and **fleet** (agentless SSH).
Still stdlib-only at runtime. Optional integrations stay in `aisb.contrib`.

## 1. Invocation context and the `invoke()` pipeline

`aisb.context.Ctx` (a `contextvars` value, propagated into fleet worker threads) describes *who acts where*:

| field | set by |
|---|---|
| `user` | the OS user (`getpass.getuser()`), overridable with `$AISB_USER` |
| `source` | `cli`, `mcp`, `portal`, `runbook`, `fleet`, `api` |
| `host` | the fleet host an inner op runs on (`None` = the local endpoint) |
| `ticket` | `--ticket` / `$AISB_TICKET` (change-management reference) |
| `run_id` | runbook run or fleet operation id, which groups audit records |

`invoke(client, op, kwargs)` then runs:

```
policy.check (deny → PolicyDenied, exit 5; in previews the violations appear as warnings)
  → preview? (dry-run / destroy-without-confirm) → planned calls
  → HOOKS (session capture: record the inverse)
  → op.call
  → audit.record (ok/error, duration, redacted args) for mutate/destroy (reads optional)
```

Fleet runs each inner op through `invoke()` **per host** with `ctx.host` set. So policy, audit and session
capture apply per machine, with that machine's groups and labels.

## 2. Configuration: `~/.aisb/config.toml` (`$AISB_CONFIG`)

```toml
[defaults]                    # default flag values per op ("resource.op" or "resource.*")
"fleet.*" = { parallel = 16 }
"containers.logs" = { tail = 500 }

[aliases]                     # `aisb restart-api [extra args]`
restart-api = "fleet apply @web --batch 1 --fail-fast -- containers restart api"

[profiles.prod]               # `aisb --profile prod ...` or AISB_PROFILE=prod
env = { AISB_FLEET = "~/infra/prod.json" }
defaults = { "fleet.*" = { parallel = 4 } }

[audit]
path = "~/.aisb/audit.jsonl"  # default; hash-chained JSONL
reads = false
syslog = "udp://logs.internal:514"   # optional, also /dev/log

[plugins]
modules = ["acme_aisb.ops"]

[notify.ops]                  # alert destinations (see §6)
type = "slack"
url_env = "SLACK_WEBHOOK_URL"

[[policy.rules]]              # see §3
name = "prod destroy needs a ticket"
match = { tier = "destroy", hosts = "@prod" }
require = { ticket = true }
```

## 3. Policy guardrails

Each rule has a `match` and an effect.

`match` fields (all optional, all must hold):
- `op`: glob(s) over `resource.op`
- `tier`: one or more tiers
- `source`: one or more sources
- `user`: glob(s)
- `hosts`: a fleet selector; `local` means the local endpoint

Effects:
- `deny = true`
- `require = { ticket = true }`
- `window = { days = [...], hours = "09-17", tz = "UTC" }`: allowed only inside the window
- `deny_if = {...}` over the op arguments:
  - `privileged`
  - `image_tag` (list), `image` (glob)
  - `host_network`
  - `docker_socket` (mounts `/var/run/docker.sock`)
  - `volumes` (`--volumes` data deletion)
  - `force`

Evaluated in `invoke()` for real runs *and* previews: a `--dry-run` shows the plan plus the rules that would block it.
MCP returns the violation as a tool error, and the portal returns 403. `aisb policy check -- RESOURCE OP ...` explains
a decision without running anything, and `aisb policy rules` lists the effective rules.

## 4. Audit log

Every mutate/destroy (reads when `audit.reads`) is one JSONL record:
- `ts`, `user`, `source`, `endpoint`, `host`, `op`, `tier`, `args` (secrets redacted), `ticket`, `run_id`;
- `ok`, `error`, `ms`;
- `prev` and `hash`: a SHA-256 chain, so `aisb audit verify` detects edits and deletions.

It can optionally be mirrored to syslog. `aisb audit log --since 1d --action 'containers.*' --on web1` queries it.

## 5. Plugins

Third-party modules register resources/ops (`Resource` subclasses), service adapters (`@register`) and doctor rules
(`@rule`) on import. Sources:
- the `aisb.plugins` entry-point group;
- `$AISB_PLUGINS` (comma-separated modules);
- `[plugins] modules`.

Plugin resources join the registry after the built-ins, so they get CLI, MCP tools, docs, tiers, policy and audit
automatically. A broken plugin is reported, not fatal.

## 6. Fleet: robustness, sessions, monitoring

- **Connection pool.** A fleet op keeps one SSH master and one Docker tunnel per host for its whole duration,
  and so does `watch` across polls, plus the lazy port forwards.
- **`--host-timeout S`** (per host) and **`--retries N`** (transient SSH/Docker errors only, with backoff).
- **`--fail-on failing|degraded|down`** on `status`/`watch`: exit 4 when any host is at or above that level.
- **Fleet-wide undo.** A session journals changes on *any* host. The first touch of a host snapshots its baseline,
  and `session rollback` undoes every host from its own journal and baseline.
- **Metrics history.** `status --record` (or `watch`) appends samples to `$AISB_HOME/metrics.db` (sqlite3).
  - `fleet trends` gives per-host series, uptime %, and a least-squares disk-full forecast.
  - `fleet report` gives an SLO/uptime table.
- **Exporter.** `aisb exporter --port 9323` serves Prometheus text metrics (fleet or local).
- **Alert destinations.** `notify` sinks: `webhook`, `slack`, `ntfy`, `email` (smtplib).
  - `status/watch --notify NAME` sends only when there is something to report.
  - `aisb notify test NAME` checks a sink.

## 7. Runbooks

A TOML/JSON procedure of steps. Each step is an aisb command, so it inherits tiers, policy and audit:

```toml
name = "rollout-api"
vars = { image = "shop-api:1.5", stack = "stacks/shop.json" }

[[steps]]
name = "ship image"
run = "fleet ship {image} @web"

[[steps]]
name = "replace api on canary"
run = "fleet destroy @canary -- stack down shop --service api"

[[steps]]
name = "up canary"
run = "fleet apply @canary -- stack up {stack}"

[[steps]]
name = "gate: canary healthy"
run = "fleet status @canary --fail-on degraded"
retry = { times = 10, delay = 15 }

[[steps]]
name = "approve rest"
approve = "Canary healthy. Roll out to the remaining web hosts?"

[[steps]]
name = "rest"
run = "fleet apply '@web,!@canary' --batch 1 --fail-fast -- stack up {stack}"
```

| command | tier | what it does |
|---|---|---|
| `runbook plan FILE` | read | dry-runs every step: the full per-host plan, policy violations and approvals needed |
| `runbook run FILE` | destroy | without `--yes`: the plan and exit 3; with `--yes`: executes |
| `runbook resume RUN` | destroy | continues after the last completed step; steps already done are skipped |
| `runbook approve RUN` | mutate | answers an `approve` step, from the CLI or the portal |
| `runbook runs`, `runbook show RUN` | read | run history, each step's result and timing |

Execution details:
- Destroy steps count as approved by `--yes` on `run`; an `approve` step pauses the run with status `waiting`.
- Every step can have `when` (`always`, `on_failure`, `STEP.ok`, `STEP.failed`), `retry = {times, delay}` and
  `continue_on_error`.
- There is no per-step timeout: an in-process op can't be killed safely mid-flight, so bound fleet steps with
  `--host-timeout` instead.
- Runs persist in `$AISB_HOME/runbooks/RUN/state.json` and audit with `run_id`.

## 8. Desired state

A fleet state file maps selectors to stack files:
`{"assign": {"@web": ["stacks/shop.json"], "@db": ["stacks/db.json"]}}`.

- `fleet diff STATE` (read): per host × stack, whether each service is missing, stopped, drifted or ok, and which unmanaged stacks exist.
- `fleet converge STATE` (mutate): creates missing services and starts stopped ones, rolling with `--batch`. Drift is reported.
- `fleet replace-drifted STATE` (destroy): recreates drifted services host by host.

GitOps is then `git pull && aisb fleet converge state.json` from cron, a systemd timer or CI.

## 9. Supply chain and certificates

- `images vulns IMG`: the SBOM matched against OSV.dev (`querybatch`, urllib), with severity and fixed versions.
  Works over a fleet with `fleet query all -- images vulns IMG`.
- `images updates [IMG]`: local tag digests compared with the registry. It uses the registry HTTP API with
  anonymous bearer tokens (Docker Hub, GHCR, others) and reports which running images are stale.
- `net tls REF`: certificate chain facts for a container's TLS port (subject, SAN, issuer, notAfter,
  days left), reached through the same dialer as HTTP. So it works fleet-wide via SSH.

## 10. Operations at scale

- `fleet logs TARGET CONTAINER`: one timestamp-ordered stream across hosts, each line tagged with its host.
  It takes `--grep`, `--since`, and `--follow --seconds N`.
- `fleet remediate TARGET`: maps doctor causes to safe actions.

  | cause | action |
  |---|---|
  | exited with no restart | start |
  | unhealthy | restart |
  | OOM-killed | raise the memory limit 25% via a live update, then restart |
  | missing-env, image-pull and similar | a suggestion only |

  `--dry-run` = suggest, `--rule` limits the actions, and policy and audit apply.
- `fleet canary CANARY BASELINE --container api`: go/no-go from error-line rate, restarts, verdicts and
  (optionally) HTTP latency on both groups, with the reasons.

## 11. Ecosystem

- `stack import docker-compose.yml`: a stdlib YAML-subset reader mapped to stack JSON (services, image,
  command, environment, ports, volumes, depends_on, restart, healthcheck). Unsupported keys are reported, not dropped silently.
- `fleet import --from ssh-config|aws|csv FILE`: build or extend the inventory.
- **MCP resources**: `aisb://fleet/inventory`, `aisb://fleet/status`, `aisb://runbooks/NAME`, `aisb://audit/recent`.
  **MCP prompts**: `investigate-incident`, `rollout`, one per runbook.
- **Portal fleet view**: hosts with verdicts and reasons, per-host drill-down, and the pending runbook approvals queue,
  with approve/deny gated by `--allow mutate`.

## 12. Productization

- `aisb --version`, a single-sourced version.
- GitHub Actions:
  - CI: ruff, mypy, and unit tests on 3.11–3.13, plus live tests with Docker.
  - Release: wheel + sdist + deterministic `aisb.pyz` attached to tags.
- `aisb docs --site DIR`: one Markdown page per resource plus an index, for any static-site generator.
