# `aisb fleet`: many machines, one CLI

One level above `aisb`: an inventory of machines, grouped and labelled, that you query, monitor, and act on
one host or many at a time. Every existing aisb op runs fleet-wide unchanged.

## Principles

- **Agentless, stdlib-only.** Transport is the system OpenSSH client (`subprocess`), so `~/.ssh/config`,
  agents, ProxyJump and known_hosts all work as usual. Each remote Docker socket is forwarded to a private
  local unix socket (`ssh -L local.sock:/var/run/docker.sock`), and a normal `Docker` client talks to it.
  **Remote hosts need only sshd and Docker: no Python, no aisb, no docker CLI.**
- **The registry still drives everything.** `fleet` is an ordinary resource: CLI, MCP tools, docs and
  tiers come for free. Fleet-wide execution keeps the inner op's tier: read ops go through `fleet query`,
  mutate through `fleet apply` (with a per-host `--dry-run` plan), destroy through `fleet destroy` (exit 3
  and a per-host plan without `--yes`).
- **Monitoring is triage, not metrics.** `status` and `watch` answer "which machines need attention and why",
  combining host vitals (load, memory, disk) with the per-container verdicts aisb already computes.

## Inventory

`$AISB_FLEET`, else `$AISB_HOME/fleet.json` (0600). Edited with `fleet add/remove/group`, or by hand:

```json
{"hosts": {
   "web1":  {"ssh": "deploy@10.0.0.5", "groups": ["web", "prod"], "labels": {"region": "eu"}},
   "db1":   {"ssh": "db1.internal", "port": 2222, "key": "~/.ssh/ops", "groups": ["db", "prod"]},
   "build": {"docker": "tcp://build:2376"},
   "here":  {}
 },
 "groups": {"edge": ["@web", "region=us"]}}
```

A host with `ssh` is tunnelled, and `docker` then names the remote socket (default `/var/run/docker.sock`).
A host without `ssh` uses `docker` as a direct endpoint (tcp+TLS, unix); an empty entry is this machine.
Top-level `groups` are computed groups defined by selectors, and they can nest.

## Selectors

`TARGET` is a comma-separated list of terms:

| term | meaning |
|---|---|
| `all` | every host |
| `web1`, `web*` | a name or a glob |
| `@prod` | a group (explicit membership or computed) |
| `region=eu` | a label |
| `&@db` | intersect with the result so far |
| `!web2` | exclude |

Plain terms are unioned first, then `&` terms intersect and `!` terms subtract. A selection with only
`!` terms starts from all hosts. An empty selection is an error, and so is an unknown bare name (typos
don't silently match nothing).

## Operations

| op | tier | what |
|---|---|---|
| `hosts [TARGET]`, `groups` | read | the inventory, resolved |
| `add NAME ...`, `remove NAME`, `group NAME --add/--remove TARGET` | mutate | edit the inventory |
| `ping TARGET` | read | SSH plus Docker round trip, latency, Docker version |
| `status TARGET` | read | per-host verdict and reasons: vitals plus container triage, worst first |
| `watch TARGET` | read | re-run status; report host down/up, verdict changes and new reasons |
| `ps TARGET`, `doctor TARGET` | read | containers or problems across hosts in one table (`host` column) |
| `query TARGET -- RESOURCE OP ARGS` | read | any read op on each host |
| `apply TARGET -- RESOURCE OP ARGS` | mutate | any mutate op; `--dry-run` shows the per-host plan |
| `destroy TARGET -- RESOURCE OP ARGS` | destroy | any destroy op; plan plus exit 3 until `--yes` |
| `shell TARGET -- CMD` | mutate | a shell command on the machines themselves (SSH) |
| `export --format pyinfra/ssh-config/json` | read | the inventory for pyinfra deploys or `ssh` |

Fan-out options:
- `--parallel N` (default 8);
- `--batch N`: rolling, N hosts at a time;
- `--fail-fast`: stop scheduling new batches after a failure;
- `--flat`: list results merged into one table with a `host` column.

Every result is `{"host", "ok", "ms", "result" | "error"}` plus a summary. Exit 4 when any host failed.

## Health assessment (pure)

| verdict | when |
|---|---|
| `down` | SSH or Docker unreachable |
| `failing` | any failing container, root disk at least 90%, or available memory under 5% |
| `degraded` | any degraded container, root disk at least 80%, available memory under 10%, or load per CPU at least 2 |
| `healthy` | otherwise |

Reasons are short strings (`disk / 93%`, `container api failing: oom-killed`), and `watch` diffs them.

## Vitals

One SSH round trip runs a POSIX script that prints `/proc/loadavg`, `/proc/meminfo`, `nproc`,
`df -P /`, `/proc/uptime` and `os-release` between markers. A pure parser turns that into numbers.
Hosts reached over TCP report Docker's `/info` (CPUs, memory) only.
