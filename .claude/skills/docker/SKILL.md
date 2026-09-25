---
name: docker
description: Inspect, diagnose, and manage Docker containers, images, networks, and volumes through the stdlib-only `aisb` CLI (JSON output, tiered safety). Use when the user asks about running containers, docker logs, why a container is crashing / restarting / unhealthy / OOM-killed, port or network problems between containers, disk usage and cleanup, building or pulling images, running a one-off container, or executing a command inside a container.
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

End every diagnosis with: **evidence** (quoted fields and log lines), **root-cause hypothesis**, and **proposed fix**, including the exact command. Mark it destroy-tier if it is one.
