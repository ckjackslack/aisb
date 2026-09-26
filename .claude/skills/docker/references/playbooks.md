# Playbooks

`A` below stands for `aisb` or `PYTHONPATH=src python3 -m aisb`.

Stop *looking for causes* at the first step that explains the problem. Still gather whatever the fix needs, such as the current env or mounts, before proposing it.

## Triage a whole host ("what's wrong with my Docker?")

1. `A system doctor` returns a summary and the problem containers, worst first. Each has a `likely_cause`. By default it scans the last 200 log lines per container; `scope` says what was checked.
2. For each problem container, run `A containers doctor NAME` (listed in `next`). It adds a deeper log scan, live stats, and whether named dependencies exist.
3. `healthy` means no signal in state, config, image or recent logs, not proven healthy. If the user reports a symptom on one, run `A containers patterns NAME` on it anyway. `numbers.trend: up` on latency, or `repeated_ids`, reveals trouble that emits no errors.
4. `A system df` if disk space may be part of it.

## Diagnose a crashing, restarting or unhealthy container

0. **`A containers doctor NAME` first.** If its top finding carries clear evidence (for example `missing-env` with the var `NOT set`, or `oom-killed`), go straight to the fix. Use the steps below only to confirm or dig deeper.
1. `A containers list --all`: find the container, its `state` and `status` (for example "Restarting (1) 5 seconds ago"). Trust `State.Status` and `State.Restarting`; `State.Running` can read `true` between restarts.
2. `A containers inspect NAME --fields State,RestartCount,Config.Image,Config.Cmd,Config.Entrypoint,HostConfig.RestartPolicy`
   - `State.ExitCode`:

     | Code | Meaning |
     |---|---|
     | 0 | The process ended normally. Wrong command, or a one-shot job? |
     | 1 or 2 | Application error. |
     | 125–127 | Docker, permission or command-not-found. |
     | 137 | SIGKILL: OOM or `stop` timeout. |
     | 139 | Segfault. |
     | 143 | SIGTERM. |
   - `State.OOMKilled: true` means go to the OOM playbook.
   - `State.Health.Log[-1].Output` shows the failing healthcheck output.
3. `A containers patterns NAME` for the error templates and the `emerging` ones. Then `A containers logs NAME --grep 'TEMPLATE WORDS' --context 3 --tail 0` for the full story around the first error. Quote the first error, not the last symptom.
4. `A system events --since 30m --filter container=NAME --limit 50` to see the die/start/oom/kill sequence and timing.
5. If it is running: `A containers top NAME` and `A containers stats NAME` to check for a CPU spin, a leak, or a zombie build-up.
6. Config mistakes: `A containers inspect NAME --fields Config.Env,HostConfig.Binds,HostConfig.PortBindings,Mounts`. Look for missing env, wrong mount path, or a port clash.
7. A config error is fixed by recreating the container. Env, ports and mounts can't be changed in place. See the next playbook.

## Recreate a container with a fixed config

1. `A containers spec NAME > spec.json` dumps the current config as RunSpec JSON. Image-default `Env` and `Volumes` entries are included; they're harmless.
2. Edit `spec.json` (add the missing env, fix the port or mount). Show the user the diff.
3. `A containers run IMAGE --spec spec.json --detach --dry-run` checks the new create body. Read its `warnings`: preflight flags a name still in use (expected before the `rm`), a missing network or volume, a non-local image, and host-port clashes. Fix everything except the name warning before going on.
4. `A containers rm NAME --force --dry-run` previews the removal. It is destroy tier: **stop and ask**. If named volumes hold data, point out that they survive `rm` without `--volumes`.
5. After approval, run `A containers rm NAME --force --yes`, then `A containers run IMAGE --spec spec.json --detach`.
6. Verify with `A containers wait NAME --running --within 30`. Add `--healthy` if it has a healthcheck, or `--log 'ready'`. Then run `A containers doctor NAME`, which should say `healthy`.

## OOM-killed

1. `A containers inspect NAME --fields State.OOMKilled,HostConfig.Memory`. A `Memory` of 0 means unlimited, so the host ran out.
2. `A containers stats NAME` to see current usage against the limit.
3. Propose either a raised `memory` in the spec or an app-level fix. Apply it with the recreate playbook.

## Container-to-container networking

1. `A net probe SRC DST --port P` checks, in order: shared user-defined network, DST listening on P (and on which address), DNS from SRC, TCP from SRC. `broken_at` is the first failing layer, and each failing step carries a `fix`.
2. Typical outcomes:

   | `broken_at` | Cause | Fix |
   |---|---|---|
   | `shared-network` | Only the default bridge is shared (no DNS by name), or no network is shared. | `networks create` + `networks connect` |
   | `listening` with "loopback only" | The server binds 127.0.0.1. | Make it bind 0.0.0.0. |
   | `listening` with "nothing listens" | The app didn't start. | `containers doctor DST` |
   | `dns` | Wrong name, or not on the same network. | Check the alias in `A net map`. |
   | `tcp` | Firewall, wrong port, or the app is overloaded. | Investigate further with the tools below. |
3. `A net map` shows every network with its containers, IPs and DNS aliases.
4. SRC has no shell or tools: `A containers debug SRC -- nc -zv DST P` (or `--image nicolaka/netshoot -- dig DST`).
5. Host to container: `A http get NAME /path` resolves the published port. If `via` says "container IP", the port isn't published.

## Reclaim disk space

1. `A system df`: counts, sizes and `reclaimable` per type.
2. List candidates and present them as a table:
   - `A containers list --all` for exited containers.
   - `A images list --dangling`.
   - `A volumes list --dangling`.
3. Run the preview: `A system prune [--managed] [--no-images] ... --dry-run`. It shows the planned calls. Tell the user what would go.
4. Only after explicit approval, re-run the same command with `--yes`. Volumes need both `--volumes` and approval that names volumes.

## Reproducible service from a RunSpec

1. Write `spec.json`. Keys are RunSpec fields; `env` accepts a `["K=V"]` list, as `containers spec` emits it, or a `{"K": "V"}` dict:
   ```json
   {"image": "postgres:16", "name": "pg", "env": {"POSTGRES_PASSWORD": "dev"},
    "ports": ["127.0.0.1:5432:5432"], "volumes": ["pgdata:/var/lib/postgresql/data"],
    "restart": "unless-stopped", "memory": "512m", "health_cmd": "pg_isready -U postgres"}
   ```
2. `A containers run postgres:16 --spec spec.json --detach --dry-run`, then run it without `--dry-run`. CLI flags override the file; the positional image always wins.
3. Verify with `A containers wait pg --healthy --within 90`, not a sleep. It exits 4 with the reason and log tail if pg dies first.

## Build and smoke-test an image

1. `A images build ./path --tag app:dev --build-arg VERSION=1`. On failure the error includes the build log tail. The failing `Step N` is the fix target.
2. `A containers run app:dev --rm -- app --version` for a one-shot check. `exit_code` and `output` come back in one JSON object.
3. `A images history app:dev` to find which layer is bloated.

## Audit and clean up after a session

1. At the start: `A system snapshot > /tmp/aisb-before.json`.
2. At the end: `A system changes /tmp/aisb-before.json` shows what was added, removed or recreated. Report it to the user.
3. `cleanup` lists dry-run destroy commands for exactly the added objects. Run them, show the plans, **ask**, then re-run the approved ones with `--yes` in place of `--dry-run`.

## Investigate a slow or stuck database

1. `A svc stats NAME` (or `A db activity NAME`). Look at `active` (longest first), `blocked_by`, `locks_waiting`, and connections against `max_connections`.
2. A query with a non-empty `blocked_by` is a victim. The pid it points to is the **blocker**, usually an idle-in-transaction session or a long migration.
3. Show the user the blocker's query, age and user. `A db kill NAME PID --dry-run`, then after approval `A db kill NAME PID` (cancel). Use `--terminate` only if cancel is not enough.
4. Re-run `A db activity NAME` to confirm `locks_waiting` is 0.
5. Near the connection limit: check the app's pool settings, and whether many sessions are `idle in transaction`.

## Safely change data in a database container

1. Explore read-only: `A db tables NAME`, `A db describe NAME TABLE`, then `A db query NAME "SELECT count(*) ... WHERE <the same predicate>"` to learn how many rows will change.
2. Back up what you will touch: `A db dump NAME /tmp/before.sql.gz --table TABLE`.
3. Preview: `A db exec NAME "UPDATE ... WHERE ..." --dry-run`. Show the statement and the expected row count, and get approval.
4. Run it and compare `affected` with the count from step 1. If they differ, stop and tell the user. The dump from step 2 is the undo path (`db restore`, destroy tier).

## Rehearse a migration on a clone

1. `A db clone NAME NAME-rehearsal` gives a copy of the data in a disposable container, ready when the command returns.
2. `A db exec NAME-rehearsal --file migration.sql`. Check the timing and errors; iterate freely.
3. `A db diff NAME NAME-rehearsal --counts` shows exactly what the migration changes. Show it to the user.
4. Only then apply it to NAME (dump first, see "Safely change data"), and remove the clone with `A containers rm NAME-rehearsal --force` (destroy tier: ask).

## Security review of a host

1. `A system audit` (add `--min-severity info` for everything). Containers are listed worst score first; `most_common` shows systemic issues.
2. For each critical finding, explain the risk in one line and give its fix. `docker-socket`, `privileged`, `datastore-exposed` and `sensitive-mount` come first.
3. `A containers secrets NAME --path /app --path /root` for the risky ones, and `A images secrets IMAGE` for images you build. A secret in image history means **rotate it**: removing the layer doesn't unpublish it.
4. Never echo secret values; the tools mask them, so quote only the masked form.

## Bring up, check and tear down a dev stack

1. Write `stack.json` (format in `src/aisb/stack.py`), then `A stack up stack.json --dry-run` to review the plan.
2. `A stack up stack.json`. When it returns `ok: true`, every service passed its readiness gate. On `ok: false`, the entry for the failing service has `ready.reason`, and `next` points to `containers doctor`.
3. `A stack ps stack.json` shows state, ports and `drift` (the file changed since the container was created). To apply drift: `A stack down stack.json --service NAME --dry-run`, ask, then `stack up` again.
4. `A net probe STACK-app db --port 5432` if a service can't reach another.
5. `A stack down NAME` (destroy tier). Volumes stay unless `--volumes` is passed, which needs explicit approval.

## Undoable session for risky work

1. `aisb session begin --name cleanup` (add `--protect-data` if you will run `db exec` writes).
2. Do the work as usual. Destroy ops still need the user's approval and `--yes`.
3. `aisb session status` lists each journaled change and whether it can be undone.
4. Keep it: `aisb session end`. Revert it: `aisb session rollback --dry-run`, show the plan, and after approval run `aisb session rollback --yes`.
5. Report `failed` and `not_undoable` from the rollback result explicitly.

## Multi-service incident root cause

1. `aisb system incident --since 30m`. Read `root_cause`, `chain`, `blast_radius` and `evidence`.
2. With `evidence: temporal` only timing supports the chain. Say so, and run `aisb net graph` while the stack is healthy to get real dependencies.
3. `aisb containers doctor ROOT` for the root's likely cause; `aisb system forensics ROOT` if it is already gone.
4. Hand over `aisb system incident --since 30m --format markdown` as the postmortem draft.

## Reproduce a production-like bug locally

1. On the machine with the bug: `aisb capsule create NAME bug.tar.gz --db-sample 0.02`. Add `--volumes` only if the data is needed and allowed to leave.
2. Elsewhere: `aisb capsule load bug.tar.gz --env SECRET=...` for each `missing_secrets` entry.
3. Before starting a new container: create it, then `aisb containers envcheck NAME` to catch missing or misspelled variables.
4. `aisb images diff GOOD_IMAGE BAD_IMAGE` when a new image is the suspect.

## Performance: missing indexes and right-sizing

1. `aisb db activity NAME` to find the slow statement, then `aisb db advise NAME "SELECT ..."`.
2. Report only `winners` (measured on a clone) with their `ddl`. Applying them is a `db exec`, so clone-rehearse first on big tables.
3. `aisb db advise NAME` with no SQL gives the unindexed-FK and unused-index report.
4. Limits: `aisb system rightsize --seconds 300` under representative load, then `containers limit` for `at-risk` and `unlimited` containers after the user agrees.

## Resilience game day

1. Only on a dev stack the user owns. Confirm first.
2. `aisb chaos run stack.json --seconds 10`. Each fault is injected, observed and reverted.
3. Present `findings`: which services went down with which dependency, and failures their own health checks missed.
4. Suggest fixes (timeouts, retries, health checks), then re-run to show the score change.

## Verify a refactor with recorded traffic

1. Point clients at `aisb http record OLD --out t.jsonl --listen 18099 --seconds 120`, or capture passively with `--via tcpdump`.
2. Start the new version as another container, then `aisb http replay t.jsonl --to NEW` (add `--ignore 'meta.*'` for known-volatile fields).
3. Report `match_rate`, each mismatch's path with old and new values, and the latency ratio.
