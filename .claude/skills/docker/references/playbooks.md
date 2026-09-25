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

1. `A containers inspect A --fields NetworkSettings.Networks` and the same for B. Do they share a user-defined network? The default `bridge` network has **no DNS by name**.
2. `A networks inspect NET --fields Containers,Internal`.
3. Resolve from inside: `A containers exec A -- getent hosts B`. Then `A containers exec A -- wget -qO- -T 3 http://B:PORT/`, or `nc -zv B PORT` if the image has it.
4. Fix, mutate tier: `A networks create app-net`, then `A networks connect app-net A` and `A networks connect app-net B --alias b`.
5. Host → container: check `HostConfig.PortBindings`, and whether the app listens on `0.0.0.0` rather than `127.0.0.1` inside the container (`A containers exec X -- netstat -tlnp`).

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
