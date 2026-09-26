# Design: undo, forensics, topology, data tooling, resilience, and a portal

Fourteen features, designed together because they share a small set of foundations. Every one is stdlib-only,
tiered like the rest of `aisb`, and exposed through the op registry, so each also appears in the CLI, the docs
and MCP. The exception is `portal`, a long-running server that is a CLI subcommand like `mcp`.

## Cross-cutting foundations (built first)

| Foundation | Purpose | Used by |
|---|---|---|
| `state.py`: `$AISB_HOME` (default `~/.aisb`) with `sessions/`, `blackbox/` and `recordings/` | Durable local state; atomic JSON writes | session, blackbox, capsule, http record |
| `Containers.transient(image)` | A context manager that creates a **never-started** labelled helper container and always removes it | rootfs, envcheck, sbom, image diff, capsule |
| `rootfs.walk(source)` | Streams tar headers (and small file contents on demand) from a container or an image via the archive API, with a byte budget | envcheck, sbom, image diff, capsule |
| `ops.HOOKS` | Called by `invoke()` just before a real (non-preview) mutate or destroy op runs | session (captures state for undo) |
| `insights/graph.py` | Established TCP connections from `/proc/net/tcp`, mapped to containers | net graph, incident, chaos blast radius |

**Tier refinement.** A transient never-started helper container is a net-zero side effect: it's labelled, and it's
removed in `finally`. Analyses built on one are **read** tier, so agents can use them freely. Ops whose purpose
is to change something stay mutate or destroy.

## 1. `session`: undo for Docker

- **Interface:** `session begin [--name N] [--protect-data]` · `session status` · `session list` · `session rollback [--id]` (destroy) · `session end`.
- **How it works:**
  - `begin` stores a baseline `snapshot` and marks the session active in `$AISB_HOME/sessions/current`.
  - While a session is active, an `ops.HOOKS` capturer runs before real destroy ops and records an inverse in `journal.jsonl`:

    | Op | Captured before it runs |
    |---|---|
    | `containers.rm` | RunSpec (`runspec_of`) plus image id |
    | `volumes.rm` | Volume tarball |
    | `db.restore` | `--clean` dump of the target DB |
    | `volumes.restore` | Volume tarball |
    | `stack.down` | Specs of the stack's containers, plus volume tarballs if `--volumes` |
    | `system.prune` | Inventory only; prune is documented as not undoable |
    | `containers.stop` / `start` | Previous state |
    | `db.exec`, `db.kill` | With `--protect-data`: a DB dump before `db.exec` |
  - `rollback` builds an inverse plan:
    1. Remove what was **added** since the baseline (snapshot diff).
    2. Replay journal inverses **newest first**: recreate containers from specs, restore volume tarballs, restore DB dumps, restore run state.
- **Refinements:**
  - Captures must not break the op. If a capture fails, the journal records `capture_failed` and rollback reports it as not undoable.
  - Secrets aren't written into specs on disk in clear: `env` values that match `SECRET_KEY` are stored. The files are mode 0600 and the capture is local. That's the only way a recreate is faithful.
  - Rollback is idempotent: each inverse is marked done in the journal.
  - `--dry-run` shows the whole inverse plan.

## 2. `system blackbox`: flight recorder

- **Interface:** `system blackbox --duration 600` records; `system forensics [NAME]` lists or reads records.
- **How it works:**
  - Streams `/events` bounded by `until = now + duration`.
  - On `die`, `oom` or `kill` it immediately captures `inspect`, the last 500 log lines and the exit code into `blackbox/<name>-<ts>.json`. The `die` event fires before `--rm` auto-removal, so capture races removal; recording the inspect first gives the best odds.
  - `forensics NAME` runs `insights.diagnose` on the saved record: a doctor for containers that no longer exist.
- **Refinement:** records are deduplicated per (container, start time), so a crash loop writes one record per death up to `--max-records`, which prevents disk blowup.

## 3. `containers capsule` / `containers uncapsule`: reproducible bug bundle

- **Capsule (read):** `capsule NAME out.tar.gz [--volumes] [--db-sample 0.05] [--image] [--log-lines 2000]`. The bundle contains:
  - `manifest.json`: version, time, Docker version, image ref, id and repo digests;
  - `spec.json`: RunSpec with secrets replaced by `"<redacted>"`, plus a list of the redacted keys;
  - `inspect.json`, with the same redaction;
  - `logs.txt` and `doctor.json`;
  - for SQL services, `db/schema.sql` and, with `--db-sample`, `db/sample.sql` (feature 8);
  - with `--volumes`, `volumes/<n>.tar` per mount, read from the **container's own archive** at the mount path, so no helper is needed;
  - with `--image`, `image.tar` from `GET /images/{ref}/get`.
- **Uncapsule (mutate):** `uncapsule FILE [--name] [--env K=V ...]`
  1. Load `image.tar` if present (`POST /images/load`); otherwise pull by digest, falling back to the ref.
  2. Create the container.
  3. `PUT` the volume archives into the created container before start.
  4. Start it, wait until `svc ready`, and load schema plus sample.
  5. Redacted env keys that aren't supplied through `--env` are reported as `missing_secrets`. The container is still created, and `doctor` will flag it.

## 4. `net graph`: live service map without instrumentation

- **Interface:** `net graph [--samples 3 --interval 1] [--stack FILE] [--format json|mermaid]`.
- **How it works:**
  - For each running container, read `/proc/net/tcp{,6}` through exec (`cat`).
  - Keep ESTABLISHED sockets (state `01`) and LISTEN sockets (`0A`).
  - Map every container IP to its name.
  - Edge rule, for a socket in A with remote `R:P`:
    - `R` belongs to container B and B listens on `P`: edge **A → B :P** (A depends on B).
    - `R` is not a container and not loopback: **egress** A → `R:P`.
    - A's local port is one of A's listeners and `R` is not a container: **external client** of A.
  - Union over the samples, because short-lived connections are missed by one snapshot.
- **Output:**
  - nodes (with `observed: false` for images that have no `cat`), edges with counts, egress, isolated nodes;
  - with `--stack`: `undeclared_dependencies` (edge but no `depends_on`) and `unused_declared` (`depends_on` but no edge);
  - Mermaid `graph LR` text.

## 5. `system incident`: causal incident report

- **Interface:** `system incident --since 30m [--format json|markdown]`.
- **How it works:**
  1. Collect **signals** with timestamps: container events (`die`, `oom`, `kill`, `restart`, `health_status: unhealthy`), and, for each container, the first time each error or warn template appears in its timestamped logs (fingerprinting), plus doctor findings.
  2. Build the dependency graph with `net graph` (one sample) and add stack labels where they exist.
  3. **Root-cause ranking:** order the failing containers by their earliest critical signal. A container is a *candidate root* if nothing it depends on failed earlier. Its **blast radius** is every container that transitively depends on it and shows signals *after* its first signal.
  4. The chain runs root, then its dependents, ordered by first signal.
- **Output:**
  - a summary sentence, root cause (container, first signal, likely_cause from doctor), chain, blast radius, and the top 60 merged signals as a timeline;
  - with `markdown`: a postmortem skeleton with Impact, Timeline, Root cause, Contributing factors, Next steps (doctor `next` commands) and Open questions.
- **Refinement:** when no failure is found, it says so, and lists the degraded containers instead of inventing a cause.

## 6. `containers envcheck` / `images envcheck`: the env contract

- **Interface:**
  - `containers envcheck NAME` (read) works on running, stopped or created containers;
  - `images envcheck IMAGE [--env K=V ...] [--env-file F]` (read) uses a transient helper.
- **How it works:**
  1. Walk the app directories: WORKDIR, `/app`, `/srv`, `/usr/src/app`, `/opt/app`, `/code`, `/workspace`, plus `--path`, and the entrypoint script. Skip dependency directories (`node_modules`, `site-packages`, `vendor`, `.git`, `dist-packages`, `__pycache__`). Read text files up to 512 KiB with source extensions, within a 256 MiB budget.
  2. Extract variables, classified per language:

     | Language | Required | Optional (has a default) | Used |
     |---|---|---|---|
     | Python | `os.environ["X"]` | `.get("X", d)`, `getenv("X", d)` | `.get("X")`, `getenv("X")` |
     | Node | | | `process.env.X`, `process.env["X"]` |
     | Go | | | `Getenv`, `LookupEnv` |
     | Ruby | `ENV.fetch("X")` | `ENV.fetch("X", d)` | `ENV["X"]` |
     | Java | | | `System.getenv("X")` |
     | Shell | `${X:?}` | `${X:-d}` | |
     | PHP | | | `getenv('X')`, `$_ENV['X']` |
     | Spring / YAML | `${X}` | `${X:d}` | |
     | `.env.example` / `.env.sample` | keys (documented contract) | | |
  3. Compare the result with the provided env: image env plus container env (or `--env`).
- **Output:** `missing_required` (critical), `missing_used` (warning), `unused_provided`, and **typo suspects**: a provided key within `difflib` ratio ≥ 0.85 of a missing one ("`DATABSE_URL` is set, the code reads `DATABASE_URL`"). Each item carries `file:line` evidence.
- **Refinement:** keys every image sets anyway (`PATH`, `HOME`, `HOSTNAME`, `LANG`, `TERM`, …) are never reported as unused.

## 7. `images sbom` / `images diff`

- **SBOM (read):** `images sbom IMAGE [--format json|cyclonedx]`. A transient helper streams `/` once and parses package databases on the fly:

  | Ecosystem | Source |
  |---|---|
  | apk | `/lib/apk/db/installed` (`P:`/`V:`) |
  | dpkg | `/var/lib/dpkg/status` (stanzas where `Status: install ok installed`) |
  | rpm | `/var/lib/rpm/rpmdb.sqlite`, via host `sqlite3`: `Packages` blobs are headers, so read `Name`/`Version` through the `Name` index table when present; otherwise report rpm as `unparsed` |
  | pypi | `*.dist-info/METADATA` (`Name`, `Version`) and `*.egg-info/PKG-INFO` |
  | npm | `node_modules/<pkg>/package.json` and `node_modules/@scope/<pkg>/package.json`, top two levels |
  | gem | `specifications/*.gemspec` filename `name-version` |

  Output: components with a purl, counts per ecosystem, OS release (`/etc/os-release`). CycloneDX 1.5 minimal JSON.
- **Diff (read):** `images diff A B [--top 20]`. The per-image file index stores path, size, mode, link target, and sha1 of content for files ≤ 1 MiB (size only above that). The output:
  - files added, removed or changed, with byte deltas and the largest changes;
  - summaries per top-level directory;
  - packages added, removed, upgraded and downgraded;
  - env, cmd, entrypoint, user, exposed ports and labels changes from the image config.

## 8. `db sample`: referentially complete subset

- **Interface:** `db sample NAME out.sql.gz --ratio 0.01 [--root T ...] [--max-rows-per-root 1000] [--with-children]` (read). Postgres, MySQL/MariaDB and SQLite.
- **Algorithm:**
  1. Build the FK graph (child columns → parent columns, composite FKs included) and the primary key of each table.
  2. Roots default to tables no FK points at (the "leaf" facts like `order_items`), plus tables with no FKs at all.
  3. Sample each root: `ceil(count × ratio)` rows chosen randomly, capped.
  4. **Upward closure:** for every selected row, pull in the parent rows its FKs reference, repeating to a fixpoint. This handles multi-level and self-referencing FKs, and parent keys are fetched in chunks of 500 with row-constructor `IN`. `--with-children` adds one downward level for the roots' direct children.
  5. Export the schema (`pg_dump --schema-only` / `mysqldump --no-data`; for SQLite, `sqlite_master` SQL), then data as multi-row `INSERT`s in topological order. The header disables FK checks for the load (`SET session_replication_role = replica` / `SET FOREIGN_KEY_CHECKS=0`) so cycles load too.
- **Refinement:** a table without a primary key can only be sampled as a root (rows can't be addressed); that's reported. Values are quoted as literals, NULL stays NULL.

## 9. `db seed`: synthetic data that satisfies the schema

- **Interface:** `db seed NAME --rows 1000 [--table T ...] [--seed 42]` (mutate; `--dry-run` shows the plan and a sample row).
- **Introspection:** columns (type, nullable, default, max length, numeric precision and scale), PK, unique sets, FKs, enums (pg `pg_enum`; MySQL `enum(...)` parsed from `column_type`), and simple `CHECK (col IN (...))` / `col >= n` constraints.
- **Generation:**
  - Order tables topologically.
  - Skip columns that have a default or are identity/serial.
  - FK columns take random existing parent keys, queried after the parents are seeded.
  - Generators are chosen **by column name first**: email, first/last/full name, phone, city, country (ISO-2), url, status (from enum/check), sku/code, slug, uuid, `*_at` / `*_date` (within the last year), price/amount/total (numeric scale respected), and so on. Otherwise **by type**: int ranges, numeric(p, s), varchar(n), bool, date/timestamp, json `{}`, uuid.
  - Uniqueness is tracked per unique set, with retries.
  - Deterministic with `--seed`. Inserted in batches of 500 in one transaction per table.

## 10. `db advise`: an index advisor that proves itself (Postgres)

- **Interface:** `db advise NAME "SELECT …" [--runs 3] [--keep-clone]` (mutate: it creates a temporary clone). With no SQL, it's a schema report instead: unindexed FKs and unused indexes (`idx_scan = 0`, by size).
- **Algorithm:**
  1. Clone the database (feature `db clone`).
  2. Baseline: `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` inside `BEGIN … ROLLBACK`; the median of the runs.
  3. Walk the plan for candidates:
     - Seq Scan with a `Filter` or `Rows Removed by Filter` over large relations: an index on the filtered columns (equality columns first, then range);
     - Sort over a scan: the sort key;
     - joins whose inner side is a Seq Scan: the inner join column;
     - unindexed FK columns that the query touches.
  4. For each candidate (at most 5): `CREATE INDEX` on the clone, `ANALYZE`, re-measure, drop. Keep candidates with more than a 20% win, then measure the winners combined.
  5. Output: baseline and the most expensive plan nodes, each candidate with its measured ms and speedup, and a final `CREATE INDEX CONCURRENTLY` DDL for production.
  6. The clone is removed in `finally` unless `--keep-clone`.

## 11. `chaos`: fault injection with automatic revert

- **Faults** (mutate; each reverts in `finally`, even on Ctrl-C):

  | Command | Mechanism |
  |---|---|
  | `chaos pause NAME --seconds S` | `pause` / `unpause` API |
  | `chaos disconnect NAME --network N --seconds S` | Network disconnect, then reconnect with the original aliases |
  | `chaos latency NAME --ms 200 [--jitter 50] [--loss 5] --seconds S` | netshoot sidecar with `NET_ADMIN` in NAME's network namespace: `tc qdisc add dev eth0 root netem …`, then `tc qdisc del` |
  | `chaos kill NAME [--signal KILL]` | No revert; it tests the restart policy |
- **Game day:** `chaos run STACK.json [--faults pause,disconnect,latency] [--seconds 10] [--recover-within 60]`. For each service and fault:
  1. Check that the stack is ready.
  2. Inject the fault.
  3. Measure which *other* services fail probes while the fault is active (blast radius), and whether doctor or probes flag the target (detection).
  4. Revert, and time recovery until every probe is green.
- **Output:** a report card per (service, fault) and an overall score.

## 12. `http record` / `http replay`: shadow traffic

- **Record:**
  - **Proxy mode (portable), `http record NAME --listen 18099 --seconds 60 --out t.jsonl`:** a stdlib reverse proxy that forwards to the container (via published port or IP) and writes each exchange (method, path, headers minus auth and cookie values, body up to 64 KiB, status, response body, latency). Read tier: clients opt in by using the port.
  - **Passive mode, `--via tcpdump`:** a netshoot sidecar in NAME's network namespace runs `timeout S tcpdump -i any -U -w - tcp port P`. The pcap is parsed on the host: LINUX_SLL2 or Ethernet, then IPv4/IPv6, then TCP. Payload is reassembled per flow and direction by sequence number, then HTTP/1.x request and response pairs are parsed (Content-Length and chunked).
- **Replay:** `http replay FILE --to NAME [--all-methods] [--ignore PATH ...]` (mutate). It replays GET/HEAD by default (anything else needs `--all-methods`) and compares:
  - status;
  - JSON bodies structurally, where volatile values (uuids, timestamps, ids, matched by the log-masking templates) are normalized and `--ignore` JSON paths are dropped;
  - latency ratio.
  Output: match rate, mismatches with a minimal diff, and the latency distribution.

## 13. `system rightsize` and `containers limit`

- **Rightsize (read):** `system rightsize --seconds 60 --interval 5 [--headroom 0.3] [--container …]` samples `stats?stream=false&one-shot=true`, computing CPU from its own successive samples. Per container:
  - memory (minus page cache): avg, p95, peak; CPU %: avg, p95, max; pids max; network and block rates.
  - **Memory recommendation:** `ceil16MiB(peak × (1 + headroom))`, at least 32 MiB. **CPUs:** `ceil0.25(p95 / 100 × (1 + headroom))`.
  - **Flags:** `at-risk` (peak over 80% of the limit), `over-provisioned` (limit over 3× the recommendation), `unlimited`, `idle` (avg CPU under 0.5% and no network traffic).
- **Limit (mutate):** `containers limit NAME --memory 256m --cpus 0.5 [--pids 512]` uses `POST /containers/{id}/update`, so there's **no recreate**. Rightsize emits these exact commands.

## 14. `aisb portal`: zero-dependency local UI

- **Interface:** `aisb portal [--port 8765] [--bind 127.0.0.1] [--allow mutate]`.
- **How it works:**
  - A stdlib `ThreadingHTTPServer` serves one self-contained HTML page (no CDN), with light and dark themes.
  - `GET /api/overview` returns containers, services, verdicts and URLs, cached for 3 s.
  - `POST /api/op/<resource>/<op>` invokes any **read** op; mutate ops only with `--allow mutate`; destroy ops never.
  - Every API call needs the per-run token (printed at startup and embedded in the page) in `X-AISB-Token`. It also checks the `Host` header, against DNS rebinding, and binds to loopback by default.
  - **UI:** a container table with state, health, ports as links and a verdict chip. Selecting a row opens a drawer with doctor findings, log patterns, service info with a copyable URL, and a read-only SQL box for SQL services. Restart and stop buttons appear only when mutate is allowed.

## Testing strategy

- **Pure logic, unit tested:** graph edge inference, incident ranking, env extraction and classification, package database parsers, pcap/HTTP parsing (fixtures built in-test with `struct`), sample closure, the seed generators' constraints, the advise candidate extractor from plan JSON, rightsize maths, and journal and inverse planning.
- **Fake daemon:** op wiring, tier gating, hooks.
- **Live (`-m docker`):** session rollback of a removed container and volume; `net graph` on a stack; envcheck typo detection; sbom on alpine and postgres; a sample loaded into a fresh DB with FK integrity; seed then FK validity; advise speedup; `chaos pause` blast radius; proxy record and replay; `containers limit`; portal API with token enforcement.
