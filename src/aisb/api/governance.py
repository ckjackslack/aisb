"""Governance resources: `audit` (who changed what), `policy` (the rules and why an op would be denied),
`config` (the effective configuration, profiles and plugins)."""

import fnmatch
import time
from pathlib import Path
from typing import Annotated, Any

from .. import audit, config, plugins, policy
from ..context import Ctx, current
from ..ops import Resource, Tier
from ..ops import op as register
from ..util import to_unix


class Audit(Resource, name="audit"):
    @register(Tier.READ)
    def log(self, *, since: Annotated[str | None, "unix ts, ISO time, or relative like 1d, 6h"] = None,
            action: Annotated[str | None, "op glob, e.g. 'containers.*' or 'fleet.apply'"] = None,
            user: Annotated[str | None, "user glob"] = None,
            on: Annotated[str | None, "fleet host glob ('local' for the local endpoint)"] = None,
            failed: Annotated[bool, "only failed or denied changes"] = False,
            run: Annotated[str | None, "one run id (a fleet op, runbook run)"] = None,
            limit: Annotated[int, "newest N records"] = 100) -> list[dict[str, Any]]:
        """Changes made through aisb (newest first): who, when, where, what (secrets redacted), outcome."""
        floor = to_unix(since) if since else 0
        out = []
        for rec in audit.read():
            h = rec.get("host") or "local"
            if rec.get("ts", 0) < floor or (action and not fnmatch.fnmatchcase(rec.get("op", ""), action)) \
                    or (user and not fnmatch.fnmatchcase(rec.get("user") or "", user)) \
                    or (on and not fnmatch.fnmatchcase(h, on)) or (failed and rec.get("ok")) \
                    or (run and rec.get("run_id") != run):
                continue
            out.append({"at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec["ts"])), "user": rec.get("user"),
                        "source": rec.get("source"), "host": h, "op": rec.get("op"), "ok": rec.get("ok"),
                        "ms": rec.get("ms"), "run_id": rec.get("run_id"), "ticket": rec.get("ticket"),
                        "error": rec.get("error"), "args": rec.get("args")})
        return out[::-1][:limit]

    @register(Tier.READ)
    def verify(self, *, anchors: Annotated[str | None, "file of checkpoints saved by `audit anchor`: the log must "
                                                       "still hold each one"] = None) -> dict[str, Any]:
        """Check the audit log's hash chain: any edited, reordered or deleted record breaks it.

        With a signing key configured ([audit] key), every signature is checked too; with --anchors, the log must
        still contain each saved checkpoint, which also catches dropped newest records and full rewrites."""
        found = audit.read_anchors(Path(anchors)) if anchors else []
        return {"path": str(audit.path()), **audit.verify(anchors=found)}

    @register(Tier.READ)
    def anchor(self) -> dict[str, Any]:
        """A checkpoint of the log (record count + head hash, signed with the key) to keep somewhere else.

        Append it to a file on another machine, a ticket or a git repo: `aisb audit anchor >> anchors.jsonl`.
        Later, `audit verify --anchors anchors.jsonl` proves nothing up to that point was removed or rewritten."""
        return audit.anchor()

    @register(Tier.MUTATE)
    def keygen(self, out: Annotated[str, "where to write the key (created 0600, never overwritten)"]
               ) -> dict[str, Any]:
        """Create a signing key for the audit log, then set `key = "PATH"` under [audit] in config.toml.

        Keep it readable only by the account that runs aisb: whoever can read it can re-sign a rewritten log."""
        target = Path(out).expanduser()
        if target.exists():
            raise ValueError(f"{target} already exists; keys are never overwritten")
        if self.t.planning:
            self.t.note(action="create audit signing key", path=str(target), mode="0600")
            return {"key": str(target)}
        try:
            made = audit.keygen(target)
        except FileExistsError:
            raise ValueError(f"{target} already exists; keys are never overwritten") from None
        return {**made, "next": f'set key = "{target}" under [audit] in {config.default_path()}'}


class Policy(Resource, name="policy"):
    @register(Tier.READ)
    def rules(self) -> list[dict[str, Any]]:
        """The effective policy rules (config + active profile)."""
        return [{"name": r.get("name") or f"rule-{i + 1}", "mode": r.get("mode", "deny"), "match": r.get("match", {}),
                 **{k: r[k] for k in ("deny", "require", "window", "deny_if", "message") if k in r}}
                for i, r in enumerate(config.load().policy)]

    @register(Tier.READ)
    def check(self, *command: Annotated[str, "RESOURCE OP [ARGS...] to evaluate (after --)"],
              on: Annotated[str | None, "evaluate as if on this fleet host"] = None,
              source: Annotated[str, "evaluate as this source (cli, mcp, portal, runbook)"] = "cli",
              user: Annotated[str | None, "as this user"] = None) -> dict[str, Any]:
        """Would this command be allowed? Evaluates every rule without running anything."""
        from ..cli import parse
        from ..fleet.inventory import Inventory
        if len(command) < 2:
            raise ValueError("give the command after --, e.g. `policy check -- containers rm web --force`")
        try:
            args = parse(list(command))
        except SystemExit:
            raise ValueError(f"invalid command: {' '.join(command)}") from None
        o = args._op
        kwargs = {p.name: getattr(args, p.name) for p in o.params}
        h = Inventory.load().hosts.get(on) if on else None
        if on and h is None:
            raise ValueError(f"unknown host {on!r}")
        me = current()
        ctx = Ctx(user or me.user, source, h, me.ticket, None)  # the ticket comes from the global --ticket
        found = policy.check(config.load().policy, o.qualname, o.tier.value, kwargs, ctx)
        return {"op": o.qualname, "tier": o.tier.value, "host": on or "local", "allowed": not any(
            v.mode != "warn" for v in found), "violations": [v.row() for v in found]}


class Config(Resource, name="config"):
    @register(Tier.READ)
    def show(self) -> dict[str, Any]:
        """Effective configuration: file, active profile, defaults, aliases, audit, notify sinks, plugins."""
        cfg = config.load()
        plugins.load()
        return {"path": str(cfg.path), "exists": bool(cfg.path and cfg.path.exists()), "profile": cfg.profile,
                "profiles": cfg.profiles, "defaults": cfg.defaults, "aliases": cfg.aliases, "audit": cfg.audit,
                "audit_log": str(audit.path()), "policy_rules": len(cfg.policy),
                "notify": {k: v.get("type") for k, v in cfg.notify.items()}, "db": cfg.db,
                "plugins": {k: (v or "ok") for k, v in plugins._LOADED.items()}}
