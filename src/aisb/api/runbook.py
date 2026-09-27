"""`aisb runbook`: plan, run, pause for approval, resume. Steps are aisb commands (tiers, policy, audit apply)."""

import time
from typing import Annotated, Any

from .. import context, runbooks
from ..errors import DockerError
from ..ops import Resource, Tier, invoke, op
from ..policy import PolicyDenied
from ..util import kv

Ref = Annotated[str, "runbook file, or NAME from $AISB_RUNBOOKS (./runbooks, ~/.aisb/runbooks)"]
Vars = Annotated[dict[str, str] | None, "KEY=VALUE overriding the runbook's vars (repeatable)"]
Run = Annotated[str, "run id (see `runbook runs`)"]


class RunbookOps(Resource, name="runbook"):
    # --- library ------------------------------------------------------------------------------------

    @op(Tier.READ, name="list")
    def ls(self) -> list[dict[str, Any]]:
        """Runbooks found in $AISB_RUNBOOKS (default ./runbooks and ~/.aisb/runbooks)."""
        out = []
        for d in runbooks.search_path():
            for p in sorted([*d.glob("*.toml"), *d.glob("*.json")]) if d.is_dir() else []:
                try:
                    rb = runbooks.load(str(p))
                    out.append({"name": rb.name, "file": str(p), "steps": len(rb.steps), "description": rb.description})
                except ValueError as e:
                    out.append({"name": p.stem, "file": str(p), "error": str(e)})
        return out

    @op(Tier.READ)
    def plan(self, runbook: Ref, *, var: Vars = None) -> dict[str, Any]:
        """Validate and dry-run a runbook: every step's command, per-host plans for changes, policy violations,
        approvals that will be asked. Nothing is changed and read steps are not executed."""
        rb = runbooks.load(runbook)
        variables = {**rb.vars, **kv(var), "run": "<plan>"}
        return {"runbook": rb.name, "file": str(rb.path), "steps": [self._plan_step(s, variables) for s in rb.steps]}

    # --- execution --------------------------------------------------------------------------------------

    @op(Tier.DESTROY)
    def run(self, runbook: Ref, *, var: Vars = None) -> dict[str, Any]:
        """Execute a runbook. Without --yes: the full plan and exit 3 (like every destroy op); with --yes the run
        starts, its destroy steps count as approved, and `approve` steps pause it (status waiting)."""
        rb = runbooks.load(runbook)
        variables = {**rb.vars, **kv(var)}
        if self.t.planning:
            steps = [self._plan_step(s, {**variables, "run": "<plan>"}) for s in rb.steps]
            for s in steps:
                self.t.note(**s)
            return {"runbook": rb.name, "steps": steps}
        st = runbooks.new_run(rb, variables, confirmed=True)
        runbooks.save(st)
        return self._execute(rb, st)

    @op(Tier.DESTROY)
    def resume(self, run: Run, *, allow_changed: Annotated[bool, "resume even if the runbook file changed"] = False
               ) -> dict[str, Any]:
        """Continue a waiting or failed run from its first unfinished step (failed steps are retried)."""
        st = runbooks.load_run(run)
        if st["status"] == "done":
            return {"run": run, "status": "done", "note": "nothing to resume"}
        rb = runbooks.load(st["file"])
        if rb.sha256 != st["sha256"] and not allow_changed:
            raise ValueError(f"{st['file']} changed since the run started; review it, then --allow-changed")
        if self.t.planning:
            left = [s for s in rb.steps if st["steps"][s.name]["status"] not in ("done",)]
            for s in left:
                self.t.note(**self._plan_step(s, {**st["vars"], "run": run}))
            return {"run": run, "remaining": [s.name for s in left]}
        for s in st["steps"].values():
            if s["status"] in ("failed", "skipped", "waiting"):
                s["status"] = "pending"
        st["status"] = "running"
        return self._execute(rb, st)

    @op(Tier.MUTATE)
    def approve(self, run: Run, *, deny: Annotated[bool, "reject instead of approving"] = False,
                note: Annotated[str | None, "reason, kept in the run record"] = None,
                resume: Annotated[bool, "continue the run right away (only if it was started with --yes)"] = False,
                ) -> dict[str, Any]:
        """Answer the approval a run is waiting for (from the CLI, the portal or an agent with the user's consent)."""
        st = runbooks.load_run(run)
        waiting = next((n for n, s in st["steps"].items() if s["status"] == "waiting"), None)
        if waiting is None:
            raise ValueError(f"run {run} is not waiting for an approval (status {st['status']})")
        ctx = context.current()
        decision = {"decision": "deny" if deny else "approve", "by": ctx.user, "source": ctx.source,
                    "at": time.time(), "note": note}
        if self.t.planning:
            self.t.note(run=run, step=waiting, **decision)
            return {"run": run, "step": waiting, **decision}
        st["approvals"][waiting] = decision
        runbooks.save(st)
        out = {"run": run, "step": waiting, **decision}
        if resume:
            if not st.get("confirmed"):
                raise ValueError("this run was not started with --yes; resume it with `runbook resume RUN --yes`")
            rb = runbooks.load(st["file"])
            st["steps"][waiting]["status"] = "pending"
            st["status"] = "running"
            out["resumed"] = self._execute(rb, st)
        return out

    # --- history -----------------------------------------------------------------------------------------

    @op(Tier.READ)
    def runs(self, *, limit: Annotated[int, "newest N runs"] = 20) -> list[dict[str, Any]]:
        """Run history, newest first."""
        return [{"run": st["run"], "runbook": st["runbook"], "status": st["status"],
                 "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st["started"])),
                 "done": sum(s["status"] == "done" for s in st["steps"].values()), "steps": len(st["steps"])}
                for st in runbooks.all_runs()[:limit]]

    @op(Tier.READ)
    def show(self, run: Run) -> dict[str, Any]:
        """One run: every step's status, timing, attempts, result summary or error, and approvals."""
        return runbooks.load_run(run)

    @op(Tier.READ)
    def pending(self) -> list[dict[str, Any]]:
        """Runs waiting for an approval (what the portal's approvals queue shows)."""
        out = []
        for st in runbooks.all_runs():
            if st["status"] != "waiting":
                continue
            step = next(n for n, s in st["steps"].items() if s["status"] == "waiting")
            out.append({"run": st["run"], "runbook": st["runbook"], "step": step,
                        "prompt": st["steps"][step].get("prompt"), "since": st["steps"][step].get("started"),
                        "confirmed": st.get("confirmed", False)})
        return out

    # --- engine ------------------------------------------------------------------------------------------

    def _client(self) -> Any:
        from ..client import Docker
        return Docker(self.t.endpoint.url, timeout=self.t.timeout)

    def _command(self, argv: list[str]) -> tuple[Any, dict[str, Any]]:
        from ..cli import parse
        try:
            args = parse(argv)
        except SystemExit:
            raise ValueError(f"invalid command: {' '.join(argv)}") from None
        if args._op is None or args._op.resource == "runbook":
            raise ValueError("a runbook step can't run `docs` or another runbook")
        return args._op, {p.name: getattr(args, p.name) for p in args._op.params}

    def _plan_step(self, step: runbooks.Step, variables: dict[str, str]) -> dict[str, Any]:
        out: dict[str, Any] = {"step": step.name, "kind": step.kind, "when": step.when}
        if step.kind == "approve":
            return {**out, "approve": runbooks.render(step.approve or "", variables)}
        if step.kind == "sleep":
            return {**out, "sleep": step.sleep}
        argv = runbooks.argv_of(step, variables)
        o, kwargs = self._command(argv)
        out.update(command=" ".join(argv), op=o.qualname, tier=o.tier.value)
        if o.tier is Tier.READ:
            return {**out, "note": "read step: evaluated when the run gets there"}
        try:
            with context.use(source="runbook"):
                res = invoke(self._client(), o, kwargs, dry_run=True)
            return {**out, "planned": res.planned, **({"warnings": res.warnings} if res.warnings else {})}
        except (DockerError, ValueError, OSError) as e:  # same failures _exec reports: a plan shows them per step
            return {**out, "plan_error": str(e)}

    def _exec(self, argv: list[str], run_id: str) -> tuple[bool, Any, str | None]:
        try:
            o, kwargs = self._command(argv)
            with context.use(source="runbook", run_id=run_id):
                res = invoke(self._client(), o, kwargs, confirm=True)
        except PolicyDenied as e:
            return False, None, str(e)
        except (DockerError, ValueError, OSError) as e:
            return False, None, f"{type(e).__name__}: {e}"
        result = res.result
        if isinstance(result, dict) and result.get("ok") is False:
            return False, result, str(result.get("reason") or "condition not met")
        return True, result, None

    def _execute(self, rb: runbooks.Runbook, st: dict[str, Any]) -> dict[str, Any]:
        variables = {**rb.vars, **st["vars"], "run": st["run"]}
        failed = False
        for step in rb.steps:
            s = st["steps"][step.name]
            if s["status"] == "done":
                continue
            if not runbooks.should_run(step, st["steps"], failed):
                s.update(status="skipped")
                runbooks.save(st)
                continue
            s["started"] = time.time()
            if step.kind == "approve":
                decision = st["approvals"].get(step.name)
                if decision is None:
                    s.update(status="waiting", prompt=runbooks.render(step.approve or "", variables))
                    st["status"] = "waiting"
                    runbooks.save(st)
                    return self._report(st, waiting=step.name)
                if decision["decision"] == "deny":
                    s.update(status="failed", error=f"denied by {decision['by']}" +
                             (f": {decision['note']}" if decision.get("note") else ""))
                    failed = True
                else:
                    s.update(status="done", result={"approved_by": decision["by"]})
                runbooks.save(st)
                continue
            if step.kind == "sleep":
                time.sleep(step.sleep or 0)
                s.update(status="done", ms=int((time.time() - s["started"]) * 1000))
                runbooks.save(st)
                continue
            argv = runbooks.argv_of(step, variables)
            ok, result, error = False, None, None
            for attempt in range(1, step.retry_times + 2):
                ok, result, error = self._exec(argv, st["run"])
                s["attempts"] = attempt
                if ok or attempt > step.retry_times:
                    break
                time.sleep(step.retry_delay)
            s.update(status="done" if ok else "failed", command=" ".join(argv), result=runbooks.summarize(result),
                     error=error, ms=int((time.time() - s["started"]) * 1000))
            if not ok and not step.continue_on_error:
                failed = True
            runbooks.save(st)
        st["status"] = "failed" if failed else "done"
        st["ended"] = time.time()
        runbooks.save(st)
        return self._report(st)

    @staticmethod
    def _report(st: dict[str, Any], *, waiting: str | None = None) -> dict[str, Any]:
        steps = [{"step": n, "status": s["status"], **{k: s[k] for k in ("attempts", "ms", "error") if s.get(k)}}
                 for n, s in st["steps"].items()]
        out: dict[str, Any] = {"run": st["run"], "runbook": st["runbook"], "status": st["status"], "steps": steps}
        if waiting:
            out.update(ok=False, reason=f"waiting for approval of {waiting!r}: {st['steps'][waiting].get('prompt')}",
                       next=[f"aisb runbook approve {st['run']} --resume", f"aisb runbook approve {st['run']} --deny"])
        elif st["status"] == "failed":
            bad = next((n for n, s in st["steps"].items() if s["status"] == "failed"), "?")
            out.update(ok=False, reason=f"step {bad!r} failed: {st['steps'][bad].get('error')}",
                       next=[f"aisb runbook show {st['run']}", f"aisb runbook resume {st['run']} --yes"])
        return out
