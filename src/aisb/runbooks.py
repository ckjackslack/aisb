"""Runbooks: declarative, resumable procedures whose steps are ordinary aisb commands.

    name = "rollout-api"
    vars = { image = "shop-api:1.5" }
    [[steps]]
    name = "ship"
    run = "fleet ship {image} @web"
    [[steps]]
    name = "go?"
    approve = "Canary looks healthy. Continue?"

Steps: `run` (an aisb command line), `approve` (pause until `runbook approve`) or `sleep` (seconds).
Options: `when` (always | on_failure | STEP.ok | STEP.failed), `retry = {times, delay}`, `continue_on_error`.
Every command goes through invoke(), so tiers, policy and audit apply; a run shares one run_id.
"""

import hashlib
import json
import os
import re
import shlex
import time
import tomllib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import state

_NAME = re.compile(r"^[\w.-]+$")
_VAR = re.compile(r"\{(\w+)\}")


@dataclass(slots=True)
class Step:
    name: str
    run: str | None = None
    approve: str | None = None
    sleep: float | None = None
    when: str = "success"          # success (default) | always | on_failure | STEP.ok | STEP.failed
    retry_times: int = 0
    retry_delay: float = 5.0
    continue_on_error: bool = False

    @property
    def kind(self) -> str:
        return "run" if self.run is not None else "approve" if self.approve is not None else "sleep"


@dataclass(slots=True)
class Runbook:
    name: str
    steps: list[Step]
    description: str = ""
    vars: dict[str, str] = field(default_factory=dict)
    path: Path | None = None
    sha256: str = ""


def search_path() -> list[Path]:
    raw = os.environ.get("AISB_RUNBOOKS") or f"runbooks{os.pathsep}{state.home('runbooks')}"
    return [Path(p).expanduser() for p in raw.split(os.pathsep) if p]


def find(ref: str) -> Path:
    """A path, or a runbook name looked up as NAME.toml / NAME.json in $AISB_RUNBOOKS."""
    p = Path(ref).expanduser()
    if p.is_file():
        return p
    for d in search_path():
        for ext in (".toml", ".json"):
            if (cand := d / f"{ref}{ext}").is_file():
                return cand
    raise ValueError(f"runbook {ref!r} not found (a file, or NAME in {', '.join(map(str, search_path()))})")


def parse(data: Mapping[str, Any], *, path: Path | None = None, sha: str = "") -> Runbook:
    if not isinstance(data.get("steps"), list) or not data["steps"]:
        raise ValueError(f"{path or 'runbook'}: needs a non-empty [[steps]] list")
    steps, seen = [], set()
    for i, raw in enumerate(data["steps"], 1):
        name = str(raw.get("name") or f"step-{i}")
        if not _NAME.match(name):
            raise ValueError(f"step {i}: invalid name {name!r} (letters, digits, _ . -)")
        if name in seen:
            raise ValueError(f"duplicate step name {name!r}")
        seen.add(name)
        kinds = [k for k in ("run", "approve", "sleep") if k in raw]
        if len(kinds) != 1:
            raise ValueError(f"step {name!r}: exactly one of run / approve / sleep (got {kinds or 'none'})")
        unknown = set(raw) - {"name", "run", "approve", "sleep", "when", "retry", "continue_on_error"}
        if unknown:
            raise ValueError(f"step {name!r}: unknown keys {sorted(unknown)}")
        when = str(raw.get("when") or "success")
        if when not in ("success", "always", "on_failure") and not re.fullmatch(r"[\w.-]+\.(ok|failed)", when):
            raise ValueError(f"step {name!r}: when must be always | on_failure | STEP.ok | STEP.failed")
        if when.endswith((".ok", ".failed")) and when.rsplit(".", 1)[0] not in seen - {name}:
            raise ValueError(f"step {name!r}: `when` refers to {when.rsplit('.', 1)[0]!r}, which is not an earlier step")
        retry = raw.get("retry") or {}
        steps.append(Step(name, raw.get("run"), raw.get("approve"), float(raw["sleep"]) if "sleep" in raw else None,
                          when, int(retry.get("times", 0)), float(retry.get("delay", 5)),
                          bool(raw.get("continue_on_error"))))
    return Runbook(str(data.get("name") or (path.stem if path else "runbook")), steps,
                   str(data.get("description") or ""), {k: str(v) for k, v in (data.get("vars") or {}).items()},
                   path, sha)


def load(ref: str) -> Runbook:
    p = find(ref)
    raw = p.read_bytes()
    try:
        data = tomllib.loads(raw.decode()) if p.suffix == ".toml" else json.loads(raw)
    except (tomllib.TOMLDecodeError, ValueError) as e:
        raise ValueError(f"{p}: {e}") from None
    return parse(data, path=p.resolve(), sha=hashlib.sha256(raw).hexdigest())


def render(template: str, variables: Mapping[str, str]) -> str:
    missing = sorted({m for m in _VAR.findall(template) if m not in variables})
    if missing:
        raise ValueError(f"undefined variable(s) {missing} in {template!r} (set them in vars or with --var)")
    return _VAR.sub(lambda m: variables[m.group(1)], template)


def argv_of(step: Step, variables: Mapping[str, str]) -> list[str]:
    line = render(step.run or "", variables).strip()
    if line.startswith("aisb "):
        line = line[5:]
    return shlex.split(line)


# --- run state ------------------------------------------------------------------------------------

def run_dir(run_id: str) -> Path:
    if not _NAME.match(run_id):
        raise ValueError(f"invalid run id {run_id!r}")
    return state.home("runs", run_id)


def new_run(rb: Runbook, variables: Mapping[str, str], *, confirmed: bool) -> dict[str, Any]:
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    return {"run": run_id, "runbook": rb.name, "file": str(rb.path) if rb.path else None, "sha256": rb.sha256,
            "vars": dict(variables), "status": "running", "confirmed": confirmed, "started": time.time(),
            "steps": {s.name: {"status": "pending"} for s in rb.steps}, "approvals": {}}


def save(st: Mapping[str, Any]) -> None:
    state.write_json(run_dir(st["run"]) / "state.json", st)


def load_run(run_id: str) -> dict[str, Any]:
    st = state.read_json(run_dir(run_id) / "state.json")
    if st is None:
        raise ValueError(f"no such run {run_id!r} (see `runbook runs`)")
    return st


def all_runs() -> list[dict[str, Any]]:
    out = []
    for d in sorted(state.home("runs").iterdir(), reverse=True):
        if (st := state.read_json(d / "state.json")) is not None:
            out.append(st)
    return out


def summarize(value: Any, limit: int = 4000) -> Any:
    text = json.dumps(value, default=str)
    return value if len(text) <= limit else {"truncated": True, "preview": text[:limit]}


def should_run(step: Step, steps_state: Mapping[str, Mapping[str, Any]], failed: bool) -> bool:
    if step.when == "always":
        return True
    if step.when == "on_failure":
        return failed
    if step.when == "success":
        return not failed
    ref, _, want = step.when.rpartition(".")
    status = (steps_state.get(ref) or {}).get("status")
    return status == ("done" if want == "ok" else "failed")


# executor signature: argv -> (ok, result, error)
Executor = Callable[[list[str]], tuple[bool, Any, str | None]]
