"""Desired state for a fleet: which stacks belong on which hosts.

    {"assign": {"@web": ["stacks/shop.json"], "@db": ["stacks/db.json"], "edge*": ["stacks/proxy.json"]}}

JSON or TOML; stack paths are relative to the state file. A host matched by several selectors gets the union.
"""

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .. import stack as stk
from .inventory import Inventory


@dataclass(frozen=True, slots=True)
class Assigned:
    file: Path
    stack: stk.Stack


def load(path: str | Path, inv: Inventory) -> dict[str, list[Assigned]]:
    p = Path(path).expanduser().resolve()
    try:
        raw = p.read_text()
        data = tomllib.loads(raw) if p.suffix == ".toml" else json.loads(raw)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
        raise ValueError(f"{path}: {e}") from None
    assign = data.get("assign")
    if not isinstance(assign, dict) or not assign:
        raise ValueError(f"{path}: needs an `assign` mapping of selector -> [stack files]")
    stacks: dict[Path, stk.Stack] = {}
    out: dict[str, list[Assigned]] = {}
    for selector, files in assign.items():
        for f in [files] if isinstance(files, str) else files:
            fp = (p.parent / f).resolve()
            if fp not in stacks:
                stacks[fp] = stk.load(fp)
            for h in inv.select(selector):
                bucket = out.setdefault(h.name, [])
                if all(a.file != fp for a in bucket):
                    bucket.append(Assigned(fp, stacks[fp]))
    names: dict[str, Path] = {}
    for fp, s in stacks.items():
        if s.name in names and names[s.name] != fp:
            raise ValueError(f"stack name {s.name!r} is defined by both {names[s.name]} and {fp}")
        names[s.name] = fp
    return out
