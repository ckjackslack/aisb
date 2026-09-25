"""`aisb RESOURCE OP [args]`: argparse generated from the operation registry.

Exit codes: 0 ok, 1 Docker error, 2 usage error, 3 confirmation required,
4 condition not met (a result with "ok": false, e.g. `containers wait`), 130 interrupted.
"""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

from .client import Docker
from .errors import DockerError
from .ops import Op, Param, Tier, invoke, jsonable, registry, render_markdown

EXIT_OK, EXIT_DOCKER, EXIT_USAGE, EXIT_CONFIRM, EXIT_UNMET = 0, 1, 2, 3, 4


def _add_param(p: argparse.ArgumentParser, prm: Param) -> None:
    kw: dict[str, Any] = {"help": prm.help or None}
    if prm.variadic:
        p.add_argument(prm.name, nargs="*", type=prm.type, metavar=prm.name.upper(), **kw)
    elif prm.positional:
        if not prm.required:
            kw.update(nargs="?", default=prm.default)
        p.add_argument(prm.name, type=prm.type, choices=prm.choices, metavar=prm.name.upper(), **kw)
    else:
        flag = "--" + prm.name.replace("_", "-")
        if prm.type is bool:
            action = argparse.BooleanOptionalAction if prm.default else "store_true"
            p.add_argument(flag, dest=prm.name, action=action, default=prm.default, **kw)
        elif prm.many or prm.mapping:
            p.add_argument(flag, dest=prm.name, action="append", type=str if prm.mapping else prm.type,
                           metavar="KEY=VALUE" if prm.mapping else prm.name.upper(), **kw)
        else:
            p.add_argument(flag, dest=prm.name, type=prm.type, choices=prm.choices,
                           default=prm.default, metavar=prm.name.upper(), **kw)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("connection/output")
    g.add_argument("--host", help="Docker endpoint, e.g. unix:///var/run/docker.sock (default: $DOCKER_HOST)")
    g.add_argument("--timeout", type=float, default=60.0, help="request timeout in seconds")
    g.add_argument("--json", action=argparse.BooleanOptionalAction, default=None,
                   help="JSON output (default when stdout is not a TTY)")

    root = argparse.ArgumentParser(prog="aisb", description="stdlib-only Docker Engine API client")
    resources = root.add_subparsers(dest="resource", required=True, metavar="RESOURCE")
    for rname, ops in registry().items():
        rp = resources.add_parser(rname, help=f"{rname} operations")
        sub = rp.add_subparsers(dest="op", required=True, metavar="OP")
        for o in ops.values():
            p = sub.add_parser(o.name, parents=[common], help=f"[{o.tier}] {o.summary}", description=o.doc)
            if o.tier is not Tier.READ:
                p.add_argument("--dry-run", action="store_true", help="print the planned API requests, change nothing")
            if o.tier is Tier.DESTROY:
                p.add_argument("--yes", action="store_true", help="confirm; only after explicit user approval")
            for prm in o.params:
                _add_param(p, prm)
            p.set_defaults(_op=o)
    resources.add_parser("docs", help="print the Markdown command reference").set_defaults(_op=None)
    return root


def _table(rows: list[dict[str, Any]]) -> str:
    cols = [k for k, v in rows[0].items() if not isinstance(v, (dict, list)) or k in ("ports", "tags")]
    cell = lambda v: ",".join(map(str, v)) if isinstance(v, list) else str(v)  # noqa: E731
    widths = {c: max(len(c), *(len(cell(r.get(c, ""))) for r in rows)) for c in cols}
    lines = ["  ".join(c.upper().ljust(widths[c]) for c in cols)]
    lines += ["  ".join(cell(r.get(c, "")).ljust(widths[c]) for c in cols) for r in rows]
    return "\n".join(line.rstrip() for line in lines)


def emit(obj: Any, as_json: bool, out: TextIO) -> None:
    data = json.loads(json.dumps(obj, default=jsonable))
    if as_json:
        out.write(json.dumps(data, ensure_ascii=False) + "\n")
    elif isinstance(data, list) and data and all(isinstance(r, dict) for r in data):
        out.write(_table(data) + "\n")
    elif isinstance(data, dict) and isinstance(data.get("output"), str):
        meta = {k: v for k, v in data.items() if k != "output"}
        out.write(data["output"] + ("" if data["output"].endswith("\n") else "\n"))
        out.write(json.dumps(meta) + "\n")
    else:
        out.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def run(op_: Op, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    as_json = args.json if args.json is not None else not out.isatty()
    kwargs = {p.name: getattr(args, p.name) for p in op_.params}
    try:
        client = Docker(args.host, timeout=args.timeout)
        outcome = invoke(client, op_, kwargs, dry_run=getattr(args, "dry_run", False), confirm=getattr(args, "yes", False))
    except DockerError as e:
        err.write(json.dumps(e.as_dict()) + "\n")
        return EXIT_DOCKER
    except ValueError as e:
        err.write(json.dumps({"error": "UsageError", "message": str(e), "status": None}) + "\n")
        return EXIT_USAGE
    if outcome.status == "confirm":
        emit({"status": "confirmation_required", "op": op_.qualname, "tier": str(op_.tier),
              "planned": outcome.planned, **({"warnings": outcome.warnings} if outcome.warnings else {}),
              "hint": "Show this to the user; re-run with --yes only after they explicitly approve."}, True, out)
        return EXIT_CONFIRM
    emit(outcome.payload(), as_json, out)
    unmet = isinstance(outcome.result, Mapping) and outcome.result.get("ok") is False
    return EXIT_UNMET if unmet else EXIT_OK


def parse(argv: Sequence[str]) -> argparse.Namespace:
    """argparse can't place a variadic positional after interleaved flags, so '--' is split off here."""
    argv = list(argv)
    head, tail = (argv[:argv.index("--")], argv[argv.index("--") + 1:]) if "--" in argv else (argv, None)
    parser = build_parser()
    args = parser.parse_args(head)
    if tail is not None:
        var = next((p for p in (args._op.params if args._op else ()) if p.variadic), None)
        if var is None:
            parser.error(f"{args.resource} {getattr(args, 'op', '')} takes no trailing command after --")
        setattr(args, var.name, [*getattr(args, var.name), *tail])
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse(sys.argv[1:] if argv is None else argv)
    if args._op is None:
        sys.stdout.write(render_markdown())
        return EXIT_OK
    try:
        return run(args._op, args, sys.stdout, sys.stderr)
    except KeyboardInterrupt:
        return 130
