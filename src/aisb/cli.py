"""`aisb RESOURCE OP [args]`: argparse generated from the operation registry.

Exit codes: 0 ok, 1 Docker error, 2 usage error, 3 confirmation required,
4 condition not met (a result with "ok": false, e.g. `containers wait`), 5 denied by policy, 130 interrupted.
"""

import argparse
import json
import os
import shlex
import sys
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

from .client import Docker
from .errors import DockerError
from .ops import Op, Param, Tier, invoke, registry, render_markdown
from .render import FORMATS

EXIT_OK, EXIT_DOCKER, EXIT_USAGE, EXIT_CONFIRM, EXIT_UNMET, EXIT_POLICY = 0, 1, 2, 3, 4, 5


def _add_param(p: argparse.ArgumentParser, prm: Param) -> None:
    kw: dict[str, Any] = {"help": prm.help.replace("%", "%%") or None}  # argparse %-formats help strings
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


def _config_defaults(o: Op) -> dict[str, Any]:
    """Flag defaults from config.toml, limited to the op's own parameters (typos are reported, not applied)."""
    from . import config
    wanted = config.load().defaults_for(o.qualname)
    names = {p.name for p in o.params}
    return {k.replace("-", "_"): v for k, v in wanted.items() if k.replace("-", "_") in names}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("connection/output")
    g.add_argument("--host", help="Docker endpoint, e.g. unix:///var/run/docker.sock (default: $DOCKER_HOST)")
    g.add_argument("--timeout", type=float, default=60.0, help="request timeout in seconds")
    g.add_argument("--json", action=argparse.BooleanOptionalAction, default=None,
                   help="JSON output (default when stdout is not a TTY)")
    g.add_argument("--output", "-o", choices=FORMATS, help="output format (overrides --json)")
    g.add_argument("--pick", metavar="PATHS", help="only these dotted fields, per row: name,state,result.ok")
    g.add_argument("--ticket", help="change ticket for policy/audit (default: $AISB_TICKET)")

    root = argparse.ArgumentParser(prog="aisb", description="stdlib-only Docker Engine API client")
    resources = root.add_subparsers(dest="resource", required=True, metavar="RESOURCE")
    for rname, ops in registry().items():
        rp = resources.add_parser(rname, help=f"{rname} operations")
        sub = rp.add_subparsers(dest="op", required=True, metavar="OP")
        for o in ops.values():
            p = sub.add_parser(o.name, parents=[common], help=f"[{o.tier}] {o.summary}".replace("%", "%%"),
                                description=o.doc)
            if o.tier is not Tier.READ:
                p.add_argument("--dry-run", action="store_true", help="print the planned API requests, change nothing")
            if o.tier is Tier.DESTROY:
                p.add_argument("--yes", action="store_true", help="confirm; only after explicit user approval")
            for prm in o.params:
                _add_param(p, prm)
            p.set_defaults(_op=o, **_config_defaults(o))
    docs = resources.add_parser("docs", help="print the Markdown command reference (or --site DIR: one page per resource)")
    docs.add_argument("--site", metavar="DIR", help="write index.md + one page per resource into DIR")
    docs.set_defaults(_op=None)
    resources.add_parser("mcp", help="run the MCP server over stdio (see `aisb mcp --help`)")
    resources.add_parser("bundle", help="write aisb as one executable .pyz (see `aisb bundle --help`)")
    resources.add_parser("portal", help="local web UI, read-only by default (see `aisb portal --help`)")
    resources.add_parser("exporter", help="Prometheus metrics endpoint (see `aisb exporter --help`)")
    return root


def emit(obj: Any, as_json: bool, out: TextIO, *, fmt: str | None = None, pick_paths: str | None = None) -> None:
    from .render import pick, render
    data = pick(obj, pick_paths) if pick_paths else obj
    out.write(render(data, fmt or ("json" if as_json else "table")) + "\n")


def run(op_: Op, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from . import context
    from .policy import PolicyDenied
    fmt = args.output or ("json" if args.json or (args.json is None and not out.isatty()) else "table")
    kwargs = {p.name: getattr(args, p.name) for p in op_.params}
    try:
        with context.use(source="cli", ticket=args.ticket):
            client = Docker(args.host, timeout=args.timeout)
            outcome = invoke(client, op_, kwargs, dry_run=getattr(args, "dry_run", False),
                             confirm=getattr(args, "yes", False))
    except PolicyDenied as e:
        err.write(json.dumps(e.as_dict()) + "\n")
        return EXIT_POLICY
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
    if outcome.status == "ok" and outcome.warnings:
        err.write(json.dumps({"warnings": outcome.warnings}) + "\n")
    emit(outcome.payload(), fmt == "json", out, fmt=fmt, pick_paths=args.pick)
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


def _preamble(argv: list[str]) -> list[str]:
    """Global options before the resource (`--profile NAME`, `--version`) and alias expansion."""
    from . import __version__, config
    while argv and argv[0] in ("--profile", "--version") or (argv and argv[0].startswith("--profile=")):
        flag = argv.pop(0)
        if flag == "--version":
            print(f"aisb {__version__}")
            raise SystemExit(EXIT_OK)
        name = flag.split("=", 1)[1] if "=" in flag else (argv.pop(0) if argv else "")
        os.environ["AISB_PROFILE"] = name
    cfg = config.load(reload=True)
    if argv and argv[0] in cfg.aliases:
        argv = [*shlex.split(cfg.aliases[argv[0]]), *argv[1:]]
    return argv


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        argv = _preamble(argv)
    except ValueError as e:  # bad config / unknown profile
        sys.stderr.write(json.dumps({"error": "ConfigError", "message": str(e), "status": None}) + "\n")
        return EXIT_USAGE
    special = {"mcp": ".mcp", "bundle": ".bundle", "portal": ".portal", "exporter": ".exporter"}
    if argv[:1] and argv[0] in special:
        import importlib
        return importlib.import_module(special[argv[0]], __package__).main(argv[1:])
    args = parse(argv)
    if args._op is None:
        if getattr(args, "site", None):
            from .ops import render_site
            files = render_site(args.site)
            sys.stdout.write(json.dumps({"site": args.site, "pages": len(files)}) + "\n")
        else:
            sys.stdout.write(render_markdown())
        return EXIT_OK
    try:
        return run(args._op, args, sys.stdout, sys.stderr)
    except KeyboardInterrupt:
        return 130
