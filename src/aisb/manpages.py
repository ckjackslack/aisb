"""`aisb docs --man DIR`: roff man pages from the registry and the special commands' parsers.

aisb.1 is the overview (global options, resources, exit status, environment, files); aisb-RESOURCE.1 documents
every op of one resource; aisb-mcp.1 etc. cover the commands with their own parser. Install into a MANPATH
directory's man1/ (the release's share tarball does) and `man aisb-containers` works.
"""

import argparse
import datetime as dt
import importlib
import os
from collections.abc import Iterable
from pathlib import Path

from . import __version__
from .ops import EMPTY, Op, Tier, registry, usage

ENVIRONMENT = (
    ("DOCKER_HOST", "Docker endpoint: unix:///path or tcp://host:port (TLS with DOCKER_TLS_VERIFY and "
                    "DOCKER_CERT_PATH). Remote machines are managed with the fleet commands, over SSH."),
    ("AISB_HOME", "State directory (sessions, runbook runs, metrics, credentials); default ~/.aisb."),
    ("AISB_CONFIG", "Configuration file; default ~/.aisb/config.toml."),
    ("AISB_PROFILE", "Active configuration profile (same as --profile)."),
    ("AISB_TICKET", "Change ticket recorded with every change and checked by policy rules (same as --ticket)."),
    ("AISB_AUDIT", "Audit log path, or off to disable it; default $AISB_HOME/audit.jsonl."),
    ("AISB_AUDIT_KEY", "Audit signing key file (same as [audit] key)."),
    ("AISB_FLEET", "Fleet inventory file; default ~/.aisb/fleet.json."),
    ("AISB_PLUGINS", "Comma-separated plugin modules to load, in addition to aisb.plugins entry points."),
)
EXIT_STATUS = (
    ("0", "Success."), ("1", "Docker or service error."), ("2", "Usage error, including a bad configuration."),
    ("3", "Confirmation required: a destroy op without --yes printed its plan and changed nothing."),
    ("4", "Condition not met: the result has \"ok\": false (a failed wait, check or verification)."),
    ("5", "Denied by a policy rule."), ("130", "Interrupted."),
)
_TIERS = "read ops run freely; mutate ops accept --dry-run; destroy ops print their plan and exit 3 unless --yes."


def esc(text: str) -> str:
    """Escape prose for roff: backslashes, and a leading . or ' that would be read as a request."""
    lines = str(text).replace("\\", "\\e").splitlines() or [""]
    return "\n".join("\\&" + ln if ln.startswith((".", "'")) else ln for ln in lines)


def lit(text: str) -> str:
    """A command, flag or path: escaped, with hyphens as \\- so they copy and search as ASCII minus."""
    return esc(text).replace("-", "\\-")


def _date() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")  # reproducible builds
    return (dt.datetime.fromtimestamp(int(epoch), dt.UTC) if epoch else dt.datetime.now(dt.UTC)).strftime("%Y-%m-%d")


def _page(name: str, summary: str, sections: Iterable[tuple[str, list[str]]]) -> str:
    out = [f'.TH {lit(name.upper())} 1 "{_date()}" "aisb {__version__}" "aisb manual"',
           ".SH NAME", f"{lit(name)} \\- {esc(summary)}"]
    for title, body in sections:
        if body:
            out += [f".SH {title}", *body]
    return "\n".join(out) + "\n"


def _tp(term: str, desc: str) -> list[str]:
    return [".TP", term, esc(desc) if desc else "\\&"]


def _param_rows(o: Op) -> list[str]:
    rows: list[str] = []
    for p in o.params:
        if p.positional or p.variadic:
            term = f"\\fI{lit(p.name.upper())}\\fR" + (" ..." if p.variadic else "")
        elif p.type is bool:
            term = f"\\fB{lit('--' + ('no-' if p.default else '') + p.name.replace('_', '-'))}\\fR"
        else:
            term = f"\\fB{lit('--' + p.name.replace('_', '-'))}\\fR \\fI{lit(p.name.upper())}\\fR"
        extra = []
        if p.choices:
            extra.append("one of: " + ", ".join(map(str, p.choices)))
        if p.many or p.mapping:
            extra.append("repeatable")
        if p.default not in (EMPTY, None, False, (), []) and not p.variadic and p.type is not bool:
            extra.append(f"default: {p.default}")
        rows += _tp(term, (p.help or "") + (f" ({'; '.join(extra)})" if extra else ""))
    if o.tier is not Tier.READ:
        rows += _tp("\\fB\\-\\-dry\\-run\\fR", "print the planned requests and change nothing")
    if o.tier is Tier.DESTROY:
        rows += _tp("\\fB\\-\\-yes\\fR", "confirm; only after explicit approval")
    return rows


def resource_page(resource: str, ops: dict[str, Op]) -> str:
    synopsis = [line for o in ops.values() for line in (".PP", f"\\fB{lit(usage(o))}\\fR")]
    body: list[str] = []
    for o in ops.values():
        body += [f".SS {lit(o.name)} ({o.tier})", ".nf", lit(usage(o)), ".fi", ".PP",
                 esc(o.doc or o.summary or o.name)]
        if rows := _param_rows(o):
            body += [".PP", "Options:", ".RS", *rows, ".RE"]
    return _page(f"aisb-{resource}", f"{resource} operations", [
        ("SYNOPSIS", synopsis),
        ("DESCRIPTION", [esc(f"Every op also takes the global options described in aisb(1). {_TIERS}")]),
        ("OPERATIONS", body),
        ("SEE ALSO", [".BR aisb (1)"]),
    ])


def _options(p: argparse.ArgumentParser) -> list[str]:
    rows: list[str] = []
    for a in p._actions:
        if isinstance(a, (argparse._HelpAction, argparse._SubParsersAction)):
            continue
        if a.option_strings:
            names = ", ".join(f"\\fB{lit(s)}\\fR" for s in a.option_strings)
            term = names + (f" \\fI{lit(_meta(a))}\\fR" if a.nargs != 0 else "")
        else:
            term = f"\\fI{lit(_meta(a))}\\fR"
        extra = [f"one of: {', '.join(map(str, a.choices))}"] if a.choices else []
        if a.default not in (None, False, argparse.SUPPRESS) and a.nargs != 0:
            extra.append(f"default: {a.default}")
        rows += _tp(term, (a.help or "").replace("%%", "%") + (f" ({'; '.join(extra)})" if extra else ""))
    return rows


def _meta(a: argparse.Action) -> str:
    return a.metavar if isinstance(a.metavar, str) else a.dest.upper()


def command_page(name: str, p: argparse.ArgumentParser) -> str:
    return _page(f"aisb-{name}", p.description or name, [
        ("SYNOPSIS", [f"\\fB{lit(p.format_usage().removeprefix('usage: ').strip())}\\fR"]),
        ("OPTIONS", _options(p)),
        ("DESCRIPTION", [".nf", esc(p.epilog), ".fi"] if p.epilog else []),
        ("SEE ALSO", [".BR aisb (1)"]),
    ])


def overview(reg: dict[str, dict[str, Op]], specials: dict[str, argparse.ArgumentParser]) -> str:
    from .cli import common_parser
    rows = _tp("\\fB\\-\\-profile\\fR \\fINAME\\fR", "use a configuration profile (before the resource)") + \
        _tp("\\fB\\-\\-version\\fR", "print the version and exit") + _options(common_parser())
    resources = [ln for name, ops in reg.items() for ln in _tp(
        f"\\fB{lit(name)}\\fR", f"{len(ops)} ops: {', '.join(ops)}. See aisb-{name}(1).")]
    commands = [ln for name, p in specials.items() for ln in _tp(f"\\fB{lit(name)}\\fR",
                                                                   f"{p.description}. See aisb-{name}(1).")]
    commands += _tp("\\fBdocs\\fR", "print the Markdown command reference; --site DIR writes one page per "
                                    "resource, --man DIR writes these man pages")
    return _page("aisb", "stdlib-only Docker client, service operator and fleet manager for people and agents", [
        ("SYNOPSIS", ["\\fBaisb\\fR [\\fB\\-\\-profile\\fR \\fINAME\\fR] \\fIRESOURCE\\fR \\fIOP\\fR [\\fIARGS\\fR]",
                      ".br", "\\fBaisb\\fR \\fICOMMAND\\fR [\\fIARGS\\fR]"]),
        ("DESCRIPTION", [esc("aisb talks to the Docker Engine API directly (Python standard library only) and "
                             "operates the services inside containers. Output is one JSON document when stdout is "
                             "not a terminal, a table otherwise."), ".PP", esc(_TIERS)]),
        ("GLOBAL OPTIONS", rows),
        ("RESOURCES", resources),
        ("COMMANDS", commands),
        ("EXIT STATUS", [ln for code, what in EXIT_STATUS for ln in _tp(f"\\fB{code}\\fR", what)]),
        ("ENVIRONMENT", [ln for var, what in ENVIRONMENT for ln in _tp(f"\\fB{lit(var)}\\fR", what)]),
        ("FILES", [*_tp("\\fI~/.aisb/config.toml\\fR", "defaults, aliases, profiles, policy, audit, notify sinks, "
                                                      "plugins"),
                   *_tp("\\fI~/.aisb/audit.jsonl\\fR", "hash-chained audit log of every change")]),
        ("SEE ALSO", [", ".join(f"\\fBaisb\\-{lit(n)}\\fR(1)" for n in [*reg, *specials])]),
    ])


def pages() -> dict[str, str]:
    from .cli import SPECIAL
    reg = registry()
    specials = {name: importlib.import_module(mod, __package__).parser() for name, mod in SPECIAL.items()}
    out = {"aisb.1": overview(reg, specials)}
    out.update({f"aisb-{name}.1": resource_page(name, ops) for name, ops in reg.items()})
    out.update({f"aisb-{name}.1": command_page(name, p) for name, p in specials.items()})
    return out


def write(out_dir: str) -> list[str]:
    root = Path(out_dir).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    for name, text in (made := pages()).items():
        (root / name).write_text(text)
    return list(made)
