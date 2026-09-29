"""Every `aisb ...` command in the operator docs must parse with the real CLI (inner fleet ops included)."""

import importlib
import re
import shlex
from pathlib import Path

import pytest

from aisb.cli import SPECIAL, build_parser, parse

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "docs" / "ops-guide.md", ROOT / "README.md"]
_SHELLISH = {"", "bash", "sh", "shell", "yaml", "cron", "ini"}


def _blocks(text: str) -> list[str]:
    """Bodies of fenced code blocks whose language is a shell-ish one."""
    blocks, lang, body = [], None, []
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if lang is None:
                lang, body = line.lstrip()[3:].strip(), []
            else:
                if lang in _SHELLISH:
                    blocks.append("\n".join(body))
                lang = None
        elif lang is not None:
            body.append(line)
    return blocks


def _commands(path: Path) -> list[tuple[str, list[str]]]:
    out = []
    for block in _blocks(path.read_text()):
        for raw in block.replace("\\\n", " ").splitlines():
            for m in re.finditer(r"(?:^|[\s(;&|`])aisb\s+(?!-)([^|;&>`)#]+)", raw):
                text = re.sub(r'"?\$\([^)]*\)"?|"?\$\{?\w+\}?"?', "X", m.group(1)).strip()
                text = re.sub(r"<\(.*", "", text).strip().rstrip("\\").strip()
                try:
                    argv = shlex.split(text)
                except ValueError:
                    continue
                if argv and not argv[0].startswith("[") and (len(argv) >= 2 or argv[0] in SPECIAL):
                    out.append((raw.strip(), argv))
    return out


CASES = [(f"{p.name}: {line[:90]}", argv) for p in DOCS for line, argv in _commands(p)]


def test_docs_have_commands():
    assert len([c for c in CASES if c[0].startswith("ops-guide.md")]) > 100


@pytest.mark.parametrize(("where", "argv"), CASES, ids=[c[0] for c in CASES])
def test_command_parses(where, argv):
    if argv[0] in SPECIAL:   # commands with their own argparse; "[--flag X]" marks an optional part
        rest, optional = [], False
        for tok in argv[1:]:
            optional = optional or tok.startswith("[")
            if not optional:
                rest.append(tok)
            optional = optional and not tok.endswith("]")
        importlib.import_module(f"aisb{SPECIAL[argv[0]]}").parser().parse_args(rest)
        return
    if argv[0] == "docs":
        build_parser().parse_args(argv)
        return
    args = parse(argv)
    assert args._op is not None, where
    if args._op.resource == "fleet" and args._op.name in ("query", "apply", "destroy"):
        inner = list(args.command)
        assert inner, f"{where}: fleet {args._op.name} needs an op after --"
        parse(inner)
