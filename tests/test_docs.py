"""Every `aisb ...` command in the operator docs must parse with the real CLI (inner fleet ops included)."""

import re
import shlex
from pathlib import Path

import pytest

from aisb.cli import parse

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "docs" / "ops-guide.md", ROOT / "README.md"]
_SHELLISH = {"", "bash", "sh", "shell", "yaml", "cron", "ini"}
_SPECIAL = {"mcp", "bundle", "portal", "docs"}   # hand-written subcommands with their own argparse


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
                if argv and argv[0] not in _SPECIAL and len(argv) >= 2 and not argv[0].startswith("["):
                    out.append((raw.strip(), argv))
    return out


CASES = [(f"{p.name}: {line[:90]}", argv) for p in DOCS for line, argv in _commands(p)]


def test_docs_have_commands():
    assert len([c for c in CASES if c[0].startswith("ops-guide.md")]) > 100


@pytest.mark.parametrize(("where", "argv"), CASES, ids=[c[0] for c in CASES])
def test_command_parses(where, argv):
    args = parse(argv)
    assert args._op is not None, where
    if args._op.resource == "fleet" and args._op.name in ("query", "apply", "destroy"):
        inner = list(args.command)
        assert inner, f"{where}: fleet {args._op.name} needs an op after --"
        parse(inner)
