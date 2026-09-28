"""Shell completion: the tables come from the real argparse tree, and the generated scripts complete correctly
in real bash, zsh and fish (the latter two skipped where not installed)."""

import argparse
import json
import shutil
import subprocess

import pytest

from aisb import completion
from aisb.cli import main
from aisb.ops import registry


@pytest.fixture(scope="module")
def scripts(tmp_path_factory) -> dict[str, str]:
    d = tmp_path_factory.mktemp("completion")
    out = {}
    for shell in completion.SHELLS:
        (d / shell).write_text(completion.script(shell))
        out[shell] = str(d / shell)
    return out


def bash(script: str, *words: str) -> list[str]:
    code = 'source "$1"; shift; COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1)); __aisb_complete; printf "%s\\n" "${COMPREPLY[@]}"'
    res = subprocess.run(["bash", "--norc", "-c", code, "_", script, *words], capture_output=True, text=True, check=True)
    return [w for w in res.stdout.splitlines() if w]


@pytest.mark.parametrize(("words", "expected"), [
    (["aisb", "con"], ["containers", "config"]),
    (["aisb", "audit", ""], ["log", "verify", "anchor", "keygen"]),
    (["aisb", "containers", "logs", "--ta"], ["--tail"]),
    (["aisb", "containers", "list", "-o", ""], ["json", "ndjson", "table", "csv", "yaml", "raw"]),
    (["aisb", "containers", "list", "--output", "y"], ["yaml"]),
    (["aisb", "--profile", "prod", "au"], ["audit"]),                  # a global option's value is skipped
    (["aisb", "containers", "logs", "--tail", "5", "--si"], ["--since"]),  # so is an op flag's value
    (["aisb", "completion", ""], ["bash", "zsh", "fish"]),              # positional choices
    (["aisb", "portal", "--allow", ""], ["read", "mutate"]),            # special commands' own parsers
    (["aisb", "containers", "logs", "--tail", ""], []),                 # free text: left to the shell
    (["aisb", "containers", "exec", "web", "--", "l"], []),             # after --: the container's command
])
def test_bash_completes(scripts, words, expected):
    assert bash(scripts["bash"], *words) == expected


def test_bash_completes_every_op_of_every_resource(scripts):
    for resource, ops in registry().items():
        assert bash(scripts["bash"], "aisb", resource, "") == list(ops), resource
    assert bash(scripts["bash"], "aisb", "nosuch", "") == bash(scripts["bash"], "aisb", "")  # unknown: path stays


def test_bash_script_is_bash_3_compatible(scripts):
    text = open(scripts["bash"]).read()
    assert "declare -A" not in text and "local -A" not in text and "mapfile" not in text  # macOS ships bash 3.2


@pytest.mark.skipif(not shutil.which("fish"), reason="fish not installed")
@pytest.mark.parametrize(("line", "expected"), [
    ("aisb audit ", ["anchor", "keygen", "log", "verify"]),
    ("aisb containers list -o ", ["csv", "json", "ndjson", "raw", "table", "yaml"]),
    ("aisb --profile prod au", ["audit"]),
    ("aisb containers logs --ta", ["--tail"]),
])
def test_fish_completes(scripts, line, expected):
    res = subprocess.run(["fish", "--no-config", "-c", f'source {scripts["fish"]}; complete -C "{line}"'],
                         capture_output=True, text=True, check=True)
    assert sorted(w.split("\t")[0] for w in res.stdout.splitlines()) == expected


@pytest.mark.skipif(not shutil.which("zsh"), reason="zsh not installed")
def test_zsh_script_loads_and_completes_through_bashcompinit(scripts):
    # _bash_complete runs the function under `emulate sh`; do the same, then read what it would offer
    code = (f'autoload -U +X compinit && compinit -u -D; source {scripts["zsh"]}; emulate sh; '
            'COMP_WORDS=(aisb containers list -o ""); COMP_CWORD=4; __aisb_complete; echo "${COMPREPLY[*]}"')
    res = subprocess.run(["zsh", "-f", "-c", code], capture_output=True, text=True, check=True)
    assert res.stdout.split() == ["json", "ndjson", "table", "csv", "yaml", "raw"]
    assert open(scripts["zsh"]).read().startswith("#compdef aisb\n")


def test_tree_reads_an_argparse_parser():
    p = argparse.ArgumentParser()
    p.add_argument("--level", choices=["a", "b c", "d"])   # a choice with a space can't be a shell word
    p.add_argument("--quiet", action="store_true")
    sub = p.add_subparsers()
    s = sub.add_parser("go")
    s.add_argument("target", choices=["x", "y"])
    s.add_argument("--name")
    n = completion.node(p)
    assert n.values == {"--level": ("a", "d")} and "--quiet" in n.flags and "--quiet" not in n.values
    assert n.subs["go"].choices == ("x", "y") and n.subs["go"].values == {"--name": ()}


def test_a_flag_with_the_same_values_everywhere_gets_one_wildcard_row():
    root = completion.Node(subs={
        "a": completion.Node(flags=["--o", "--x"], values={"--o": ("j", "k"), "--x": ("1",)}),
        "b": completion.Node(flags=["--o", "--x"], values={"--o": ("j", "k"), "--x": ("2",)}),
    })
    _, _, values = completion._tables(root)
    assert ("*|--o", "j k") in values and ("a|--x", "1") in values and ("b|--x", "2") in values


def test_cli_prints_the_script(capsys):
    assert main(["completion", "fish"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# aisb completion for fish") and "complete -c aisb" in out
    with pytest.raises(SystemExit):
        main(["completion", "tcsh"])
    with pytest.raises(ValueError, match="unknown shell"):
        completion.script("tcsh")
    assert json.dumps(completion.INSTALL)  # the install hint is shown by --help and the man page
