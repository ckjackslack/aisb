"""`aisb completion bash|zsh|fish`: shell completion generated from the argparse tree the CLI itself uses.

The script is static data (subcommands, flags, flag values per command path) plus a small walker, so pressing
TAB never starts Python. It is regenerated from the registry, so plugin ops complete too once installed.
Bash 3.2 compatible (macOS): `case` tables, no associative arrays. zsh runs the bash script via bashcompinit.
"""

import argparse
import importlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

SHELLS = ("bash", "zsh", "fish")
INSTALL = """install (then open a new shell):
  bash  aisb completion bash > ~/.local/share/bash-completion/completions/aisb
  zsh   aisb completion zsh > ~/.zfunc/_aisb    # with fpath=(~/.zfunc $fpath) before compinit in ~/.zshrc
  fish  aisb completion fish > ~/.config/fish/completions/aisb.fish"""
_WORD = re.compile(r"^[A-Za-z0-9_.:/@%+=,-]+$")  # safe inside a quoted shell word list


@dataclass(slots=True)
class Node:
    """One command path: its subcommands, flags, the flags that take a value (-> choices; empty = free text)
    and the choices of its first positional argument."""
    subs: dict[str, "Node"] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    values: dict[str, tuple[str, ...]] = field(default_factory=dict)
    choices: tuple[str, ...] = ()


def _words(items: Iterable[Any] | None) -> tuple[str, ...]:
    return tuple(w for w in map(str, items or ()) if _WORD.match(w))


def node(p: argparse.ArgumentParser) -> Node:
    n = Node()
    for a in p._actions:
        if isinstance(a, argparse._SubParsersAction):
            n.subs.update({name: node(sub) for name, sub in a.choices.items()})
        elif a.option_strings:
            n.flags += a.option_strings
            if a.nargs != 0:
                n.values.update(dict.fromkeys(a.option_strings, _words(a.choices)))
        elif a.choices and not n.choices:
            n.choices = _words(a.choices)
    return n


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aisb completion", description="print a shell completion script",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=INSTALL)
    p.add_argument("shell", choices=SHELLS, help="the shell to generate the script for")
    return p


def tree() -> Node:
    from .cli import SPECIAL, build_parser
    root = node(build_parser())
    for name, mod in SPECIAL.items():
        root.subs[name] = node(importlib.import_module(mod, __package__).parser())
    root.flags += ["--profile", "--version"]
    root.values["--profile"] = ()
    return root


def walk(n: Node, path: str = "") -> Iterator[tuple[str, Node]]:
    yield path, n
    for name, sub in n.subs.items():
        yield from walk(sub, f"{path} {name}".strip())


def _tables(root: Node) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """(pattern, words) rows for three lookups: next words, flags, and flag values keyed "path|--flag".
    A flag whose values are the same everywhere it appears gets one wildcard row instead of one per command."""
    words: list[tuple[str, str]] = []
    flags: list[tuple[str, str]] = []
    per_flag: dict[str, dict[str, str]] = {}
    for path, n in walk(root):
        if nxt := [*n.subs, *n.choices]:
            words.append((path, " ".join(nxt)))
        if n.flags:
            flags.append((path, " ".join(n.flags)))
        for f, vals in n.values.items():
            per_flag.setdefault(f, {})[path] = " ".join(vals)
    values = []
    for f, by_path in sorted(per_flag.items()):
        if len(set(by_path.values())) == 1 and len(by_path) > 1:
            values.append((f"*|{f}", next(iter(by_path.values()))))
        else:
            values += [(f"{path}|{f}", v) for path, v in by_path.items()]
    return words, flags, values


def _case(name: str, rows: list[tuple[str, str]], fish: bool = False) -> str:
    def pat(p: str) -> str:  # bash: a leading * stays a wildcard only unquoted; fish: quoted patterns still glob
        return ("*" + _q(p[1:])) if p.startswith("*|") else _q(p)
    if fish:
        body = "".join(f"        case {_q(p)}\n            printf '%s\\n' {' '.join(map(_q, w.split(' ')))}\n"
                       for p, w in rows)
        return f"function {name}\n    switch $argv[1]\n{body}        case '*'\n            return 1\n    end\nend\n"
    body = "".join(f"    {pat(p)}) echo {_q(w)} ;;\n" for p, w in rows)
    return f"{name}() {{\n  case \"$1\" in\n{body}    *) return 1 ;;\n  esac\n}}\n"


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


_BASH = r"""
__aisb_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}" prev="" path="" w i
  COMPREPLY=()
  for ((i = 1; i < COMP_CWORD; i++)); do
    w="${COMP_WORDS[i]}"
    [[ $w == -- ]] && return 0          # a command after --: default (file) completion
    if [[ $w == -* ]]; then
      if _aisb_values "$path|$w" >/dev/null; then
        ((i + 1 == COMP_CWORD)) && prev="$w"
        ((i++))                           # skip the flag's value
      fi
      continue
    fi
    [[ " $(_aisb_words "$path") " == *" $w "* ]] && path="${path:+$path }$w"
  done
  local vals
  if [[ -n $prev ]]; then
    vals="$(_aisb_values "$path|$prev")"
    [[ -n $vals ]] && COMPREPLY=($(compgen -W "$vals" -- "$cur"))
    return 0                              # a free-text value: default (file) completion
  fi
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$(_aisb_flags "$path")" -- "$cur"))
  else
    COMPREPLY=($(compgen -W "$(_aisb_words "$path")" -- "$cur"))
  fi
}
complete -o default -F __aisb_complete aisb
"""
# autoloaded from $fpath as _aisb, the file body runs on the first TAB: complete that one too
_ZSH_TAIL = '[[ ${funcstack[1]-} == _aisb ]] && _bash_complete -o default -F __aisb_complete\n'


_FISH = r"""
function __aisb_complete
    set -l tokens (commandline -opc)
    set -l cur (commandline -ct)
    set -l path ''
    set -l flag ''
    for w in $tokens[2..-1]
        if test -n "$flag"
            set flag ''
            continue
        end
        if test "$w" = '--'
            __fish_complete_path $cur
            return
        end
        if string match -q -- '-*' $w
            __aisb_values "$path|$w" >/dev/null; and set flag $w
            continue
        end
        if contains -- $w (__aisb_words "$path")
            set path (string trim -- "$path $w")
        end
    end
    if test -n "$flag"
        set -l vals (__aisb_values "$path|$flag")
        if test -n "$vals"
            string split ' ' -- $vals
        else
            __fish_complete_path $cur
        end
    else if string match -q -- '-*' $cur
        string split ' ' -- (__aisb_flags "$path")
    else
        __aisb_words "$path" | string split ' '
    end
end
complete -c aisb -f -a '(__aisb_complete)'
"""


def script(shell: str, root: Node | None = None) -> str:
    if shell not in SHELLS:
        raise ValueError(f"unknown shell {shell!r} (one of: {', '.join(SHELLS)})")
    words, flags, values = _tables(root or tree())
    fish = shell == "fish"
    head = f"# aisb completion for {shell}. Generated by `aisb completion {shell}`; regenerate after upgrading aisb.\n"
    if shell == "zsh":
        head = "#compdef aisb\n" + head + "autoload -U +X bashcompinit && bashcompinit\n"
    tables = "".join(_case(f"{'__' if fish else '_'}aisb_{name}", rows, fish)
                     for name, rows in (("words", words), ("flags", flags), ("values", values)))
    return head + tables + (_FISH if fish else _BASH) + (_ZSH_TAIL if shell == "zsh" else "")


def main(argv: list[str] | None = None) -> int:
    print(script(parser().parse_args(argv).shell), end="")
    return 0
