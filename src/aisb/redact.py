"""Redact secrets from container config beyond env: command-line args, entrypoints, health checks, labels.

Each secret becomes a named placeholder, `<redacted:NAME>`, so a consumer (`capsule load --env NAME=value`) can
put it back. Names: `arg:--flag` for a secret flag's value, `arg:N` for a token found in the N-th argument,
`label:KEY` for labels. Pure functions.
"""

import re
import shlex
from collections.abc import Mapping, Sequence

from .insights.audit import TOKEN_PATTERNS
from .transport import SECRET_KEY

_PH = re.compile(r"<redacted:([^<>]+)>")
_URL_PW = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s/@]{1,})(@)", re.I)


def placeholder(name: str) -> str:
    return f"<redacted:{name}>"


def secret_flag(flag: str) -> bool:
    """`--requirepass`, `--db-password`, `--api-key`: flags whose value is a secret."""
    return flag.startswith("-") and bool(SECRET_KEY.search(flag.lstrip("-").replace("-", "_").upper()))


def _tokens(value: str, name: str) -> tuple[str, bool]:
    """Mask a URL's password part and any known token format inside `value`."""
    out = _URL_PW.sub(lambda m: m[1] + placeholder(name) + m[3], value)
    for _, rx in TOKEN_PATTERNS:
        if rx.pattern.startswith(r"\b[a-z][a-z0-9+.-]*://"):
            continue  # URLs handled above, keeping user and host readable
        out = rx.sub(placeholder(name), out)
    return out, out != value


def args(argv: Sequence[str], *, prefix: str = "arg") -> tuple[list[str], list[str]]:
    """(masked argv, placeholder names) for `--flag=value`, `--flag value` and tokens in plain arguments."""
    out: list[str] = []
    names: list[str] = []
    mask_next: str | None = None
    for i, a in enumerate(argv):
        if mask_next is not None:
            out.append(placeholder(mask_next))
            names.append(mask_next)
            mask_next = None
            continue
        flag, eq, value = a.partition("=")
        if eq and value and secret_flag(flag):
            name = f"{prefix}:{flag}"
            out.append(f"{flag}={placeholder(name)}")
            names.append(name)
        elif not eq and secret_flag(a) and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            out.append(a)
            mask_next = f"{prefix}:{a}"
        else:
            masked, hit = _tokens(a, f"{prefix}:{i}")
            out.append(masked)
            if hit:
                names.append(f"{prefix}:{i}")
    return out, names


def shell(text: str | None, *, prefix: str) -> tuple[str | None, list[str]]:
    """A command string (entrypoint, health check): masked word by word when it parses, else tokens only."""
    if not text:
        return text, []
    try:
        words = shlex.split(text)
    except ValueError:
        masked, hit = _tokens(text, prefix)
        return masked, [prefix] if hit else []
    masked_words, names = args(words, prefix=prefix)
    return (shlex.join(masked_words), names) if names else (text, [])


def healthcheck(test: Sequence[str]) -> tuple[list[str], list[str]]:
    """Docker's Healthcheck.Test: ["CMD-SHELL", "<shell>"] or ["CMD", arg, ...] (or ["NONE"])."""
    if len(test) == 2 and test[0] == "CMD-SHELL":
        text, names = shell(test[1], prefix="health")
        return [test[0], text or ""], names
    if test and test[0] == "CMD":
        rest, names = args(test[1:], prefix="health")
        return [test[0], *rest], names
    return list(test), []


def labels(values: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    out: dict[str, str] = {}
    names: list[str] = []
    for k, v in values.items():
        name = f"label:{k}"
        if v and SECRET_KEY.search(k.replace(".", "_").replace("-", "_").upper()):
            out[k], hit = placeholder(name), True
        else:
            out[k], hit = _tokens(v, name)
        if hit:
            names.append(name)
    return out, names


def fill(value: str, supplied: Mapping[str, str]) -> tuple[str, list[str]]:
    """Put supplied secrets back into placeholders; returns (value, names still missing)."""
    missing: list[str] = []

    def one(m: re.Match[str]) -> str:
        if m[1] in supplied:
            return supplied[m[1]]
        missing.append(m[1])
        return m[0]
    return _PH.sub(one, value), missing
