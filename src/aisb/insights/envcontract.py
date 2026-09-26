"""Which environment variables does the code actually read, and does the container provide them?"""

import difflib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

Need = Literal["required", "optional", "used"]
SOURCE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".rb", ".java", ".kt", ".php", ".sh", ".bash",
              ".yml", ".yaml", ".properties", ".toml", ".ini", ".conf", ".rs", ".ex", ".exs", ".cs")
SKIP_DIRS = ("node_modules/", "site-packages/", "dist-packages/", "vendor/", ".git/", "__pycache__/", ".venv/",
             "venv/", "target/", ".cache/", "bower_components/")
CONTRACT_FILES = (".env.example", ".env.sample", ".env.template", ".env.dist", "env.example")
AMBIENT = {"PATH", "HOME", "HOSTNAME", "LANG", "LC_ALL", "TERM", "PWD", "SHLVL", "USER", "SHELL", "TZ", "OLDPWD",
           "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHON_VERSION", "PYTHON_SHA256", "GPG_KEY", "NODE_VERSION",
           "YARN_VERSION", "NODE_ENV", "JAVA_HOME", "JAVA_VERSION", "GOPATH", "GOLANG_VERSION", "RUBY_VERSION",
           "GEM_HOME", "BUNDLE_APP_CONFIG", "PIP_NO_CACHE_DIR", "PHP_VERSION", "LANGUAGE", "DEBIAN_FRONTEND"}

_V = r"([A-Z][A-Z0-9_]{1,})"
_Q = r"""["']"""
PATTERNS: tuple[tuple[Need, re.Pattern[str]], ...] = (
    # Python
    ("required", re.compile(rf"os\.environ\[{_Q}{_V}{_Q}\]")),
    ("optional", re.compile(rf"(?:os\.environ\.get|os\.getenv|getenv)\(\s*{_Q}{_V}{_Q}\s*,")),
    ("used", re.compile(rf"(?:os\.environ\.get|os\.getenv)\(\s*{_Q}{_V}{_Q}\s*\)")),
    # Node
    ("used", re.compile(rf"process\.env\.{_V}\b")),
    ("used", re.compile(rf"process\.env\[{_Q}{_V}{_Q}\]")),
    # Go
    ("used", re.compile(rf"os\.(?:Getenv|LookupEnv)\(\s*\"{_V}\"\s*\)")),
    # Ruby
    ("required", re.compile(rf"ENV\.fetch\(\s*{_Q}{_V}{_Q}\s*\)")),
    ("optional", re.compile(rf"ENV\.fetch\(\s*{_Q}{_V}{_Q}\s*,")),
    ("used", re.compile(rf"ENV\[{_Q}{_V}{_Q}\]")),
    # Java / Kotlin / C#
    ("used", re.compile(rf"(?:System\.getenv|Environment\.GetEnvironmentVariable)\(\s*\"{_V}\"\s*\)")),
    # PHP
    ("used", re.compile(rf"(?:getenv\(\s*{_Q}{_V}{_Q}\s*\)|\$_ENV\[{_Q}{_V}{_Q}\])")),
    # Shell: ${X:?msg} required, ${X:-d} optional
    ("required", re.compile(rf"\$\{{{_V}:?\?")),
    ("optional", re.compile(rf"\$\{{{_V}:?[-=]")),
    # Spring / YAML placeholders: ${X} required, ${X:default} optional
    ("required", re.compile(rf"\$\{{{_V}\}}")),
    ("optional", re.compile(rf"\$\{{{_V}:[^}}?\-=]")),
)
_RANK = {"required": 0, "used": 1, "optional": 2}


@dataclass(slots=True)
class Use:
    var: str
    need: Need
    where: str


def is_source(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return (path.endswith(SOURCE_EXT) or name in CONTRACT_FILES or name in ("Dockerfile", "entrypoint", "docker-entrypoint")
            ) and not any(d in f"/{path}" for d in (f"/{s}" for s in SKIP_DIRS))


def extract(path: str, text: str) -> list[Use]:
    uses: list[Use] = []
    name = path.rsplit("/", 1)[-1]
    for no, line in enumerate(text.splitlines(), 1):
        if name in CONTRACT_FILES:
            if m := re.match(rf"\s*(?:export\s+)?{_V}\s*=", line):
                uses.append(Use(m.group(1), "used", f"{path}:{no}"))
            continue
        for need, rx in PATTERNS:
            for m in rx.finditer(line):
                var = next(g for g in m.groups() if g)
                uses.append(Use(var, need, f"{path}:{no}"))
    return uses


def check(uses: Iterable[Use], provided: Mapping[str, str]) -> dict[str, Any]:
    """Compare what the code reads with what the environment provides; suggest likely typos."""
    by_var: dict[str, dict[str, Any]] = {}
    for u in uses:
        entry = by_var.setdefault(u.var, {"var": u.var, "need": u.need, "where": []})
        if _RANK[u.need] < _RANK[entry["need"]]:
            entry["need"] = u.need
        if u.where not in entry["where"]:
            entry["where"].append(u.where)
    for entry in by_var.values():  # code evidence first, documentation (.env.example) last; keep three
        entry["where"] = sorted(entry["where"], key=lambda w: w.split(":")[0].rsplit("/", 1)[-1] in CONTRACT_FILES)[:3]
    keys = set(provided)
    missing = [e for v, e in sorted(by_var.items()) if v not in keys and e["need"] != "optional"]
    unused = sorted(k for k in keys - by_var.keys() if k not in AMBIENT and not k.endswith("_FILE"))
    typos = []
    for e in missing:
        close = difflib.get_close_matches(e["var"], unused, n=1, cutoff=0.85)
        if close:
            e["did_you_mean"] = close[0]
            typos.append({"provided": close[0], "code_reads": e["var"], "where": e["where"][0]})
    # A `${X}` in a YAML file is required only when the app really loads it; treat non-code sources softer.
    required = [e for e in missing if e["need"] == "required"]
    return {
        "variables_read": len(by_var),
        "ok": not required,
        "missing_required": required,
        "missing_used": [e for e in missing if e["need"] == "used"],
        "typo_suspects": typos,
        "unused_provided": unused,
        "optional_unset": sorted(v for v, e in by_var.items() if e["need"] == "optional" and v not in keys),
    }
