"""`~/.aisb/config.toml` ($AISB_CONFIG): flag defaults, aliases, profiles, audit, plugins, notify sinks, policy.

Loaded once per process (`load()`), with the active profile ($AISB_PROFILE or `aisb --profile NAME`) merged over
the top level. A missing file is an empty config; a malformed one is a clear error, never a silent default.
"""

import fnmatch
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_CACHE: "Config | None" = None


@dataclass(slots=True)
class Config:
    path: Path | None = None
    profile: str | None = None
    defaults: dict[str, dict[str, Any]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)
    plugins: list[str] = field(default_factory=list)
    notify: dict[str, dict[str, Any]] = field(default_factory=dict)
    policy: list[dict[str, Any]] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    profiles: list[str] = field(default_factory=list)

    def defaults_for(self, qualname: str) -> dict[str, Any]:
        """Flag defaults for an op. Every matching glob applies; more specific keys win:
        `*` < `resource.*` < other globs < the exact `resource.op`."""
        resource = qualname.split(".")[0]

        def rank(key: str) -> int:
            return 0 if key == "*" else 1 if key == f"{resource}.*" else 3 if key == qualname else 2
        out: dict[str, Any] = {}
        for key in sorted((k for k in self.defaults if fnmatch.fnmatchcase(qualname, k)), key=rank):
            out.update(self.defaults[key])
        return out


def default_path() -> Path:
    return Path(os.environ.get("AISB_CONFIG") or "~/.aisb/config.toml").expanduser()


def _merge(base: dict[str, Any], over: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, Mapping) and isinstance(out.get(k), dict) else v
    return out


def parse(data: Mapping[str, Any], *, profile: str | None = None, path: Path | None = None) -> Config:
    profiles = dict(data.get("profiles") or {})
    if profile and profile not in profiles:
        raise ValueError(f"unknown profile {profile!r} (profiles: {', '.join(sorted(profiles)) or 'none'})")
    merged = _merge({k: v for k, v in data.items() if k != "profiles"}, profiles.get(profile, {})) if profile \
        else {k: v for k, v in data.items() if k != "profiles"}
    known = {"defaults", "aliases", "audit", "plugins", "notify", "policy", "env"}
    if unknown := set(merged) - known:
        raise ValueError(f"{path or 'config'}: unknown sections {sorted(unknown)} (known: {sorted(known | {'profiles'})})")
    policy = merged.get("policy") or {}
    return Config(
        path=path, profile=profile,
        defaults={k: dict(v) for k, v in (merged.get("defaults") or {}).items()},
        aliases={k: str(v) for k, v in (merged.get("aliases") or {}).items()},
        audit=dict(merged.get("audit") or {}),
        plugins=list((merged.get("plugins") or {}).get("modules") or []),
        notify={k: dict(v) for k, v in (merged.get("notify") or {}).items()},
        policy=[dict(r) for r in (policy.get("rules") or [])],
        env={k: str(v) for k, v in (merged.get("env") or {}).items()},
        profiles=sorted(profiles),
    )


def load(*, profile: str | None = None, path: Path | None = None, reload: bool = False) -> Config:
    """The effective config. Profile env vars are applied to os.environ (only those not already set)."""
    global _CACHE
    profile = profile or os.environ.get("AISB_PROFILE") or None
    if _CACHE is not None and not reload and _CACHE.profile == profile and (path is None or path == _CACHE.path):
        return _CACHE
    p = path or default_path()
    try:
        data = tomllib.loads(p.read_text()) if p.exists() else {}
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"{p}: invalid TOML: {e}") from None
    cfg = parse(data, profile=profile, path=p)
    for k, v in cfg.env.items():
        os.environ.setdefault(k, os.path.expanduser(v))
    _CACHE = cfg
    return cfg


def reset() -> None:
    global _CACHE
    _CACHE = None
