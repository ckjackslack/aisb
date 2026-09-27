"""Plugin discovery: modules that register resources/ops, service adapters (@register) or doctor rules (@rule).

Sources, in order: the `aisb.plugins` entry-point group, `$AISB_PLUGINS` (comma-separated module names), and
`[plugins] modules` in config.toml. Importing the module is the whole protocol; a module may also expose
`setup()` which is called once. Failures are collected (see `errors()`), never fatal for the rest of aisb.
"""

import importlib
import os
from importlib.metadata import entry_points

_LOADED: dict[str, str | None] = {}   # module -> error (None = ok)
_DONE = False


def _sources() -> list[str]:
    from . import config
    mods = [ep.value.split(":")[0] for ep in entry_points(group="aisb.plugins")]
    mods += [m.strip() for m in os.environ.get("AISB_PLUGINS", "").split(",") if m.strip()]
    try:
        mods += config.load().plugins
    except ValueError:
        pass  # a broken config is reported where it's used, not here
    return list(dict.fromkeys(mods))


def load() -> dict[str, str | None]:
    global _DONE
    if _DONE:
        return _LOADED
    _DONE = True
    for name in _sources():
        try:
            mod = importlib.import_module(name)
            if callable(setup := getattr(mod, "setup", None)):
                setup()
            _LOADED[name] = None
        except Exception as e:  # noqa: BLE001 - a plugin must never take the CLI down
            _LOADED[name] = f"{type(e).__name__}: {e}"
    return _LOADED


def errors() -> dict[str, str]:
    return {k: v for k, v in _LOADED.items() if v}


def reset() -> None:
    global _DONE
    _DONE = False
    _LOADED.clear()
