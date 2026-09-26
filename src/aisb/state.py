"""Local durable state under $AISB_HOME (default ~/.aisb): sessions, blackbox records, recordings."""

import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def home(*parts: str) -> Path:
    """$AISB_HOME/<parts>, created with owner-only permissions (it can hold captured secrets)."""
    root = Path(os.environ.get("AISB_HOME") or "~/.aisb").expanduser()
    path = root.joinpath(*parts)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def write_json(path: Path, obj: Any) -> Path:
    """Atomic write (temp file + rename), mode 0600."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh, indent=1, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def append_jsonl(path: Path, obj: Any) -> None:
    with open(path, "a") as fh:
        fh.write(json.dumps(obj, default=str) + "\n")
    os.chmod(path, 0o600)


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                yield json.loads(line)
