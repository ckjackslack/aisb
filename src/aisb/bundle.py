"""`aisb bundle`: aisb as one self-contained, reproducible `.pyz` (runs on any host with Python >= 3.11).

Being stdlib-only is what makes this possible: no wheels, no venv, no pip on the target. The archive is
byte-for-byte deterministic (sorted entries, fixed timestamps), so its sha256 identifies the version and tools
such as pyinfra's `files.put` only re-upload when the code actually changed.
"""

import argparse
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

SHEBANG = b"#!/usr/bin/env python3\n"
MAIN = b"from aisb.cli import main\n\nraise SystemExit(main())\n"
EXCLUDE = ("contrib",)  # optional integrations import third-party packages; the bundle stays stdlib-only
_EPOCH = (1980, 1, 1, 0, 0, 0)


def sources(pkg: Path | None = None) -> list[tuple[str, bytes]]:
    root = pkg or Path(sys.modules["aisb"].__path__[0])
    out = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if rel.parts[0] in EXCLUDE or "__pycache__" in rel.parts:
            continue
        out.append((f"aisb/{rel.as_posix()}", path.read_bytes()))
    return out


def build(pkg: Path | None = None) -> bytes:
    """The .pyz bytes: shebang + a zip with `__main__.py` and the aisb package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in [("__main__.py", MAIN), *sources(pkg)]:
            info = zipfile.ZipInfo(name, _EPOCH)
            info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            z.writestr(info, data)
    return SHEBANG + buf.getvalue()


def write(out: str | Path, pkg: Path | None = None) -> dict[str, object]:
    data = build(pkg)
    path = Path(out).expanduser()
    path.write_bytes(data)
    path.chmod(0o755)
    return {"bundle": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "run": f"python3 {path.name} system ping"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aisb bundle", description="write aisb as a single executable .pyz")
    p.add_argument("out", nargs="?", default="aisb.pyz")
    print(json.dumps(write(p.parse_args(argv).out)))
    return 0
