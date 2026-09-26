"""Package inventory (SBOM) and file index of a filesystem stream; diff two of them."""

import hashlib
import json
import re
import sqlite3
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HASH_LIMIT = 1 << 20

_PKG_PATHS = (
    re.compile(r"^lib/apk/db/installed$"),
    re.compile(r"^var/lib/dpkg/status$"),
    re.compile(r"^var/lib/dpkg/status\.d/[^/]+$"),  # distroless
    re.compile(r"^var/lib/rpm/rpmdb\.sqlite$"),
    re.compile(r"(^|/)[^/]+\.dist-info/METADATA$"),
    re.compile(r"(^|/)[^/]+\.egg-info/PKG-INFO$"),
    re.compile(r"(^|/)node_modules/(@[^/]+/)?[^/]+/package\.json$"),
    re.compile(r"(^|/)specifications/[^/]+\.gemspec$"),
    re.compile(r"^(etc|usr/lib)/os-release$"),
)


def wants(path: str, size: int) -> bool:
    """Should the walker hand us this file's content?"""
    return any(rx.search(path) for rx in _PKG_PATHS) and size < 64 << 20


@dataclass(slots=True)
class Package:
    ecosystem: str
    name: str
    version: str
    path: str

    @property
    def purl(self) -> str:
        eco = {"apk": "apk/alpine", "dpkg": "deb/debian", "rpm": "rpm", "pypi": "pypi", "npm": "npm", "gem": "gem"}
        name = self.name.lower() if self.ecosystem == "pypi" else self.name
        return f"pkg:{eco[self.ecosystem]}/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{self.version}"


def parse(path: str, data: bytes) -> list[Package]:
    text = data.decode(errors="replace")
    if path == "lib/apk/db/installed":
        out, cur = [], {}
        for line in text.splitlines() + [""]:
            if not line:
                if "P" in cur:
                    out.append(Package("apk", cur["P"], cur.get("V", ""), path))
                cur = {}
            elif line[1:2] == ":":
                cur[line[0]] = line[2:]
        return out
    if path.startswith("var/lib/dpkg/status"):
        out = []
        for stanza in text.split("\n\n"):
            f = dict(re.findall(r"^([A-Za-z-]+): (.*)$", stanza, re.M))
            if f.get("Package") and ("install ok installed" in f.get("Status", "") or "status.d" in path):
                out.append(Package("dpkg", f["Package"], f.get("Version", ""), path))
        return out
    if path.endswith("rpmdb.sqlite"):
        return _rpm(data, path)
    if path.endswith(("METADATA", "PKG-INFO")):
        f = dict(re.findall(r"^(Name|Version): (.*)$", text.split("\n\n")[0], re.M))
        return [Package("pypi", f["Name"], f.get("Version", ""), path)] if "Name" in f else []
    if path.endswith("package.json"):
        try:
            meta = json.loads(text)
        except ValueError:
            return []
        return [Package("npm", meta["name"], str(meta.get("version", "")), path)] if meta.get("name") else []
    if path.endswith(".gemspec"):
        m = re.match(r"(.+)-(\d[\w.]*)\.gemspec$", path.rsplit("/", 1)[-1])
        return [Package("gem", m[1], m[2], path)] if m else []
    return []


def _rpm(data: bytes, path: str) -> list[Package]:
    """rpmdb.sqlite keeps names in an index table; versions live in binary headers (tag 1001 = VERSION)."""
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "rpm.sqlite"
        db.write_bytes(data)
        try:
            conn = sqlite3.connect(db)
            rows = conn.execute("select p.blob from Packages p").fetchall()
        except sqlite3.Error:
            return [Package("rpm", "<unparsed rpmdb>", "", path)]
    out = []
    for (blob,) in rows:
        tags = _rpm_header(blob)
        if tags.get(1000):
            out.append(Package("rpm", tags[1000], f"{tags.get(1001, '')}-{tags.get(1002, '')}".strip("-"), path))
    return out


def _rpm_header(blob: bytes) -> dict[int, str]:
    import struct
    try:
        count, size = struct.unpack(">II", blob[:8])
        store = 8 + count * 16
        tags = {}
        for i in range(count):
            tag, typ, off, _ = struct.unpack(">IIII", blob[8 + i * 16:24 + i * 16])
            if tag in (1000, 1001, 1002) and typ == 6:  # STRING
                end = blob.index(b"\0", store + off)
                tags[tag] = blob[store + off:end].decode(errors="replace")
        return tags
    except (struct.error, ValueError):
        return {}


def os_release(data: bytes) -> dict[str, str]:
    f = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', data.decode(errors="replace"), re.M))
    return {"id": f.get("ID", ""), "version": f.get("VERSION_ID", ""), "name": f.get("PRETTY_NAME", "")}


@dataclass(slots=True)
class FileEntry:
    size: int
    mode: int
    kind: str
    link: str = ""
    digest: str = ""


@dataclass(slots=True)
class Inventory:
    packages: list[Package] = field(default_factory=list)
    files: dict[str, FileEntry] = field(default_factory=dict)
    os: dict[str, str] = field(default_factory=dict)

    def add(self, path: str, member: Any, data: bytes | None) -> None:
        kind = "dir" if member.isdir() else "link" if member.issym() or member.islnk() else "file" if member.isfile() else "other"
        digest = hashlib.sha1(data).hexdigest() if data is not None and len(data) <= HASH_LIMIT else ""
        self.files[path] = FileEntry(member.size, member.mode & 0o7777, kind, member.linkname, digest)
        if data is not None and wants(path, member.size):
            if path.endswith("os-release"):
                self.os = self.os or os_release(data)
            else:
                self.packages += parse(path, data)

    def summary(self) -> dict[str, Any]:
        eco: dict[str, int] = {}
        for p in self.packages:
            eco[p.ecosystem] = eco.get(p.ecosystem, 0) + 1
        return {"os": self.os, "packages": len(self.packages), "by_ecosystem": eco, "files": len(self.files),
                "bytes": sum(f.size for f in self.files.values() if f.kind == "file")}


def cyclonedx(image: str, inv: Inventory) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "container", "name": image}},
            "components": [{"type": "library", "name": p.name, "version": p.version, "purl": p.purl}
                           for p in sorted(inv.packages, key=lambda p: (p.ecosystem, p.name))]}


def _vkey(v: str) -> list[Any]:
    return [(0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"[.\-+~_:]", v) if x]


def diff(a: Inventory, b: Inventory, *, top: int = 20) -> dict[str, Any]:
    fa, fb = a.files, b.files
    added, removed = sorted(fb.keys() - fa.keys()), sorted(fa.keys() - fb.keys())
    changed = [p for p in fa.keys() & fb.keys() if fa[p].kind == fb[p].kind == "file" and
               (fa[p].size != fb[p].size or (fa[p].digest and fb[p].digest and fa[p].digest != fb[p].digest))]
    delta = lambda p: (fb[p].size if p in fb else 0) - (fa[p].size if p in fa else 0)  # noqa: E731
    by_dir: dict[str, int] = {}
    for p in added + removed + changed:
        top_dir = "/" + p.split("/", 1)[0]
        by_dir[top_dir] = by_dir.get(top_dir, 0) + delta(p)
    pa = {(p.ecosystem, p.name): p.version for p in a.packages}
    pb = {(p.ecosystem, p.name): p.version for p in b.packages}
    ups, downs = [], []
    for k in sorted(pa.keys() & pb.keys()):
        if pa[k] != pb[k]:
            (ups if _vkey(pb[k]) > _vkey(pa[k]) else downs).append(
                {"ecosystem": k[0], "name": k[1], "from": pa[k], "to": pb[k]})
    fmt = lambda ks, src: [{"ecosystem": k[0], "name": k[1], "version": src[k]} for k in sorted(ks)]  # noqa: E731
    return {
        "files": {"added": len(added), "removed": len(removed), "changed": len(changed),
                  "bytes_delta": sum(delta(p) for p in added + removed + changed),
                  "by_top_dir": dict(sorted(by_dir.items(), key=lambda kv: -abs(kv[1]))[:10]),
                  "largest_changes": [{"path": "/" + p, "bytes_delta": delta(p),
                                       "change": "added" if p in added else "removed" if p in removed else "changed"}
                                      for p in sorted(added + removed + changed, key=lambda p: -abs(delta(p)))[:top]]},
        "packages": {"added": fmt(pb.keys() - pa.keys(), pb), "removed": fmt(pa.keys() - pb.keys(), pa),
                     "upgraded": ups, "downgraded": downs},
        "os": {"a": a.os, "b": b.os} if a.os != b.os else a.os,
    }


def config_diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for key in ("Env", "Cmd", "Entrypoint", "User", "WorkingDir", "ExposedPorts", "Labels", "Volumes"):
        x, y = a.get(key), b.get(key)
        if x != y:
            if isinstance(x, list) or isinstance(y, list):
                sx, sy = set(map(str, x or [])), set(map(str, y or []))
                out[key] = {"only_in_a": sorted(sx - sy), "only_in_b": sorted(sy - sx)}
            elif isinstance(x, dict) or isinstance(y, dict):
                x, y = x or {}, y or {}
                out[key] = {"only_in_a": sorted(x.keys() - y.keys()), "only_in_b": sorted(y.keys() - x.keys()),
                            "changed": sorted(k for k in x.keys() & y.keys() if x[k] != y[k])}
            else:
                out[key] = {"a": x, "b": y}
    return out


def dedupe(pkgs: Iterable[Package]) -> list[Package]:
    seen, out = set(), []
    for p in pkgs:
        key = (p.ecosystem, p.name, p.version)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out
