"""Fleet inventory: hosts with groups and labels, computed groups, and the selector language."""

import fnmatch
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Self

from .. import state

DEFAULT_SOCKET = "/var/run/docker.sock"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


# one selector term: an optional operator (`,` union, `&` intersect, `!` exclude, `&!` and-not), then an atom
_TERM = re.compile(r"(,|&!|&|!|^)\s*([^,&!]+)")

@dataclass(frozen=True, slots=True)
class Host:
    name: str
    ssh: str | None = None            # user@host (or an ~/.ssh/config alias): tunnel the remote Docker socket
    port: int | None = None
    key: str | None = None
    docker: str | None = None         # remote socket path with ssh; a direct endpoint without; None = local
    groups: tuple[str, ...] = ()
    labels: Mapping[str, str] = field(default_factory=dict)
    ssh_options: tuple[str, ...] = ()

    @property
    def transport(self) -> str:
        return "ssh" if self.ssh else ("tcp" if (self.docker or "").startswith("tcp://") else "local")

    @property
    def socket(self) -> str:
        return (self.docker or DEFAULT_SOCKET).removeprefix("unix://")

    @classmethod
    def from_dict(cls, name: str, d: Mapping[str, Any]) -> Self:
        if not _NAME.match(name):
            raise ValueError(f"invalid host name {name!r} (letters, digits, . _ -)")
        unknown = set(d) - {"ssh", "port", "key", "docker", "groups", "labels", "ssh_options"}
        if unknown:
            raise ValueError(f"host {name}: unknown keys {sorted(unknown)}")
        return cls(name, d.get("ssh"), d.get("port"), d.get("key"), d.get("docker"),
                   tuple(dict.fromkeys(d.get("groups") or ())), dict(d.get("labels") or {}),
                   tuple(d.get("ssh_options") or ()))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("name")
        d["groups"], d["ssh_options"] = list(self.groups), list(self.ssh_options)
        return {k: v for k, v in d.items() if v not in (None, [], {})}


@dataclass(slots=True)
class Inventory:
    hosts: dict[str, Host] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)  # computed groups: name -> selector terms
    path: Path | None = None

    # --- persistence --------------------------------------------------------------------------

    @staticmethod
    def default_path() -> Path:
        return Path(os.environ["AISB_FLEET"]).expanduser() if os.environ.get("AISB_FLEET") else state.home() / "fleet.json"

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Inventory":
        p = Path(path).expanduser() if path else cls.default_path()
        data = json.loads(p.read_text()) if p.exists() else {}
        inv = cls({n: Host.from_dict(n, d or {}) for n, d in (data.get("hosts") or {}).items()},
                  {g: list(terms) for g, terms in (data.get("groups") or {}).items()}, p)
        inv.validate()
        return inv

    def save(self) -> Path:
        assert self.path is not None
        self.validate()
        state.write_json(self.path, {"hosts": {n: h.to_dict() for n, h in sorted(self.hosts.items())},
                                     **({"groups": self.groups} if self.groups else {})})
        return self.path

    def validate(self) -> None:
        clash = set(self.groups) & {g for h in self.hosts.values() for g in h.groups}
        if clash:
            raise ValueError(f"groups {sorted(clash)} are both computed and assigned to hosts; pick one")
        for g in self.groups:
            self.members(g)  # raises on cycles / unknown references

    # --- editing ------------------------------------------------------------------------------

    def upsert(self, host: Host, *, merge: bool = True) -> Host:
        old = self.hosts.get(host.name)
        if old and merge:
            host = replace(host, groups=tuple(dict.fromkeys(old.groups + host.groups)),
                           labels={**old.labels, **host.labels},
                           **{f: getattr(old, f) for f in ("ssh", "port", "key", "docker", "ssh_options")
                              if not getattr(host, f)})
        self.hosts[host.name] = host
        return host

    def regroup(self, group: str, *, add: Iterable[str] = (), remove: Iterable[str] = ()) -> None:
        if group in self.groups:
            raise ValueError(f"@{group} is computed from selectors; edit `groups` in {self.path}")
        for n in add:
            h = self.hosts[n]
            self.hosts[n] = replace(h, groups=tuple(dict.fromkeys((*h.groups, group))))
        for n in remove:
            h = self.hosts[n]
            self.hosts[n] = replace(h, groups=tuple(g for g in h.groups if g != group))

    # --- selection ----------------------------------------------------------------------------

    def group_names(self) -> list[str]:
        return sorted({g for h in self.hosts.values() for g in h.groups} | set(self.groups))

    def members(self, group: str, _seen: frozenset[str] = frozenset()) -> set[str]:
        if group in _seen:
            raise ValueError(f"group cycle: {' -> '.join([*_seen, group])}")
        found = {n for n, h in self.hosts.items() if group in h.groups}
        if terms := self.groups.get(group):  # a computed group is a selector too: `["web*", "!web2"]`
            found |= self._resolve(",".join(terms), _seen | {group})
        if not found and group not in self.groups and group not in self.group_names():
            raise ValueError(f"unknown group @{group} (groups: {', '.join(self.group_names()) or 'none'})")
        return found

    def _atom(self, atom: str, seen: frozenset[str] = frozenset()) -> set[str]:
        if atom in ("all", "*"):
            return set(self.hosts)
        if atom.startswith("@"):
            return self.members(atom[1:], seen)
        if "=" in atom:
            k, _, v = atom.partition("=")
            return {n for n, h in self.hosts.items() if fnmatch.fnmatchcase(str(h.labels.get(k, "\0")), v)}
        if any(c in atom for c in "*?["):
            return set(fnmatch.filter(self.hosts, atom))
        if atom not in self.hosts:
            close = [n for n in self.hosts if n.startswith(atom[:2])][:5]
            raise ValueError(f"unknown host {atom!r}" + (f" (did you mean {', '.join(close)}?)" if close else ""))
        return {atom}

    def select(self, expr: str) -> list[Host]:
        """`web*,@db,&region=eu,!web2` -> hosts (sorted). Union of plain terms, then & intersects, ! subtracts.
        `&` and `!` work with or without a comma before them: `@web&region=eu!web2`."""
        chosen = self._resolve(expr)
        if not chosen:
            raise ValueError(f"{expr!r} selects no hosts")
        return [self.hosts[n] for n in sorted(chosen)]

    def _resolve(self, expr: str, seen: frozenset[str] = frozenset()) -> set[str]:
        terms = [(op, atom.strip()) for op, atom in _TERM.findall(expr) if atom.strip()]
        if not terms:
            raise ValueError("empty target (use `all`, a host, @group, label=value, a glob)")
        plain = [atom for op, atom in terms if op not in ("&", "!", "&!")]
        chosen = set().union(*(self._atom(a, seen) for a in plain)) if plain else set(self.hosts)
        for op, atom in terms:
            if op == "&":
                chosen &= self._atom(atom, seen)
            elif op in ("!", "&!"):  # "&!x" (and not x) is the same as "!x"
                chosen -= self._atom(atom, seen)
        return chosen

    def groups_of(self, name: str) -> list[str]:
        return sorted(g for g in self.group_names() if name in self.members(g))
