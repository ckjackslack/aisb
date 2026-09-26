"""Runtime topology from socket tables: who actually talks to whom, without instrumentation."""

import ipaddress
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

LISTEN, ESTABLISHED = "0A", "01"


@dataclass(frozen=True, slots=True)
class Sock:
    local: tuple[str, int]
    remote: tuple[str, int]
    state: str


def _addr(hexaddr: str) -> tuple[str, int]:
    hexip, hexport = hexaddr.rsplit(":", 1)
    raw = bytes.fromhex(hexip)
    if len(raw) == 4:
        ip = ipaddress.IPv4Address(raw[::-1])
    else:  # /proc stores IPv6 as four little-endian 32-bit words
        ip = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
    return str(ip), int(hexport, 16)


def parse_sockets(text: str) -> list[Sock]:
    """/proc/net/tcp{,6} (possibly concatenated) -> sockets. Header lines are skipped."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[1] or parts[0] == "sl":
            continue
        try:
            out.append(Sock(_addr(parts[1]), _addr(parts[2]), parts[3]))
        except ValueError:
            continue
    return out


def listeners(socks: Iterable[Sock]) -> list[tuple[str, int]]:
    return sorted({s.local for s in socks if s.state == LISTEN})


@dataclass(slots=True)
class Node:
    name: str
    ips: set[str]
    socks: list[Sock] = field(default_factory=list)
    observed: bool = True

    @property
    def ports(self) -> set[int]:
        return {p for _, p in listeners(self.socks)}


def build(nodes: Mapping[str, Node]) -> dict[str, Any]:
    """Edges A -> B:port when A has an established socket to a port B listens on; plus egress and clients."""
    owner = {ip: n.name for n in nodes.values() for ip in n.ips}
    edges: Counter[tuple[str, str, int]] = Counter()
    egress: Counter[tuple[str, str, int]] = Counter()
    clients: Counter[tuple[str, str, int]] = Counter()
    for n in nodes.values():
        mine = n.ports
        for s in n.socks:
            if s.state != ESTABLISHED:
                continue
            rip, rport = s.remote
            if ipaddress.ip_address(rip).is_loopback:
                continue
            peer = owner.get(rip)
            if peer and peer != n.name and rport in nodes[peer].ports:
                edges[(n.name, peer, rport)] += 1
            elif s.local[1] in mine:
                if not peer:
                    clients[(rip, n.name, s.local[1])] += 1
            elif not peer:
                egress[(n.name, rip, rport)] += 1
    connected = {a for a, _, _ in edges} | {b for _, b, _ in edges}
    return {
        "nodes": [{"container": n.name, "listens": sorted(n.ports), "observed": n.observed} for n in nodes.values()],
        "edges": [{"from": a, "to": b, "port": p, "connections": c} for (a, b, p), c in sorted(edges.items())],
        "egress": [{"from": a, "to": f"{ip}:{p}", "connections": c} for (a, ip, p), c in sorted(egress.items())],
        "external_clients": [{"client": ip, "to": b, "port": p, "connections": c}
                             for (ip, b, p), c in sorted(clients.items())],
        "isolated": sorted(n.name for n in nodes.values() if n.observed and n.name not in connected),
    }


def depends_on(graph: Mapping[str, Any]) -> dict[str, set[str]]:
    deps: dict[str, set[str]] = {}
    for e in graph["edges"]:
        deps.setdefault(e["from"], set()).add(e["to"])
    return deps


def mermaid(graph: Mapping[str, Any]) -> str:
    ids = {n["container"]: f"n{i}" for i, n in enumerate(graph["nodes"])}
    lines = ["graph LR"]
    for n in graph["nodes"]:
        label = n["container"] + ("" if n["observed"] else " (unobserved)")
        lines.append(f'  {ids[n["container"]]}["{label}"]')
    lines += [f'  {ids[e["from"]]} -->|{e["port"]}| {ids[e["to"]]}' for e in graph["edges"]]
    for i, e in enumerate(graph["egress"]):
        lines.append(f'  {ids[e["from"]]} -.->|egress| x{i}(("{e["to"]}"))')
    return "\n".join(lines) + "\n"
