"""Container networking: who can reach whom, and exactly where a connection breaks."""

import ipaddress
from typing import Annotated, Any

from ..errors import NotFound
from ..ops import Resource, Tier, op
from ..services import Target
from ..util import q
from .containers import Containers

Ref = Annotated[str, "container name or id"]

# Try whatever the source image has: busybox/netcat, bash's /dev/tcp, python, then wget.
_TCP = r'''H="$1"; P="$2"
if command -v nc >/dev/null 2>&1; then nc -z -w 3 "$H" "$P" && echo "OK nc" || echo "FAIL nc"
elif command -v bash >/dev/null 2>&1; then timeout 3 bash -c "</dev/tcp/$H/$P" 2>/dev/null && echo "OK bash" || echo "FAIL bash"
elif command -v python3 >/dev/null 2>&1; then python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)" "$H" "$P" 2>/dev/null && echo "OK python3" || echo "FAIL python3"
else echo "NOTOOL"; fi'''
_DNS = r'''N="$1"
if command -v getent >/dev/null 2>&1; then getent hosts "$N" | head -1 | awk '{print "IP " $1}'
elif command -v nslookup >/dev/null 2>&1; then nslookup "$N" 2>/dev/null | awk '/^Address/ && !/#/ {print "IP " $NF; exit}'
else echo "NOTOOL"; fi'''


def parse_listeners(text: str) -> list[tuple[str, int]]:
    """/proc/net/tcp{,6} -> [(ip, port)] of sockets in LISTEN (state 0A)."""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A" or ":" not in parts[1]:
            continue
        hexip, hexport = parts[1].rsplit(":", 1)
        raw = bytes.fromhex(hexip)
        if len(raw) == 4:
            ip = str(ipaddress.IPv4Address(raw[::-1]))
        elif len(raw) == 16:  # four little-endian 32-bit words
            ip = str(ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))))
        else:
            continue
        out.append((ip, int(hexport, 16)))
    return sorted(set(out))


class Net(Resource, name="net"):
    @op(Tier.READ, name="map")
    def map_(self) -> dict[str, Any]:
        """Networks with their containers, IPs and DNS aliases; flags the default bridge (no DNS by name)."""
        nets = []
        for n in self.t.json("GET", "/networks") or []:
            if n.get("Name") in ("host", "none"):
                continue
            detail = self.t.json("GET", f"/networks/{n['Id']}") or {}
            members = []
            for cid, c in (detail.get("Containers") or {}).items():
                info = self.t.json("GET", f"/containers/{cid}/json") or {}
                ep = ((info.get("NetworkSettings") or {}).get("Networks") or {}).get(n["Name"]) or {}
                members.append({"container": c.get("Name"), "ip": (c.get("IPv4Address") or "").split("/")[0],
                                "aliases": sorted(a for a in ep.get("Aliases") or [] if not cid.startswith(a))})
            nets.append({"network": n["Name"], "driver": n.get("Driver"), "internal": n.get("Internal", False),
                         "dns_by_name": n["Name"] != "bridge", "containers": sorted(members, key=lambda m: m["container"])})
        return {"networks": sorted(nets, key=lambda x: (not x["containers"], x["network"]))}

    def _find(self, dst: str, src_info: dict[str, Any]) -> dict[str, Any] | None:
        """A container by name, else by DNS alias on one of src's networks, else None (external host)."""
        try:
            return self.t.json("GET", f"/containers/{q(dst)}/json")
        except NotFound:
            pass
        for net in ((src_info.get("NetworkSettings") or {}).get("Networks") or {}):
            for cid in ((self.t.json("GET", f"/networks/{q(net)}") or {}).get("Containers") or {}):
                info = self.t.json("GET", f"/containers/{cid}/json")
                endpoint = ((info.get("NetworkSettings") or {}).get("Networks") or {}).get(net) or {}
                if dst in (endpoint.get("Aliases") or []):
                    return info
        return None

    @op(Tier.READ)
    def probe(self, src: Annotated[str, "container the connection starts from"],
              dst: Annotated[str, "container (or hostname) to reach"], *,
              port: Annotated[int | None, "destination port (default: its first exposed port)"] = None) -> dict[str, Any]:
        """Layer-by-layer check of src -> dst: shared network, dst listening (and on which address), DNS, TCP."""
        ctr = Containers(self.t)
        s = self.t.json("GET", f"/containers/{q(src)}/json")
        d = self._find(dst, s)
        steps: list[dict[str, Any]] = []
        target = Target.from_inspect(d) if d else None
        port = port or (target.exposed[0] if target and target.exposed else None)
        if port is None:
            raise ValueError(f"no --port given and {dst!r} exposes none")
        dst_name = (d.get("Name") or dst).lstrip("/") if d else dst  # container name, for exec

        if d:
            sn = set(((s.get("NetworkSettings") or {}).get("Networks") or {}))
            dn = set(((d.get("NetworkSettings") or {}).get("Networks") or {}))
            shared = sorted(sn & dn)
            only_default = shared == ["bridge"]
            steps.append({"step": "shared-network", "ok": bool(shared) and not only_default, "networks": shared,
                          "detail": "only the default bridge: no DNS by container name" if only_default else
                          None if shared else f"{src} is on {sorted(sn)}, {dst_name} on {sorted(dn)}",
                          "fix": None if shared and not only_default else
                          f"aisb networks create app-net; aisb networks connect app-net {src}; aisb networks connect app-net {dst_name}"})
            res = ctr.run_in(dst_name, ["cat", "/proc/net/tcp", "/proc/net/tcp6"])
            if "local_address" in res.stdout:  # exit 1 just means no tcp6 (IPv6 disabled)
                listeners = parse_listeners(res.stdout)
                on_port = [ip for ip, p in listeners if p == port]
                loopback_only = bool(on_port) and all(ipaddress.ip_address(ip).is_loopback for ip in on_port)
                steps.append({"step": "listening", "ok": bool(on_port) and not loopback_only,
                              "addresses": on_port or None, "all_listeners": [f"{ip}:{p}" for ip, p in listeners][:20],
                              "detail": f"{dst_name} listens on {port} on loopback only: other containers can't connect"
                              if loopback_only else None if on_port else f"nothing listens on port {port} in {dst_name}",
                              "fix": "bind the server to 0.0.0.0 (or ::)" if loopback_only else
                              None if on_port else f"check the app started: aisb containers doctor {dst_name}"})
            else:
                steps.append({"step": "listening", "ok": None, "detail": f"can't read /proc/net/tcp in {dst_name} (no cat)"})

        dns = ctr.run_in(src, ["sh", "-c", _DNS, "_", dst])  # resolve what the app would use
        if dns.code in (126, 127) or "executable file not found" in dns.stdout + dns.stderr:
            return {"src": src, "dst": dst_name, "port": port, "ok": None, "steps": steps,
                    "detail": f"{src} has no shell; run the checks from a sidecar",
                    "next": [f"aisb containers debug {src} -- nc -zv {dst_name} {port}"]}
        ip = next((line.split()[1] for line in dns.stdout.splitlines() if line.startswith("IP ")), None)
        steps.append({"step": "dns", "ok": ip is not None if "NOTOOL" not in dns.stdout else None, "resolved": ip,
                      "detail": None if ip else "no resolver tool in the source image" if "NOTOOL" in dns.stdout
                      else f"{dst!r} does not resolve from {src}"})
        tcp = ctr.run_in(src, ["sh", "-c", _TCP, "_", ip or dst, str(port)]).stdout.strip()
        steps.append({"step": "tcp", "ok": True if tcp.startswith("OK") else None if tcp == "NOTOOL" else False,
                      "via": tcp.split()[-1] if tcp and tcp != "NOTOOL" else None,
                      "detail": None if tcp.startswith("OK") else "no nc/bash/python3 in the source image"
                      if tcp == "NOTOOL" else f"connection to {ip or dst_name}:{port} failed"})
        broken = next((st for st in steps if st["ok"] is False), None)
        return {"src": src, "dst": dst_name, "port": port, "ok": broken is None and steps[-1]["ok"] is True,
                "broken_at": broken["step"] if broken else None, "steps": steps}
