"""HTTP traffic: pcap -> TCP streams -> HTTP/1.x exchanges, and structural response comparison."""

import base64
import fnmatch
import json
import re
import struct
from collections.abc import Iterator
from typing import Any

from .logs import template

SENSITIVE = re.compile(r"^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)$", re.I)


def body_repr(data: bytes, content_type: str, limit: int) -> dict[str, Any]:
    cut = data[:limit]
    if b"\0" in cut[:1024] and "json" not in content_type and "text" not in content_type:
        return {"b64": base64.b64encode(cut).decode(), "bytes": len(data), "truncated": len(data) > limit}
    return {"text": cut.decode(errors="replace"), "bytes": len(data), "truncated": len(data) > limit}


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: ("***" if SENSITIVE.match(k) else v) for k, v in headers.items()}


# --- pcap -------------------------------------------------------------------------------------

def packets(pcap: bytes) -> Iterator[tuple[float, bytes, int]]:
    """(timestamp, frame, linktype) for a classic pcap file (either endianness, micro or nano seconds)."""
    if len(pcap) < 24:
        return
    magic = pcap[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if endian is None:
        raise ValueError("not a pcap file (pcapng is not supported; tcpdump -w writes classic pcap)")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", pcap[20:24])[0]
    off = 24
    while off + 16 <= len(pcap):
        sec, frac, incl, _ = struct.unpack(endian + "IIII", pcap[off:off + 16])
        off += 16
        yield sec + frac / (1e9 if nano else 1e6), pcap[off:off + incl], linktype
        off += incl


def _l3(frame: bytes, linktype: int) -> tuple[int, bytes] | None:
    if linktype == 1:  # Ethernet (+ VLAN tags)
        off, etype = 14, struct.unpack(">H", frame[12:14])[0]
        while etype in (0x8100, 0x88A8):
            etype, off = struct.unpack(">H", frame[off + 2:off + 4])[0], off + 4
        return etype, frame[off:]
    if linktype == 113:  # Linux cooked v1
        return struct.unpack(">H", frame[14:16])[0], frame[16:]
    if linktype == 276:  # Linux cooked v2 (tcpdump -i any)
        return struct.unpack(">H", frame[0:2])[0], frame[20:]
    if linktype in (101, 12):  # raw IP
        return (0x0800 if frame[0] >> 4 == 4 else 0x86DD), frame
    return None


def segments(pcap: bytes) -> Iterator[tuple[float, tuple[str, int, str, int], int, int, bytes]]:
    """(ts, (src, sport, dst, dport), seq, flags, payload) for every TCP segment."""
    import ipaddress
    for ts, frame, lt in packets(pcap):
        l3 = _l3(frame, lt)
        if not l3:
            continue
        etype, ip = l3
        if etype == 0x0800 and len(ip) >= 20 and ip[9] == 6:
            ihl, total = (ip[0] & 0x0F) * 4, struct.unpack(">H", ip[2:4])[0]
            src, dst, tcp = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20])), ip[ihl:total]
        elif etype == 0x86DD and len(ip) >= 40 and ip[6] == 6:
            plen = struct.unpack(">H", ip[4:6])[0]
            src, dst, tcp = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40])), ip[40:40 + plen]
        else:
            continue
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        doff, flags = (tcp[12] >> 4) * 4, tcp[13]
        yield ts, (src, sport, dst, dport), seq, flags, tcp[doff:]


def streams(pcap: bytes) -> dict[tuple[str, int, str, int], tuple[float, bytes]]:
    """Reassemble each direction of each connection by sequence number (first-seen timestamp, bytes)."""
    parts: dict[tuple[str, int, str, int], dict[int, bytes]] = {}
    first: dict[tuple[str, int, str, int], float] = {}
    for ts, key, seq, _, payload in segments(pcap):
        if payload:
            parts.setdefault(key, {}).setdefault(seq, payload)
            first.setdefault(key, ts)
    out = {}
    for key, segs in parts.items():
        data, end = bytearray(), None
        for seq in sorted(segs, key=lambda s: (s - min(segs)) % (1 << 32)):
            payload = segs[seq]
            if end is None:
                data += payload
                end = seq + len(payload)
            elif (seq - end) % (1 << 32) < (1 << 31):  # at or beyond the current end
                data += payload
                end = seq + len(payload)
            else:  # overlap / retransmission: keep only the new tail
                overlap = (end - seq) % (1 << 32)
                if overlap < len(payload):
                    data += payload[overlap:]
                    end = seq + len(payload)
        out[key] = (first[key], bytes(data))
    return out


def parse_http(data: bytes, *, requests: bool, head_flags: list[bool] | None = None) -> list[dict[str, Any]]:
    """Split a byte stream into HTTP/1.x messages (Content-Length and chunked bodies)."""
    msgs, off, idx = [], 0, 0
    while off < len(data):
        end = data.find(b"\r\n\r\n", off)
        if end < 0:
            break
        head = data[off:end].decode("latin-1").split("\r\n")
        headers = {k.strip(): v.strip() for k, _, v in (h.partition(":") for h in head[1:])}
        lower = {k.lower(): v for k, v in headers.items()}
        off = end + 4
        body = b""
        is_head = bool(head_flags and idx < len(head_flags) and head_flags[idx])
        if "chunked" in lower.get("transfer-encoding", "").lower():
            while True:
                nl = data.find(b"\r\n", off)
                if nl < 0:
                    break
                size = int(data[off:nl].split(b";")[0] or b"0", 16)
                off = nl + 2
                if size == 0:
                    off = data.find(b"\r\n", off) + 2 if data.find(b"\r\n", off) >= 0 else len(data)
                    break
                body += data[off:off + size]
                off += size + 2
        elif not is_head and "content-length" in lower:
            n = int(lower["content-length"])
            body, off = data[off:off + n], off + n
        first = head[0].split(" ", 2)
        msg: dict[str, Any] = {"headers": headers, "body": body}
        if requests:
            msg.update(method=first[0], path=first[1] if len(first) > 1 else "/")
        else:
            msg.update(status=int(first[1]) if len(first) > 1 and first[1].isdigit() else 0)
        msgs.append(msg)
        idx += 1
    return msgs


def exchanges_from_pcap(pcap: bytes, port: int, *, max_body: int = 65536) -> list[dict[str, Any]]:
    flows = streams(pcap)
    out = []
    for key, (ts, data) in flows.items():
        src, sport, dst, dport = key
        if dport != port:
            continue
        reqs = parse_http(data, requests=True)
        _, resp_data = flows.get((dst, dport, src, sport), (ts, b""))
        resps = parse_http(resp_data, requests=False, head_flags=[r["method"] == "HEAD" for r in reqs])
        for req, resp in zip(reqs, resps + [None] * (len(reqs) - len(resps))):
            ctype = (resp or {}).get("headers", {}).get("Content-Type", "")
            out.append({"t": ts, "method": req["method"], "path": req["path"],
                        "req_headers": safe_headers(req["headers"]),
                        "req_body": body_repr(req["body"], req["headers"].get("Content-Type", ""), max_body),
                        "status": resp["status"] if resp else None,
                        "resp_headers": safe_headers(resp["headers"]) if resp else {},
                        "resp_body": body_repr(resp["body"], ctype, max_body) if resp else None, "ms": None})
    return sorted(out, key=lambda e: e["t"])


# --- comparison -------------------------------------------------------------------------------

def normalize(value: Any, ignore: list[str], path: str = "") -> Any:
    """Mask volatile values (ids, timestamps, uuids, hex) and drop ignored JSON paths (`a.*.b`)."""
    if any(fnmatch.fnmatch(path, pat) for pat in ignore):
        return "<ignored>"
    if isinstance(value, dict):
        return {k: normalize(v, ignore, f"{path}.{k}" if path else k) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v, ignore, f"{path}.{i}" if path else str(i)) for i, v in enumerate(value)]
    if isinstance(value, str):
        return template(value)
    return value


def _paths(a: Any, b: Any, path: str = "") -> Iterator[tuple[str, Any, Any]]:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(a.keys() | b.keys()):
            yield from _paths(a.get(k, "<missing>"), b.get(k, "<missing>"), f"{path}.{k}" if path else k)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            yield from _paths(x, y, f"{path}[{i}]")
    elif a != b:
        yield path or "$", a, b


def compare_bodies(a: str, b: str, ignore: list[str]) -> list[dict[str, Any]]:
    try:
        ja, jb = json.loads(a), json.loads(b)
    except ValueError:
        ta, tb = template(a), template(b)
        return [] if ta == tb else [{"path": "$", "recorded": ta[:200], "replayed": tb[:200]}]
    return [{"path": p, "recorded": x, "replayed": y}
            for p, x, y in _paths(normalize(ja, ignore), normalize(jb, ignore))][:5]
