"""Inventory sources: turn an ssh_config, `aws ec2 describe-instances` JSON, CSV or JSON into Host entries."""

import csv
import fnmatch
import io
import json
import re
from collections.abc import Iterable
from typing import Any

from .inventory import Host

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _name(s: str) -> str:
    return _SAFE.sub("-", s).strip("-.") or "host"


def ssh_config(text: str) -> list[Host]:
    """Every concrete `Host` alias (no wildcards). The alias itself is the ssh target, so ssh keeps applying
    HostName/User/Port/IdentityFile/ProxyJump from the config."""
    out = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "host":
            for alias in parts[1].split():
                if not any(c in alias for c in "*?!"):
                    out.append(Host(_name(alias), ssh=alias))
    return out


def aws(text: str, *, user: str = "ec2-user", public: bool = False, group_tag: str | None = "Role") -> list[Host]:
    """Running instances from `aws ec2 describe-instances --output json`: Name tag -> host name, private (or
    public) IP -> ssh target, tags -> labels, the `group_tag` tag value -> group."""
    data = json.loads(text)
    out = []
    for res in data.get("Reservations", []):
        for inst in res.get("Instances", []):
            if (inst.get("State") or {}).get("Name") != "running":
                continue
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags") or []}
            addr = inst.get("PublicIpAddress" if public else "PrivateIpAddress")
            if not addr:
                continue
            labels = {_SAFE.sub("_", k.lower()).strip("_"): v for k, v in tags.items() if not k.startswith("aws:")}
            labels.update(instance_id=inst["InstanceId"], az=(inst.get("Placement") or {}).get("AvailabilityZone", ""))
            groups = (_name(tags[group_tag]).lower(),) if group_tag and tags.get(group_tag) else ()
            out.append(Host(_name(tags.get("Name") or inst["InstanceId"]), ssh=f"{user}@{addr}", groups=groups,
                            labels={k: v for k, v in labels.items() if v}))
    return out


def table(text: str) -> list[Host]:
    """CSV with a header: name,ssh[,port,key,docker,groups,labels]; groups `a;b`, labels `k=v;k2=v2`."""
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        row = {k.strip(): (v or "").strip() for k, v in row.items() if k}
        if not row.get("name"):
            continue
        out.append(Host.from_dict(row["name"], {
            "ssh": row.get("ssh") or None, "port": int(row["port"]) if row.get("port") else None,
            "key": row.get("key") or None, "docker": row.get("docker") or None,
            "groups": [g for g in row.get("groups", "").split(";") if g],
            "labels": dict(kv.split("=", 1) for kv in row.get("labels", "").split(";") if "=" in kv)}))
    return out


def json_hosts(text: str) -> list[Host]:
    """An aisb inventory (`{"hosts": {...}}`) or a list of `{"name": ..., "ssh": ...}` objects."""
    data = json.loads(text)
    if isinstance(data, dict):
        return [Host.from_dict(n, d or {}) for n, d in (data.get("hosts") or {}).items()]
    return [Host.from_dict(d["name"], {k: v for k, v in d.items() if k != "name"}) for d in data]


def select(hosts: Iterable[Host], pattern: str | None) -> list[Host]:
    return [h for h in hosts if not pattern or fnmatch.fnmatchcase(h.name, pattern)]


PARSERS: dict[str, Any] = {"ssh-config": ssh_config, "aws": aws, "csv": table, "json": json_hosts}
