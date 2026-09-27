"""Alert destinations configured in config.toml `[notify.NAME]`: webhook, slack, ntfy, email. Stdlib only.

    [notify.ops]
    type = "slack"
    url_env = "SLACK_WEBHOOK_URL"        # secrets come from the environment, never the config file

    [notify.pager]
    type = "ntfy"
    url = "https://ntfy.sh/acme-ops"
    min_level = "failing"               # skip messages below this level

    [notify.mail]
    type = "email"
    smtp = "smtp.example.com:587"
    from = "aisb@example.com"
    to = ["oncall@example.com"]
    user = "aisb"
    password_env = "SMTP_PASSWORD"
"""

import json
import os
import smtplib
import ssl
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

from . import config

LEVELS = {"info": 0, "degraded": 1, "warning": 1, "failing": 2, "critical": 2, "down": 3}
_NTFY_PRIORITY = {0: "default", 1: "default", 2: "high", 3: "urgent"}


@dataclass(slots=True)
class Message:
    title: str
    text: str
    level: str = "info"
    data: Mapping[str, Any] = field(default_factory=dict)


class NotifyError(ValueError):
    pass


def sink(name: str) -> dict[str, Any]:
    sinks = config.load().notify
    if name not in sinks:
        raise NotifyError(f"unknown notify sink {name!r} (configured: {', '.join(sorted(sinks)) or 'none'})")
    s = dict(sinks[name])
    if s.get("type") not in ("webhook", "slack", "ntfy", "email"):
        raise NotifyError(f"notify.{name}: type must be webhook | slack | ntfy | email")
    return s


def _secret(s: Mapping[str, Any], key: str) -> str | None:
    if env := s.get(f"{key}_env"):
        val = os.environ.get(str(env))
        if not val:
            raise NotifyError(f"${env} is not set (needed by the notify sink)")
        return val
    return s.get(key)


def _post(url: str, body: bytes, headers: Mapping[str, str], timeout: float = 10) -> int:
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            return resp.status
    except OSError as e:
        raise NotifyError(f"POST {url.split('?')[0]} failed: {e}") from None


def payload(s: Mapping[str, Any], msg: Message) -> tuple[str, bytes, dict[str, str]] | EmailMessage:
    """What would be sent (also used by --dry-run)."""
    kind = s["type"]
    if kind == "email":
        em = EmailMessage()
        em["Subject"], em["From"] = f"[aisb:{msg.level}] {msg.title}", s.get("from") or "aisb@localhost"
        em["To"] = ", ".join(s.get("to") or [])
        em.set_content(msg.text + ("\n\n" + json.dumps(dict(msg.data), indent=1, default=str) if msg.data else ""))
        return em
    url = _secret(s, "url") or ""
    if not url:
        raise NotifyError(f"{kind} sink needs url or url_env")
    if kind == "slack":
        icon = {0: ":information_source:", 1: ":warning:", 2: ":rotating_light:", 3: ":red_circle:"}[LEVELS.get(msg.level, 0)]
        return url, json.dumps({"text": f"{icon} *{msg.title}*\n{msg.text}"}).encode(), {"Content-Type": "application/json"}
    if kind == "ntfy":
        return url, msg.text.encode(), {"Title": msg.title, "Priority": _NTFY_PRIORITY[LEVELS.get(msg.level, 0)],
                                        "Tags": msg.level}
    return url, json.dumps({"title": msg.title, "text": msg.text, "level": msg.level, "data": dict(msg.data)},
                           default=str).encode(), {"Content-Type": "application/json", **(s.get("headers") or {})}


def send(name: str, msg: Message) -> dict[str, Any]:
    s = sink(name)
    if LEVELS.get(msg.level, 0) < LEVELS.get(str(s.get("min_level", "info")), 0):
        return {"sink": name, "sent": False, "reason": f"below min_level {s['min_level']}"}
    p = payload(s, msg)
    if isinstance(p, EmailMessage):
        host, _, port = str(s.get("smtp") or "localhost:25").rpartition(":")
        try:
            with smtplib.SMTP(host or "localhost", int(port or 25), timeout=15) as smtp:
                if s.get("starttls", int(port or 25) != 25):
                    smtp.starttls(context=ssl.create_default_context())
                if s.get("user"):
                    smtp.login(s["user"], _secret(s, "password") or "")
                smtp.send_message(p)
        except (OSError, smtplib.SMTPException) as e:
            raise NotifyError(f"email via {s.get('smtp')} failed: {e}") from None
        return {"sink": name, "sent": True, "type": "email", "to": s.get("to")}
    url, body, headers = p
    status = _post(url, body, headers)
    return {"sink": name, "sent": True, "type": s["type"], "status": status}


def fan(names: list[str] | None, msg: Message) -> list[dict[str, Any]]:
    """Send to several sinks; one failing sink never hides the others."""
    out = []
    for n in names or []:
        try:
            out.append(send(n, msg))
        except NotifyError as e:
            out.append({"sink": n, "sent": False, "error": str(e)})
    return out
