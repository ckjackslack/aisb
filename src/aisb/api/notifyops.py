"""`aisb notify`: send to or test the alert sinks configured in config.toml [notify.NAME]."""

from email.message import EmailMessage
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from .. import config, notify
from ..ops import Resource, Tier, op

Sink = Annotated[str, "sink name from config [notify.NAME]"]
Level = Annotated[Literal["info", "warning", "degraded", "failing", "critical", "down"], "severity"]


class NotifyOps(Resource, name="notify"):
    @op(Tier.READ, name="list")
    def ls(self) -> list[dict[str, Any]]:
        """Configured sinks (secrets never shown)."""
        return [{"sink": n, "type": s.get("type"), "min_level": s.get("min_level", "info"),
                 "target": s.get("to") if s.get("type") == "email" else
                 (urlsplit(str(s["url"])).netloc if s.get("url") else f"${s.get('url_env')}")}
                for n, s in config.load().notify.items()]

    @op(Tier.MUTATE)
    def send(self, sink: Sink, *, title: Annotated[str, "headline"], text: Annotated[str, "body"] = "",
             level: Level = "info") -> dict[str, Any]:
        """Send a message (runbooks use this for announcements). --dry-run shows what would be sent, not secrets."""
        msg = notify.Message(title, text, level)
        if self.t.planning:
            p = notify.payload(notify.sink(sink), msg)
            where = ", ".join(p.get_all("To") or []) if isinstance(p, EmailMessage) else urlsplit(p[0]).netloc
            self.t.note(notify=sink, to=where, title=title, level=level)
            return {}
        return notify.send(sink, msg)

    @op(Tier.MUTATE)
    def test(self, sink: Sink) -> dict[str, Any]:
        """Send a test message to check a sink's configuration and credentials."""
        return self.send(sink, title="aisb test message", text="If you can read this, the sink works.")
