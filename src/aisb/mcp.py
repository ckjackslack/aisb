"""MCP server over stdio (newline-delimited JSON-RPC 2.0): every registry op becomes a tool.

    claude mcp add aisb -- aisb mcp                    # all tools
    claude mcp add aisb-ro -- aisb mcp --max-tier read  # read-only toolset

Mutate tools accept `dry_run`; destroy tools only execute with `confirm: true` and otherwise return
the planned API calls, so the client must go back to the user first.
"""

import json
import sys
from collections.abc import Callable
from typing import IO, Any

from . import __version__
from .errors import DockerError
from .ops import Op, Tier, invoke, jsonable, registry

PROTOCOL = "2025-06-18"
_ORDER = [Tier.READ, Tier.MUTATE, Tier.DESTROY]
INSTRUCTIONS = (
    "Docker and the services inside containers. Tool names are RESOURCE_OP. Tiers: read tools are safe; "
    "mutate tools change state (pass dry_run=true to preview); destroy tools delete state and return a plan "
    "unless confirm=true, which you may only pass after the user explicitly approved that exact action. "
    "Start diagnosis with system_doctor or containers_doctor; use svc_ready before querying a new database.")


def tool_name(o: Op) -> str:
    return f"{o.resource}_{o.name}"


def describe(o: Op) -> dict[str, Any]:
    schema = o.json_schema()
    props = dict(schema["properties"])
    if o.tier is not Tier.READ:
        props["dry_run"] = {"type": "boolean", "description": "only return the planned API calls"}
    if o.tier is Tier.DESTROY:
        props["confirm"] = {"type": "boolean",
                            "description": "execute; only after the user explicitly approved this exact action"}
    return {
        "name": tool_name(o),
        "description": f"[{o.tier}] {o.doc or o.summary}",
        "inputSchema": {**schema, "properties": props},
        "annotations": {"title": f"{o.resource} {o.name}", "readOnlyHint": o.tier is Tier.READ,
                        "destructiveHint": o.tier is Tier.DESTROY, "openWorldHint": False},
    }


class Server:
    def __init__(self, client_factory: Callable[[], Any], *, max_tier: Tier = Tier.DESTROY) -> None:
        self._factory, self._client = client_factory, None
        allowed = _ORDER[:_ORDER.index(max_tier) + 1]
        self.tools = {tool_name(o): o for ops in registry().values() for o in ops.values() if o.tier in allowed}

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._factory()
        return self._client

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        o = self.tools.get(name)
        if o is None:
            return _text({"error": f"unknown tool {name!r}"}, error=True)
        args = dict(args or {})
        dry_run, confirm = bool(args.pop("dry_run", False)), bool(args.pop("confirm", False))
        try:
            outcome = invoke(self.client, o, args, dry_run=dry_run, confirm=confirm)
        except DockerError as e:
            return _text(e.as_dict(), error=True)
        except (ValueError, TypeError) as e:
            return _text({"error": "UsageError", "message": str(e)}, error=True)
        if outcome.status == "confirm":
            return _text({"status": "confirmation_required", "planned": outcome.planned,
                          **({"warnings": outcome.warnings} if outcome.warnings else {}),
                          "hint": "Nothing was changed. Show this plan to the user; call again with confirm=true "
                                  "only after they explicitly approve."})
        return _text(outcome.payload())

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if mid is None:  # notification (e.g. notifications/initialized): no response
            return None
        if method == "initialize":
            result: Any = {"protocolVersion": params.get("protocolVersion") or PROTOCOL,
                           "capabilities": {"tools": {"listChanged": False}},
                           "serverInfo": {"name": "aisb", "version": __version__}, "instructions": INSTRUCTIONS}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [describe(o) for o in self.tools.values()]}
        elif method == "tools/call":
            result = self.call(params.get("name", ""), params.get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError as e:
                reply: dict[str, Any] | None = {"jsonrpc": "2.0", "id": None,
                                                "error": {"code": -32700, "message": f"parse error: {e}"}}
            else:
                reply = self.handle(msg) if isinstance(msg, dict) else \
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "batches are not supported"}}
            if reply is not None:
                stdout.write(json.dumps(reply, default=jsonable) + "\n")
                stdout.flush()


def _text(payload: Any, *, error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, default=jsonable, ensure_ascii=False)}],
            "isError": error}


def main(argv: list[str] | None = None) -> int:
    import argparse

    from .client import Docker
    p = argparse.ArgumentParser(prog="aisb mcp", description="MCP server over stdio")
    p.add_argument("--host", help="Docker endpoint (default: $DOCKER_HOST or local socket)")
    p.add_argument("--max-tier", choices=[t.value for t in _ORDER], default="destroy",
                   help="expose only tools up to this tier")
    args = p.parse_args(argv)
    Server(lambda: Docker(args.host, timeout=120), max_tier=Tier(args.max_tier)).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
