"""MCP server over stdio (newline-delimited JSON-RPC 2.0): every registry op becomes a tool.

    claude mcp add aisb -- aisb mcp                    # all tools
    claude mcp add aisb-ro -- aisb mcp --max-tier read  # read-only toolset

Mutate tools accept `dry_run`; destroy tools only execute with `confirm: true` and otherwise return
the planned API calls, so the client must go back to the user first.
"""

import argparse
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
    if o.tier is not Tier.READ:
        props["ticket"] = {"type": "string", "description": "change ticket, when the operator's policy requires one"}
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
        from . import config, context
        from .policy import PolicyDenied
        args = dict(args or {})
        dry_run, confirm = bool(args.pop("dry_run", False)), bool(args.pop("confirm", False))
        ticket = args.pop("ticket", None)
        names = {p.name for p in o.params}
        args = {**{k: v for k, v in config.load().defaults_for(o.qualname).items() if k in names}, **args}
        try:
            with context.use(source="mcp", ticket=ticket):
                outcome = invoke(self.client, o, args, dry_run=dry_run, confirm=confirm)
        except PolicyDenied as e:
            return _text({**e.as_dict(), "hint": "Blocked by the operator's policy. Tell the user which rule; "
                                                  "do not try to work around it."}, error=True)
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
                           "capabilities": {"tools": {"listChanged": False},
                                            "resources": {"subscribe": False, "listChanged": False},
                                            "prompts": {"listChanged": False}},
                           "serverInfo": {"name": "aisb", "version": __version__}, "instructions": INSTRUCTIONS}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [describe(o) for o in self.tools.values()]}
        elif method == "tools/call":
            result = self.call(params.get("name", ""), params.get("arguments") or {})
        elif method == "resources/list":
            result = {"resources": [{k: v for k, v in r.items() if k != "read"} for r in resources()]}
        elif method == "resources/templates/list":
            result = {"resourceTemplates": [{"uriTemplate": "aisb://runbooks/{name}", "name": "runbook source",
                                             "mimeType": "text/plain", "description": "a runbook file by name"}]}
        elif method == "resources/read":
            try:
                result = read_resource(self.client, str(params.get("uri", "")))
            except (KeyError, ValueError, DockerError) as e:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32002, "message": str(e)}}
        elif method == "prompts/list":
            result = {"prompts": [{k: v for k, v in p.items() if k != "render"} for p in prompts()]}
        elif method == "prompts/get":
            try:
                result = get_prompt(str(params.get("name", "")), params.get("arguments") or {})
            except (KeyError, ValueError) as e:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(e)}}
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


# --- resources: read-only context an agent can load without calling tools -------------------------------

def resources() -> list[dict[str, Any]]:
    def op_reader(qualname: str, **kwargs: Any) -> Callable[[Any], Any]:
        from .ops import get_op
        return lambda client: invoke(client, get_op(qualname), kwargs).result
    return [
        {"uri": "aisb://fleet/inventory", "name": "fleet inventory", "mimeType": "application/json",
         "description": "hosts with transport, groups and labels", "read": op_reader("fleet.hosts")},
        {"uri": "aisb://fleet/status", "name": "fleet status", "mimeType": "application/json",
         "description": "per-host verdict and reasons (vitals + container triage), worst first",
         "read": op_reader("fleet.status", tail=0)},
        {"uri": "aisb://local/doctor", "name": "local triage", "mimeType": "application/json",
         "description": "every container on the local endpoint, worst first", "read": op_reader("system.doctor", tail=50)},
        {"uri": "aisb://runbooks", "name": "runbook library", "mimeType": "application/json",
         "description": "runbooks available in $AISB_RUNBOOKS", "read": op_reader("runbook.list")},
        {"uri": "aisb://runbooks/pending", "name": "pending approvals", "mimeType": "application/json",
         "description": "runs waiting for a human approval", "read": op_reader("runbook.pending")},
        {"uri": "aisb://audit/recent", "name": "recent changes", "mimeType": "application/json",
         "description": "the last 50 changes made through aisb (audit log)", "read": op_reader("audit.log", limit=50)},
        {"uri": "aisb://policy/rules", "name": "policy rules", "mimeType": "application/json",
         "description": "what the operator's policy allows and blocks", "read": op_reader("policy.rules")},
        {"uri": "aisb://config", "name": "effective config", "mimeType": "application/json",
         "description": "profile, defaults, aliases, sinks, plugins (no secrets)", "read": op_reader("config.show")},
    ]


def read_resource(client: Any, uri: str) -> dict[str, Any]:
    from . import runbooks
    if uri.startswith("aisb://runbooks/") and uri != "aisb://runbooks/pending":
        path = runbooks.find(uri.removeprefix("aisb://runbooks/"))
        return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": path.read_text()}]}
    entry = next((r for r in resources() if r["uri"] == uri), None)
    if entry is None:
        raise KeyError(f"unknown resource {uri}")
    data = entry["read"](client)
    return {"contents": [{"uri": uri, "mimeType": "application/json",
                          "text": json.dumps(data, default=jsonable, ensure_ascii=False)}]}


# --- prompts: vetted procedures an operator (or agent UI) can start from -----------------------------------

_SAFETY = ("Rules: use read tools freely; preview every change with dry_run=true and show the plan; destroy tools "
           "only with confirm=true after the user approved that exact plan; if a tool reports PolicyDenied, stop and "
           "tell the user which rule blocked it.")


def prompts() -> list[dict[str, Any]]:
    from . import runbooks
    out: list[dict[str, Any]] = [
        {"name": "investigate-incident", "description": "find the root cause of an outage, read-only",
         "arguments": [{"name": "target", "description": "fleet selector (default all)"},
                       {"name": "since", "description": "window, e.g. 30m"}],
         "render": lambda a: (
             f"Investigate an incident on {a.get('target') or 'all'} over the last {a.get('since') or '30m'}. "
             "Start with fleet_status, then fleet_doctor for the hosts that aren't healthy, then system_incident "
             "(via fleet_query) on the worst host and containers_doctor for the root-cause container. Don't change "
             "anything. Finish with: evidence (quoted), root cause, blast radius, and the exact fix commands with "
             f"their tiers. {_SAFETY}")},
        {"name": "rollout", "description": "canary-first rollout of a stack change with approval",
         "arguments": [{"name": "stack", "description": "stack file", "required": True},
                       {"name": "canary", "description": "canary selector, e.g. @canary", "required": True},
                       {"name": "rest", "description": "remaining hosts, e.g. '@web,!@canary'", "required": True}],
         "render": lambda a: (
             f"Roll out {a['stack']}: 1) fleet_diff to show what changes; 2) on {a['canary']}: fleet_replace-drifted "
             f"(dry_run first, then confirm after approval) and fleet_converge; 3) fleet_watch {a['canary']} with "
             "until_change for 5 minutes and fleet_canary against the baseline; 4) only if go and the user approves, "
             f"repeat on {a['rest']} with batch=1, fail_fast=true. {_SAFETY}")},
        {"name": "daily-check", "description": "morning health check of the fleet",
         "arguments": [],
         "render": lambda a: ("Run fleet_status (record=true), fleet_trends since 7d, and images_updates via "
                              "fleet_query on all hosts. Summarise: hosts needing attention with reasons, disks "
                              f"filling within 14 days, outdated images. Propose fixes, don't apply them. {_SAFETY}")},
    ]
    for d in runbooks.search_path():
        for p in sorted([*d.glob("*.toml"), *d.glob("*.json")]) if d.is_dir() else []:
            try:
                rb = runbooks.load(str(p))
            except ValueError:
                continue
            out.append({"name": f"runbook-{rb.name}", "description": rb.description or f"run the {rb.name} runbook",
                        "arguments": [{"name": "vars", "description": "KEY=VALUE overrides, space separated"}],
                        "render": lambda a, rb=rb, p=p: (
                            f"Run the runbook {rb.name} ({p}). First runbook_plan with var={(a.get('vars') or '').split()} "
                            "and show the plan (per-host changes, approvals, policy warnings). Only after the user "
                            "approves, runbook_run with confirm=true. If it pauses for approval, show the prompt and "
                            f"wait for the user; then runbook_approve with resume=true. {_SAFETY}")})
    return out


def get_prompt(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    p = next((x for x in prompts() if x["name"] == name), None)
    if p is None:
        raise KeyError(f"unknown prompt {name}")
    missing = [a["name"] for a in p["arguments"] if a.get("required") and not arguments.get(a["name"])]
    if missing:
        raise ValueError(f"missing argument(s): {', '.join(missing)}")
    return {"description": p["description"],
            "messages": [{"role": "user", "content": {"type": "text", "text": p["render"](arguments)}}]}


def _text(payload: Any, *, error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, default=jsonable, ensure_ascii=False)}],
            "isError": error}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aisb mcp", description="MCP server over stdio")
    p.add_argument("--host", help="Docker endpoint (default: $DOCKER_HOST or local socket)")
    p.add_argument("--max-tier", choices=[t.value for t in _ORDER], default="destroy",
                   help="expose only tools up to this tier")
    return p


def main(argv: list[str] | None = None) -> int:
    from .client import Docker
    args = parser().parse_args(argv)
    Server(lambda: Docker(args.host, timeout=120), max_tier=Tier(args.max_tier)).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
