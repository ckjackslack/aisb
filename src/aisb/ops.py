"""Operation registry: one declaration drives CLI, JSON schemas, docs, and tier enforcement."""

import dataclasses
import inspect
import types
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Protocol, Union, get_args, get_origin, get_type_hints

from .transport import Transport
from .util import kv

EMPTY = inspect.Parameter.empty
_P = inspect.Parameter


class Tier(StrEnum):
    READ = "read"          # never changes state; always runs
    MUTATE = "mutate"      # changes state; supports --dry-run
    DESTROY = "destroy"    # deletes state; previews unless confirmed


@dataclass(frozen=True, slots=True)
class Param:
    name: str
    kind: inspect._ParameterKind
    type: type
    default: Any = EMPTY
    help: str = ""
    many: bool = False
    mapping: bool = False
    choices: tuple[Any, ...] | None = None

    @property
    def variadic(self) -> bool:
        return self.kind is _P.VAR_POSITIONAL

    @property
    def positional(self) -> bool:
        return self.kind in (_P.POSITIONAL_ONLY, _P.POSITIONAL_OR_KEYWORD)

    @property
    def required(self) -> bool:
        return self.default is EMPTY and not self.variadic

    @classmethod
    def of(cls, p: inspect.Parameter, hint: Any) -> "Param":
        help_ = ""
        if get_origin(hint) is Annotated:
            hint, *meta = get_args(hint)
            help_ = next((m for m in meta if isinstance(m, str)), "")
        if get_origin(hint) in (Union, types.UnionType):
            args = [a for a in get_args(hint) if a is not type(None)]
            hint = args[0] if len(args) == 1 else str
        origin, many, mapping, choices = get_origin(hint), False, False, None
        if origin is Literal:
            choices = get_args(hint)
            hint = type(choices[0])
        elif origin in (list, tuple):
            many, hint = True, get_args(hint)[0]
        elif origin is dict:
            mapping, hint = True, str
        return cls(p.name, p.kind, hint, p.default, help_, many, mapping, choices)

    def coerce(self, value: Any) -> Any:
        if self.mapping and value is not None:
            return kv(value)
        return value

    def schema(self) -> dict[str, Any]:
        scalar = {str: "string", int: "integer", float: "number", bool: "boolean"}.get(self.type, "string")
        s: dict[str, Any] = {"type": scalar}
        if self.choices:
            s["enum"] = list(self.choices)
        if self.many or self.variadic:
            s = {"type": "array", "items": s}
        elif self.mapping:
            s = {"type": "object", "additionalProperties": {"type": "string"}}
        if self.help:
            s["description"] = self.help
        if self.default not in (EMPTY, None):
            s["default"] = self.default
        return s


@dataclass(frozen=True, slots=True)
class Op:
    resource: str
    name: str
    tier: Tier
    func: Callable[..., Any]
    params: tuple[Param, ...]
    doc: str = ""

    @property
    def qualname(self) -> str:
        return f"{self.resource}.{self.name}"

    @property
    def summary(self) -> str:
        return self.doc.strip().splitlines()[0] if self.doc.strip() else ""

    @classmethod
    def build(cls, resource: str, func: Callable[..., Any], tier: Tier, name: str | None) -> "Op":
        hints = get_type_hints(func, include_extras=True)
        params = tuple(Param.of(p, hints.get(p.name, str)) for p in list(inspect.signature(func).parameters.values())[1:])
        return cls(resource, name or func.__name__, tier, func, params, inspect.getdoc(func) or "")

    def call(self, client: "HasResources", kwargs: Mapping[str, Any]) -> Any:
        if unknown := set(kwargs) - {p.name for p in self.params}:
            raise ValueError(f"unknown argument(s) for {self.qualname}: {sorted(unknown)}")
        args: list[Any] = []
        kw: dict[str, Any] = {}
        for p in self.params:
            if p.variadic:
                args.extend(kwargs.get(p.name) or ())
                continue
            if p.name in kwargs:
                value = p.coerce(kwargs[p.name])
            elif p.required:
                raise ValueError(f"missing argument for {self.qualname}: {p.name}")
            else:
                value = p.default
            if p.positional:
                args.append(value)
            else:
                kw[p.name] = value
        return self.func(client.resource(self.resource), *args, **kw)

    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {p.name: p.schema() for p in self.params},
            "required": [p.name for p in self.params if p.required],
            "additionalProperties": False,
        }


_REGISTRY: dict[str, dict[str, Op]] = {}


def op(tier: Tier, *, name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark a Resource method as a registered operation."""
    def mark(func: Callable[..., Any]) -> Callable[..., Any]:
        func.__aisb_op__ = (tier, name)  # type: ignore[attr-defined]
        return func
    return mark


class Resource:
    name: ClassVar[str]

    def __init__(self, transport: Transport) -> None:
        self.t = transport

    def __init_subclass__(cls, *, name: str, **kw: Any) -> None:
        super().__init_subclass__(**kw)
        cls.name = name
        ops = _REGISTRY.setdefault(name, {})
        for func in vars(cls).values():
            if meta := getattr(func, "__aisb_op__", None):
                built = Op.build(name, func, *meta)
                ops[built.name] = built


class HasResources(Protocol):
    transport: Transport

    def resource(self, name: str) -> Resource: ...


def registry() -> dict[str, dict[str, Op]]:
    from .api import ORDER  # importing the package registers every resource
    return {name: _REGISTRY[name] for name in ORDER}


def get_op(qualname: str) -> Op:
    resource, _, name = qualname.partition(".")
    try:
        return registry()[resource][name]
    except KeyError:
        raise ValueError(f"unknown operation: {qualname}") from None


@dataclass(slots=True)
class Outcome:
    status: Literal["ok", "dry-run", "confirm"]
    result: Any = None
    planned: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def payload(self) -> Any:
        if self.status == "ok":
            return self.result
        return {"status": self.status, "planned": self.planned, **({"warnings": self.warnings} if self.warnings else {})}


Hook = Callable[["HasResources", Op, Mapping[str, Any]], None]
HOOKS: list[Hook] = []


def invoke(client: HasResources, op_: Op, kwargs: Mapping[str, Any], *,
           dry_run: bool = False, confirm: bool = False) -> Outcome:
    """Run an op under its tier policy: DESTROY without confirm degrades to a preview."""
    preview = op_.tier is not Tier.READ and (dry_run or (op_.tier is Tier.DESTROY and not confirm))
    if not preview:
        if op_.tier is not Tier.READ:
            for hook in HOOKS:  # e.g. session capture: record how to undo before the change happens
                hook(client, op_, kwargs)
        return Outcome("ok", op_.call(client, kwargs))
    with client.transport.dry_run() as planned:
        result = op_.call(client, kwargs)
    warnings = list(result.get("warnings") or []) if isinstance(result, Mapping) else []
    return Outcome("dry-run" if dry_run else "confirm", planned=[r.preview() for r in planned], warnings=warnings)


def jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode(errors="replace")
    if isinstance(obj, (set, frozenset, tuple)):
        return list(obj)
    return str(obj)


def usage(op_: Op) -> str:
    parts = [f"aisb {op_.resource} {op_.name}"]
    for p in op_.params:
        flag, meta = "--" + p.name.replace("_", "-"), p.name.upper()
        if p.variadic:
            parts.append(f"[-- {meta}...]")
        elif p.positional:
            parts.append(meta if p.required else f"[{meta}]")
        elif p.type is bool:
            parts.append(f"[--no-{p.name.replace('_', '-')}]" if p.default else f"[{flag}]")
        elif p.many or p.mapping:
            parts.append(f"[{flag} {meta}]...")
        else:
            parts.append(f"[{flag} {meta}]")
    if op_.tier is not Tier.READ:
        parts.append("[--dry-run]")
    if op_.tier is Tier.DESTROY:
        parts.append("[--yes]")
    return " ".join(parts)


def render_markdown() -> str:
    lines = [
        "# aisb command reference",
        "",
        "_Generated by `aisb docs` from the operation registry; do not edit by hand._",
        "",
        "Tiers: **read** runs freely; **mutate** supports `--dry-run`; "
        "**destroy** previews and exits 3 unless `--yes` (only after explicit user approval).",
        "Run `aisb RESOURCE OP --help` for per-flag help.",
    ]
    for resource, ops in registry().items():
        lines += ["", f"## {resource}", "", "| op | tier | usage | summary |", "|---|---|---|---|"]
        for o in ops.values():
            lines.append(f"| {o.name} | {o.tier} | `{usage(o)}` | {o.summary} |")
    return "\n".join(lines) + "\n"
