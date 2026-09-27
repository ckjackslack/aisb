"""Output rendering for every op: json | ndjson | table | csv | yaml | raw, plus `--pick` field projection."""

import csv
import io
import json
import re
from collections.abc import Callable
from typing import Any

from .ops import jsonable
from .util import dig

FORMATS = ("json", "ndjson", "table", "csv", "yaml", "raw")


def plain(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=jsonable))


def rows_of(data: Any) -> tuple[list[dict[str, Any]] | None, str | None]:
    """The tabular part of a result: a list of dicts, or the single list-of-dicts value inside a dict."""
    if isinstance(data, list) and data and all(isinstance(r, dict) for r in data):
        return data, None
    if isinstance(data, dict):
        lists = [k for k, v in data.items() if isinstance(v, list) and v and all(isinstance(r, dict) for r in v)]
        if len(lists) == 1:
            return data[lists[0]], lists[0]
    return None, None


def pick(data: Any, paths: str) -> Any:
    """Project dotted paths (`name,state,result.ok`) on each row, or on the object itself."""
    keys = [p.strip() for p in paths.split(",") if p.strip()]
    one = lambda r: {k: dig(r, k) for k in keys}  # noqa: E731
    rows, key = rows_of(data)
    if rows is None:
        return one(data) if isinstance(data, dict) else data
    picked = [one(r) for r in rows]
    return picked if key is None else {**data, key: picked}


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list) and not any(isinstance(x, (dict, list)) for x in v):
        return "; ".join(map(str, v))
    return json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)


def table(rows: list[dict[str, Any]]) -> str:
    keys = list(dict.fromkeys(k for r in rows for k in r))
    sample = {k: next(r[k] for r in rows if k in r) for k in keys}
    cols = [k for k, v in sample.items()
            if not isinstance(v, dict) and not (isinstance(v, list) and any(isinstance(x, (dict, list)) for x in v))]
    widths = {c: max(len(c), *(len(_cell(r.get(c))) for r in rows)) for c in cols}
    lines = ["  ".join(c.upper().ljust(widths[c]) for c in cols)]
    lines += ["  ".join(_cell(r.get(c)).ljust(widths[c]) for c in cols) for r in rows]
    return "\n".join(line.rstrip() for line in lines)


def _csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    keys = list(dict.fromkeys(k for r in rows for k in r))
    w = csv.DictWriter(buf, fieldnames=keys, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: _cell(r.get(k)) for k in keys})
    return buf.getvalue()


_PLAIN_KEY = re.compile(r"^[A-Za-z_][\w.-]*$")
_PLAIN_STR = re.compile(r"^[A-Za-z0-9_./@%+-][\w ./@%+:-]*$")


def _yscalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    s = str(v)
    reserved = s.lower() in ("true", "false", "null", "yes", "no", "on", "off", "~", "")
    looks_number = re.fullmatch(r"[-+]?(\d[\d_]*)(\.\d+)?([eE][-+]?\d+)?", s) is not None
    return s if _PLAIN_STR.match(s) and not reserved and not looks_number and not s.endswith(":") \
        and ": " not in s and " #" not in s else json.dumps(s, ensure_ascii=False)


def yaml(v: Any, indent: int = 0) -> str:
    """A small, safe YAML emitter (block style; strings quoted whenever plain style could be misread)."""
    pad = "  " * indent
    if isinstance(v, dict):
        if not v:
            return pad + "{}"
        out = []
        for k, x in v.items():
            key = k if _PLAIN_KEY.match(str(k)) else json.dumps(str(k))
            if isinstance(x, (dict, list)) and x:
                out.append(f"{pad}{key}:\n{yaml(x, indent + 1)}")
            else:
                out.append(f"{pad}{key}: {yaml(x).strip() if isinstance(x, (dict, list)) else _yscalar(x)}")
        return "\n".join(out)
    if isinstance(v, list):
        if not v:
            return pad + "[]"
        out = []
        for x in v:
            if isinstance(x, (dict, list)) and x:
                body = yaml(x, indent + 1).lstrip()
                out.append(f"{pad}- {body}")
            else:
                out.append(f"{pad}- {yaml(x).strip() if isinstance(x, (dict, list)) else _yscalar(x)}")
        return "\n".join(out)
    return pad + _yscalar(v)


def render(obj: Any, fmt: str) -> str:
    data = plain(obj)
    rows, key = rows_of(data)
    if fmt == "json":
        return json.dumps(data, ensure_ascii=False)
    if fmt == "yaml":
        return yaml(data)
    if fmt == "ndjson":
        items = rows if rows is not None else data if isinstance(data, list) else [data]
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in items)
    if fmt == "csv":
        if rows is None:
            rows = [data] if isinstance(data, dict) else [{"value": x} for x in (data if isinstance(data, list) else [data])]
        return _csv(rows).rstrip("\n")
    if fmt == "raw":
        if isinstance(data, str):
            return data.rstrip("\n")
        if isinstance(data, dict) and isinstance(data.get("output"), str):
            return data["output"].rstrip("\n")
        return json.dumps(data, indent=2, ensure_ascii=False)
    # table: the human view
    if rows is not None:
        rest = {k: v for k, v in data.items() if k != key} if key else {}
        return table(rows) + (("\n" + json.dumps(rest, ensure_ascii=False)) if rest else "")
    if isinstance(data, dict) and isinstance(data.get("output"), str):
        meta = {k: v for k, v in data.items() if k != "output"}
        return data["output"].rstrip("\n") + "\n" + json.dumps(meta)
    return json.dumps(data, indent=2, ensure_ascii=False)


Emitter = Callable[[Any], str]
