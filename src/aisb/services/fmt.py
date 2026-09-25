"""Tabular results: type inference and rendering as JSON records, text table, markdown or CSV."""

import csv
import io
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

Format = Literal["json", "table", "markdown", "csv"]
_INT = re.compile(r"-?(?:0|[1-9]\d{0,17})")
_FLOAT = re.compile(r"-?(?:0|[1-9]\d*)\.\d+(?:[eE][-+]?\d+)?")


def infer(columns: Sequence[str], rows: list[list[Any]]) -> list[list[Any]]:
    """Convert a string column to int only when *every* non-null value is a canonical integer.

    Decimals stay strings on purpose: '2998.20' keeps its scale and money stays exact, and
    version-like text ('16.10') is never mangled into a float.
    """
    out = [list(r) for r in rows]
    for i in range(len(columns)):
        values = [r[i] for r in out if i < len(r) and r[i] is not None]
        if values and all(isinstance(v, str) and _INT.fullmatch(v) for v in values):
            for r in out:
                if i < len(r) and r[i] is not None:
                    r[i] = int(r[i])
    return out


def _cell(v: Any) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v).replace("\n", "\\n").replace("\t", "\\t")


def render(columns: Sequence[str], rows: Sequence[Sequence[Any]], fmt: Format) -> str:
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(columns)
        w.writerows(["" if v is None else v for v in r] for r in rows)
        return buf.getvalue()
    cells = [[_cell(v) for v in r] for r in rows]
    widths = [max([len(c), *(len(r[i]) for r in cells if i < len(r))]) for i, c in enumerate(columns)]
    if fmt == "markdown":
        esc = lambda s: s.replace("|", "\\|")  # noqa: E731
        lines = ["| " + " | ".join(esc(c) for c in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
        lines += ["| " + " | ".join(esc(c) for c in r) + " |" for r in cells]
        return "\n".join(lines) + "\n"
    num = lambda v: v is None or isinstance(v, (int, float)) or bool(isinstance(v, str) and (_INT.fullmatch(v) or _FLOAT.fullmatch(v)))  # noqa: E731
    numeric = [bool(rows) and all(num(r[i]) for r in rows if i < len(r)) for i in range(len(columns))]
    fit = lambda s, i: s.rjust(widths[i]) if numeric[i] else s.ljust(widths[i])  # noqa: E731
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(columns)) + " |", sep]
    lines += ["| " + " | ".join(fit(c, i) for i, c in enumerate(r)) + " |" for r in cells]
    return "\n".join([*lines, sep]) + "\n"


def records(columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> list[dict[str, Any]]:
    return [dict(zip(columns, r)) for r in rows]


def shape(columns: list[str], rows: list[list[Any]], *, fmt: Format, limit: int, out: str | None,
          meta: dict[str, Any]) -> dict[str, Any]:
    """Apply limit, then return JSON records, rendered text, or write a host file."""
    truncated = limit > 0 and len(rows) > limit
    rows = rows[:limit] if truncated else rows
    info = {**meta, "row_count": len(rows), "truncated": truncated}
    if out:
        path = Path(out).expanduser()
        kind: Format = "csv" if path.suffix == ".csv" else "markdown" if path.suffix == ".md" else \
            fmt if fmt != "table" else "csv"
        text = json.dumps(records(columns, rows), ensure_ascii=False, indent=1, default=str) + "\n" \
            if kind == "json" else render(columns, rows, kind)
        path.write_text(text)
        return {**info, "written": str(path), "format": kind, "columns": columns}
    if fmt == "json":
        return {**info, "columns": columns, "rows": records(columns, rows)}
    return {**info, "output": render(columns, rows, fmt)}
