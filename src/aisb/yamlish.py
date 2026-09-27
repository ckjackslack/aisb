"""A small, strict YAML-subset reader (stdlib only) for docker-compose files and similar config.

Supported: block mappings and sequences (including `- key: value` items), plain/single/double-quoted scalars,
flow `[a, b]` / `{a: 1}` collections, `|` and `>` block scalars (with `-`/`+` chomping), comments, a leading
`---`. YAML 1.2 scalars: null/~, true/false, ints, floats; everything else is a string.

Not supported, and rejected with the line number instead of being misread: anchors (&), aliases (*),
merge keys (<<), tags (!), multiple documents.
"""

import json
import re
from typing import Any

_INT = re.compile(r"[-+]?(0|[1-9][0-9_]*)$")
_FLOAT = re.compile(r"[-+]?(\d[\d_]*\.\d*|\.\d+|\d[\d_]*)([eE][-+]?\d+)?$")


class YAMLError(ValueError):
    pass


def _strip_comment(s: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'" and (i == 0 or s[i - 1] in " \t[{,:"):
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


class _Lines:
    def __init__(self, text: str) -> None:
        self.raw = text.expandtabs(2).splitlines()
        self.i = 0

    def next_significant(self) -> tuple[int, int, str] | None:
        """(index, indent, content) of the next non-blank, non-comment line, without consuming it."""
        j = self.i
        while j < len(self.raw):
            line = _strip_comment(self.raw[j])
            text = line.strip()
            if text == "..." or (line.startswith("---") and self._seen_content(j)):
                return None                     # end of the (first) document
            if text and not line.startswith("---"):
                return j, len(line) - len(line.lstrip(" ")), text
            j += 1
        return None

    def _seen_content(self, j: int) -> bool:
        return any(_strip_comment(r).strip() not in ("", "---") for r in self.raw[:j])


def _check(text: str, lineno: int) -> None:
    t = text.lstrip("- ")
    if t.startswith(("&", "*", "!")) or re.search(r":\s+[&*!]", text) or t.startswith("<<"):
        raise YAMLError(f"line {lineno}: anchors, aliases, merge keys and tags are not supported")


def scalar(s: str, lineno: int = 0) -> Any:
    s = s.strip()
    if not s:
        return None
    if s[0] == '"':
        if not s.endswith('"') or len(s) < 2:
            raise YAMLError(f"line {lineno}: unterminated double-quoted string")
        try:
            return json.loads(s.replace("\\/", "/"))
        except ValueError as e:
            raise YAMLError(f"line {lineno}: bad escape in {s}: {e}") from None
    if s[0] == "'":
        if not s.endswith("'") or len(s) < 2:
            raise YAMLError(f"line {lineno}: unterminated single-quoted string")
        return s[1:-1].replace("''", "'")
    if s[0] in "[{":
        val, rest = _flow(s, 0, lineno)
        if s[rest:].strip():
            raise YAMLError(f"line {lineno}: unexpected text after flow collection: {s[rest:]!r}")
        return val
    if s in ("null", "Null", "NULL", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if _INT.match(s):
        return int(s.replace("_", ""))
    if _FLOAT.match(s) and any(c.isdigit() for c in s):
        return float(s.replace("_", ""))
    return s


def _flow(s: str, i: int, lineno: int) -> tuple[Any, int]:
    """Parse a flow collection starting at s[i] ('[' or '{'); returns (value, index after it)."""
    open_, close = s[i], "]" if s[i] == "[" else "}"
    items: list[Any] = []
    obj: dict[Any, Any] = {}
    i += 1
    while True:
        while i < len(s) and s[i] in " ,":
            i += 1
        if i >= len(s):
            raise YAMLError(f"line {lineno}: unterminated flow collection")
        if s[i] == close:
            return (items if open_ == "[" else obj), i + 1
        if s[i] in "[{":
            val, i = _flow(s, i, lineno)
            items.append(val)
            continue
        j, depth, quote = i, 0, None
        while j < len(s):
            ch = s[j]
            if quote:
                quote = None if ch == quote else quote
            elif ch in "\"'":
                quote = ch
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                break
            j += 1
        token = s[i:j].strip()
        if open_ == "{":
            k, sep, v = _split_key(token)
            if not sep:
                raise YAMLError(f"line {lineno}: expected key: value in {{...}}, got {token!r}")
            obj[scalar(k, lineno)] = scalar(v, lineno)
        else:
            items.append(scalar(token, lineno))
        i = j


def _split_key(text: str) -> tuple[str, str, str]:
    """`key: value` -> (key, ':', value), honouring quoted keys; ('', '', text) when it isn't a mapping entry."""
    if text[:1] in "\"'":
        q = text[0]
        end = text.find(q, 1)
        while end != -1 and q == "'" and text[end:end + 2] == "''":
            end = text.find(q, end + 2)
        if end != -1 and text[end + 1:end + 2] == ":" and (end + 2 == len(text) or text[end + 2] == " "):
            return text[:end + 1], ":", text[end + 2:].strip()
        return "", "", text
    m = re.match(r"^([^\s\[\]{},#][^#]*?)\s*:(\s+|$)(.*)$", text)
    if not m or m.group(1).startswith(("- ", "[", "{")):
        return "", "", text
    return m.group(1), ":", m.group(3).strip()


def _block_scalar(lines: _Lines, header: str, parent_indent: int) -> str:
    style, chomp = header[0], ("-" if "-" in header else "+" if "+" in header else "")
    body: list[str] = []
    indent = None
    while lines.i < len(lines.raw):
        raw = lines.raw[lines.i]
        if raw.strip() == "":
            body.append("")
            lines.i += 1
            continue
        ind = len(raw) - len(raw.lstrip(" "))
        if ind <= parent_indent:
            break
        indent = ind if indent is None else indent
        body.append(raw[indent:] if len(raw) >= indent else raw.strip())
        lines.i += 1
    while body and body[-1] == "" and chomp != "+":
        body.pop()
    text = "\n".join(body) if style == "|" else re.sub(r"(?<!\n)\n(?!\n)", " ", "\n".join(body))
    return text + ("" if chomp == "-" else "\n") if body else ""


def _block(lines: _Lines, indent: int) -> Any:
    nxt = lines.next_significant()
    if nxt is None:
        return None
    _, ind, content = nxt
    if content == "-" or content.startswith("- "):
        return _seq(lines, ind)
    return _map(lines, ind)


def _value_after(lines: _Lines, rest: str, indent: int, lineno: int, *, seq_same_indent: bool) -> Any:
    if rest[:1] in ("|", ">") and re.fullmatch(r"[|>][-+]?\d?", rest):
        return _block_scalar(lines, rest, indent)
    if rest:
        return scalar(rest, lineno)
    nxt = lines.next_significant()
    if nxt is None:
        return None
    _, ind, content = nxt
    if ind > indent or (seq_same_indent and ind == indent and (content == "-" or content.startswith("- "))):
        return _block(lines, ind)
    return None


def _map(lines: _Lines, indent: int) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    while (nxt := lines.next_significant()) is not None:
        j, ind, content = nxt
        if ind < indent or (ind == indent and (content == "-" or content.startswith("- "))):
            break
        if ind > indent:
            raise YAMLError(f"line {j + 1}: unexpected indentation")
        _check(content, j + 1)
        key, sep, rest = _split_key(content)
        if not sep:
            raise YAMLError(f"line {j + 1}: expected `key: value`, got {content!r}")
        k = scalar(key, j + 1)
        if k in out:
            raise YAMLError(f"line {j + 1}: duplicate key {k!r}")
        lines.i = j + 1
        out[k] = _value_after(lines, rest, indent, j + 1, seq_same_indent=True)
    return out


def _seq(lines: _Lines, indent: int) -> list[Any]:
    out: list[Any] = []
    while (nxt := lines.next_significant()) is not None:
        j, ind, content = nxt
        if ind != indent or not (content == "-" or content.startswith("- ")):
            if ind > indent:
                raise YAMLError(f"line {j + 1}: unexpected indentation")
            break
        _check(content, j + 1)
        item = content[1:].strip()
        if not item:
            lines.i = j + 1
            out.append(_value_after(lines, "", indent, j + 1, seq_same_indent=False))
            continue
        key, sep, _ = _split_key(item)
        if sep and item[:1] not in "[{":
            # `- key: value` starts a mapping whose keys align with `key`: re-indent this line and parse a mapping
            col = lines.raw[j].index(item[0], len(lines.raw[j]) - len(lines.raw[j].lstrip(" ")) + 1)
            lines.raw[j] = " " * col + lines.raw[j][col:]
            lines.i = j
            out.append(_map(lines, col))
        else:
            lines.i = j + 1
            out.append(_value_after(lines, item, indent, j + 1, seq_same_indent=False)
                       if item[:1] in ("|", ">") else scalar(item, j + 1))
    return out


def loads(text: str) -> Any:
    lines = _Lines(text)
    value = _block(lines, 0)
    rest = lines.next_significant()
    if rest is not None:
        raise YAMLError(f"line {rest[0] + 1}: unexpected content {rest[2]!r}")
    for j in range(lines.i, len(lines.raw)):
        if lines.raw[j].startswith("---") and any(_strip_comment(r).strip() for r in lines.raw[j + 1:]):
            raise YAMLError(f"line {j + 1}: multiple documents are not supported")
    return value
