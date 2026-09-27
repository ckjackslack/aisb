"""A small, strict YAML-subset reader (stdlib only) for docker-compose files and similar config.

Supported: block mappings and sequences (including `- key: value` items), plain/single/double-quoted scalars,
flow `[a, b]` / `{a: 1}` collections, `|` and `>` block scalars (with `-`/`+` chomping), comments, a leading
`---`. YAML 1.2 scalars: null/~, true/false, ints, floats; everything else is a string.

Not supported, and rejected with the line number instead of being misread: anchors (&), aliases (*),
merge keys (<<), tags (!), multiple documents.
"""

import re
from typing import Any

_INT = re.compile(r"[-+]?(0|[1-9][0-9_]*)$")
_FLOAT = re.compile(r"[-+]?([0-9][0-9_]*\.[0-9]*|\.[0-9]+|[0-9][0-9_]*)([eE][-+]?[0-9]+)?$")  # ASCII digits only


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
    return "".join(out).rstrip(" \t")


class _Lines:
    def __init__(self, text: str) -> None:
        # YAML 1.2 breaks lines only at \n / \r; str.splitlines() would also split at \x85, \u2028, \f...
        self.raw = re.split(r"\r\n|\r|\n", text.expandtabs(2).removesuffix("\n"))
        self.i = 0

    def next_significant(self) -> tuple[int, int, str] | None:
        """(index, indent, content) of the next non-blank, non-comment line, without consuming it."""
        j = self.i
        while j < len(self.raw):
            line = _strip_comment(self.raw[j])
            text = line.strip(" \t")
            if text == "..." or (line.startswith("---") and self._seen_content(j)):
                return None                     # end of the (first) document
            if text and not line.startswith("---"):
                return j, len(line) - len(line.lstrip(" ")), text
            j += 1
        return None

    def _seen_content(self, j: int) -> bool:
        return any(_strip_comment(r).strip(" \t") not in ("", "---") for r in self.raw[:j])


def _check(text: str, lineno: int) -> None:
    t = text.lstrip("- ")
    if t.startswith(("&", "*", "!")) or re.search(r":[ \t]+[&*!]", text) or t.startswith("<<"):
        raise YAMLError(f"line {lineno}: anchors, aliases, merge keys and tags are not supported")


def scalar(s: str, lineno: int = 0) -> Any:
    s = s.strip(" \t")
    if not s:
        return None
    if s[0] == '"':
        if not s.endswith('"') or len(s) < 2 or _unterminated(s):
            raise YAMLError(f"line {lineno}: unterminated double-quoted string")
        return _unescape(s[1:-1], lineno)
    if s[0] == "'":
        if not s.endswith("'") or len(s) < 2:
            raise YAMLError(f"line {lineno}: unterminated single-quoted string")
        return s[1:-1].replace("''", "'")
    if s[0] in "[{":
        val, rest = _flow(s, 0, lineno)
        if s[rest:].strip(" \t"):
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
    if _FLOAT.match(s) and any(c in "0123456789" for c in s):
        return float(s.replace("_", ""))
    return s


_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
            "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
            "L": "\u2028", "P": "\u2029"}
_HEX = {"x": 2, "u": 4, "U": 8}


def _unescape(body: str, lineno: int) -> str:
    """YAML double-quoted escapes (a superset of JSON's: \\x80, \\N, \\e, \\_ ...)."""
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        code = body[i + 1:i + 2]
        if code in _ESCAPES:
            out.append(_ESCAPES[code])
            i += 2
        elif code in _HEX and re.fullmatch(r"[0-9a-fA-F]+", digits := body[i + 2:i + 2 + _HEX[code]]) \
                and len(digits) == _HEX[code]:
            out.append(chr(int(digits, 16)))
            i += 2 + _HEX[code]
        else:
            raise YAMLError(f"line {lineno}: bad escape \\{code} in a double-quoted string")
    return "".join(out)


def _unterminated(s: str) -> bool:
    """True when a scalar that starts with a quote doesn't end with its (unescaped) closing quote."""
    q, i = s[0], 1
    while i < len(s):
        if q == '"' and s[i] == "\\":
            i += 2
            continue
        if s[i] == q:
            if q == "'" and s[i + 1:i + 2] == "'":
                i += 2
                continue
            return i != len(s) - 1
        i += 1
    return True


def _open_flow(s: str) -> bool:
    """True when a flow collection's brackets are not yet balanced (it continues on the next line)."""
    depth, quote, i = 0, None, 0
    while i < len(s):
        ch = s[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'" and (i == 0 or s[i - 1] in " [{,:"):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        i += 1
    return depth > 0 or quote is not None


def _fold(parts: list[str], quoted: str) -> str:
    """Join a scalar's lines the YAML way: a single break is a space, an empty line a newline, and in double
    quotes a trailing backslash joins lines without a space."""
    out = parts[0]
    blank = 0
    for part in parts[1:]:
        if not part:
            blank += 1
            continue
        if quoted == '"' and out.endswith("\\") and not out.endswith("\\\\"):
            out = out[:-1] + part
        else:
            out += "\n" * blank if blank else " " + part if out else part
            if blank:
                out += part
        blank = 0
    return out + "\n" * blank


def _continued(lines: "_Lines", first: str, indent: int) -> str:
    """`first` plus the following lines of the same scalar (more indented than `indent`), folded."""
    kind = first[:1] if first[:1] in "\"'[{" else ""
    needs_more = (lambda s: _unterminated(s)) if kind in "\"'" and kind else (lambda s: _open_flow(s)) if kind \
        else (lambda s: True)
    parts = [first]
    while lines.i < len(lines.raw) and needs_more(" ".join(parts)):
        raw = lines.raw[lines.i]
        if raw.strip(" \t") == "":
            if kind == "" and (nxt := lines.next_significant()) is not None and nxt[1] > indent:
                parts.append("")
                lines.i += 1
                continue
            if kind == "":
                break
            parts.append("")
            lines.i += 1
            continue
        ind = len(raw) - len(raw.lstrip(" "))
        if ind <= indent and not (kind in "[{" and kind and raw.strip(" \t")[:1] in "]}"):
            break
        text = raw.strip(" \t") if kind else _strip_comment(raw).strip(" \t")
        if kind == "" and (text.startswith("- ") or text == "-" or _split_key(text)[1]):
            break  # structure, not a continuation of a plain scalar
        parts.append(text)
        lines.i += 1
    return _fold(parts, kind) if kind != "[" and kind != "{" else _join_flow([p for p in parts if p])


def _join_flow(parts: list[str]) -> str:
    """Lines of a flow collection: joined by a space, except after an escaped line break (a trailing odd
    backslash inside a double-quoted scalar), which joins directly."""
    out = parts[0]
    for part in parts[1:]:
        trailing = len(out) - len(out.rstrip("\\"))
        out = out[:-1] + part if trailing % 2 else out + " " + part
    return out


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
                if quote == '"' and ch == "\\":
                    j += 2  # an escaped character, e.g. \" inside a double-quoted scalar
                    continue
                if ch == quote and quote == "'" and s[j + 1:j + 2] == "'":
                    j += 2  # '' inside a single-quoted scalar
                    continue
                quote = None if ch == quote else quote
            elif ch in "\"'" and (j == i or s[j - 1] in " [{,:"):  # quotes open only at the start of a scalar
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
        token = s[i:j].strip(" \t")
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
            return text[:end + 1], ":", text[end + 2:].strip(" \t")
        return "", "", text
    m = re.match(r"^([^ \t\[\]{},#][^#]*?)[ \t]*:([ \t]+|$)(.*)$", text)
    if not m or m.group(1).startswith(("- ", "[", "{")):
        return "", "", text
    return m.group(1), ":", m.group(3).strip(" \t")


def _block_scalar(lines: _Lines, header: str, parent_indent: int) -> str:
    style, chomp = header[0], ("-" if "-" in header else "+" if "+" in header else "")
    body: list[str] = []
    indent = None
    while lines.i < len(lines.raw):
        raw = lines.raw[lines.i]
        if raw.strip(" \t") == "":
            body.append("")
            lines.i += 1
            continue
        ind = len(raw) - len(raw.lstrip(" "))
        if ind <= parent_indent:
            break
        indent = ind if indent is None else indent
        body.append(raw[indent:] if len(raw) >= indent else raw.strip(" \t"))
        lines.i += 1
    while body and body[-1] == "" and chomp != "+":
        body.pop()
    text = "\n".join(body) if style == "|" else re.sub(r"(?<!\n)\n(?!\n)", " ", "\n".join(body))
    return text + ("" if chomp == "-" else "\n") if body else ""


def _block(lines: _Lines, indent: int) -> Any:
    nxt = lines.next_significant()
    if nxt is None:
        return None
    j, ind, content = nxt
    if content == "-" or content.startswith("- "):
        return _seq(lines, ind)
    if content[:1] in "[{":  # `{a: 1}` / `[1, 2]` as the whole (block) value, possibly over several lines
        lines.i = j + 1
        return scalar(_continued(lines, content, ind - 1), j + 1)
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
        if rest and rest[:1] not in "|>":
            rest = _continued(lines, rest, indent)
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
        item = content[1:].strip(" \t")
        if not item:
            lines.i = j + 1
            out.append(_value_after(lines, "", indent, j + 1, seq_same_indent=False))
            continue
        if item == "-" or item.startswith("- "):
            # `- - x`: a sequence nested in this item; re-indent the line so the inner `-` starts it
            col = lines.raw[j].index("-", len(lines.raw[j]) - len(lines.raw[j].lstrip(" ")) + 1)
            lines.raw[j] = " " * col + lines.raw[j][col:]
            lines.i = j
            out.append(_seq(lines, col))
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
                       if item[:1] in ("|", ">") else scalar(_continued(lines, item, indent), j + 1))
    return out


def loads(text: str) -> Any:
    lines = _Lines(text)
    value = _block(lines, 0)
    rest = lines.next_significant()
    if rest is not None:
        raise YAMLError(f"line {rest[0] + 1}: unexpected content {rest[2]!r}")
    for j in range(lines.i, len(lines.raw)):
        if lines.raw[j].startswith("---") and any(_strip_comment(r).strip(" \t") for r in lines.raw[j + 1:]):
            raise YAMLError(f"line {j + 1}: multiple documents are not supported")
    return value
