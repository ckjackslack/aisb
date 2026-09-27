"""Property-based tests (Hypothesis): the parsers, matchers and encoders the safety story rests on, checked
against independent models or round trips instead of hand-picked examples."""

import datetime as dt
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from aisb import audit, policy, redact, yamlish  # noqa: E402
from aisb.context import Ctx  # noqa: E402
from aisb.fleet.inventory import Host, Inventory  # noqa: E402
from aisb.insights.vulns import cvss3  # noqa: E402
from aisb.services.sql import lit, mysql_client_command  # noqa: E402
from test_services_more import mysql_unquote  # noqa: E402

# AISB_PROPERTY_EXAMPLES=5000 for a deep local run; CI uses the default
SETTINGS = settings(max_examples=int(os.environ.get("AISB_PROPERTY_EXAMPLES", "300")), deadline=None,
                    suppress_health_check=[HealthCheck.too_slow])
TEXT = st.text(st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=40)


# --- fleet selectors against a set-algebra model -------------------------------------------------------------

HOSTS = [f"h{i}" for i in range(6)]
GROUPS = ["g0", "g1", "g2"]


@st.composite
def fleets(draw: Any) -> Inventory:
    groups = {h: draw(st.lists(st.sampled_from(GROUPS), unique=True, max_size=2)) for h in HOSTS}
    for i, g in enumerate(GROUPS):  # every group has at least one member, so "@g" is never an unknown group
        groups[HOSTS[i]] = sorted({*groups[HOSTS[i]], g})
    region = {h: draw(st.sampled_from(["eu", "us"])) for h in HOSTS}
    return Inventory({h: Host(h, groups=tuple(groups[h]), labels={"r": region[h]}) for h in HOSTS})


ATOMS = st.sampled_from([*HOSTS, *(f"@{g}" for g in GROUPS), "r=eu", "r=us", "all", "h[0-2]", "h*"])
OPS = st.sampled_from([",", "&", "!", "&!"])


def model(inv: Inventory, terms: list[tuple[str, str]]) -> set[str]:
    def atom(a: str) -> set[str]:
        if a in ("all", "h*"):
            return set(HOSTS)
        if a == "h[0-2]":
            return {"h0", "h1", "h2"}
        if a.startswith("@"):
            return {n for n, h in inv.hosts.items() if a[1:] in h.groups}
        if "=" in a:
            k, v = a.split("=")
            return {n for n, h in inv.hosts.items() if h.labels.get(k) == v}
        return {a}
    plain = [a for op, a in terms if op in ("", ",")]
    chosen = set().union(*(atom(a) for a in plain)) if plain else set(HOSTS)
    for op, a in terms:
        if op == "&":
            chosen &= atom(a)
        elif op in ("!", "&!"):
            chosen -= atom(a)
    return chosen


@SETTINGS
@given(fleets(), ATOMS, st.lists(st.tuples(OPS, ATOMS), max_size=4), st.booleans())
def test_selectors_agree_with_set_algebra(inv, first, rest, spaced):
    terms = [("", first), *rest]
    expr = ("" if not spaced else " ").join(op + a for op, a in terms)
    want = model(inv, terms)
    if not want:
        with pytest.raises(ValueError, match="selects no hosts"):
            inv.select(expr)
    else:
        assert {h.name for h in inv.select(expr)} == want


# --- policy time windows --------------------------------------------------------------------------------------

DAY = dt.datetime(2026, 9, 28, tzinfo=dt.UTC)  # a Monday
MINUTES = [DAY + dt.timedelta(minutes=m) for m in range(0, 24 * 60, 7)]


@SETTINGS
@given(st.integers(0, 23), st.integers(0, 24))
def test_a_window_and_its_complement_partition_the_day(a, b):
    assume(a != b % 24)
    for now in MINUTES:
        inside = policy.in_window({"hours": f"{a:02d}-{b:02d}"}, now)
        outside = policy.in_window({"hours": f"{b % 24:02d}-{a:02d}"}, now)
        assert inside != outside, now


@SETTINGS
@given(st.integers(0, 23), st.integers(1, 24))
def test_a_window_contains_exactly_its_hours(a, b):
    assume(a < b)
    minutes = sum(policy.in_window({"hours": f"{a}-{b}"}, DAY + dt.timedelta(minutes=m)) for m in range(24 * 60))
    assert minutes == (b - a) * 60


@SETTINGS
@given(st.sampled_from(policy.DAYS), st.integers(0, 6))
def test_day_lists_select_only_their_days(day, offset):
    now = DAY + dt.timedelta(days=offset, hours=12)
    assert policy.in_window({"days": [day]}, now) is (policy.DAYS[now.weekday()] == day)


# --- SQL string literals and the mysql client-command scanner ------------------------------------------------

@SETTINGS
@given(TEXT)
def test_standard_sql_literal_round_trips(value):
    conn = sqlite3.connect(":memory:")  # standard quoting, as PostgreSQL uses with standard_conforming_strings
    assert conn.execute(f"select {lit(value)}").fetchone() == (value,)


@SETTINGS
@given(TEXT, TEXT.filter(lambda s: not s.startswith("'")))  # '' then ' is ambiguous without a separator
def test_mysql_literal_round_trips_and_ends_where_it_should(value, tail):
    assert mysql_unquote(lit(value, backslash=True) + tail) == (value, tail)


@SETTINGS
@given(TEXT, st.sampled_from(["SELECT {} AS x", "SELECT * FROM t WHERE a = {}", "SELECT {}, {} FROM t"]))
def test_literals_never_look_like_client_commands(value, template):
    sql = template.format(*[lit(value, backslash=True)] * template.count("{}"))
    assert mysql_client_command(sql) is None


@SETTINGS
@given(st.text(st.sampled_from("abcdefgh xyz0123=*,()"), max_size=30),
       st.sampled_from(["\\! sh", "system id", "\\. /tmp/x.sql", "tee /tmp/o", "source /tmp/x.sql", "\\T /tmp/o",
                        "connect other", "resetconnection"]),
       st.sampled_from([";\n", ";\n  ", ";"]))
def test_client_commands_after_a_statement_are_always_found(prefix, command, sep):
    sql = f"SELECT {prefix or 1}{sep}{command}"
    assert mysql_client_command(sql) is not None, sql  # mysql 8.4 runs long forms after `;` on the same line too


# --- yamlish against PyYAML ------------------------------------------------------------------------------------

yaml = pytest.importorskip("yaml")
KEYS = st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True)
# \x85 is a line break in YAML 1.1 (PyYAML, the reference here) but not in YAML 1.2 (yamlish, compose)
PLAIN_TEXT = st.text(st.characters(min_codepoint=32, max_codepoint=0x2FF, blacklist_characters="\x7f\x85"), max_size=120)
SCALARS = st.none() | st.booleans() | st.integers(-10**12, 10**12) | \
    st.floats(allow_nan=False, allow_infinity=False, width=64) | PLAIN_TEXT
DOCS = st.recursive(SCALARS, lambda inner: st.lists(inner, max_size=4) | st.dictionaries(KEYS, inner, max_size=4),
                    max_leaves=20)


def _yaml11_only_string(value: Any) -> bool:
    """`1e5` is a float in YAML 1.2 (yamlish, compose) but a string in 1.1, so PyYAML writes it unquoted."""
    if isinstance(value, dict):
        return any(_yaml11_only_string(v) for v in value.values())
    if isinstance(value, list):
        return any(_yaml11_only_string(v) for v in value)
    return isinstance(value, str) and re.fullmatch(r"[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+", value) is not None


@SETTINGS
@given(st.dictionaries(KEYS, DOCS, min_size=1, max_size=5), st.booleans())
def test_yamlish_reads_what_pyyaml_writes(doc, flow):
    assume(not _yaml11_only_string(doc))
    text = yaml.safe_dump(doc, default_flow_style=flow, sort_keys=False, allow_unicode=True)
    assert yamlish.loads(text) == yaml.safe_load(text) == doc


# --- the audit chain detects every edit but the dropped tail ----------------------------------------------------

@SETTINGS
@given(st.lists(st.dictionaries(KEYS, st.integers() | PLAIN_TEXT, max_size=3), min_size=2, max_size=6),
       st.data())
def test_audit_chain_detects_tampering(argsets, data):
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "audit.jsonl"
        os.environ["AISB_AUDIT"] = str(log)
        try:
            for i, args in enumerate(argsets):
                audit.record(op=f"containers.op{i}", tier="mutate", args=args, ctx=Ctx("alice"), endpoint=None,
                             ok=True, error=None, ms=i)
            assert audit.verify(log)["ok"] is True
            lines = log.read_text().splitlines()
            kind = data.draw(st.sampled_from(["edit", "delete", "swap"]))
            i = data.draw(st.integers(0, len(lines) - 1 if kind == "edit" else len(lines) - 2))
            if kind == "edit":
                rec = json.loads(lines[i])
                rec[data.draw(st.sampled_from(["op", "ok", "ms", "user", "args"]))] = "tampered"
                lines[i] = json.dumps(rec)
            elif kind == "delete":
                del lines[i]
            else:
                j = data.draw(st.integers(i + 1, len(lines) - 1))
                lines[i], lines[j] = lines[j], lines[i]
            log.write_text("\n".join(lines) + "\n")
            assert audit.verify(log)["ok"] is False
        finally:
            del os.environ["AISB_AUDIT"]


# --- redaction never lets a flagged secret through ---------------------------------------------------------------

SECRET_FLAGS = st.sampled_from(["--password", "--requirepass", "--api-key", "--db-token", "--client-secret"])


@SETTINGS
@given(SECRET_FLAGS, st.text(min_size=1, max_size=30).filter(lambda s: not s.startswith("-")), st.booleans(),
       st.lists(st.sampled_from(["serve", "--port", "80", "-v"]), max_size=3))
def test_secret_flag_values_are_always_replaced(flag, secret, joined, around):
    argv = [*around, f"{flag}={secret}"] if joined else [*around, flag, secret]
    masked, names = redact.args(argv)
    name = f"arg:{flag}"
    assert name in names
    assert masked[-1] == (f"{flag}={redact.placeholder(name)}" if joined else redact.placeholder(name))
    assert redact.fill(masked[-1], {name: secret})[0] == argv[-1]


# --- CVSS ------------------------------------------------------------------------------------------------------

@SETTINGS
@given(*(st.sampled_from(v) for v in (["N", "A", "L", "P"], ["L", "H"], ["N", "L", "H"], ["N", "R"], ["U", "C"],
                                      ["N", "L", "H"], ["N", "L", "H"], ["N", "L", "H"])))
def test_cvss3_scores_are_bounded_rounded_and_monotone_in_impact(av, ac, pr, ui, s, c, i, a):
    vec = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    score = cvss3(vec)
    assert score is not None and 0.0 <= score <= 10.0 and round(score, 1) == score
    if c != "H":  # raising confidentiality impact never lowers the score
        worse = cvss3(vec.replace(f"/C:{c}/", "/C:H/"))
        assert worse is not None and worse >= score
