"""Pure logic behind the killer features: no daemon, no containers."""

import sqlite3
import struct
import tarfile
from typing import Any

import pytest

from aisb.insights import envcontract as env
from aisb.insights import graph, incident, packages, rightsize as rs, traffic
from aisb.rootfs import relative
from aisb.services import advise, seed, subset
from aisb.services.sql import SQL, Relations, Result


# --- graph -------------------------------------------------------------------------------------

def _hex4(ip: str, port: int) -> str:
    return bytes(map(int, ip.split(".")))[::-1].hex().upper() + f":{port:04X}"


def _tcp(*rows: tuple[str, int, str, int, str]) -> str:
    head = "  sl  local_address rem_address   st\n"
    return head + "".join(f"   {i}: {_hex4(a, p)} {_hex4(b, q)} {st} 0\n" for i, (a, p, b, q, st) in enumerate(rows))


def test_parse_sockets_ipv4_and_v4_mapped_v6():
    v6 = "   0: 0000000000000000FFFF00000200000A:18EB 0000000000000000FFFF00000300000A:C000 01 0\n"
    socks = graph.parse_sockets(_tcp(("0.0.0.0", 6379, "0.0.0.0", 0, "0A")) + v6)
    assert socks[0].local == ("0.0.0.0", 6379) and socks[0].state == graph.LISTEN
    assert (socks[1].local, socks[1].remote) == (("10.0.0.2", 6379), ("10.0.0.3", 49152))


def test_build_edges_egress_and_isolated():
    nodes = {
        "cache": graph.Node("cache", {"10.0.0.2"}, graph.parse_sockets(_tcp(
            ("0.0.0.0", 6379, "0.0.0.0", 0, "0A"), ("10.0.0.2", 6379, "10.0.0.3", 40000, "01")))),
        "api": graph.Node("api", {"10.0.0.3"}, graph.parse_sockets(_tcp(
            ("0.0.0.0", 8080, "0.0.0.0", 0, "0A"), ("10.0.0.3", 40000, "10.0.0.2", 6379, "01"),
            ("10.0.0.3", 40001, "1.1.1.1", 443, "01"), ("10.0.0.3", 8080, "172.17.0.1", 50000, "01")))),
        "lonely": graph.Node("lonely", {"10.0.0.9"}, []),
    }
    g = graph.build(nodes)
    assert g["edges"] == [{"from": "api", "to": "cache", "port": 6379, "connections": 1}]
    assert g["egress"] == [{"from": "api", "to": "1.1.1.1:443", "connections": 1}]
    assert g["external_clients"][0]["client"] == "172.17.0.1"
    assert g["isolated"] == ["lonely"]
    assert graph.depends_on(g) == {"api": {"cache"}}
    assert "-->|6379|" in graph.mermaid(g)


# --- incident ----------------------------------------------------------------------------------

def _sig(t: float, c: str, sev: str = "critical") -> incident.Signal:
    return incident.Signal(t, c, "event", sev, f"{c} died")  # type: ignore[arg-type]


def test_root_is_the_upstream_that_failed_first():
    r = incident.analyze([_sig(3, "web"), _sig(1, "cache"), _sig(2, "api")],
                         {"web": {"api"}, "api": {"cache"}}, likely_causes={"cache": "oom"})
    assert r["root_cause"]["container"] == "cache" and r["root_cause"]["likely_cause"] == "oom"
    assert r["chain"] == ["cache", "api", "web"] and r["evidence"] == "traffic"


def test_independent_failure_is_not_blamed_on_topology():
    r = incident.analyze([_sig(1, "cache"), _sig(2, "batch")], {"api": {"cache"}})
    assert r["root_cause"]["container"] == "cache"
    assert r["blast_radius"] == [] and r["other_roots"] == ["batch"]


def test_without_topology_only_earliest_is_root_and_postmortem_renders():
    r = incident.analyze([_sig(5, "b"), _sig(4, "a"), _sig(6, "c", "warning")], {})
    assert (r["root_cause"]["container"], r["evidence"], r["blast_radius"]) == ("a", "temporal", ["b"])
    md = incident.postmortem(r, window="10m", next_steps=["aisb containers doctor a"])
    assert md.startswith("# Incident report (10m)") and "`a`" in md


def test_no_failures():
    r = incident.analyze([_sig(1, "x", "warning")], {})
    assert r["root_cause"] is None and "degraded: x" in r["summary"]


# --- env contract ------------------------------------------------------------------------------

@pytest.mark.parametrize(("line", "var", "need"), [
    ('os.environ["DB_URL"]', "DB_URL", "required"),
    ('os.getenv("DEBUG", "0")', "DEBUG", "optional"),
    ("os.environ.get('TOKEN')", "TOKEN", "used"),
    ("const x = process.env.API_KEY;", "API_KEY", "used"),
    ('v := os.Getenv("PORT")', "PORT", "used"),
    ("ENV.fetch('SECRET_KEY_BASE')", "SECRET_KEY_BASE", "required"),
    ('exec app --jwt "${JWT_SECRET:?missing}"', "JWT_SECRET", "required"),
    ('LOG="${LOG_LEVEL:-info}"', "LOG_LEVEL", "optional"),
])
def test_extract_patterns(line, var, need):
    assert [(u.var, u.need) for u in env.extract("app/x.py", line)] == [(var, need)]


def test_is_source_skips_vendored_code():
    assert env.is_source("app/main.py") and env.is_source("app/.env.example")
    assert not env.is_source("app/node_modules/x/index.js") and not env.is_source("app/logo.png")


def test_check_classifies_and_suggests_typos():
    uses = [*env.extract("app/db.py", 'url = os.environ["DATABASE_URL"]'),
            *env.extract("app/.env.example", "REDIS_URL=\n"),
            *env.extract("app/x.py", 'os.getenv("FEATURE_X", "")')]
    r = env.check(uses, {"DATABSE_URL": "pg://", "PATH": "/bin", "EXTRA": "1"})
    assert not r["ok"]
    assert r["missing_required"][0]["did_you_mean"] == "DATABSE_URL"
    assert [e["var"] for e in r["missing_used"]] == ["REDIS_URL"]
    assert r["unused_provided"] == ["DATABSE_URL", "EXTRA"] and r["optional_unset"] == ["FEATURE_X"]


# --- packages ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("path", "data", "expected"), [
    ("lib/apk/db/installed", b"P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r29\n", [("apk", "musl", "1.2.5-r0"),
                                                                                  ("apk", "busybox", "1.36.1-r29")]),
    ("var/lib/dpkg/status", b"Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n"
                            b"Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n", [("dpkg", "bash", "5.2-1")]),
    ("usr/lib/python3/site-packages/Flask-3.0.dist-info/METADATA", b"Metadata-Version: 2.1\nName: Flask\nVersion: 3.0.0\n",
     [("pypi", "Flask", "3.0.0")]),
    ("app/node_modules/@scope/pkg/package.json", b'{"name": "@scope/pkg", "version": "1.2.3"}', [("npm", "@scope/pkg", "1.2.3")]),
    ("usr/lib/ruby/gems/3.2.0/specifications/rack-3.0.8.gemspec", b"", [("gem", "rack", "3.0.8")]),
    ("app/package.json", b"not json", []),
])
def test_package_parsers(path, data, expected):
    assert [(p.ecosystem, p.name, p.version) for p in packages.parse(path, data)] == expected


def test_purl():
    assert packages.Package("npm", "@scope/pkg", "1.0", "").purl == "pkg:npm/%40scope/pkg@1.0"
    assert packages.Package("pypi", "Flask", "3.0", "").purl == "pkg:pypi/flask@3.0"


def _member(name: str, size: int) -> tarfile.TarInfo:
    m = tarfile.TarInfo(name)
    m.size, m.mode = size, 0o644
    return m


def test_inventory_diff_reports_files_and_versions():
    a, b = packages.Inventory(), packages.Inventory()
    a.add("lib/apk/db/installed", _member("x", 10), b"P:openssl\nV:3.1.4-r0\n\nP:curl\nV:8.0-r0\n")
    b.add("lib/apk/db/installed", _member("x", 10), b"P:openssl\nV:3.1.10-r0\n\nP:jq\nV:1.7-r0\n")
    a.add("app/big.bin", _member("app/big.bin", 100), b"a" * 100)
    b.add("app/big.bin", _member("app/big.bin", 5000), b"b" * 5000)
    b.add("app/new.txt", _member("app/new.txt", 3), b"new")
    d = packages.diff(a, b)
    assert d["packages"]["upgraded"] == [{"ecosystem": "apk", "name": "openssl", "from": "3.1.4-r0", "to": "3.1.10-r0"}]
    assert [p["name"] for p in d["packages"]["added"]] == ["jq"]
    assert [p["name"] for p in d["packages"]["removed"]] == ["curl"]
    assert d["files"]["added"] == 1 and d["files"]["largest_changes"][0]["path"] == "/app/big.bin"
    bom = packages.cyclonedx("img", b)
    assert bom["bomFormat"] == "CycloneDX" and len(bom["components"]) == 2


def test_config_diff():
    d = packages.config_diff({"Env": ["A=1"], "User": "root"}, {"Env": ["A=2"], "User": "app"})
    assert d["Env"] == {"only_in_a": ["A=1"], "only_in_b": ["A=2"]} and d["User"] == {"a": "root", "b": "app"}


# --- rootfs ------------------------------------------------------------------------------------

@pytest.mark.parametrize(("name", "root", "rel"), [
    ("./.env", "", ".env"), ("app/.env", "app", ".env"), ("/etc/os-release", "", "etc/os-release"),
])
def test_relative_keeps_dotfiles(name, root, rel):
    assert relative(name, root) == rel


# --- traffic (pcap built with struct) ----------------------------------------------------------

def _pkt(src: str, sport: int, dst: str, dport: int, seq: int, payload: bytes) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + tcp
    return b"\0" * 12 + b"\x08\x00" + ip  # Ethernet


def _pcap(*frames: bytes) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1000 + i, 0, len(f), len(f)) + f
    return out


def test_pcap_to_http_exchanges_with_reordering_chunked_and_head():
    c, s = ("10.0.0.3", 40000), ("10.0.0.2", 80)
    req1, req2 = b"GET /api/price HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\n\r\n", b"HEAD / HTTP/1.1\r\n\r\n"
    resp1 = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
             b"5\r\n{\"p\":\r\n3\r\n10}\r\n0\r\n\r\n")
    resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 612\r\n\r\n"
    pcap = _pcap(
        _pkt(*c, *s, 100 + len(req1), req2),  # arrives before the first segment: reassembly must reorder
        _pkt(*c, *s, 100, req1),
        _pkt(*s, *c, 900, resp1[:30]), _pkt(*s, *c, 930, resp1[30:]), _pkt(*s, *c, 930, resp1[30:]),  # retransmit
        _pkt(*s, *c, 900 + len(resp1), resp2),
    )
    ex = traffic.exchanges_from_pcap(pcap, 80)
    assert [(e["method"], e["path"], e["status"]) for e in ex] == [("GET", "/api/price", 200), ("HEAD", "/", 200)]
    assert ex[0]["resp_body"]["text"] == '{"p":10}' and ex[0]["req_headers"]["Authorization"] == "***"


def test_pcap_rejects_pcapng():
    with pytest.raises(ValueError, match="pcapng"):
        list(traffic.packets(b"\x0a\x0d\x0d\x0a" + b"\0" * 40))


def test_compare_bodies_masks_volatile_and_ignored_paths():
    a = '{"id": "6f1c1b3e-8a3f-4b7a-9d2e-1c2b3a4d5e6f", "price": 10, "at": "2026-01-01T00:00:00Z", "meta": {"x": 1}}'
    b = '{"id": "0a1b2c3d-8a3f-4b7a-9d2e-1c2b3a4d5e6f", "price": 12, "at": "2026-02-01T10:00:00Z", "meta": {"x": 2}}'
    assert traffic.compare_bodies(a, b, ["meta.*"]) == [{"path": "price", "recorded": 10, "replayed": 12}]


# --- SQL subset over an in-process sqlite (a real engine; only the container hop is skipped) ---------

class Lite(SQL):
    dialect = "sqlite"

    def __init__(self, conn: sqlite3.Connection) -> None:  # noqa: D107 - no container behind it
        self.conn = conn

    def query(self, sql: str, *, readonly: bool = True, database: str | None = None, seconds: int = 30) -> Result:
        cur = self.conn.execute(sql)
        return Result([d[0] for d in cur.description or []], [list(r) for r in cur.fetchall()])


@pytest.fixture
def shop() -> tuple[Lite, Relations]:
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        create table customers(id integer primary key, name text, referrer integer references customers(id));
        create table products(sku text, rev integer, title text, primary key (sku, rev));
        create table orders(id integer primary key, customer_id integer references customers(id));
        create table items(id integer primary key, order_id integer references orders(id),
                           sku text, rev integer, foreign key (sku, rev) references products(sku, rev));
    """)
    conn.executemany("insert into customers values (?, ?, ?)", [(i, f"c{i}", i - 1 if i > 1 else None) for i in range(1, 21)])
    conn.executemany("insert into products values (?, ?, ?)", [(f"s{i}", 1, f"p{i}") for i in range(10)])
    conn.executemany("insert into orders values (?, ?)", [(i, i % 20 + 1) for i in range(1, 101)])
    conn.executemany("insert into items values (?, ?, ?, 1)", [(i, i % 100 + 1, f"s{i % 10}") for i in range(1, 301)])
    rel = Relations.build(["customers", "products", "orders", "items"],
                          [["customers", "id"], ["products", "sku"], ["products", "rev"], ["orders", "id"], ["items", "id"]],
                          [["fk1", "customers", "referrer", "customers", "id"], ["fk2", "orders", "customer_id", "customers", "id"],
                           ["fk3", "items", "order_id", "orders", "id"], ["fk4", "items", "sku", "products", "sku"],
                           ["fk4", "items", "rev", "products", "rev"]])
    return Lite(conn), rel


def test_relations_order_and_roots(shop):
    _, rel = shop
    order = rel.parents_first()
    assert order.index("customers") < order.index("orders") < order.index("items")
    assert rel.roots() == ["items"]
    assert next(f for f in rel.fks if f.name == "fk4").columns == ("sku", "rev")


def test_subset_is_referentially_closed_and_loads_cleanly(shop):
    db, rel = shop
    sub = subset.plan(db, rel, ratio=0.05)
    stmts, counts = subset.export(db, rel, sub)
    assert counts["items"] == 15 and stmts[0] == "PRAGMA foreign_keys=OFF;"
    target = sqlite3.connect(":memory:")
    target.executescript("\n".join(r[0] + ";" for r in db.conn.execute("select sql from sqlite_master where type='table'")))
    target.executescript("\n".join(stmts))
    target.execute("PRAGMA foreign_keys=ON")
    assert target.execute("PRAGMA foreign_key_check").fetchall() == []
    # the self-referencing chain was followed all the way up
    top = target.execute("select min(id) from customers").fetchone()[0]
    assert top == 1


def test_subset_with_children(shop):
    db, rel = shop
    sub = subset.plan(db, rel, ratio=0.1, roots=["customers"], with_children=True)
    assert sub.selection.get("orders") and sub.selection.get("items")


# --- seed --------------------------------------------------------------------------------------

@pytest.mark.parametrize(("data_type", "norm"), [
    ("character varying", "varchar"), ("character", "char"), ("timestamp with time zone", "timestamp"),
    ("tinyint(1)", "bool"), ("bigint", "bigint"), ("USER-DEFINED", "other"),
])
def test_normalize(data_type, norm):
    assert seed.normalize(data_type) == norm


@pytest.mark.parametrize(("clause", "attr", "value"), [
    ("CHECK (((status)::text = ANY ((ARRAY['new'::character varying, 'paid'::character varying])::text[])))",
     "choices", ("new", "paid")),
    ("`status` in ('new','paid')", "choices", ("new", "paid")),
    ("CHECK ((qty > 0))", "minimum", 1.0),
    ("CHECK ((qty >= 5))", "minimum", 5.0),
])
def test_apply_check(clause, attr, value):
    col = "status" if attr == "choices" else "qty"
    meta = seed.TableMeta({col: seed.Column(col, "text" if attr == "choices" else "int", False, False)})
    seed.apply_check(meta, clause)
    assert getattr(meta.columns[col], attr) == value


def test_generator_is_deterministic_and_respects_constraints():
    cols = [seed.Column("email", "varchar", False, False, maxlen=40), seed.Column("age", "int", True, False),
            seed.Column("code", "char", False, False, maxlen=3), seed.Column("status", "text", False, False, choices=("a", "b")),
            seed.Column("qty", "int", False, False, minimum=5)]
    run = lambda: [seed.Generator(7).value(c, i, unique=c.name == "email") for i in range(20) for c in cols]  # noqa: E731
    first = run()
    assert first == run()
    by = {c.name: [v for j, v in enumerate(first) if j % len(cols) == k] for k, c in enumerate(cols)}
    assert all(len(v) <= 40 and "@" in v for v in by["email"]) and len(set(by["email"])) == 20
    assert all(v is None or 0 < v <= 120 for v in by["age"])
    assert all(len(v) <= 3 for v in by["code"]) and set(by["status"]) <= {"a", "b"} and min(by["qty"]) >= 5


# --- advise ------------------------------------------------------------------------------------

PLAN: dict[str, Any] = {"Node Type": "Sort", "Sort Key": ["o.created_at"], "Actual Total Time": 90, "Plans": [
    {"Node Type": "Hash Join", "Hash Cond": "(o.customer_id = c.id)", "Actual Total Time": 80, "Plans": [
        {"Node Type": "Seq Scan", "Relation Name": "orders", "Schema": "public", "Alias": "o", "Actual Total Time": 60,
         "Filter": "((status)::text = 'paid'::text)", "Rows Removed by Filter": 150000, "Plan Rows": 5000},
        {"Node Type": "Seq Scan", "Relation Name": "customers", "Schema": "public", "Alias": "c", "Actual Total Time": 5,
         "Plan Rows": 10},
    ]}]}


def test_advise_candidates_and_hot_nodes():
    cands = advise.candidates(PLAN)
    assert [(c.relation, c.columns) for c in cands] == [("public.orders", ("status",)),
                                                          ("public.orders", ("customer_id",))]
    assert cands[0].ddl == 'CREATE INDEX CONCURRENTLY ON public.orders ("status");'
    assert advise.hot_nodes(PLAN)[0] == {"node": "Seq Scan", "relation": "public.orders", "self_ms": 60, "rows": None,
                                         "filter": "((status)::text = 'paid'::text)"}


# --- rightsize ---------------------------------------------------------------------------------

def _samples(mem_mib: list[int], cpu_pct: list[float], *, net: int = 0) -> list[rs.Sample]:
    out, cpu_ns, sys_ns = [], 0, 0
    for i, (m, c) in enumerate(zip(mem_mib, cpu_pct)):
        out.append(rs.Sample(float(i * 5), cpu_ns, sys_ns, 2, m << 20, 0, 10, net * i, 0))
        sys_ns += 10**9  # host time per step; container share gives c% of one core with 2 cpus
        cpu_ns += int(c / 100 / 2 * 10**9)
    return out


def test_cpu_series_and_percentile():
    s = _samples([10] * 4, [50, 100, 25, 0])
    assert [round(x) for x in rs.cpu_series(s)] == [50, 100, 25]
    assert rs.percentile([1, 2, 3, 4, 100], 95) == 100 and rs.percentile([], 95) == 0


@pytest.mark.parametrize(("limits", "mem", "flags", "command"), [
    (rs.Limits(), [100, 120, 110], ["unlimited"], True),
    (rs.Limits(128 << 20, 10**9, 100), [100, 120, 110], ["at-risk"], True),
    (rs.Limits(4 << 30, 4 * 10**9, 100), [100, 120, 110], ["over-provisioned"], True),
    (rs.Limits(256 << 20, 10**9, 100), [100, 120, 110], [], False),
])
def test_recommend_flags(limits, mem, flags, command):
    r = rs.recommend("svc", _samples(mem, [40, 60, 50], net=1000), limits)
    assert r.flags == flags and bool(r.command) is command
    assert r.recommend["memory_bytes"] == 160 << 20  # ceil16(120 MiB * 1.3 = 156 MiB)
    assert r.recommend["cpus"] == 1.0                # ceil0.25(0.6 * 1.3 = 0.78)


def test_recommend_idle_minimums():
    r = rs.recommend("idle", _samples([1, 1, 1], [0, 0, 0]), rs.Limits(96 << 20, 5 * 10**8, 64))
    assert r.flags == ["idle"] and r.command is None
    assert (r.recommend["memory"], r.recommend["cpus"], r.recommend["pids"]) == ("32m", 0.25, 64)


def test_limits_from_quota():
    assert rs.Limits.from_host_config({"CpuQuota": 50000, "CpuPeriod": 100000, "PidsLimit": -1}).nano_cpus == 5 * 10**8
