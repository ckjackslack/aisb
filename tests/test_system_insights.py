"""Pure analyses behind `system audit` / `containers secrets` / `images slim` (insights.audit) and the SBOM /
image-diff inventory (insights.packages)."""

import io
import sqlite3
import struct
import tarfile

import pytest

from aisb.insights import audit as au
from aisb.insights import packages as pk

MIB = 1 << 20


# --- secret detection -----------------------------------------------------------------------------------

@pytest.mark.parametrize(("value", "masked"), [("abcdefghi", "abcd***"), ("12345678", "***"), ("", "***")])
def test_mask(value, masked):
    assert au.mask(value) == masked


@pytest.mark.parametrize(("text", "kind"), [
    ("AKIA" + "A" * 16, "aws-access-key-id"),
    ("ghp_" + "a" * 36, "github-token"),
    ("glpat-" + "a" * 20, "gitlab-token"),
    ("xoxb-" + "1" * 10, "slack-token"),
    ("sk_live_" + "a" * 20, "stripe-key"),
    ("AIza" + "a" * 35, "google-api-key"),
    ("sk-" + "a" * 32, "openai-key"),
    ("eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10, "jwt"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key"),
    ("postgres://app:s3cret@db:5432/x", "url-with-password"),
])
def test_scan_text_known_formats(text, kind):
    hits = au.scan_text(f"prefix {text} suffix", "f")
    assert kind in {h["kind"] for h in hits} and all(h["where"] == "f" for h in hits)
    assert all(text not in h["sample"] for h in hits)


@pytest.mark.parametrize(("entry", "kinds"), [
    ("DB_PASSWORD=hunter2", ["secret-in-env"]),
    ("API_KEY=changeme", []),                  # placeholder
    ("TOKEN=${TOKEN}", []),
    ("SECRET=", []),
    ("DB_PASSWORD_FILE=/run/secrets/db", []),  # the recommended pattern
    ("MODE=production", []),
    ("DSN=redis://u:pa55w0rd@cache:6379", ["url-with-password"]),
    ("GH_TOKEN=ghp_" + "x" * 36, ["secret-in-env", "github-token"]),
])
def test_scan_env(entry, kinds):
    hits = au.scan_env([entry], "ctr")
    assert [h["kind"] for h in hits] == kinds
    assert all(h["where"] == f"ctr:{entry.partition('=')[0]}" for h in hits)


def test_scan_history_env_arg_and_build_args():
    history = [
        {"created_by": "/bin/sh -c #(nop)  ENV API_TOKEN=abcdef123456"},
        {"CreatedBy": "|2 NPM_TOKEN=npmsecretvalue X=1 /bin/sh -c npm ci"},
        {"created_by": "ARG PASSWORD=changeme"},                    # placeholder: ignored
        {"created_by": "RUN echo AKIA" + "Q" * 16},
        {},
    ]
    hits = au.scan_history(history)
    by = {(h["where"], h["kind"]) for h in hits}
    assert ("layer 0:API_TOKEN", "secret-in-image-history") in by
    assert ("layer 1:NPM_TOKEN", "secret-in-image-history") in by
    assert ("layer 3", "aws-access-key-id") in by
    assert not any(w.startswith("layer 2") for w, _ in by)
    assert all("BuildKit" in h["fix"] for h in hits if h["kind"] == "secret-in-image-history")


def test_dedupe_by_where_and_sample():
    a = {"kind": "x", "where": "w", "sample": "s"}
    assert au.dedupe([a, {**a, "kind": "y"}, {**a, "sample": "t"}]) == [a, {**a, "sample": "t"}]


# --- configuration audit --------------------------------------------------------------------------------

def container(**kw) -> dict:
    base = {"Name": "/c", "Config": {"Image": "app:1.2", "User": "app", "Healthcheck": {"Test": ["CMD", "true"]}},
            "HostConfig": {"Memory": 64 * MIB, "NanoCpus": 10**9, "PidsLimit": 100,
                           "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": {"Name": "always"}},
            "State": {"Running": True}}
    for k, v in kw.items():
        base[k] = {**base.get(k, {}), **v} if isinstance(v, dict) else v
    return base


def codes(c, image=None) -> list[str]:
    return [f["code"] for f in au.audit(c, image)["findings"]]


def test_clean_container_scores_100():
    assert au.audit(container()) == {"container": "c", "score": 100, "findings": []}


@pytest.mark.parametrize(("patch", "code", "severity"), [
    ({"HostConfig": {"Privileged": True}}, "privileged", "critical"),
    ({"HostConfig": {"CapAdd": ["SYS_ADMIN", "CHOWN"]}}, "dangerous-caps", "warning"),
    ({"HostConfig": {"NetworkMode": "host"}}, "host-network", "warning"),
    ({"HostConfig": {"PidMode": "host"}}, "host-pid", "warning"),
    ({"HostConfig": {"IpcMode": "host"}}, "host-ipc", "warning"),
    ({"HostConfig": {"SecurityOpt": []}}, "no-new-privileges-unset", "info"),
    ({"Mounts": [{"Source": "/run/docker.sock", "Destination": "/d"}]}, "docker-socket", "critical"),
    ({"Mounts": [{"Type": "bind", "Source": "/etc/", "Destination": "/e", "RW": True}]}, "sensitive-mount", "critical"),
    ({"Mounts": [{"Type": "bind", "Source": "", "Destination": "/h", "RW": False}]}, "sensitive-mount", "warning"),
    ({"Config": {"User": "0:0"}}, "runs-as-root", "warning"),
    ({"Config": {"Image": "nginx"}}, "unpinned-image", "warning"),
    ({"Config": {"Image": "reg:5000/nginx:latest"}}, "unpinned-image", "warning"),
    ({"HostConfig": {"Memory": 0}}, "no-memory-limit", "warning"),
    ({"HostConfig": {"NanoCpus": 0}}, "no-cpu-limit", "info"),
    ({"HostConfig": {"PidsLimit": -1}}, "no-pids-limit", "info"),
    ({"NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "15432"}]}}},
     "datastore-exposed", "critical"),
    ({"Config": {"Healthcheck": {"Test": ["NONE"]}}}, "no-healthcheck", "info"),
    ({"HostConfig": {"RestartPolicy": {"Name": "no"}}}, "no-restart-policy", "info"),
    ({"Config": {"Env": ["DB_PASSWORD=hunter2hunter2"]}}, "secret-in-env", "warning"),
])
def test_audit_rules(patch, code, severity):
    rep = au.audit(container(**patch))
    f = next(f for f in rep["findings"] if f["code"] == code)
    assert f["severity"] == severity
    assert rep["score"] == 100 - {"critical": 30, "warning": 10, "info": 2}[severity] * len(rep["findings"]) or \
        rep["score"] < 100


@pytest.mark.parametrize("patch", [
    {"HostConfig": {"CapAdd": ["CHOWN"]}},
    {"HostConfig": {"Privileged": True, "SecurityOpt": []}},        # privileged: no separate nnp info
    {"Mounts": [{"Type": "volume", "Source": "/var/lib/docker/volumes/x/_data", "Destination": "/d"}]},
    {"Mounts": [{"Type": "bind", "Source": "/srv/data", "Destination": "/d"}]},
    {"Config": {"Image": "app@sha256:" + "a" * 64}},
    {"Config": {"Image": "sha256:" + "a" * 64}},
    {"NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}], "80/tcp": None,
                                   "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}}},
    {"State": {"Running": False}, "HostConfig": {"RestartPolicy": {"Name": ""}}},
    {"HostConfig": {"NanoCpus": 0, "CpuShares": 512}},
])
def test_audit_rules_negative(patch):
    found = codes(container(**patch))
    assert not {"dangerous-caps", "no-new-privileges-unset", "sensitive-mount", "unpinned-image",
                "datastore-exposed", "no-restart-policy", "no-cpu-limit"} & set(found)


def test_audit_falls_back_to_image_user_and_healthcheck():
    c = container(Config={"User": "", "Healthcheck": None})
    assert {"runs-as-root", "no-healthcheck"} <= set(codes(c))
    img = {"Config": {"User": "1000", "Healthcheck": {"Test": ["CMD", "curl", "-f", "localhost"]}}}
    assert not {"runs-as-root", "no-healthcheck"} & set(codes(c, img))


def test_audit_one_finding_per_variable_and_ranking():
    c = container(Config={"Env": ["GH_TOKEN=ghp_" + "x" * 36, "OTHER_SECRET=abcdefghij"]},
                  HostConfig={"Privileged": True, "Memory": 0})
    rep = au.audit(c)
    env_findings = [f for f in rep["findings"] if "env" in f["summary"]]
    assert len(env_findings) == 2                                    # GH_TOKEN matched twice, reported once
    sev = [f["severity"] for f in rep["findings"]]
    assert sev == sorted(sev, key=["critical", "warning", "info"].index)
    assert rep["score"] == max(0, 100 - 30 - 10 * 3)


def test_audit_score_floors_at_zero():
    c = {"Name": "/worst", "Config": {"Image": "x", "Env": [f"K{i}_PASSWORD=verysecret{i}" for i in range(12)]},
         "HostConfig": {"Privileged": True}}
    assert au.audit(c)["score"] == 0 and au.audit({})["container"] == ""


# --- image slimming -------------------------------------------------------------------------------------

def test_slim_hints_and_largest():
    history = [  # newest first, like the API
        {"created_by": "COPY . /app", "size": 5 * MIB},
        {"created_by": "RUN npm install", "size": 0},
        {"CreatedBy": "RUN pip install -r req.txt && apk add curl", "Size": 60 * MIB},
        {"created_by": "RUN apt-get install -y gcc && rm -rf /var/lib/apt/lists/*", "size": 80 * MIB},
        {"created_by": "RUN apt-get install --no-install-recommends -y curl", "size": 1},
    ]
    out = au.slim(history, 200 * MIB)
    got = {(h["code"], h["layer"]) for h in out["hints"]}
    assert {("apt-lists-kept", 0), ("build-tools-in-final", 1), ("apt-recommends", 1), ("pip-cache", 2),
            ("apk-cache", 2), ("npm-dev-deps", 3), ("copy-everything", 4)} == got
    assert ("apt-lists-kept", 1) not in got
    assert out["over_50mb"] == 2 and out["largest"][0]["size"] == 80 * MIB and out["layers"] == 5
    assert out["estimated_waste_hint"]


def test_slim_many_layers_and_clean():
    many = [{"created_by": "RUN true", "size": 1} for _ in range(26)]
    assert [h["code"] for h in au.slim(many, 26)["hints"]] == ["many-layers"]
    clean = au.slim([{"created_by": "RUN npm ci --omit=dev", "size": 0}], 0)
    assert clean["hints"] == [] and clean["estimated_waste_hint"] is None


# --- packages: parsers ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("path", "size", "wanted"), [
    ("lib/apk/db/installed", 10, True), ("var/lib/dpkg/status", 10, True), ("var/lib/dpkg/status.d/base", 1, True),
    ("usr/lib/python3/site-packages/requests-2.0.dist-info/METADATA", 1, True),
    ("app/node_modules/@scope/pkg/package.json", 1, True), ("app/node_modules/a/node_modules/b/package.json", 1, True),
    ("app/package.json", 1, False), ("etc/os-release", 1, True), ("etc/passwd", 1, False),
    ("var/lib/dpkg/status", 64 << 20, False),
])
def test_wants(path, size, wanted):
    assert pk.wants(path, size) is wanted


def test_parse_apk_and_dpkg():
    apk = b"P:musl\nV:1.2.4-r2\nA:x86_64\ngarbage\n\nP:busybox\nV:1.36\n\nV:orphan\n"
    assert [(p.name, p.version) for p in pk.parse("lib/apk/db/installed", apk)] == [("musl", "1.2.4-r2"),
                                                                                    ("busybox", "1.36")]
    dpkg = (b"Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\n"
            b"Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n\nVersion: 3\n")
    assert [(p.name, p.version) for p in pk.parse("var/lib/dpkg/status", dpkg)] == [("libc6", "2.36-9")]
    distroless = b"Package: tzdata\nVersion: 2024a\n"
    assert [p.name for p in pk.parse("var/lib/dpkg/status.d/tzdata", distroless)] == ["tzdata"]


@pytest.mark.parametrize(("path", "data", "expected"), [
    ("x/Req-2.0.dist-info/METADATA", b"Metadata-Version: 2.1\nName: Requests\nVersion: 2.31.0\n\nName: body",
     [("pypi", "Requests", "2.31.0")]),
    ("x/foo.egg-info/PKG-INFO", b"Version: 1\n", []),
    ("node_modules/@s/p/package.json", b'{"name": "@s/p", "version": 3}', [("npm", "@s/p", "3")]),
    ("node_modules/p/package.json", b"{not json", []),
    ("node_modules/p/package.json", b'{"version": "1"}', []),
    ("gems/specifications/rack-3.0.8.gemspec", b"", [("gem", "rack", "3.0.8")]),
    ("gems/specifications/weird.gemspec", b"", []),
    ("etc/unknown", b"", []),
])
def test_parse_language_ecosystems(path, data, expected):
    assert [(p.ecosystem, p.name, p.version) for p in pk.parse(path, data)] == expected


def _rpm_blob(name: str, version: str, release: str | None, *, bad: bool = False) -> bytes:
    strings, entries = b"", []
    for tag, val in ((1000, name), (1001, version), (1002, release), (1004, "summary")):
        if val is None:
            continue
        entries.append(struct.pack(">IIII", tag, 6, len(strings), 1))
        strings += val.encode() + (b"" if bad else b"\0")
    return struct.pack(">II", len(entries), len(strings)) + b"".join(entries) + strings


def _rpmdb(blobs: list[bytes]) -> bytes:
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "db"
        conn = sqlite3.connect(p)
        conn.execute("create table Packages (hnum integer primary key, blob blob)")
        conn.executemany("insert into Packages (blob) values (?)", [(b,) for b in blobs])
        conn.commit()
        conn.close()
        return p.read_bytes()


def test_rpmdb_sqlite():
    db = _rpmdb([_rpm_blob("bash", "5.2", "1.el9"), _rpm_blob("gpg-pubkey", "abc", None), b"\x00\x01",
                 _rpm_blob("", "1", "1")])
    pkgs = pk.parse("var/lib/rpm/rpmdb.sqlite", db)
    assert [(p.ecosystem, p.name, p.version) for p in pkgs] == [("rpm", "bash", "5.2-1.el9"), ("rpm", "gpg-pubkey", "abc")]
    assert pk.parse("var/lib/rpm/rpmdb.sqlite", b"not a database at all" * 10)[0].name == "<unparsed rpmdb>"
    assert pk._rpm_header(_rpm_blob("x", "1", "1", bad=True)[:-1]) == {}             # unterminated string


def test_os_release():
    data = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'
    assert pk.os_release(data) == {"id": "debian", "version": "12", "name": "Debian GNU/Linux 12 (bookworm)"}
    assert pk.os_release(b"") == {"id": "", "version": "", "name": ""}


@pytest.mark.parametrize(("pkg", "purl"), [
    (pk.Package("pypi", "Django", "5.0", ""), "pkg:pypi/django@5.0"),
    (pk.Package("npm", "@types/node", "20", ""), "pkg:npm/%40types/node@20"),
    (pk.Package("apk", "musl", "1", ""), "pkg:apk/alpine/musl@1"),
    (pk.Package("dpkg", "libc6", "2", ""), "pkg:deb/debian/libc6@2"),
    (pk.Package("rpm", "bash", "5", ""), "pkg:rpm/bash@5"),
    (pk.Package("gem", "rack", "3", ""), "pkg:gem/rack@3"),
])
def test_purl(pkg, purl):
    assert pkg.purl == purl


# --- packages: inventory, diff --------------------------------------------------------------------------

def _inventory(files: dict[str, bytes], *, dirs=(), links=(), big: dict[str, int] | None = None) -> pk.Inventory:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for d in dirs:
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode = tarfile.DIRTYPE, 0o40755
            tar.addfile(ti)
        for name, target in links:
            ti = tarfile.TarInfo(name)
            ti.type, ti.linkname = tarfile.SYMTYPE, target
            tar.addfile(ti)
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o100644
            tar.addfile(ti, io.BytesIO(data))
        ti = tarfile.TarInfo("dev/null")
        ti.type = tarfile.CHRTYPE
        tar.addfile(ti)
    inv = pk.Inventory()
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        for m in tar:
            data = tar.extractfile(m).read() if m.isfile() else None
            inv.add(m.name, m, data)
    for name, size in (big or {}).items():
        ti = tarfile.TarInfo(name)
        ti.size = size
        inv.add(name, ti, None)                     # content not handed over (too large): no digest
    return inv


def test_inventory_add_and_summary():
    inv = _inventory({"etc/os-release": b"ID=alpine\nVERSION_ID=3.20\n", "usr/lib/os-release": b"ID=other\n",
                      "lib/apk/db/installed": b"P:musl\nV:1\n\nP:zlib\nV:2\n", "bin/sh": b"\x7fELF"},
                     dirs=("etc",), links=(("bin/ash", "/bin/sh"),))
    assert inv.os["id"] == "alpine"                                                   # first os-release wins
    assert (inv.files["etc"].kind, inv.files["bin/ash"].kind, inv.files["dev/null"].kind) == ("dir", "link", "other")
    assert inv.files["bin/ash"].link == "/bin/sh" and inv.files["bin/sh"].digest
    assert inv.summary() == {"os": {"id": "alpine", "version": "3.20", "name": ""}, "packages": 2,
                             "by_ecosystem": {"apk": 2}, "files": 7,
                             "bytes": sum(len(v) for v in (b"ID=alpine\nVERSION_ID=3.20\n", b"ID=other\n",
                                                           b"P:musl\nV:1\n\nP:zlib\nV:2\n", b"\x7fELF"))}
    bom = pk.cyclonedx("alpine:3.20", inv)
    assert bom["metadata"]["component"]["name"] == "alpine:3.20"
    assert [c["purl"] for c in bom["components"]] == ["pkg:apk/alpine/musl@1", "pkg:apk/alpine/zlib@2"]


def test_diff_files_and_packages():
    a = _inventory({"lib/apk/db/installed": b"P:musl\nV:1.2.3\n\nP:old\nV:1\n\nP:curl\nV:8.10\n\nP:same\nV:1\n",
                    "app/main.py": b"print(1)", "app/gone.py": b"x" * 100, "etc/os-release": b"ID=alpine\n"},
                   big={"var/big.bin": 1000})
    b = _inventory({"lib/apk/db/installed": b"P:musl\nV:1.2.10\n\nP:new\nV:2\n\nP:curl\nV:8.9\n\nP:same\nV:1\n",
                    "app/main.py": b"print(2)", "app/new.py": b"y" * 300, "etc/os-release": b"ID=alpine\n"},
                   big={"var/big.bin": 1000})
    d = pk.diff(a, b, top=2)
    assert d["packages"]["upgraded"] == [{"ecosystem": "apk", "name": "musl", "from": "1.2.3", "to": "1.2.10"}]
    assert d["packages"]["downgraded"] == [{"ecosystem": "apk", "name": "curl", "from": "8.10", "to": "8.9"}]
    assert d["packages"]["added"] == [{"ecosystem": "apk", "name": "new", "version": "2"}]
    assert d["packages"]["removed"] == [{"ecosystem": "apk", "name": "old", "version": "1"}]
    f = d["files"]
    assert (f["added"], f["removed"]) == (1, 1) and f["changed"] == 2       # main.py (digest), installed (size)
    assert [c["path"] for c in f["largest_changes"]] == ["/app/new.py", "/app/gone.py"]
    assert f["by_top_dir"]["/app"] == 200 and d["os"] == {"id": "alpine", "version": "", "name": ""}
    other = _inventory({"etc/os-release": b"ID=debian\n"})
    assert set(pk.diff(a, other)["os"]) == {"a", "b"}


def test_config_diff():
    a = {"Env": ["A=1", "B=2"], "Cmd": ["run"], "User": "app", "Labels": {"x": "1", "y": "2"}, "Volumes": None}
    b = {"Env": ["A=1", "C=3"], "Cmd": None, "User": "root", "Labels": {"x": "9", "z": "3"}, "Volumes": {"/d": {}}}
    assert pk.config_diff(a, b) == {
        "Env": {"only_in_a": ["B=2"], "only_in_b": ["C=3"]},
        "Cmd": {"only_in_a": ["run"], "only_in_b": []},
        "User": {"a": "app", "b": "root"},
        "Labels": {"only_in_a": ["y"], "only_in_b": ["z"], "changed": ["x"]},
        "Volumes": {"only_in_a": [], "only_in_b": ["/d"], "changed": []},
    }
    assert pk.config_diff(a, dict(a)) == {}


def test_package_dedupe():
    p = pk.Package("npm", "a", "1", "x/package.json")
    assert pk.dedupe([p, pk.Package("npm", "a", "1", "y/package.json"), pk.Package("npm", "a", "2", "")]) == [
        p, pk.Package("npm", "a", "2", "")]
