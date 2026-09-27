"""Edge branches of pure helpers across modules: fleet (desired state, health, metrics, sources, inventory),
insights (envcontract, incident, vulns, triage, remediate), runbook state, services (advise, fmt), streams,
transport, models and util."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aisb import runbooks, state
from aisb.fleet import desired, health, metrics, sources
from aisb.fleet.inventory import Host, Inventory
from aisb.insights import envcontract, graph, incident, remediate, triage, vulns
from aisb.models import parse_size
from aisb.services import advise, fmt
from aisb.streams import tar_path
from aisb.transport import Endpoint, Transport, resolve_endpoint
from aisb.util import filters

MIB = 1 << 20


# --- fleet ------------------------------------------------------------------------------------------------------

def _stack(path: Path, name: str) -> str:
    path.write_text(json.dumps({"name": name, "services": {"web": {"image": "nginx:1"}}}))
    return path.name


def test_desired_same_stack_from_two_selectors_is_assigned_once(tmp_path):
    f = _stack(tmp_path / "shop.json", "shop")
    (tmp_path / "s.json").write_text(json.dumps({"assign": {"a": [f], "*": f}}))
    out = desired.load(tmp_path / "s.json", Inventory({"a": Host("a"), "b": Host("b")}))
    assert {h: [a.stack.name for a in v] for h, v in out.items()} == {"a": ["shop"], "b": ["shop"]}


def test_desired_rejects_one_stack_name_in_two_files(tmp_path):
    one, two = _stack(tmp_path / "one.json", "shop"), _stack(tmp_path / "two.json", "shop")
    (tmp_path / "s.json").write_text(json.dumps({"assign": {"a": [one, two]}}))
    with pytest.raises(ValueError, match="stack name 'shop' is defined by both .*one.json and .*two.json"):
        desired.load(tmp_path / "s.json", Inventory({"a": Host("a")}))


@pytest.mark.parametrize("disk", ["Filesystem 1K-blocks Used", "/dev/sda1 100 50 50 n/a% /"])
def test_health_ignores_malformed_disk_line(disk):
    v = health.parse(f"preamble\n@@disk\n\n{disk}\n@@uptime\n12.5 3.0\n")  # text outside sections is ignored
    assert (v.disk_used_pct, v.disk_free, v.uptime_s) == (None, None, 12)


def test_health_changes_ignores_reordered_reasons():
    a = {"verdict": "degraded", "reasons": ["disk 91%", "load high"]}
    b = {"verdict": "degraded", "reasons": ["load high", "disk 91%"]}
    assert health.changes({"h": a}, {"h": b}) == []


@pytest.mark.parametrize(("xs", "ys"), [([], []), ([1.0], [2.0])])
def test_linear_fit_needs_two_points(xs, ys):
    assert metrics.linear_fit(xs, ys) is None


def test_forecast_full_without_time_spread():
    assert metrics.forecast_full([(100.0, 1.0), (100.0, 2.0), (100.0, 3.0)], min_span=0) is None


def test_aws_source_skips_instances_without_the_wanted_address():
    data = {"Reservations": [{"Instances": [
        {"InstanceId": "i-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5"},
        {"InstanceId": "i-2", "State": {"Name": "running"}, "PublicIpAddress": "3.3.3.3"},
    ]}]}
    assert [h.name for h in sources.aws(json.dumps(data), public=True)] == ["i-2"]
    assert [h.name for h in sources.aws(json.dumps(data))] == ["i-1"]


def test_regroup_refuses_computed_groups(tmp_path):
    inv = Inventory({"a": Host("a")}, {"web": ["a"]}, tmp_path / "fleet.json")
    with pytest.raises(ValueError, match="@web is computed from selectors"):
        inv.regroup("web", add=["a"])


# --- insights ---------------------------------------------------------------------------------------------------

def test_envcontract_contract_file_skips_non_assignments_and_strongest_need_wins():
    uses = envcontract.extract(".env.example", "# DATABASE_URL is required\nDATABASE_URL=\nexport API_KEY=x\n")
    assert [(u.var, u.need, u.where) for u in uses] == [("DATABASE_URL", "used", ".env.example:2"),
                                                         ("API_KEY", "used", ".env.example:3")]
    uses += [envcontract.Use("API_KEY", "optional", "app.py:3"), envcontract.Use("API_KEY", "required", "app.py:9")]
    rep = envcontract.check(uses, {})
    by_var = {e["var"]: e for e in rep["missing_required"] + rep["missing_used"]}
    assert by_var["API_KEY"]["need"] == "required"
    assert by_var["API_KEY"]["where"] == ["app.py:3", "app.py:9", ".env.example:3"]  # code first, docs last


def _sig(t: float, c: str, sev: str = "critical") -> incident.Signal:
    return incident.Signal(t, c, "event", sev, f"{c} died")


def test_postmortem_without_root_cause():
    r = incident.analyze([_sig(1, "x", "warning")], {})
    md = incident.postmortem(r, window="5m")
    assert "## Root cause" not in md and "- no failing containers" in md and "degraded: x" in md


def test_postmortem_root_without_blast_radius():
    r = incident.analyze([_sig(1, "cache")], {"api": {"cache"}}, evidence="config")
    md = incident.postmortem(r, window="5m")
    assert "## Root cause" in md and "## Blast radius" not in md
    assert "Evidence for causality: configured endpoints (env URLs)" in md


def test_vuln_severity_skips_unparseable_vectors_and_uses_the_label():
    v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/garbage"}, {"type": "CVSS_V2", "score": "AV:N"}],
         "database_specific": {"severity": "MODERATE"}}
    assert vulns.severity(v) == ("medium", None)


def test_fixed_versions_only_for_the_matching_package():
    v = {"affected": [
        {"package": {"name": "other", "ecosystem": "PyPI"}, "ranges": [{"events": [{"fixed": "9.9"}]}]},
        {"package": {"name": "requests", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "8.8"}]}]},
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "ranges": [{"events": [{"introduced": "0"},
                                                                                     {"fixed": "2.32.0"}]}]},
    ]}
    assert vulns.fixed_versions(v, "requests", "PyPI") == ["2.32.0"]


def test_triage_paused_container():
    found = list(triage.state_rules(triage.Facts("w", {"State": {"Status": "paused", "Running": True}})))
    assert [(f.severity, f.code) for f in found] == [("warning", "paused")]


def test_remediate_oom_with_raise_memory_disabled_only_suggests():
    report = {"container": "w", "findings": [{"code": "oom-killed"}], "state": {"status": "exited"}}
    p = remediate.plan(report, {"HostConfig": {"Memory": 256 * MIB}}, rules=("start-exited",))
    assert p.actions == []


# --- runbook run state ---------------------------------------------------------------------------------------------

def test_load_run_unknown_and_all_runs_skips_dirs_without_state():
    with pytest.raises(ValueError, match="no such run 'r-1'"):
        runbooks.load_run("r-1")
    state.home("runs", "partial")  # a run dir whose state was never written
    state.write_json(runbooks.run_dir("r-2") / "state.json", {"run": "r-2"})
    assert runbooks.all_runs() == [{"run": "r-2"}]


# --- services ------------------------------------------------------------------------------------------------------

def test_advise_sort_over_seq_scan_and_filters_without_columns():
    plan = {"Node Type": "Sort", "Sort Key": ["o.created_at DESC"], "Plans": [
        {"Node Type": "Seq Scan", "Relation Name": "orders", "Alias": "o", "Filter": "(true)",
         "Rows Removed by Filter": 5000}]}
    (c,) = advise.candidates(plan)
    assert (c.relation, c.columns) == ("public.orders", ("created_at",))
    assert c.reason == "sort over a seq scan by o.created_at DESC"


@pytest.mark.parametrize(("kind", "cell"), [
    ("csv", '"{""$oid"": ""65a"", ""tags"": [1, ""é""]}"'),   # a Mongo document cell stays valid JSON in CSV
    ("markdown", '{"$oid": "65a", "tags": [1, "é"]}'),
    ("table", '{"$oid": "65a", "tags": [1, "é"]}'),
])
def test_fmt_renders_nested_values_as_json(kind, cell):
    out = fmt.render(["_id", "n"], [[{"$oid": "65a", "tags": [1, "é"]}, None]], kind)
    assert cell in out


# --- streams / transport / models / util ------------------------------------------------------------------------------

def test_tar_path_missing(tmp_path):
    with pytest.raises(ValueError, match="no such local path"):
        tar_path(tmp_path / "nope")


def test_tls_endpoint_loads_client_certificate(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("needs the openssl CLI")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-days", "1", "-subj", "/CN=client", "-keyout", str(tmp_path / "key.pem"),
                    "-out", str(tmp_path / "cert.pem")], check=True, capture_output=True)
    ep = resolve_endpoint("tcp://docker.example:2376", {"DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": str(tmp_path)})
    assert ep.tls is not None


def test_note_outside_dry_run_records_nothing():
    t = Transport(Endpoint("unix:///nonexistent"))
    t.note(action="ignored")
    with t.dry_run() as plan:
        t.note(action="kept")
    assert [n.data for n in plan] == [{"action": "kept"}]


@pytest.mark.parametrize("bad", ["lots", "12 parsecs", "-1m"])
def test_parse_size_rejects_garbage(bad):
    with pytest.raises(ValueError, match="invalid size"):
        parse_size(bad)


def test_filters_skip_empty_extras():
    assert filters(None, label=[], name=["web"]) == {"name": ["web"]}
    assert filters(None, label=[]) is None


# --- small validation paths -------------------------------------------------------------------------------------------

def test_desired_unreadable_state_file(tmp_path):
    with pytest.raises(ValueError, match="s.json"):
        desired.load(tmp_path / "s.json", Inventory({}))


def test_runbook_invalid_file_and_run_id(tmp_path):
    bad = tmp_path / "rb.json"
    bad.write_text("{")
    with pytest.raises(ValueError, match="rb.json: "):
        runbooks.load(str(bad))
    with pytest.raises(ValueError, match="invalid run id '../x'"):
        runbooks.run_dir("../x")


def test_vitals_row_and_level_unknown():
    assert health.Vitals(mem_total=4 * MIB, mem_available=MIB).row()["mem_available_pct"] == 25.0
    assert vulns.level(None) == "unknown"


def test_parse_sockets_skips_undecodable_rows():
    assert graph.parse_sockets("   0: ZZZZ:0050 00000000:0000 0A 0\n") == []


@pytest.mark.parametrize(("url", "tls", "port"), [("tcp://127.0.0.1", False, 2375), ("tcp://127.0.0.1", True, 2376),
                                                  ("tcp://127.0.0.1:9999", True, 9999)])
def test_tcp_endpoint_connections(url, tls, port):
    import http.client
    import ssl
    conn = Endpoint(url, ssl.create_default_context() if tls else None).connection(3)
    assert isinstance(conn, http.client.HTTPSConnection if tls else http.client.HTTPConnection)
    assert (conn.host, conn.port) == ("127.0.0.1", port)


@pytest.mark.parametrize("retries", [-5, -1, 0])
def test_fan_out_negative_retries_means_one_attempt(retries):
    from aisb.fleet import runner
    from aisb.fleet.inventory import Host
    from aisb.fleet.ssh import Unreachable
    calls = []

    def fn(h):
        calls.append(h.name)
        raise Unreachable("no route")
    results, _ = runner.fan_out([Host("down")], fn, retries=retries)
    assert (results[0].ok, results[0].attempts, calls) == (False, 1, ["down"])

