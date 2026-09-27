"""The invoke pipeline's audit trail, found thin by mutation testing (`mutmut run "aisb.ops.x_invoke*"`): what a
failed or successful change records, and its run id."""

import json
import re
import time
from pathlib import Path

import pytest

from aisb import Docker, get_op, invoke

from conftest import Reply


@pytest.fixture
def audit_log(tmp_path, monkeypatch) -> Path:
    p = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AISB_AUDIT", str(p))
    return p


def records(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text().splitlines()]


def test_a_failed_change_records_tier_endpoint_duration_and_a_bounded_error(host, daemon, audit_log):
    def slow_failure(_):
        time.sleep(0.3)
        return Reply(500, json={"message": "x" * 900})
    daemon.on("POST", "/containers/web/stop", slow_failure)
    with pytest.raises(Exception, match="xxx"):
        invoke(Docker(host), get_op("containers.stop"), {"ref": "web"})
    (r,) = records(audit_log)
    assert (r["op"], r["tier"], r["endpoint"], r["ok"]) == ("containers.stop", "mutate", host, False)
    assert len(r["error"]) == 500 and r["error"].startswith("APIError: xxx")
    assert 250 <= r["ms"] < 5000
    assert re.fullmatch(r"[0-9a-f]{12}", r["run_id"])


def test_a_successful_change_records_no_error_and_its_duration(host, daemon, audit_log):
    def slow_ok(_):
        time.sleep(0.3)
        return Reply(204)
    daemon.on("POST", "/containers/web/stop", slow_ok)
    out = invoke(Docker(host), get_op("containers.stop"), {"ref": "web"})
    assert out.status == "ok"
    (r,) = records(audit_log)
    assert r["ok"] is True and r["error"] is None and r["tier"] == "mutate" and r["endpoint"] == host
    assert 250 <= r["ms"] < 5000


def test_a_denied_change_records_zero_duration_and_the_rules(host, daemon, audit_log):
    import os

    from aisb import config
    Path(os.environ["AISB_CONFIG"]).write_text('[[policy.rules]]\nname = "no"\ndeny = true\n')
    config.reset()
    with pytest.raises(Exception, match="denied by policy"):
        invoke(Docker(host), get_op("volumes.rm"), {"ref": "v"}, confirm=True)
    (r,) = records(audit_log)
    assert (r["ok"], r["ms"], r["denied"], r["tier"], r["endpoint"]) == (False, 0, True, "destroy", host)
    assert r["error"] == "volumes.rm denied by policy: [no] volumes.rm is not allowed here"
