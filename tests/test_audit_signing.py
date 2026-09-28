"""Audit signing (HMAC per record) and anchors (checkpoints kept elsewhere): the attacks each layer must catch,
and the ones the plain hash chain alone cannot."""

import json
import os
import stat
from pathlib import Path

import pytest

from aisb import audit, config
from aisb.cli import EXIT_OK, EXIT_UNMET, EXIT_USAGE, main
from aisb.context import Ctx


def rec(ref: str = "web") -> None:
    audit.record(op="containers.stop", tier="mutate", args={"ref": ref}, ctx=Ctx("alice"), endpoint="unix:///x",
                 ok=True, error=None, ms=1)


@pytest.fixture
def log(tmp_path, monkeypatch) -> Path:
    p = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AISB_AUDIT", str(p))
    return p


@pytest.fixture
def key(tmp_path, monkeypatch) -> Path:
    k = tmp_path / "keys" / "audit.key"
    audit.keygen(k)
    monkeypatch.setenv("AISB_AUDIT_KEY", str(k))
    return k


def records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def rechain(log: Path, recs: list[dict]) -> None:
    """What an attacker with write access (and no key) can do: fix up every prev/hash after an edit."""
    prev = audit.GENESIS
    for r in recs:
        r["prev"] = prev
        r["hash"] = prev = audit._digest(prev, r)
    log.write_text("".join(json.dumps(r) + "\n" for r in recs))


def test_without_a_key_a_rechained_edit_goes_unnoticed(log):
    rec("a")
    rec("b")
    recs = records(log)
    recs[0]["args"]["ref"] = "someone-else"
    rechain(log, recs)
    assert audit.verify(log) == {"ok": True, "records": 2, "head": recs[-1]["hash"]}   # the gap signing closes


def test_signed_records_verify_and_say_which_key(log, key):
    rec("a")
    rec("b")
    kid = audit.key_id(key.read_bytes().strip())
    assert all(r["kid"] == kid and len(r["mac"]) == 64 for r in records(log))
    assert audit.verify(log) == {"ok": True, "records": 2, "head": records(log)[-1]["hash"], "signed": 2,
                                 "unsigned": 0, "signatures": f"checked with key {kid}"}


@pytest.mark.parametrize(("tamper", "reason"), [
    (lambda rs: rs[0]["args"].update(ref="x"), "signature does not match: the record was forged or re-chained"),
    (lambda rs: rs[1].pop("mac"), "unsigned record after signing began: signatures were stripped"),
    (lambda rs: rs[0].update(kid="000000000000"), "signed with another key (kid 000000000000, configured "),
])
def test_rechained_tampering_is_caught_with_a_key(log, key, tamper, reason):
    rec("a")
    rec("b")
    recs = records(log)
    tamper(recs)
    rechain(log, recs)
    res = audit.verify(log)
    assert res["ok"] is False and res["reason"].startswith(reason)


def test_a_log_that_predates_the_key_verifies_its_unsigned_prefix(log, tmp_path, monkeypatch):
    rec("old")
    k = tmp_path / "k"
    audit.keygen(k)
    monkeypatch.setenv("AISB_AUDIT_KEY", str(k))
    rec("new")
    res = audit.verify(log)
    assert res["ok"] and (res["signed"], res["unsigned"]) == (1, 1)
    monkeypatch.delenv("AISB_AUDIT_KEY")
    assert audit.verify(log)["signatures"] == "not checked: no key configured"


def test_a_signing_failure_keeps_the_record_and_fails_verification(log, key, tmp_path):
    rec("a")
    moved = key.rename(tmp_path / "elsewhere")
    rec("b")                                   # the change already happened: never lose its record
    assert "not found" in records(log)[1]["unsigned"]
    moved.rename(key)
    res = audit.verify(log)
    assert res["ok"] is False and res["broken_at"] == 2 and res["reason"].startswith("record was not signed: audit key")


@pytest.mark.parametrize(("content", "mode", "error"), [
    (b"x" * 64, 0o644, "readable by others"),
    (b"short\n", 0o600, "too short"),
])
def test_unsafe_keys_are_refused(tmp_path, monkeypatch, content, mode, error):
    k = tmp_path / "k"
    k.write_bytes(content)
    k.chmod(mode)
    monkeypatch.setenv("AISB_AUDIT_KEY", str(k))
    with pytest.raises(ValueError, match=error):
        audit.load_key()


def test_the_key_comes_from_config_when_the_env_is_unset(tmp_path):
    k = tmp_path / "k"
    audit.keygen(k)
    Path(config.default_path()).write_text(f'[audit]\nkey = "{k}"\n')
    config.reset()
    assert audit.key_path() == k and audit.load_key() == k.read_bytes().strip()


def test_keygen_writes_a_private_key_once(tmp_path):
    k = tmp_path / "new" / "dir" / "audit.key"
    made = audit.keygen(k)
    assert stat.S_IMODE(k.stat().st_mode) == 0o600 and stat.S_IMODE(k.parent.stat().st_mode) == 0o700
    assert made == {"key": str(k), "kid": audit.key_id(k.read_bytes().strip())} and len(k.read_bytes().strip()) == 64
    with pytest.raises(FileExistsError):
        audit.keygen(k)


# --- anchors -----------------------------------------------------------------------------------------------------

def test_anchors_catch_dropped_newest_records(log, tmp_path):
    for r in "abc":
        rec(r)
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text(json.dumps(audit.anchor(log)) + "\n")
    log.write_text("".join(line + "\n" for line in log.read_text().splitlines()[:2]))
    assert audit.verify(log)["ok"] is True                       # the chain alone can't see it
    assert audit.verify(log, anchors=audit.read_anchors(anchors)) == {
        "ok": False, "records": 2, "broken_at": 3,
        "reason": "the log has 2 records but an anchor holds 3: newer records were removed"}


def test_anchors_catch_a_full_rewrite_even_by_a_key_holder(log, key):
    rec("a")
    rec("b")
    a = audit.anchor(log)
    log.unlink()
    rec("x")
    rec("y")                                   # a fresh, validly signed log of the same length
    res = audit.verify(log, anchors=[a])
    assert res["ok"] is False and res["broken_at"] == 2 and "differs from its anchor" in res["reason"]


def test_anchors_are_signed_and_checked(log, key):
    rec("a")
    a = audit.anchor(log)
    assert a["kid"] == audit.key_id(key.read_bytes().strip()) and len(a["mac"]) == 64
    rec("b")
    later = audit.anchor(log)
    res = audit.verify(log, anchors=[a, later])
    assert res["ok"] and res["anchors"] == 2
    assert "bad signature" in audit.verify(log, anchors=[{**a, "ts": a["ts"] + 1}])["reason"]
    assert "another key" in audit.verify(log, anchors=[{**a, "kid": "000000000000"}])["reason"]


def test_an_anchor_of_an_empty_log_and_two_anchors_for_one_record(log):
    empty = audit.anchor(log)
    assert (empty["records"], empty["head"]) == (0, audit.GENESIS)
    assert audit.verify(log, anchors=[empty])["ok"]
    bad = {"records": 0, "head": "f" * 64}
    assert audit.verify(log, anchors=[empty, bad])["broken_at"] == 0
    rec("a")
    good = audit.anchor(log)
    assert audit.verify(log, anchors=[good, {**good, "head": "f" * 64}])["reason"].endswith("the log was rewritten")


def test_anchoring_a_broken_log_returns_the_failure(log):
    rec("a")
    rec("b")
    log.write_text(log.read_text().replace('"ref": "a"', '"ref": "z"'))
    assert audit.anchor(log) == {"ok": False, "records": 1, "broken_at": 1, "reason": "record content was modified"}


def test_read_anchors_accepts_appended_json_in_any_layout(tmp_path):
    p = tmp_path / "a"
    one, two = {"records": 1, "head": "h1"}, {"records": 2, "head": "h2"}
    p.write_text(json.dumps(one) + "\n" + json.dumps(two, indent=2) + "\n" + json.dumps([one]) + "\n\n")
    assert audit.read_anchors(p) == [one, two, one]
    p.write_text('{"records": "1", "head": "h"}')
    with pytest.raises(ValueError, match="not an audit anchor"):
        audit.read_anchors(p)


# --- the CLI -----------------------------------------------------------------------------------------------------

def run(capsys, *argv: str) -> tuple[int, dict]:
    code = main([*argv, "--json"])
    out, err = capsys.readouterr()
    return code, json.loads(out or err)


def test_cli_keygen_anchor_and_verify(log, tmp_path, capsys, monkeypatch):
    k = tmp_path / "k"
    code, out = run(capsys, "audit", "keygen", str(k), "--dry-run")
    assert code == EXIT_OK and out["planned"] == [{"action": "create audit signing key", "path": str(k),
                                                   "mode": "0600"}]
    assert not k.exists()
    code, out = run(capsys, "audit", "keygen", str(k))
    assert code == EXIT_OK and out["key"] == str(k) and out["next"].startswith(f'set key = "{k}" under [audit]')
    assert run(capsys, "audit", "keygen", str(k)) == (EXIT_USAGE, {
        "error": "UsageError", "message": f"{k} already exists; keys are never overwritten", "status": None})
    monkeypatch.setenv("AISB_AUDIT_KEY", str(k))
    rec("a")
    code, a = run(capsys, "audit", "anchor")
    assert code == EXIT_OK and a["records"] == 3 and "mac" in a   # both keygens were audited too (unsigned)
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text(json.dumps(a) + "\n")
    code, out = run(capsys, "audit", "verify", "--anchors", str(anchors))
    assert code == EXIT_OK and out["anchors"] == 1 and out["signed"] == 1
    log.write_text(log.read_text().splitlines()[0] + "\n")
    code, out = run(capsys, "audit", "verify", "--anchors", str(anchors))
    assert code == EXIT_UNMET and out["reason"].endswith("newer records were removed")


def test_anchor_is_a_governance_read(tmp_path):
    from aisb import policy
    rules = [{"name": "tickets", "match": {}, "require": {"ticket": True}}]
    assert policy.check(rules, "audit.anchor", "read", {}, Ctx("alice")) == []
    assert policy.check(rules, "audit.keygen", "mutate", {"out": "k"}, Ctx("alice"))
    assert os.environ.get("AISB_AUDIT_KEY") is None     # conftest isolates the key per test


def test_cli_keygen_losing_a_race_is_a_usage_error(tmp_path, capsys, monkeypatch):
    def racing(out: Path) -> dict:
        out.write_text("someone else's key")          # created between the exists() check and O_EXCL
        raise FileExistsError(out)
    monkeypatch.setattr(audit, "keygen", racing)
    k = tmp_path / "k"
    assert run(capsys, "audit", "keygen", str(k))[0] == EXIT_USAGE and k.read_text() == "someone else's key"


# --- found by mutation testing (`mutmut run "aisb.audit*"`) ---------------------------------------------------

def test_key_length_boundary_and_a_stable_key_id(tmp_path, monkeypatch):
    k = tmp_path / "k"
    monkeypatch.setenv("AISB_AUDIT_KEY", str(k))
    for size, ok in ((31, False), (32, True)):
        k.unlink(missing_ok=True)
        k.write_bytes(b"k" * size)
        k.chmod(0o600)
        if ok:
            assert audit.load_key() == b"k" * 32
        else:
            with pytest.raises(ValueError, match="too short"):
                audit.load_key()
    # kid is written into every record: it must never change between versions for the same key
    assert audit.key_id(b"k" * 32) == "21db70ee6f26"


def test_anchor_checks_at_record_zero_and_unsigned_anchors(log, key):
    empty = audit.anchor(log)
    forged = {**empty, "mac": "0" * 64}
    assert audit.verify(log, anchors=[forged]) == {
        "ok": False, "records": 0, "broken_at": 0,
        "reason": "anchor for record 0 has a bad signature: the anchor itself was altered"}
    rec("a")
    unsigned = {k: v for k, v in audit.anchor(log).items() if k not in ("kid", "mac")}   # e.g. made before the key
    assert audit.verify(log, anchors=[unsigned])["ok"] is True
    res = audit.verify(log, anchors=[{**audit.anchor(log), "kid": "abc"}])
    assert res["reason"] == "anchor for record 1 was signed with another key (kid abc)"


def test_anchor_reads_the_file_it_is_given(log, tmp_path, monkeypatch):
    rec("a")
    other = tmp_path / "other.jsonl"
    monkeypatch.setenv("AISB_AUDIT", str(other))
    rec("b")
    rec("c")
    a = audit.anchor(log)
    assert a["records"] == 1 and isinstance(a["ts"], float) and a["ts"] == round(a["ts"], 3)
