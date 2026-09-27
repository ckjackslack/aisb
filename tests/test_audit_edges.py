"""Audit-log edge cases found by mutation testing (`mutmut run "aisb.audit*"`): hashing that survives JSON
rewrites and non-JSON values, verifying the file you name, and the syslog mirror over real UDP and TCP."""

import json
import logging
import os
import socket
import socketserver
import threading
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

from aisb import audit, config
from aisb.context import Ctx


def rec(op: str = "containers.stop", **args: object) -> None:
    audit.record(op=op, tier="mutate", args=args, ctx=Ctx("alice"), endpoint="unix:///x", ok=True, error=None, ms=1)


@pytest.fixture
def log(tmp_path, monkeypatch) -> Path:
    p = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AISB_AUDIT", str(p))
    return p


def test_hashes_do_not_depend_on_key_order(log):
    rec(ref="a")
    rec(ref="b", env=["X=1"])
    # another JSON tool rewrites the file with keys in a different order: nothing was tampered with
    lines = [json.dumps(dict(sorted(json.loads(line).items(), reverse=True))) for line in log.read_text().splitlines()]
    log.write_text("\n".join(lines) + "\n")
    assert audit.verify(log) == {"ok": True, "records": 2, "head": json.loads(lines[-1])["hash"]}


def test_non_json_argument_values_are_hashed_and_verified(log):
    rec(path=Path("/data/x"), when=datetime(2026, 1, 2, 3, 4, 5))
    rec(ref="b")
    stored = json.loads(log.read_text().splitlines()[0])
    assert stored["args"] == {"path": "/data/x", "when": "2026-01-02 03:04:05"}
    assert audit.verify(log)["ok"] is True


def test_verify_reads_the_file_it_is_given(log, tmp_path):
    rec(ref="a")
    other = tmp_path / "other.jsonl"
    os.environ["AISB_AUDIT"] = str(other)
    rec(ref="b")
    rec(ref="c")
    assert audit.verify(log)["records"] == 1 and audit.verify(other)["records"] == 2


@pytest.mark.parametrize(("tamper", "reason"), [
    (lambda ls: ls[1:], "chain broken: a record was removed or reordered"),
    (lambda ls: [ls[0].replace("containers.stop", "containers.rm"), *ls[1:]], "record content was modified"),
])
def test_failed_verification_says_where_and_why(log, tamper, reason):
    rec()
    rec()
    rec()
    log.write_text("\n".join(tamper(log.read_text().splitlines())) + "\n")
    assert audit.verify(log) == {"ok": False, "records": 1, "broken_at": 1, "reason": reason}


# --- the syslog mirror over real sockets ------------------------------------------------------------------------

class _Collect(socketserver.BaseRequestHandler):
    got: list[bytes] = []

    def handle(self) -> None:
        if isinstance(self.request, tuple):   # udp: (data, socket)
            self.got.append(self.request[0])
        else:                                 # tcp: a stream of records
            while chunk := self.request.recv(65536):
                self.got.append(chunk)


@pytest.fixture
def syslog_server(request) -> Iterator[tuple[str, list[bytes]]]:
    kind = request.param
    cls = socketserver.ThreadingUDPServer if kind == "udp" else socketserver.ThreadingTCPServer
    srv = cls(("127.0.0.1", 0), type("H", (_Collect,), {"got": []}))
    srv.daemon_threads, srv.block_on_close = True, False  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"{kind}://127.0.0.1:{srv.server_address[1]}", srv.RequestHandlerClass.got  # type: ignore[attr-defined]
    finally:
        for logger in audit._SYSLOG.values():  # close the client side first: a tcp handler waits for EOF
            for h in logger.handlers:
                h.close()
        audit._SYSLOG.clear()
        srv.shutdown()
        srv.server_close()


def _wait_for(got: list[bytes], n: int) -> bytes:
    import time
    for _ in range(100):
        if b"".join(got).count(b"aisb: ") >= n:
            break
        time.sleep(0.02)
    return b"".join(got)


@pytest.mark.parametrize("syslog_server", ["udp", "tcp"], indirect=True)
def test_mirror_sends_each_record_over_the_configured_transport(log, syslog_server):
    target, got = syslog_server
    Path(os.environ["AISB_CONFIG"]).write_text(f'[audit]\nsyslog = "{target}"\n')
    config.reset()
    rec(path=Path("/data/x"))
    rec(ref="second")
    data = _wait_for(got, 2)
    assert data.count(b"aisb: ") == 2  # tcp is a stream, udp one datagram each: both carry every record
    first = json.loads(data.split(b"aisb: ")[1].split(b"\x00")[0])  # SysLogHandler ends records with NUL
    assert first["args"] == {"path": "/data/x"} and "hash" not in first and "prev" not in first
    assert list(audit._SYSLOG) == [target]    # one cached handler per target, not one per record
    (logger,) = audit._SYSLOG.values()
    assert logger.name == f"aisb.audit.syslog.{target}" and logger is not logging.getLogger()
    assert len(logger.handlers) == 1           # a reloaded config never keeps an earlier target's handler
    assert logger.propagate is False           # never leaks into the application's own logging
    sock_type = logger.handlers[0].socket.type  # type: ignore[attr-defined]
    assert sock_type == (socket.SOCK_STREAM if target.startswith("tcp") else socket.SOCK_DGRAM)


def test_log_in_a_new_directory_is_created_private(tmp_path, monkeypatch):
    p = tmp_path / "var" / "log" / "aisb" / "audit.jsonl"
    monkeypatch.setenv("AISB_AUDIT", str(p))
    rec(ref="a")
    assert audit.verify(p)["records"] == 1
    assert oct(p.parent.stat().st_mode & 0o777) == "0o700"   # it can hold redacted-but-sensitive arguments
    stored = json.loads(p.read_text())
    assert isinstance(stored["ts"], float) and stored["ts"] == round(stored["ts"], 3)
