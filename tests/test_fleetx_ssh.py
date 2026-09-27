"""OpenSSH transport at the process boundary: a fake `ssh` executable on PATH stands in for the real client.

The fake is a "loopback ssh": commands run locally through `sh -c`, `-L local.sock:remote.sock` becomes a symlink
to the remote socket (a FakeDaemon), and `-L 127.0.0.1:PORT:HOST:PORT` listens on PORT. Behaviour is switched
with FAKE_SSH_MODE, and every invocation's argv is appended to FAKE_SSH_LOG.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import types
from pathlib import Path

import pytest

from aisb.cli import EXIT_OK, EXIT_UNMET, main
from aisb.fleet import runner, ssh
from aisb.fleet.inventory import Host
from aisb.fleet.ssh import Forwarder, Ssh, Tunnel, Unreachable, local_run, quote

from conftest import FakeDaemon

FAKE_SSH = textwrap.dedent(f"""\
    #!{sys.executable}
    import json, os, signal, socket, subprocess, sys, time
    args = sys.argv[1:]
    if os.environ.get("FAKE_SSH_LOG"):
        with open(os.environ["FAKE_SSH_LOG"], "a") as f:
            f.write(json.dumps(args) + "\\n")
    mode = os.environ.get("FAKE_SSH_MODE", "ok")
    if mode == "refused":
        sys.stderr.write("ssh: connect to host x port 22: Connection refused\\n")
        sys.exit(255)
    if mode == "silent255":
        sys.exit(255)
    if mode == "hang":
        time.sleep(30)
    rest, fwd, i = [], None, 0
    while i < len(args):
        if args[i] in ("-o", "-p", "-i", "-L"):
            if args[i] == "-L":
                fwd = args[i + 1]
            i += 2
            continue
        if args[i] != "-N":
            rest.append(args[i])
        i += 1
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    if "-N" in args:
        if mode == "fwd-exit":
            sys.stderr.write("channel_setup_fwd_listener: cannot listen\\n")
            sys.exit(255)
        if mode == "no-listen":
            time.sleep(30)
            sys.exit(0)
        if fwd.startswith("127.0.0.1:"):
            _, lport, _ = fwd.split(":", 2)
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", int(lport)))
            srv.listen(8)
        else:
            local, remote = fwd.split(":", 1)
            os.symlink(remote, local)
        while True:
            time.sleep(0.05)
    target, command = rest[0], " ".join(rest[1:])
    proc = subprocess.run(["sh", "-c", command], stdin=sys.stdin)
    sys.exit(proc.returncode)
""")


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "ssh"
    exe.write_text(FAKE_SSH)
    exe.chmod(0o755)
    log = tmp_path / "ssh.log"
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_SSH_LOG", str(log))
    monkeypatch.delenv("FAKE_SSH_MODE", raising=False)

    def calls() -> list[list[str]]:
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return types.SimpleNamespace(exe=str(exe), calls=calls, mode=lambda m: monkeypatch.setenv("FAKE_SSH_MODE", m))


class Clock:
    """A fake time module for aisb.fleet.ssh: sleeping advances the clock instantly."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.now += max(s, 0.5)


# --- argv construction --------------------------------------------------------------------------------

@pytest.mark.parametrize(("ssh_kw", "present", "absent"), [
    ({}, ["BatchMode=yes", "ConnectTimeout=5", "ServerAliveInterval=15", "ControlMaster=auto", "ControlPersist=120"],
     ["-p", "-i", "IdentitiesOnly=yes"]),
    ({"port": 2222}, ["-p", "2222"], ["-i"]),
    ({"key": "~/k"}, ["-i", os.path.expanduser("~/k"), "IdentitiesOnly=yes"], ["-p"]),
    ({"options": ("ProxyJump=b", "Compression=yes"), "connect_timeout": 9}, ["ProxyJump=b", "Compression=yes",
                                                                           "ConnectTimeout=9"], []),
])
def test_argv(fake_ssh, ssh_kw, present, absent):
    argv = Ssh("ops@h", **ssh_kw).argv()
    assert argv[0] == fake_ssh.exe
    assert all(p in argv for p in present) and not any(a in argv for a in absent)
    control = next(a for a in argv if a.startswith("ControlPath="))
    ctl_dir = Path(control.removeprefix("ControlPath=")).parent
    assert ctl_dir.is_dir() and (ctl_dir.stat().st_mode & 0o777) == 0o700 and control.endswith("/%C")
    assert len(control) < 100                                   # fits AF_UNIX with the %C hash expanded


def test_argv_without_multiplexing_never_uses_the_master(fake_ssh):
    argv = Ssh("h").argv(multiplex=False)
    assert "ControlMaster=no" in argv and "ControlPath=none" in argv and "ControlMaster=auto" not in argv


def test_of_host():
    s = Ssh.of(Host("w", ssh="ops@w", port=22, key="k", ssh_options=("A=b",)))
    assert (s.target, s.port, s.key, s.options) == ("ops@w", 22, "k", ("A=b",))
    with pytest.raises(AssertionError):
        Ssh.of(Host("local"))


def test_quote():
    assert quote(["echo", "a b", "$x"]) == "echo 'a b' '$x'"


# --- run ---------------------------------------------------------------------------------------------

def test_run_passes_target_command_and_stdin(fake_ssh):
    proc = Ssh("ops@h", port=2200).run("cat; echo done; exit 7", stdin=b"in\n")
    assert (proc.returncode, proc.stdout) == (7, b"in\ndone\n")
    (argv,) = fake_ssh.calls()
    assert argv[-2:] == ["ops@h", "cat; echo done; exit 7"] and argv[argv.index("-p") + 1] == "2200"


@pytest.mark.parametrize(("mode", "message"), [("refused", "ssh: connect to host x port 22: Connection refused"), ("silent255", "ssh failed")])
def test_run_exit_255_is_unreachable(fake_ssh, mode, message):
    fake_ssh.mode(mode)
    with pytest.raises(Unreachable, match=f"ops@h: {message}"):
        Ssh("ops@h").run("true")


def test_run_timeout_is_unreachable(fake_ssh):
    fake_ssh.mode("hang")
    t0 = time.monotonic()
    with pytest.raises(Unreachable, match="no answer within 0.3s"):
        Ssh("ops@h").run("true", timeout=0.3)
    assert time.monotonic() - t0 < 5


def test_local_run_and_its_timeout():
    assert local_run("echo $((1+2))").stdout == b"3\n"
    with pytest.raises(Unreachable, match="timed out after 0.2s"):
        local_run("sleep 5", timeout=0.2)


# --- Tunnel -------------------------------------------------------------------------------------------

@pytest.fixture
def remote():
    d = Path(tempfile.mkdtemp(prefix="aisb-x-", dir="/tmp"))
    fake = FakeDaemon(d / "r.sock")
    fake.start()
    yield fake
    fake.stop()
    shutil.rmtree(d, ignore_errors=True)


def test_tunnel_forwards_the_remote_socket_and_cleans_up(fake_ssh, remote):
    remote.on("GET", "/version", json={"Version": "27"})
    t = Tunnel.open(Ssh("ops@h"), str(remote.sock))
    try:
        assert t.alive and Path(t.path).exists()
        from aisb import Docker
        assert Docker(f"unix://{t.path}", timeout=5).transport.json("GET", "/version")["Version"] == "27"
        (argv,) = fake_ssh.calls()
        assert "-N" in argv and "ControlPath=none" in argv and "ExitOnForwardFailure=yes" in argv
        assert argv[argv.index("-L") + 1] == f"{t.path}:{remote.sock}" and argv[-1] == "ops@h"
    finally:
        t.close()
    assert not t.alive and not t.workdir.exists()


def test_tunnel_context_manager(fake_ssh, remote):
    with Ssh("ops@h").tunnel(str(remote.sock)) as path:
        assert Path(path).exists()
    assert not Path(path).parent.exists()


def test_tunnel_failure_reports_ssh_stderr(fake_ssh):
    fake_ssh.mode("fwd-exit")
    with pytest.raises(Unreachable, match="ops@h: channel_setup_fwd_listener: cannot listen"):
        Tunnel.open(Ssh("ops@h"), "/var/run/docker.sock")
    assert not any(ssh._control_dir().glob("aisb-t-*/d.sock"))


def test_tunnel_that_never_comes_up_times_out(fake_ssh, monkeypatch):
    fake_ssh.mode("no-listen")
    monkeypatch.setattr(ssh, "time", Clock())
    with pytest.raises(Unreachable, match="tunnel to /r.sock did not come up"):
        Tunnel.open(Ssh("ops@h", connect_timeout=1), "/r.sock")


def test_tunnel_close_kills_a_process_that_ignores_sigterm(tmp_path):
    proc = subprocess.Popen(["sh", "-c", "trap '' TERM; sleep 30"], stderr=subprocess.PIPE)
    work = tmp_path / "w"
    work.mkdir()
    time.sleep(0.1)                       # let the trap be installed

    orig_wait = proc.wait       # the boundary: instead of waiting 5 s for a stuck ssh, give up after 0.2 s
    proc.wait = lambda timeout=None: orig_wait(timeout=0.2 if timeout == 5 else timeout)
    Tunnel(proc, str(work / "d.sock"), work).close()
    orig_wait(timeout=5)
    assert proc.poll() is not None and not work.exists() and proc.stderr.closed


# --- Forwarder ------------------------------------------------------------------------------------------

def test_forwarder_opens_reuses_and_closes(fake_ssh):
    fwd = Forwarder(Ssh("ops@h"))
    host, port = fwd("10.0.0.5", 5432)
    try:
        assert host == "127.0.0.1"
        with socket.create_connection((host, port), timeout=2):
            pass
        assert fwd("10.0.0.5", 5432) == (host, port)             # reused, not reopened
        _, port6 = fwd("fd00::5", 80)
        specs = [a[a.index("-L") + 1] for a in fake_ssh.calls()]
        assert specs == [f"127.0.0.1:{port}:10.0.0.5:5432", f"127.0.0.1:{port6}:[fd00::5]:80"]
        procs = [p for _, p in fwd._open.values()]
    finally:
        fwd.close()
    assert fwd._open == {} and all(p.poll() is not None for p in procs)


def test_forwarder_reopens_a_dead_forward(fake_ssh):
    fwd = Forwarder(Ssh("ops@h"))
    try:
        fwd("db", 5432)
        (_, proc), = fwd._open.values()
        proc.kill()
        proc.wait()
        fwd("db", 5432)
        assert len(fake_ssh.calls()) == 2
    finally:
        fwd.close()


def test_forwarder_failure_and_timeout(fake_ssh, monkeypatch):
    fake_ssh.mode("fwd-exit")
    with pytest.raises(Unreachable, match="port forward to db:5432 failed: channel_setup_fwd_listener"):
        Forwarder(Ssh("ops@h"))("db", 5432)
    fake_ssh.mode("no-listen")
    monkeypatch.setattr(ssh, "time", Clock())
    with pytest.raises(Unreachable, match="port forward to db:5432 did not come up"):
        Forwarder(Ssh("ops@h", connect_timeout=1))("db", 5432)


# --- the fleet over (fake) SSH end to end --------------------------------------------------------------------

@pytest.fixture
def ssh_fleet(fake_ssh, remote, tmp_path, monkeypatch, capsys):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": {
        "r1": {"ssh": "ops@r1", "port": 2201, "docker": str(remote.sock), "groups": ["web"]},
        "r2": {"ssh": "ops@r2", "docker": str(remote.sock), "groups": ["web"]}}}))
    monkeypatch.setenv("AISB_FLEET", str(inv))

    def run(*argv: str):
        i = argv.index("--") if "--" in argv else len(argv)
        code = main([*argv[:i], "--json", *argv[i:]])
        out, err = capsys.readouterr()
        return code, json.loads(out) if out.strip() else None, err
    return run


def test_fleet_query_over_ssh_uses_one_tunnel_per_host(ssh_fleet, remote, fake_ssh):
    remote.on("GET", "/containers/json", json=[{"Id": "x" * 12, "Names": ["/api"], "Image": "i", "State": "running",
                                                "Status": "Up", "Labels": {}}])
    code, out, _ = ssh_fleet("fleet", "query", "@web", "--flat", "--", "containers", "list")
    assert code == EXIT_OK and [r["host"] for r in out["rows"]] == ["r1", "r2"]
    tunnels = [a for a in fake_ssh.calls() if "-N" in a]
    assert sorted(a[-1] for a in tunnels) == ["ops@r1", "ops@r2"]
    assert not list(ssh._control_dir().glob("aisb-t-*/d.sock"))   # tunnels closed with the pool


def test_fleet_shell_over_ssh_with_sudo_quoting(ssh_fleet, fake_ssh):
    code, out, _ = ssh_fleet("fleet", "shell", "r1", "--", "echo", "it's")
    assert code == EXIT_OK and out["results"][0]["result"]["stdout"] == "it's\n"
    assert fake_ssh.calls()[-1][-1] == "echo 'it'\"'\"'s'"


def test_fleet_retries_hosts_whose_ssh_failed(ssh_fleet, fake_ssh, monkeypatch):
    fake_ssh.mode("refused")
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    code, out, _ = ssh_fleet("fleet", "shell", "r1", "--retries", "2", "--", "true")
    assert code == EXIT_UNMET and out["results"][0]["attempts"] == 3 and "Connection refused" in out["results"][0]["error"]
    assert len(fake_ssh.calls()) == 3


def test_fleet_status_over_ssh_probes_vitals(ssh_fleet, remote):
    remote.on("GET", "/info", json={"ContainersRunning": 0, "Containers": 0, "ServerVersion": "27"})
    code, out, _ = ssh_fleet("fleet", "status", "r1", "--no-doctor")
    row = out["hosts"][0]
    assert code == EXIT_OK and row["host"] == "r1" and row["docker"] == "27" and row["cpus"] and row["verdict"] != "down"


def test_docker_error_over_ssh_hints_at_permissions(ssh_fleet, tmp_path, monkeypatch):
    inv = tmp_path / "fleet.json"
    (tmp_path / "nothing.sock").write_text("")         # the tunnel comes up, but nothing answers behind it
    inv.write_text(json.dumps({"hosts": {"r3": {"ssh": "ops@r3", "docker": str(tmp_path / "nothing.sock")}}}))
    code, out, _ = ssh_fleet("fleet", "ping", "r3")
    assert code == EXIT_UNMET and "may ops@r3 open" in out["results"][0]["error"]
