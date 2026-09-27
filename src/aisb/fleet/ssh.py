"""OpenSSH client transport: multiplexed command execution and Docker-socket tunnels (stdlib subprocess only)."""

import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .inventory import Host


class Unreachable(Exception):
    """SSH could not connect, or the tunnel never came up."""


def _control_dir() -> Path:
    # Control sockets must fit AF_UNIX's ~108-byte limit, so keep them short and outside $AISB_HOME.
    d = Path(tempfile.gettempdir()) / f"aisb-ssh-{os.getuid()}"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


@dataclass(frozen=True, slots=True)
class Ssh:
    target: str
    port: int | None = None
    key: str | None = None
    options: tuple[str, ...] = ()
    connect_timeout: int = 5

    @classmethod
    def of(cls, host: Host) -> "Ssh":
        assert host.ssh, f"{host.name} has no ssh target"
        return cls(host.ssh, host.port, host.key, host.ssh_options)

    def argv(self, *, multiplex: bool = True) -> list[str]:
        exe = shutil.which("ssh")
        if not exe:
            raise Unreachable("the OpenSSH client (`ssh`) is not installed on this machine")
        args = [exe, "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.connect_timeout}",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
        if multiplex:
            args += ["-o", "ControlMaster=auto", "-o", f"ControlPath={_control_dir()}/%C", "-o", "ControlPersist=120"]
        else:
            args += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        if self.port:
            args += ["-p", str(self.port)]
        if self.key:
            args += ["-i", os.path.expanduser(self.key), "-o", "IdentitiesOnly=yes"]
        for opt in self.options:
            args += ["-o", opt]
        return args

    def run(self, command: str, *, stdin: bytes | None = None, timeout: float = 60.0) -> subprocess.CompletedProcess[bytes]:
        """Run a shell command remotely. Exit 255 is ssh's own failure and becomes Unreachable."""
        try:
            proc = subprocess.run([*self.argv(), self.target, command], input=stdin, capture_output=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise Unreachable(f"{self.target}: no answer within {timeout:g}s") from e
        if proc.returncode == 255:
            raise Unreachable(f"{self.target}: {proc.stderr.decode(errors='replace').strip()[-300:] or 'ssh failed'}")
        return proc

    @contextmanager
    def tunnel(self, remote_socket: str) -> Iterator[str]:
        """Forward the remote Docker socket to a private local unix socket for the duration of the block."""
        d = Path(tempfile.mkdtemp(prefix="aisb-t-", dir=_control_dir()))
        local = d / "d.sock"
        proc = subprocess.Popen(
            [*self.argv(multiplex=False), "-N", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=yes",
             "-L", f"{local}:{remote_socket}", self.target],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + self.connect_timeout + 5
            while not local.exists():
                if proc.poll() is not None:
                    err = (proc.stderr.read() if proc.stderr else b"").decode(errors="replace").strip()
                    raise Unreachable(f"{self.target}: {err[-300:] or 'tunnel closed'}")
                if time.monotonic() > deadline:
                    raise Unreachable(f"{self.target}: tunnel to {remote_socket} did not come up")
                time.sleep(0.02)
            yield str(local)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            if proc.stderr:
                proc.stderr.close()
            shutil.rmtree(d, ignore_errors=True)


class Forwarder:
    """`Transport.dialer` for an SSH host: HOST:PORT on the remote network -> an on-demand `ssh -L` on 127.0.0.1.

    Forwards are opened lazily (only ops that dial containers pay for them), reused per address, and closed
    together with the Docker tunnel.
    """

    def __init__(self, ssh: Ssh) -> None:
        self.ssh = ssh
        self._open: dict[tuple[str, int], tuple[int, subprocess.Popen[bytes]]] = {}
        self._lock = threading.Lock()

    def __call__(self, host: str, port: int) -> tuple[str, int]:
        with self._lock:
            if (hit := self._open.get((host, port))) and hit[1].poll() is None:
                return "127.0.0.1", hit[0]
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                lport = s.getsockname()[1]
            target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            proc = subprocess.Popen([*self.ssh.argv(multiplex=False), "-N", "-o", "ExitOnForwardFailure=yes",
                                     "-L", f"127.0.0.1:{lport}:{target}", self.ssh.target],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            deadline = time.monotonic() + self.ssh.connect_timeout + 5
            while True:
                if proc.poll() is not None:
                    err = (proc.stderr.read() if proc.stderr else b"").decode(errors="replace").strip()
                    raise Unreachable(f"{self.ssh.target}: port forward to {target} failed: {err[-200:]}")
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", lport)) == 0:
                        break
                if time.monotonic() > deadline:
                    proc.kill()
                    raise Unreachable(f"{self.ssh.target}: port forward to {target} did not come up")
                time.sleep(0.02)
            self._open[(host, port)] = (lport, proc)
            return "127.0.0.1", lport

    def close(self) -> None:
        with self._lock:
            for _, proc in self._open.values():
                proc.terminate()
            for _, proc in self._open.values():
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if proc.stderr:
                    proc.stderr.close()
            self._open.clear()


def local_run(command: str, *, stdin: bytes | None = None, timeout: float = 60.0) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(["sh", "-c", command], input=stdin, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise Unreachable(f"local command timed out after {timeout:g}s") from e


def quote(argv: list[str]) -> str:
    return shlex.join(argv)
