"""`@aisb` pyinfra connector: run operations *inside* containers through the Docker Engine API.

    pyinfra @aisb/web exec -- nginx -t
    pyinfra @aisb/stack:shop deploy.py         # every container of an aisb stack, in parallel
    DOCKER_HOST=tcp://build-box:2376 pyinfra @aisb/app fact server.LinuxName

Unlike pyinfra's `@docker` connector it needs no docker CLI (exec and the archive API are HTTP calls, so
`DOCKER_HOST` / host data `aisb_docker_host` can point at a remote daemon), never commits images, and only
targets existing running containers: it changes what's inside them, not their lifecycle.
"""

import io
import os
import tarfile
import time
import uuid
from collections.abc import Iterator
from typing import Any

from pyinfra.api.exceptions import ConnectError, InventoryError
from pyinfra.api.output import echo
from pyinfra.api.util import get_file_io
from pyinfra.connectors.base import BaseConnector, DataMeta
from pyinfra.connectors.util import CommandOutput, OutputLine, extract_control_arguments, make_unix_command_for_host
from typing_extensions import TypedDict

from ...client import Docker
from ...errors import DockerError
from ...rootfs import read_file
from ...stack import STACK_KEY
from ...util import q


class ConnectorData(TypedDict, total=False):
    aisb_container: str
    aisb_docker_host: str


def _tar_one(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), 0o644, int(time.time())
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class AisbConnector(BaseConnector):
    handles_execution = True
    data_cls = ConnectorData
    data_meta = {
        "aisb_container": DataMeta("container name or id"),
        "aisb_docker_host": DataMeta("Docker endpoint (default: $DOCKER_HOST or the local socket)"),
    }

    @staticmethod
    def make_names_data(name: str | None = None) -> Iterator[tuple[str, dict[str, Any], list[str]]]:
        if not name:
            raise InventoryError("@aisb needs a target: @aisb/CONTAINER or @aisb/stack:NAME")
        if name.startswith("stack:"):
            stack = name.removeprefix("stack:")
            rows = Docker().transport.json("GET", "/containers/json",
                                           query={"filters": {"label": [f"{STACK_KEY}={stack}"]}}) or []
            if not rows:
                raise InventoryError(f"no running containers in aisb stack {stack!r}")
            for r in sorted(rows, key=lambda r: r["Names"][0]):
                cname = r["Names"][0].lstrip("/")
                yield f"@aisb/{cname}", {"aisb_container": cname}, ["@aisb", f"@aisb/stack:{stack}"]
            return
        yield f"@aisb/{name}", {"aisb_container": name}, ["@aisb"]

    def connect(self) -> None:
        self.client = Docker(self.data.get("aisb_docker_host") or os.environ.get("DOCKER_HOST"), timeout=60)
        self.ref = self.data["aisb_container"]
        try:
            state = (self.client.transport.json("GET", f"/containers/{q(self.ref)}/json") or {}).get("State") or {}
        except DockerError as e:
            raise ConnectError(f"{self.ref}: {e}") from e
        if not state.get("Running"):
            raise ConnectError(f"{self.ref} is not running (@aisb targets running containers only)")

    def _put(self, path: str, data: bytes) -> None:
        parent, _, base = path.rstrip("/").rpartition("/")
        self.client.transport.json("PUT", f"/containers/{q(self.ref)}/archive", query={"path": parent or "/"},
                                   data=_tar_one(base, data), content_type="application/x-tar")

    def run_shell_command(self, command, print_output=False, print_input=False, **arguments):  # type: ignore[override]
        control = extract_control_arguments(arguments)
        stdin, ok_codes = control.get("_stdin"), control.get("_success_exit_codes") or [0]
        raw = make_unix_command_for_host(self.state, self.host, command, **arguments).get_raw_value()
        cleanup = None
        if stdin is not None:  # exec has no stdin here: stage it as a file and redirect
            lines = [stdin] if isinstance(stdin, str) else list(stdin)
            cleanup = f"/tmp/.aisb-stdin-{uuid.uuid4().hex[:8]}"
            self._put(cleanup, "".join(line if line.endswith("\n") else line + "\n" for line in lines).encode())
            raw = f"( {raw} ) < {cleanup}; rc=$?; rm -f {cleanup}; exit $rc"
        if print_input:
            echo(f"{self.host.print_prefix}>>> {raw}", err=True)
        try:
            res = self.client.containers.run_in(self.ref, ["sh", "-c", raw])
        except DockerError as e:
            return False, CommandOutput([OutputLine("stderr", str(e))])
        lines = ([OutputLine("stdout", line) for line in res.stdout.splitlines()]
                 + [OutputLine("stderr", line) for line in res.stderr.splitlines()])
        if print_output:
            for line in lines:
                echo(f"{self.host.print_prefix}{line.line}", err=line.buffer_name == "stderr")
        return res.code in ok_codes, CommandOutput(lines)

    def put_file(self, filename_or_io, remote_filename, remote_temp_filename=None, print_output=False,  # type: ignore[override]
                 print_input=False, **arguments) -> bool:
        with get_file_io(filename_or_io) as f:
            data = f.read()
        self._put(remote_filename, data.encode() if isinstance(data, str) else data)
        if print_output:
            echo(f"{self.host.print_prefix}file uploaded to container: {remote_filename}", err=True)
        return True

    def get_file(self, remote_filename, filename_or_io, remote_temp_filename=None, print_output=False,  # type: ignore[override]
                 print_input=False, **arguments) -> bool:
        data = read_file(self.client.transport, self.ref, remote_filename)
        if data is None:
            raise OSError(f"{self.ref}:{remote_filename} does not exist or is not a regular file")
        with get_file_io(filename_or_io, "wb") as f:
            f.write(data)
        if print_output:
            echo(f"{self.host.print_prefix}file downloaded from container: {remote_filename}", err=True)
        return True
