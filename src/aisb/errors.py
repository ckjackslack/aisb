"""Typed errors mapped from Docker Engine API status codes."""

from typing import Any


class DockerError(Exception):
    status: int | None = None

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        if status is not None:
            self.status = status

    def as_dict(self) -> dict[str, Any]:
        return {"error": type(self).__name__, "message": str(self), "status": self.status}


class DockerUnavailable(DockerError):
    """The daemon endpoint could not be reached."""


class NotModified(DockerError):
    status = 304


class BadRequest(DockerError):
    status = 400


class NotFound(DockerError):
    status = 404


class Conflict(DockerError):
    status = 409


class APIError(DockerError):
    """Any other daemon-side failure, including errors embedded in JSON streams."""


_BY_STATUS: dict[int, type[DockerError]] = {
    cls.status: cls for cls in (NotModified, BadRequest, NotFound, Conflict) if cls.status
}


def error_for(status: int, message: str) -> DockerError:
    return _BY_STATUS.get(status, APIError)(message or f"HTTP {status}", status=status)
