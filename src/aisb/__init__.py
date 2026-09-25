"""aisb: a stdlib-only Docker Engine API client with an agent-friendly CLI."""

from .client import Docker
from .errors import APIError, Conflict, DockerError, DockerUnavailable, NotFound, NotModified
from .models import RunSpec
from .ops import Tier, get_op, invoke, registry

__all__ = [
    "APIError", "Conflict", "Docker", "DockerError", "DockerUnavailable", "NotFound", "NotModified",
    "RunSpec", "Tier", "get_op", "invoke", "registry",
]
__version__ = "0.1.0"
