from types import TracebackType

from .api import Containers, Db, Fs, Http, Images, MongoOps, Networks, RedisOps, Svc, System, Volumes
from .ops import Resource
from .transport import Transport, resolve_endpoint


class Docker:
    """Facade over the resource APIs: ``Docker().containers.ls(all=True)``."""

    def __init__(self, host: str | None = None, *, timeout: float | None = 60.0, version: str | None = None) -> None:
        self.transport = Transport(resolve_endpoint(host), timeout=timeout, version=version)
        self.containers = Containers(self.transport)
        self.images = Images(self.transport)
        self.networks = Networks(self.transport)
        self.volumes = Volumes(self.transport)
        self.system = System(self.transport)
        self.svc = Svc(self.transport)
        self.db = Db(self.transport)
        self.redis = RedisOps(self.transport)
        self.mongo = MongoOps(self.transport)
        self.http = Http(self.transport)
        self.fs = Fs(self.transport)

    def resource(self, name: str) -> Resource:
        res = getattr(self, name, None)
        if not isinstance(res, Resource):
            raise ValueError(f"unknown resource: {name}")
        return res

    def __enter__(self) -> "Docker":
        return self

    def __exit__(self, et: type[BaseException] | None, ev: BaseException | None, tb: TracebackType | None) -> None:
        return None
