from types import TracebackType

from .api import (Capsule, Chaos, Containers, Db, Fleet, Fs, Http, Images, KafkaOps, MongoOps, Net, Networks, RabbitOps, RedisOps, SearchOps,
                  Session, StackOps, Svc, System, Volumes)
from .ops import Resource
from .transport import Transport, resolve_endpoint


class Docker:
    """Facade over the resource APIs: ``Docker().containers.ls(all=True)``, ``Docker().db.query("pg", "select 1")``."""

    def __init__(self, host: str | None = None, *, timeout: float | None = 60.0, version: str | None = None) -> None:
        t = self.transport = Transport(resolve_endpoint(host), timeout=timeout, version=version)
        self.containers, self.images, self.networks, self.volumes = Containers(t), Images(t), Networks(t), Volumes(t)
        self.system, self.stack, self.net = System(t), StackOps(t), Net(t)
        self.svc, self.db, self.redis, self.mongo = Svc(t), Db(t), RedisOps(t), MongoOps(t)
        self.kafka, self.rabbit, self.es = KafkaOps(t), RabbitOps(t), SearchOps(t)
        self.http, self.fs = Http(t), Fs(t)
        self.session, self.capsule, self.chaos = Session(t), Capsule(t), Chaos(t)
        self.fleet = Fleet(t)

    def resource(self, name: str) -> Resource:
        res = getattr(self, name, None)
        if isinstance(res, Resource):
            return res
        from .ops import resource_class
        if (cls := resource_class(name)) is None:  # plugin resources are instantiated on first use
            raise ValueError(f"unknown resource: {name}")
        res = cls(self.transport)
        setattr(self, name, res)
        return res

    def __enter__(self) -> "Docker":
        return self

    def __exit__(self, et: type[BaseException] | None, ev: BaseException | None, tb: TracebackType | None) -> None:
        return None
