"""Resource APIs; importing this package registers every operation."""

from .containers import Containers
from .fs import Fs
from .http import Http
from .images import Images
from .networks import Networks
from .services import Db, MongoOps, RedisOps, Svc
from .system import System
from .volumes import Volumes

ORDER = ("containers", "images", "networks", "volumes", "system", "svc", "db", "redis", "mongo", "http", "fs")
__all__ = ["ORDER", "Containers", "Db", "Fs", "Http", "Images", "MongoOps", "Networks", "RedisOps", "Svc", "System",
           "Volumes"]
