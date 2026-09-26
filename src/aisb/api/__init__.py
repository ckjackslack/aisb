"""Resource APIs; importing this package registers every operation."""

from .containers import Containers
from .fs import Fs
from .http import Http
from .images import Images
from .net import Net
from .networks import Networks
from .services import Db, KafkaOps, MongoOps, RabbitOps, RedisOps, SearchOps, Svc
from .stack import StackOps
from .system import System
from .volumes import Volumes

ORDER = ("containers", "images", "networks", "volumes", "system", "stack", "net", "svc", "db", "redis", "mongo",
         "kafka", "rabbit", "es", "http", "fs")
__all__ = ["ORDER", "Containers", "Db", "Fs", "Http", "Images", "KafkaOps", "MongoOps", "Net", "Networks", "RabbitOps",
           "RedisOps", "SearchOps", "StackOps", "Svc", "System", "Volumes"]
