"""Resource APIs; importing this package registers every operation."""

from .capsule import Capsule
from .chaos import Chaos
from .containers import Containers
from .fleet import Fleet
from .governance import Audit, Config, Policy
from .runbook import RunbookOps
from .fs import Fs
from .http import Http
from .images import Images
from .net import Net
from .networks import Networks
from .session import Session
from .services import Db, KafkaOps, MongoOps, RabbitOps, RedisOps, SearchOps, Svc
from .stack import StackOps
from .system import System
from .volumes import Volumes

ORDER = ("containers", "images", "networks", "volumes", "system", "session", "stack", "net", "svc", "db", "redis",
         "mongo", "kafka", "rabbit", "es", "http", "fs", "capsule", "chaos", "fleet", "runbook", "audit", "policy", "config")
__all__ = ["ORDER", "Audit", "Config", "Policy", "Capsule", "Chaos", "Containers", "Db", "Fleet", "Fs", "Http", "Images", "KafkaOps", "MongoOps", "Net", "Networks", "RabbitOps",
           "RedisOps", "RunbookOps", "SearchOps", "Session", "StackOps", "Svc", "System", "Volumes"]
