"""Resource APIs; importing this package registers every operation."""

from .containers import Containers
from .images import Images
from .networks import Networks
from .system import System
from .volumes import Volumes

ORDER = ("containers", "images", "networks", "volumes", "system")
__all__ = ["ORDER", "Containers", "Images", "Networks", "System", "Volumes"]
