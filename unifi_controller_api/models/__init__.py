"""
Type definitions for UniFi Controller API objects.

This package contains dataclass models for all UniFi objects returned by the API.
"""

from .device import UnifiDevice, LLDPEntry
from .site import UnifiSite
from .client import UnifiClient
from .event import UnifiEvent
from .alarm import UnifiAlarm
from .wlanconf import UnifiWlanConf

__all__ = [
    "UnifiDevice",
    "LLDPEntry",
    "UnifiSite",
    "UnifiClient",
    "UnifiEvent",
    "UnifiAlarm",
    "UnifiWlanConf"
]
