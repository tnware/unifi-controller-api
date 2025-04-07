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
from .rogueap import UnifiRogueAp
from .networkconf import UnifiNetworkConf
from .health import UnifiHealth, UnifiSubsystemHealth
from .portconf import UnifiPortConf

__all__ = [
    "UnifiDevice",
    "LLDPEntry",
    "UnifiSite",
    "UnifiClient",
    "UnifiEvent",
    "UnifiAlarm",
    "UnifiWlanConf",
    "UnifiRogueAp",
    "UnifiNetworkConf",
    "UnifiHealth",
    "UnifiSubsystemHealth",
    "UnifiPortConf"
]
