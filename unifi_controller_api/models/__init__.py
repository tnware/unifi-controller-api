"""
Type definitions for UniFi Controller API objects.

This package contains dataclass models for all UniFi objects returned by the API.
"""

from .device import UnifiDevice, LLDPEntry
from .site import UnifiSite
from .client import UnifiClient

__all__ = [
    "UnifiDevice",
    "LLDPEntry",
    "UnifiSite",
    "UnifiClient",
]
