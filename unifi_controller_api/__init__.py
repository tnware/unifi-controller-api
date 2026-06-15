"""
UniFi Controller API client for interacting with UniFi Controller API.

This package provides a Python interface to the UniFi Controller API,
allowing read-only access to sites, devices, and other network information.
"""

from .api_client import UnifiController
from .models import (
    UnifiSite, UnifiDevice, LLDPEntry, UnifiClient,
    UnifiEvent, UnifiAlarm, UnifiWlanConf, UnifiRogueAp, UnifiNetworkConf,
    UnifiFirewallRule
)
from .export import export_csv, export_json, to_dict_list
from .exceptions import (
    UnifiControllerError,
    UnifiAuthenticationError,
    UnifiAPIError,
    UnifiDataError,
    UnifiModelError
)

__all__ = [
    "UnifiController",
    "UnifiSite",
    "UnifiDevice",
    "LLDPEntry",
    "UnifiClient",
    "UnifiEvent",
    "UnifiAlarm",
    "UnifiWlanConf",
    "UnifiRogueAp",
    "UnifiNetworkConf",
    "UnifiFirewallRule",
    "export_csv",
    "export_json",
    "to_dict_list",
    "UnifiControllerError",
    "UnifiAuthenticationError",
    "UnifiAPIError",
    "UnifiDataError",
    "UnifiModelError",
]
