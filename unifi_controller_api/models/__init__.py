"""
Data models for UniFi Controller API responses.

.. warning::
    The dataclasses defined in this module represent commonly observed fields in the
    UniFi Controller's **undocumented** private API responses. However, the actual
    data structure returned by the API can vary significantly based on:

    *   Controller version
    *   Device model
    *   Firmware version
    *   Specific device configuration

    Therefore, these models should be treated as **suggestions** rather than strict schemas.
    Fields defined in the models may be missing from the actual API response, and the
    response may contain additional, undocumented fields.

    When using API client methods with `raw=False`:

    *   Missing fields will typically result in the dataclass attribute having a default
        value (often `None`).
    *   Unexpected or undocumented fields returned by the API will be captured in the
        `_extra_fields` dictionary attribute on the dataclass instance (if the dataclass
        inherits from a base class that supports this, like potentially a future
        `BaseUnifiModel`).

    It is recommended to handle potential `AttributeError` exceptions or check for `None`
    values when accessing dataclass attributes, and to inspect `_extra_fields` if you
    need to access data not explicitly defined in the models.

    For guaranteed access to the exact data returned by the controller, use the API
    client methods with the default `raw=True` setting, which returns raw dictionaries.
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
