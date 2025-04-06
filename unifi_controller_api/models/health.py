"""
Models for UniFi health data and related objects.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class UnifiSubsystemHealth:
    """
    Represents health data for a specific UniFi subsystem.

    Subsystems can include: wlan, lan, vpn, www, wan, etc.
    Each subsystem can have different metrics, but they all share
    a common "status" indicator.
    """
    subsystem: str
    status: Optional[str] = None

    num_user: Optional[int] = None
    num_guest: Optional[int] = None
    num_iot: Optional[int] = None
    tx_bytes_r: Optional[int] = field(
        default=None, metadata={"unifi_api_field": "tx_bytes-r"})
    rx_bytes_r: Optional[int] = field(
        default=None, metadata={"unifi_api_field": "rx_bytes-r"})

    num_ap: Optional[int] = None

    num_sw: Optional[int] = None

    num_gw: Optional[int] = None

    num_adopted: Optional[int] = None
    num_disabled: Optional[int] = None
    num_disconnected: Optional[int] = None
    num_pending: Optional[int] = None

    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values and internal fields."""
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith('_') and value is not None:
                result[key] = value
        return result


@dataclass
class UnifiHealth:
    """
    Represents comprehensive health data for a UniFi site.

    This acts as a container for all subsystem health data associated
    with a specific site.
    """
    site_name: str
    subsystems: Dict[str, UnifiSubsystemHealth] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with subsystems expanded to dictionaries."""
        result = {
            "site_name": self.site_name
        }

        for name, subsystem in self.subsystems.items():
            result[name] = subsystem.to_dict()

        return result

    def add_subsystem(self, subsystem: UnifiSubsystemHealth) -> None:
        """Add a subsystem to this health object."""
        if subsystem.subsystem:
            self.subsystems[subsystem.subsystem] = subsystem
