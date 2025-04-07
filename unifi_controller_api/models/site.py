"""
Models for UniFi sites and related objects.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict
from ..logging import get_logger

logger = get_logger(__name__)


@dataclass
class UnifiSite:
    """
    Represents a UniFi site.

    A site in UniFi represents a logical grouping of devices and network segments,
    typically representing a physical location or organization.
    """
    # Basic site identification
    name: str
    desc: Optional[str] = None
    health: Optional[List[Dict[str, Any]]] = None

    # Additional site fields from API
    _id: Optional[str] = None
    anonymous_id: Optional[str] = None
    attr_hidden_id: Optional[str] = None
    attr_no_delete: Optional[bool] = None
    num_new_alarms: Optional[int] = None
    role: Optional[str] = None
    device_count: Optional[int] = None

    # Store any extra fields that aren't explicitly defined
    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def get_subsystem(self, subsystem_name: str) -> Optional[Dict[str, Any]]:
        """
        Get data for a specific subsystem by name.

        Args:
            subsystem_name: Name of the subsystem to retrieve

        Returns:
            Subsystem data dictionary if found, None otherwise
        """
        if not self.health:
            return None

        if isinstance(self.health, list):
            for subsystem_data in self.health:
                if isinstance(subsystem_data, dict) and subsystem_data.get('subsystem') == subsystem_name:
                    return subsystem_data
        return None

    def get_wlan_metric(self, metric_name: str) -> Optional[Any]:
        """
        Get a specific metric from the WLAN subsystem health data.

        Args:
            metric_name: Name of the metric to retrieve

        Returns:
            The metric value if found, None otherwise
        """
        wlan_data = self.get_subsystem('wlan')
        if wlan_data and metric_name in wlan_data:
            return wlan_data[metric_name]
        return None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the UnifiSite to a dictionary.

        Returns:
            Dictionary representation of the site with all fields.
        """
        return {k: v for k, v in self.__dict__.items() if v is not None}
