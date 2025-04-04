"""
Models for UniFi sites and related objects.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict
from ..logging import get_logger
from ..utils import map_api_data_to_model

logger = get_logger(__name__)


class WLANMetrics(TypedDict, total=False):
    """Type definition for WLAN metrics from the UniFi API."""
    status: str
    num_user: int
    num_guest: int
    num_iot: int
    tx_bytes_r: int  # Maps to 'tx_bytes-r' in API
    rx_bytes_r: int  # Maps to 'rx_bytes-r' in API
    num_ap: int
    num_adopted: int
    num_disabled: int
    num_disconnected: int
    num_pending: int


@dataclass
class UnifiSite:
    """
    Represents a UniFi site.

    A site in UniFi represents a logical grouping of devices and network segments,
    typically representing a physical location or organization.

    Field Mapping:
    This class uses Pythonic attribute names (with underscores) while the UniFi API
    uses hyphenated field names. The mapping is handled through field metadata.
    For example:
    - API field 'tx_bytes-r' → Python attribute 'tx_bytes_r'
    - API field 'rx_bytes-r' → Python attribute 'rx_bytes_r'
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

    # Health metrics from WLAN subsystem
    status: Optional[str] = None
    num_user: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_user"})
    num_guest: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_guest"})
    num_iot: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_iot"})
    num_ap: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_ap"})
    num_adopted: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_adopted"})
    num_disabled: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_disabled"})
    num_disconnected: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_disconnected"})
    num_pending: Optional[int] = field(default=None, metadata={"unifi_api_field": "num_pending"})
    tx_bytes_r: Optional[int] = field(default=None, metadata={"unifi_api_field": "tx_bytes-r"})
    rx_bytes_r: Optional[int] = field(default=None, metadata={"unifi_api_field": "rx_bytes-r"})

    # Site health subsystems
    subsystems: Optional[Dict[str, Any]] = None

    # Store any extra fields that aren't explicitly defined
    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        """
        Process the site data after initialization.

        This extracts health metrics from the health field if present.
        The health data can be in two formats:
        1. A list of subsystem data dictionaries
        2. A single dictionary with direct metrics and optional subsystem list
        """
        if not self.health:
            return

        # Initialize subsystems dict if we have health data to process
        self.subsystems = {}

        # Handle different health data formats
        if isinstance(self.health, dict):
            # Handle health data as a single dictionary
            # First extract any direct metrics from the health dictionary itself
            self._extract_wlan_metrics(self.health)

            # Then handle subsystems if present
            subsystems = self.health.get('subsystem')
            if isinstance(subsystems, list):
                for subsystem_data in subsystems:
                    if isinstance(subsystem_data, dict) and 'subsystem' in subsystem_data:
                        subsystem_name = subsystem_data['subsystem']
                        self.subsystems[subsystem_name] = {k: v for k, v in subsystem_data.items()
                                                           if k != 'subsystem'}
                        # Extract metrics from this subsystem if it's WLAN
                        if subsystem_name == 'wlan':
                            self._extract_wlan_metrics(subsystem_data)
        elif isinstance(self.health, list):
            # API format: health is a list of subsystems
            for subsystem_data in self.health:
                if isinstance(subsystem_data, dict) and 'subsystem' in subsystem_data:
                    subsystem_name = subsystem_data['subsystem']
                    self.subsystems[subsystem_name] = {k: v for k, v in subsystem_data.items()
                                                       if k != 'subsystem'}
                    # Extract metrics from this subsystem if it's WLAN
                    if subsystem_name == 'wlan':
                        self._extract_wlan_metrics(subsystem_data)

    def _extract_wlan_metrics(self, data: Dict[str, Any]) -> None:
        """
        Extract WLAN metrics from a data dictionary using map_api_data_to_model.
        
        Args:
            data: Dictionary containing WLAN metrics from the UniFi API
        """
        if not isinstance(data, dict):
            logger.warning(f"Expected dict for WLAN metrics, got {type(data)}")
            return

        # Use map_api_data_to_model to handle field mapping
        model_fields, extra_fields = map_api_data_to_model(data, type(self))
        
        # Update instance with mapped fields
        for field_name, value in model_fields.items():
            setattr(self, field_name, value)

        # Store any extra fields
        self._extra_fields.update(extra_fields)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the UnifiSite to a dictionary.

        Returns:
            Dictionary representation of the site with all fields.
        """
        return {k: v for k, v in self.__dict__.items() if v is not None}
