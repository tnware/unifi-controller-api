from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union


@dataclass
class UnifiNetworkConf:
    """Represents a network configuration (LAN, VLAN, etc.) from UniFi."""

    _id: str
    name: str
    site_id: str
    enabled: bool
    purpose: str  # e.g., 'corporate', 'vlan-only', 'guest'

    # Common optional fields
    is_nat: Optional[bool] = None
    vlan_enabled: Optional[bool] = None
    vlan: Optional[Union[str, int]] = None  # Can be string or int
    networkgroup: Optional[str] = None  # e.g., 'LAN', 'WAN', 'VPN'
    igmp_snooping: Optional[bool] = None
    dhcpguard_enabled: Optional[bool] = None
    mdns_enabled: Optional[bool] = None

    # Corporate network specific fields (often present when purpose='corporate')
    ip_subnet: Optional[str] = None
    domain_name: Optional[str] = None
    dhcpd_enabled: Optional[bool] = None
    dhcpd_start: Optional[str] = None
    dhcpd_stop: Optional[str] = None
    dhcpd_leasetime: Optional[int] = None  # Seconds
    dhcpd_gateway_enabled: Optional[bool] = None
    dhcpd_dns_enabled: Optional[bool] = None
    dhcpd_dns_1: Optional[str] = None
    dhcpd_dns_2: Optional[str] = None
    dhcp_relay_enabled: Optional[bool] = None
    lte_lan_enabled: Optional[bool] = None
    auto_scale_enabled: Optional[bool] = None

    # Attributes (often present)
    attr_hidden_id: Optional[str] = None
    attr_no_delete: Optional[bool] = None

    # Less common / potentially new fields
    setting_preference: Optional[str] = None  # e.g., 'manual'
    dhcpd_time_offset_enabled: Optional[bool] = None

    # Store any extra fields not explicitly defined
    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass instance to a dictionary for API responses."""
        data = {k: v for k, v in self.__dict__.items(
        ) if not k.startswith('_') and v is not None}
        # Include fields that start with '_' but are not '_extra_fields' (like _id)
        if hasattr(self, '_id'):
            data['_id'] = self._id
        return data
