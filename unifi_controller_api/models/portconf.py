from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class UnifiPortConf:
    """
    Represents a UniFi switch port profile configuration.

    Port profiles define settings that can be applied to switch ports, including
    operation mode, PoE settings, VLAN configurations, and security controls.
    """

    # Basic identification
    _id: Optional[str] = None
    name: Optional[str] = None
    site_id: Optional[str] = None

    # General port settings
    setting_preference: Optional[str] = None  # 'auto' or 'manual'
    op_mode: Optional[str] = None  # 'switch', etc.
    autoneg: Optional[bool] = None  # Auto-negotiation enabled

    # PoE settings
    poe_mode: Optional[str] = None  # 'auto', 'off', etc.

    # Network configuration
    forward: Optional[str] = None  # 'native', 'customize'
    native_networkconf_id: Optional[str] = None  # Primary/native network
    voice_networkconf_id: Optional[str] = None  # Voice VLAN
    excluded_networkconf_ids: List[str] = field(
        default_factory=list)  # Excluded VLANs

    # Port security settings
    isolation: Optional[bool] = None  # Port isolation
    dot1x_ctrl: Optional[str] = None  # 802.1X control mode
    dot1x_idle_timeout: Optional[int] = None  # 802.1X idle timeout

    # Storm control
    stormctrl_bcast_enabled: Optional[bool] = None
    stormctrl_bcast_rate: Optional[int] = None
    stormctrl_mcast_enabled: Optional[bool] = None
    stormctrl_mcast_rate: Optional[int] = None
    stormctrl_ucast_enabled: Optional[bool] = None
    stormctrl_ucast_rate: Optional[int] = None

    # Rate limiting
    egress_rate_limit_kbps_enabled: Optional[bool] = None
    egress_rate_limit_kbps: Optional[int] = None

    # Spanning Tree Protocol
    stp_port_mode: Optional[bool] = None

    # LLDP-MED settings
    lldpmed_enabled: Optional[bool] = None
    lldpmed_notify_enabled: Optional[bool] = None

    # Extra fields not explicitly defined
    _extra_fields: Dict[str, Any] = field(default_factory=dict)
