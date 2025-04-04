"""
Models for UniFi devices and related objects.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LLDPEntry:
    """
    LLDP (Link Layer Discovery Protocol) information entry for a device port.

    Contains information about connected neighbors discovered via LLDP.
    """
    chassis_descr: Optional[str] = None
    chassis_id: Optional[str] = None
    chassis_id_subtype: Optional[str] = None
    local_port_idx: Optional[int] = None
    local_port_name: Optional[str] = None
    port_descr: Optional[str] = None
    port_id: Optional[str] = None
    power_allocated: Optional[int] = None
    power_requested: Optional[int] = None
    is_wired: Optional[bool] = None


@dataclass
class UnifiDevice:
    """
    Represents a UniFi network device.

    This class models a device managed by a UniFi controller, such as an access point,
    switch, gateway, or other UniFi device.
    """
    # Basic device identification
    mac: str
    name: Optional[str] = None
    ip: Optional[str] = None
    model: Optional[str] = None
    type: Optional[str] = None

    # Model and hardware information
    serial: Optional[str] = None
    model_in_lts: Optional[bool] = None
    model_in_eol: Optional[bool] = None
    model_incompatible: Optional[bool] = None
    manufacturer_id: Optional[str] = None
    board_rev: Optional[int] = None
    architecture: Optional[str] = None

    # UniFi controller identification
    _id: Optional[str] = None
    device_id: Optional[str] = None
    hash_id: Optional[str] = None
    site_id: Optional[str] = None
    anon_id: Optional[str] = None

    # Status information
    version: Optional[str] = None
    adopted: Optional[bool] = None
    last_seen: Optional[int] = None
    disconnected_at: Optional[int] = None
    uptime: Optional[int] = None
    state: Optional[int] = None
    disconnection_reason: Optional[str] = None
    connected_at: Optional[int] = None
    provisioned_at: Optional[int] = None
    upgrade_state: Optional[str] = None
    unsupported_reason: Optional[str] = None

    # Network information
    connect_request_ip: Optional[str] = None
    inform_ip: Optional[str] = None
    inform_url: Optional[str] = None
    gateway_mac: Optional[str] = None
    internet: Optional[bool] = None

    # Site information
    site_name: Optional[str] = None
    unifi_id: Optional[str] = None

    # Statistics fields with special mapping
    user_num_sta: Optional[int] = field(default=None, metadata={"unifi_api_field": "user-num_sta"})
    user_wlan_num_sta: Optional[int] = field(default=None, metadata={"unifi_api_field": "user-wlan-num_sta"})
    guest_num_sta: Optional[int] = field(default=None, metadata={"unifi_api_field": "guest-num_sta"})
    guest_wlan_num_sta: Optional[int] = field(default=None, metadata={"unifi_api_field": "guest-wlan-num_sta"})
    rx_bytes_r: Optional[int] = field(default=None, metadata={"unifi_api_field": "rx_bytes-r"})
    tx_bytes_r: Optional[int] = field(default=None, metadata={"unifi_api_field": "tx_bytes-r"})

    # Table data and capabilities
    port_table: Optional[List[Dict[str, Any]]] = None
    radio_table: Optional[List[Dict[str, Any]]] = None
    radio_table_stats: Optional[List[Dict[str, Any]]] = None
    vap_table: Optional[List[Dict[str, Any]]] = None
    ethernet_table: Optional[List[Dict[str, Any]]] = None
    uplink_table: Optional[List[Dict[str, Any]]] = None
    antenna_table: Optional[List[Dict[str, Any]]] = None
    scan_radio_table: Optional[List[Dict[str, Any]]] = None
    countrycode_table: Optional[List[Dict[str, Any]]] = None
    vwire_table: Optional[List[Dict[str, Any]]] = None
    config_network: Optional[Dict[str, Any]] = None
    lldp_info: List[LLDPEntry] = field(default_factory=list)
    lldp_table: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    fw_caps: Optional[int] = None
    hw_caps: Optional[int] = None
    wifi_caps: Optional[int] = None
    switch_caps: Optional[int] = None
    sys_error_caps: Optional[int] = None

    # Device features and settings
    in_gateway_mode: Optional[bool] = None
    vwireEnabled: Optional[bool] = None
    has_speaker: Optional[bool] = None
    has_eth1: Optional[bool] = None
    has_fan: Optional[bool] = None
    has_temperature: Optional[bool] = None
    outdoor_mode_override: Optional[bool] = None
    lcm_brightness_override: Optional[int] = None
    lcm_idle_timeout_override: Optional[int] = None
    led_override: Optional[bool] = None
    led_override_color: Optional[str] = None
    led_override_color_brightness: Optional[int] = None
    atf_enabled: Optional[bool] = None
    mesh_sta_vap_enabled: Optional[bool] = None
    dot1x_portctrl_enabled: Optional[bool] = None
    wlangroup_id_ng: Optional[str] = None
    fixed_ap_available: Optional[bool] = None
    two_phase_adopt: Optional[bool] = None

    # System information
    cfgversion: Optional[str] = None
    kernel_version: Optional[str] = None
    country_code: Optional[str] = None
    syslog_key: Optional[str] = None
    required_version: Optional[str] = None
    setup_id: Optional[str] = None
    license_state: Optional[str] = None

    # Security and authentication
    x_has_ssh_hostkey: Optional[bool] = None
    x_fingerprint: Optional[str] = None
    x_vwirekey: Optional[str] = None
    x_authkey: Optional[str] = None
    x_aes_gcm: Optional[bool] = None

    # Additional tracking fields
    upgrade_to_firmware: Optional[str] = None
    uplink: Optional[Dict[str, Any]] = None
    start_disconnected_millis: Optional[int] = None
    start_connected_millis: Optional[int] = None
    startup_timestamp: Optional[int] = None
    unsupported: Optional[bool] = None
    disabled: Optional[bool] = None

    # Optional display fields
    model_name: Optional[str] = None

    # Store any additional fields that aren't explicitly defined
    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        """
        Process object initialization.

        - Convert lldp_table to lldp_info if present
        - Ensure nested LLDP entries are properly typed
        """
        # Handle lldp_table to lldp_info conversion automatically
        if self.lldp_table and not self.lldp_info:
            self.lldp_info = [LLDPEntry(**entry) if isinstance(entry, dict) else entry
                              for entry in self.lldp_table]
            self.lldp_table = []  # Clear after conversion to avoid duplication

        # Ensure lldp_info contains proper LLDPEntry objects
        elif self.lldp_info and isinstance(self.lldp_info, list):
            if not all(isinstance(entry, LLDPEntry) for entry in self.lldp_info):
                self.lldp_info = [LLDPEntry(**entry) if isinstance(entry, dict) else entry
                                  for entry in self.lldp_info]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the UnifiDevice to a dictionary.

        Returns:
            Dictionary representation of the device with all fields.
        """
        # Start with the standard fields
        result = {k: v for k, v in self.__dict__.items()
                  if not k.startswith('_')}

        # Convert LLDP entries to dictionaries
        if result.get('lldp_info'):
            result['lldp_info'] = [entry.__dict__ for entry in self.lldp_info]

        # Add any extra fields
        if hasattr(self, '_extra_fields'):
            result.update(self._extra_fields)

        return result
