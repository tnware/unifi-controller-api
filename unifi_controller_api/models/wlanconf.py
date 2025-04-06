from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class UnifiWlanConf:
    """
    Represents a WLAN configuration entry from the UniFi Controller API.

    Attributes:
        _id: Unique identifier for the WLAN configuration.
        name: The SSID (network name) of the WLAN.
        site_id: Identifier of the site this WLAN belongs to.
        enabled: Whether the WLAN is currently active.
        security: Security mode (e.g., 'wpapsk').
        wpa_mode: WPA mode (e.g., 'wpa2').
        wpa_enc: WPA encryption type (e.g., 'ccmp').
        wpa3_support: Whether WPA3 is supported.
        wpa3_transition: Whether WPA3 transition mode is enabled.
        pmf_mode: Protected Management Frames mode (e.g., 'disabled', 'optional', 'required').
        x_passphrase: The WPA pre-shared key (password). Will be masked in dict output.
        wlan_band: The primary band ('ng', 'na', 'both'). Deprecated in newer controllers?
        wlan_bands: List of bands the WLAN operates on (e.g., ['2g', '5g']).
        hide_ssid: Whether the SSID is hidden.
        networkconf_id: Identifier for the associated network configuration.
        usergroup_id: Identifier for the user group associated with this WLAN.
        ap_group_ids: List of AP group IDs this WLAN is restricted to (if any).
        schedule_enabled: Whether a schedule is enabled for this WLAN.
        schedule: List of schedule rules (usually empty if schedule_enabled is False).
        l2_isolation: Whether Layer 2 isolation is enabled.
        mcastenhance_enabled: Whether multicast enhancement (IGMPv3) is enabled.
        proxy_arp: Whether proxy ARP is enabled.
        bss_transition: Whether BSS Transition (802.11v) is enabled.
        fast_roaming_enabled: Whether Fast Roaming (802.11r) is enabled.
        optimize_iot_wifi_connectivity: Whether IoT optimization is enabled.
        minrate_setting_preference: Min rate setting preference ('auto' or 'manual').
        minrate_na_enabled: Whether minimum data rate control is enabled for 5GHz.
        minrate_na_data_rate_kbps: Minimum data rate for 5GHz in Kbps.
        minrate_ng_enabled: Whether minimum data rate control is enabled for 2.4GHz.
        minrate_ng_data_rate_kbps: Minimum data rate for 2.4GHz in Kbps.
        mac_filter_enabled: Whether MAC filtering is enabled.
        mac_filter_policy: MAC filter policy ('allow' or 'deny').
        mac_filter_list: List of MAC addresses for filtering.
        # Add other fields as needed from the JSON structure
        setting_preference: Optional[str] = None
        dtim_6e: Optional[int] = None
        dtim_na: Optional[int] = None
        dtim_ng: Optional[int] = None
        dtim_mode: Optional[str] = None
        minrate_na_advertising_rates: Optional[bool] = None
        minrate_ng_advertising_rates: Optional[bool] = None
        b_supported: Optional[bool] = None # Legacy 802.11b support
        radius_das_enabled: Optional[bool] = None
        group_rekey: Optional[int] = None # Group rekey interval in seconds
        radius_macacl_format: Optional[str] = None
        bc_filter_enabled: Optional[bool] = None # Broadcast filter enabled
        bc_filter_list: List[str] = field(default_factory=list)
        iapp_enabled: Optional[bool] = None # Inter-Access Point Protocol (802.11f)
        uapsd_enabled: Optional[bool] = None # Unscheduled Automatic Power Save Delivery
        no2ghz_oui: Optional[bool] = None
        x_iapp_key: Optional[str] = None
        wep_idx: Optional[int] = None # WEP key index (only relevant for WEP security)
        wpa3_fast_roaming: Optional[bool] = None
        radius_mac_auth_enabled: Optional[bool] = None
        wpa3_enhanced_192: Optional[bool] = None
        _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False) # Store unmapped fields

    """
    _id: str
    name: str
    site_id: str
    enabled: bool
    security: str
    wpa_mode: str
    wpa_enc: str
    wpa3_support: bool
    wpa3_transition: bool
    pmf_mode: str
    hide_ssid: bool
    networkconf_id: str
    usergroup_id: str
    schedule_enabled: bool
    l2_isolation: bool
    mcastenhance_enabled: bool
    proxy_arp: bool
    bss_transition: bool
    fast_roaming_enabled: bool
    optimize_iot_wifi_connectivity: bool
    minrate_setting_preference: str
    minrate_na_enabled: bool
    minrate_na_data_rate_kbps: int
    minrate_ng_enabled: bool
    minrate_ng_data_rate_kbps: int
    mac_filter_enabled: bool
    mac_filter_policy: str

    x_passphrase: Optional[str] = None
    wlan_band: Optional[str] = None
    wlan_bands: List[str] = field(default_factory=list)
    ap_group_ids: List[str] = field(default_factory=list)
    schedule: List[Dict[str, Any]] = field(default_factory=list)
    mac_filter_list: List[str] = field(default_factory=list)
    setting_preference: Optional[str] = None
    dtim_6e: Optional[int] = None
    dtim_na: Optional[int] = None
    dtim_ng: Optional[int] = None
    dtim_mode: Optional[str] = 'default'
    minrate_na_advertising_rates: Optional[bool] = None
    minrate_ng_advertising_rates: Optional[bool] = None
    b_supported: Optional[bool] = None
    radius_das_enabled: Optional[bool] = None
    group_rekey: Optional[int] = 3600
    radius_macacl_format: Optional[str] = 'none_lower'
    bc_filter_enabled: Optional[bool] = False
    bc_filter_list: List[str] = field(default_factory=list)
    iapp_enabled: Optional[bool] = None
    uapsd_enabled: Optional[bool] = False
    no2ghz_oui: Optional[bool] = None
    x_iapp_key: Optional[str] = None
    wep_idx: Optional[int] = 1
    wpa3_fast_roaming: Optional[bool] = None
    radius_mac_auth_enabled: Optional[bool] = False
    wpa3_enhanced_192: Optional[bool] = False

    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass instance to a dictionary, masking the passphrase."""
        data = self.__dict__.copy()
        if data.get('x_passphrase'):
            data['x_passphrase'] = '********'
        data.pop('_extra_fields', None)
        return data

    def __post_init__(self):
        """Handle potential type inconsistencies after initialization."""
        if self.wlan_bands is None:
            self.wlan_bands = []
        if self.ap_group_ids is None:
            self.ap_group_ids = []
        if self.schedule is None:
            self.schedule = []
        if self.mac_filter_list is None:
            self.mac_filter_list = []
        if self.bc_filter_list is None:
            self.bc_filter_list = []
