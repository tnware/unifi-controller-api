from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class UnifiRogueAp:
    """Represents a neighboring or potentially rogue access point detected by UniFi."""

    _id: str
    ap_mac: str  # MAC of the UniFi AP that detected this neighbor
    bssid: str  # MAC of the neighboring AP
    band: str  # e.g., 'ng', 'na', 'ac'
    bw: int  # Bandwidth, e.g., 20, 40, 80
    channel: int
    essid: str  # SSID of the neighboring AP
    freq: int  # Frequency in MHz
    is_adhoc: bool
    is_rogue: bool  # Flagged as rogue by the controller?
    is_ubnt: bool  # Is it a Ubiquiti device?
    last_seen: int  # Unix timestamp
    noise: int  # Noise floor in dBm (negative value)
    oui: str  # Manufacturer OUI based on BSSID
    radio: str  # Radio type, e.g., 'ng', 'na'
    radio_name: str  # Radio identifier on the detecting UniFi AP, e.g., 'wifi0', 'wifi1'
    report_time: int  # Unix timestamp when the report was generated
    # Received Signal Strength Indicator (positive value, higher is better, relative to noise)
    rssi: int
    rssi_age: int  # Age of RSSI reading in seconds since last update
    security: str  # e.g., "WPA2 (AES/CCMP)"
    # Signal strength in dBm (negative value, closer to 0 is better)
    signal: int
    site_id: str

    # Optional fields that might not always be present
    center_freq: Optional[int] = None
    age: Optional[int] = None  # Often seems redundant with rssi_age

    # Store any extra fields not explicitly defined
    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass instance to a dictionary for API responses."""
        data = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        # Include fields that start with '_' but are not '_extra_fields' (like _id)
        if hasattr(self, '_id'):
            data['_id'] = self._id
        return data
