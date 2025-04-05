from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class UnifiClient:
    """Represents a client (user device) connected to the UniFi network (using dataclass, raw types)."""
    _id: str
    mac: str
    site_id: str
    oui: Optional[str] = None
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    disconnect_timestamp: Optional[int] = None
    ip: Optional[str] = None
    is_guest: Optional[bool] = None
    is_wired: Optional[bool] = None
    hostname: Optional[str] = None
    name: Optional[str] = None
    noted: Optional[bool] = None
    note: Optional[str] = None
    usergroup_id: Optional[str] = None
    network_id: Optional[str] = None
    fixed_ip: Optional[str] = None
    wlanconf_id: Optional[str] = None

    # _extra_fields: Dict[str, Any] = field(default_factory=dict)
