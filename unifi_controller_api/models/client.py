from dataclasses import dataclass
from typing import Optional


@dataclass
class UnifiClient:
    """Represents a client (user device) connected to the UniFi network (using dataclass, raw types).

    Attributes:
        _id: Unique identifier for the client.
        mac: MAC address of the client.
        site_id: Identifier for the site the client is connected to.
        oui: Organizationally Unique Identifier.
        first_seen: Timestamp of when the client was first seen.
        last_seen: Timestamp of when the client was last seen.
        disconnect_timestamp: Timestamp of when the client was disconnected.
        ip: IP address assigned to the client.
        is_guest: Indicates if the client is a guest.
        is_wired: Indicates if the client is connected via wired connection.
        hostname: Hostname of the client.
        name: Name of the client.
        noted: Indicates if the client has been noted.
        note: Additional notes about the client.
        usergroup_id: Identifier for the user group.
        network_id: Identifier for the network.
        fixed_ip: Fixed IP address assigned to the client.
        wlanconf_id: Identifier for the WLAN configuration.
    """
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
