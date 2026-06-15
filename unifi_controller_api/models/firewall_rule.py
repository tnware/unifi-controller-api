from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


@dataclass
class UnifiFirewallRule:
    """Represents a UniFi firewall rule.

    UniFi Network firewall rule payloads vary by controller version. Common
    fields are modeled directly and any unrecognized fields are preserved in
    ``_extra_fields`` when mapping API responses with ``raw=False``.
    """

    _id: Optional[str] = None
    name: Optional[str] = None
    site_id: Optional[str] = None
    enabled: Optional[bool] = None
    action: Optional[str] = None
    ruleset: Optional[str] = None
    rule_index: Optional[Union[int, str]] = None
    protocol: Optional[str] = None
    protocol_v6: Optional[str] = None
    dst_port: Optional[str] = None
    src_port: Optional[str] = None
    dst_address: Optional[str] = None
    src_address: Optional[str] = None
    dst_address_ipv6: Optional[str] = None
    src_address_ipv6: Optional[str] = None
    dst_networkconf_id: Optional[str] = None
    src_networkconf_id: Optional[str] = None
    dst_networkconf_type: Optional[str] = None
    src_networkconf_type: Optional[str] = None
    dst_firewallgroup_ids: Optional[List[str]] = None
    src_firewallgroup_ids: Optional[List[str]] = None
    src_mac_address: Optional[str] = None
    logging: Optional[bool] = None
    state_established: Optional[bool] = None
    state_invalid: Optional[bool] = None
    state_new: Optional[bool] = None
    state_related: Optional[bool] = None
    ipsec: Optional[str] = None
    icmp_typename: Optional[str] = None
    icmpv6_typename: Optional[str] = None
    setting_preference: Optional[str] = None
    attr_hidden: Optional[bool] = None
    attr_hidden_id: Optional[str] = None
    attr_no_delete: Optional[bool] = None
    attr_no_edit: Optional[bool] = None

    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the dataclass instance to a dictionary for API payloads."""
        data = {
            k: v
            for k, v in self.__dict__.items()
            if not k.startswith("_") and v is not None
        }
        if self._id is not None:
            data["_id"] = self._id
        data.update(self._extra_fields)
        return data
