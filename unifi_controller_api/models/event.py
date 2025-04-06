from dataclasses import dataclass, field, fields
from typing import Optional, Dict, Any


@dataclass
class UnifiEvent:
    """Represents a single event entry from the UniFi Controller API (/api/s/<site_name>/stat/event)."""
    _id: str
    key: str
    time: int
    datetime: str
    msg: str
    site_id: str
    subsystem: Optional[str] = None
    is_admin: Optional[bool] = None
    admin: Optional[str] = None
    ip: Optional[str] = None
    is_negative: Optional[bool] = None

    _extra_fields: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        """Ensure timestamp is integer."""
        if isinstance(self.time, str):
            try:
                self.time = int(self.time)
            except ValueError:
                self.time = 0
        elif not isinstance(self.time, int):
            self.time = 0

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass instance to a dictionary."""
        data = {f.name: getattr(self, f.name)
                for f in fields(self) if f.name != '_extra_fields'}
        data.update(self._extra_fields)
        return data
