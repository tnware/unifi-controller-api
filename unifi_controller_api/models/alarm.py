from dataclasses import dataclass, field, fields
from typing import Optional, Dict, Any


@dataclass
class UnifiAlarm:
    """Represents a single alarm entry from the UniFi Controller API (/api/s/<site_name>/stat/alarm)."""
    _id: str
    key: str
    time: int
    datetime: str
    msg: str
    site_id: str
    archived: Optional[bool] = None
    subsystem: Optional[str] = None
    is_negative: Optional[bool] = None

    usable_bytes: Optional[int] = None
    total_bytes: Optional[int] = None

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
