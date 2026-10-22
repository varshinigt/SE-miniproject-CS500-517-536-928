from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class NormalizedRecord:
    timestamp: float
    interface: str
    link_type: str
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "UNKNOWN"
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
