
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ZeekEvent:
    """Normalized representation of a Zeek log event."""

    timestamp: float
    log_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    uid: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "timestamp": self.timestamp,
            "log_type": self.log_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "uid": self.uid,
            "metadata": self.metadata,
        }
