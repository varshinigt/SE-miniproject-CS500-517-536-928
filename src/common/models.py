from dataclasses import dataclass
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

    # ── SRS Table B.1 aliases ────────────────────────────────────────────────

    @property
    def payload_len(self) -> int:
        """SRS Table B.1 read alias for ``length``."""
        return self.length

    @property
    def metadata(self) -> dict[str, Any]:
        """
        SRS Table B.1 alias for ``details``.

        Auto-initialises ``details`` to an empty dict on first access so that
        in-place mutations (``record.metadata["key"] = val``) are never lost.
        """
        if self.details is None:
            self.details = {}
        return self.details

    @metadata.setter
    def metadata(self, value: dict[str, Any]) -> None:
        """Allow ``record.metadata = {...}`` to propagate to ``details``."""
        self.details = value

    # ── Serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict using SRS Table B.1 field names."""
        return {
            "timestamp": self.timestamp,
            "interface": self.interface,
            "link_type": self.link_type,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_len": self.length,
            "metadata": self.details if self.details is not None else {},
        }
