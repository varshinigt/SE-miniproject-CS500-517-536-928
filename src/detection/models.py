"""
F3 Threat Detection Data Models
Defines standard schemas for incoming normalized packets and outgoing security alerts.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
import uuid


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    ARP_SPOOFING = "ARP_SPOOFING"
    PORT_SCAN = "PORT_SCAN"
    DNS_ANOMALY = "DNS_ANOMALY"
    WIFI_DEAUTH = "WIFI_DEAUTH"
    ROGUE_AP = "ROGUE_AP"
    BLE_FLOOD = "BLE_FLOOD"


@dataclass
class NormalizedRecord:
    """
    Standard data contract ingested from F2 (Protocol Parser).
    Regardless of whether traffic is Ethernet, WiFi, or BLE, F2 maps
    it to this unified record so F3 can inspect it seamlessly.
    """
    timestamp: float                       # Epoch timestamp in seconds
    interface: str                         # Interface e.g. 'eth0', 'wlan0mon', 'hci0'
    link_type: str                         # 'ETHERNET', 'WIFI', 'BLE'
    src_mac: Optional[str] = None          # MAC address if available (e.g. 'aa:bb:cc:dd:ee:ff')
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None           # IP address if L3 exists (e.g. '192.168.1.50')
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None         # 'ARP', 'TCP', 'UDP', 'ICMP', 'DNS', '802.11', 'BLE'
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload_len: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)  # Protocol-specific fields (e.g., arp_op, wifi_subtype)


@dataclass
class Alert:
    """
    Standard alert schema produced by F3 detection engine,
    consumed by F4 (Dashboard) and logged into database/alerts.json.
    """
    threat_type: ThreatType
    severity: Severity
    title: str
    description: str
    source_interface: str
    evidence: Dict[str, Any]
    mitigation: str
    timestamp: float = field(default_factory=lambda: datetime.utcnow().timestamp())
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert object to dictionary for JSON/WebSocket serialization."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_interface": self.source_interface,
            "evidence": self.evidence,
            "mitigation": self.mitigation,
        }
