"""
ARP Spoofing and Cache Poisoning Detector
Monitors ARP traffic to detect:
1. IP-to-MAC address mapping conflicts (one IP claimed by multiple distinct MACs).
2. Gratuitous / Unsolicited ARP reply floods used by MITM tools (e.g., arpspoof, ettercap).
"""

from collections import defaultdict, deque
from typing import Dict, List, Optional
from .base import BaseDetector
from ..models import NormalizedRecord, Alert, ThreatType, Severity


class ArpSpoofDetector(BaseDetector):
    """
    Detects ARP Cache Poisoning (Man-in-the-Middle) attacks.
    Maintains a dynamic IP-MAC binding table and watches for conflicts and reply floods.
    """

    def __init__(
        self,
        name: str = "arp_spoof_detector",
        enabled: bool = True,
        flood_threshold: int = 5,
        flood_window_seconds: float = 3.0,
    ):
        super().__init__(name=name, enabled=enabled)
        # Dynamic IP -> MAC binding table {ip: mac}
        self.ip_mac_table: Dict[str, str] = {}
        # Track ARP reply timestamps per MAC for flood detection {mac: deque([timestamps])}
        self.reply_history: Dict[str, deque] = defaultdict(deque)
        # Thresholds
        self.flood_threshold = flood_threshold
        self.flood_window_seconds = flood_window_seconds

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """Inspect ARP packets for conflicts or high-rate gratuitous floods."""
        if not self.enabled or record is None:
            return []

        # Only inspect ARP traffic on Ethernet / WiFi link types
        if record.protocol != "ARP" or not record.src_ip or not record.src_mac:
            return []

        alerts: List[Alert] = []
        claimed_ip = record.src_ip.strip()
        sender_mac = record.src_mac.strip().lower()
        metadata = record.metadata or {}
        arp_op = metadata.get("arp_op", 2)  # 1 = Request, 2 = Reply

        # 1. Check for IP-MAC Conflict (Cache Poisoning)
        if claimed_ip in self.ip_mac_table:
            original_mac = self.ip_mac_table[claimed_ip]
            if original_mac != sender_mac:
                alert = Alert(
                    threat_type=ThreatType.ARP_SPOOFING,
                    severity=Severity.CRITICAL,
                    title="ARP Cache Poisoning Detected",
                    description=(
                        f"Host with MAC {sender_mac} is claiming IP {claimed_ip}, "
                        f"which was previously associated with MAC {original_mac}."
                    ),
                    source_interface=record.interface,
                    evidence={
                        "detection_type": "IP_MAC_CONFLICT",
                        "claimed_ip": claimed_ip,
                        "original_mac": original_mac,
                        "spoofed_mac": sender_mac,
                        "timestamp": record.timestamp,
                    },
                    mitigation=(
                        f"Isolate switch port or disconnect device {sender_mac}. "
                        f"Enable Dynamic ARP Inspection (DAI) on the switch."
                    ),
                    timestamp=record.timestamp,
                )
                alerts.append(alert)
                # Note: We keep the original binding intact to prevent attacker from overwriting
        else:
            # First time seeing this IP: establish the baseline binding
            self.ip_mac_table[claimed_ip] = sender_mac

        # 2. Check for ARP Reply Flooding (typical of rapid MITM poisoning engines)
        if arp_op in (2, "reply", "REPLY"):
            timestamps = self.reply_history[sender_mac]
            timestamps.append(record.timestamp)

            # Evict timestamps older than sliding window
            cutoff = record.timestamp - self.flood_window_seconds
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.flood_threshold:
                alert = Alert(
                    threat_type=ThreatType.ARP_SPOOFING,
                    severity=Severity.HIGH,
                    title="Suspicious ARP Reply Flood Detected",
                    description=(
                        f"Host {sender_mac} transmitted {len(timestamps)} ARP replies "
                        f"within {self.flood_window_seconds}s (threshold: {self.flood_threshold})."
                    ),
                    source_interface=record.interface,
                    evidence={
                        "detection_type": "ARP_REPLY_FLOOD",
                        "sender_mac": sender_mac,
                        "reply_count": len(timestamps),
                        "window_seconds": self.flood_window_seconds,
                        "timestamp": record.timestamp,
                    },
                    mitigation=(
                        f"Check host {sender_mac} for active MITM poisoning tools (arpspoof/ettercap). "
                        f"Apply rate limiting for ARP replies on switch interfaces."
                    ),
                    timestamp=record.timestamp,
                )
                alerts.append(alert)
                # Clear history to avoid re-triggering on every subsequent packet in the same burst
                timestamps.clear()

        return alerts

    def reset(self) -> None:
        """Clear all active bindings and timestamp queues."""
        self.ip_mac_table.clear()
        self.reply_history.clear()
