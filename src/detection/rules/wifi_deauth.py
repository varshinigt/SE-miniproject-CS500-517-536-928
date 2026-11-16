"""
WiFi Deauthentication and Disassociation Flood Detector
Monitors 802.11 wireless management traffic to detect:
1. Deauthentication frame floods (Subtype 12 / 0x0C)
2. Disassociation frame floods (Subtype 10 / 0x0A)
Commonly used in Wi-Fi denial-of-service and WPA handshake capture attacks (aireplay-ng).
"""

from collections import defaultdict, deque
from typing import Dict, List, Optional
from .base import BaseDetector
from ..models import NormalizedRecord, Alert, ThreatType, Severity


class WifiDeauthDetector(BaseDetector):
    """
    Detects 802.11 deauthentication and disassociation flood attacks.
    Maintains a sliding-time window of management frame counts indexed by BSSID/Client.
    """

    def __init__(
        self,
        name: str = "wifi_deauth_detector",
        enabled: bool = True,
        deauth_threshold: int = 10,
        window_seconds: float = 2.0,
    ):
        super().__init__(name=name, enabled=enabled)
        self.deauth_threshold = deauth_threshold
        self.window_seconds = window_seconds
        # Mapping: (bssid, client_mac) -> deque of frame timestamps
        self.frame_history: Dict[str, deque] = defaultdict(deque)

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """Inspect wireless frames for deauthentication/disassociation flooding."""
        if not self.enabled or record is None:
            return []

        # Check link type or protocol for WiFi 802.11 traffic
        is_wifi = (
            record.link_type == "WIFI"
            or record.protocol in ("802.11", "WIFI", "WIFI_DEAUTH", "WIFI_DISASSOC")
            or "wifi_subtype" in record.metadata
            or "frame_type" in record.metadata
        )
        if not is_wifi:
            return []

        metadata = record.metadata or {}
        subtype = metadata.get("wifi_subtype") or metadata.get("subtype")
        frame_type = str(metadata.get("frame_type", "")).lower()

        # Identify deauth (12) or disassoc (10)
        is_deauth = False
        action_name = "Deauthentication"

        if (
            subtype in (12, "12", "deauth", "DEAUTH")
            or "deauth" in frame_type
            or record.protocol == "WIFI_DEAUTH"
        ):
            is_deauth = True
            action_name = "Deauthentication"
        elif (
            subtype in (10, "10", "disassoc", "DISASSOC")
            or "disassoc" in frame_type
            or record.protocol == "WIFI_DISASSOC"
        ):
            is_deauth = True
            action_name = "Disassociation"

        if not is_deauth:
            return []

        # Target BSSID and Client MAC
        bssid = metadata.get("bssid") or record.dst_mac or "ff:ff:ff:ff:ff:ff"
        client_mac = metadata.get("client_mac") or record.src_mac or "unknown"
        target_key = f"{bssid.lower()}_{client_mac.lower()}"

        ts = record.timestamp
        history = self.frame_history[target_key]
        history.append(ts)

        # Evict timestamps outside sliding window
        cutoff = ts - self.window_seconds
        while history and history[0] < cutoff:
            history.popleft()

        # Evaluate threshold
        if len(history) >= self.deauth_threshold:
            count = len(history)
            # Drain window upon alert generation to prevent spamming duplicate alerts
            history.clear()

            alert = Alert(
                threat_type=ThreatType.WIFI_DEAUTH,
                severity=Severity.HIGH,
                title=f"WiFi {action_name} Flood Detected",
                description=(
                    f"Excessive {action_name.lower()} frames ({count} frames in <= {self.window_seconds}s) "
                    f"targeting BSSID {bssid} and client {client_mac}."
                ),
                source_interface=record.interface,
                evidence={
                    "bssid": bssid,
                    "client_mac": client_mac,
                    "frame_count": count,
                    "frame_type": action_name.lower(),
                    "window_seconds": self.window_seconds,
                    "timestamp": ts,
                    "reason_code": metadata.get("reason_code", 7),
                },
                mitigation=(
                    "Enable 802.11w Protected Management Frames (PMF) on the wireless access point "
                    "to prevent unauthorized management frame injection."
                ),
                timestamp=ts,
            )
            return [alert]

        return []

    def reset(self) -> None:
        """Clear all sliding window history."""
        self.frame_history.clear()
