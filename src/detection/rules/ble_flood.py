"""
Bluetooth Low Energy (BLE) Advertisement Flood and MAC Churning Detector
Monitors BLE advertising frames to detect:
1. High-rate advertisement flooding targeting Bluetooth receivers or denial-of-service.
2. MAC address churning / rapid rotating random address bursts used by spoofing tools.
Handles incomplete or malformed BLE payloads gracefully.
"""

from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
from .base import BaseDetector
from ..models import NormalizedRecord, Alert, ThreatType, Severity


class BleFloodDetector(BaseDetector):
    """
    Detects BLE advertisement floods and anomalous MAC address churning.
    """

    def __init__(
        self,
        name: str = "ble_flood_detector",
        enabled: bool = True,
        flood_threshold: int = 20,
        window_seconds: float = 3.0,
        mac_churn_threshold: int = 10,
    ):
        super().__init__(name=name, enabled=enabled)
        self.flood_threshold = flood_threshold
        self.window_seconds = window_seconds
        self.mac_churn_threshold = mac_churn_threshold

        # Track advertisement timestamps per device MAC {mac: deque([ts])}
        self.adv_history: Dict[str, deque] = defaultdict(deque)
        # Track overall BLE frames with (ts, mac) for churning detection: deque([(ts, mac)])
        self.interface_history: deque = deque()

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """Inspect BLE advertisement packets for flooding or rapid MAC rotation."""
        if not self.enabled or record is None:
            return []

        # Only process BLE traffic
        is_ble = (
            record.link_type == "BLE"
            or record.protocol == "BLE"
            or (record.interface and record.interface.startswith("hci"))
            or ("ble_adv" in (record.metadata or {}))
        )
        if not is_ble:
            return []

        alerts: List[Alert] = []
        ts = record.timestamp
        device_mac = (record.src_mac or "00:00:00:00:00:00").lower().strip()
        metadata = record.metadata or {}
        rssi = metadata.get("rssi")
        adv_data = metadata.get("adv_data")

        # 1. Per-device flood detection
        history = self.adv_history[device_mac]
        history.append(ts)

        # Evict timestamps outside sliding window
        cutoff = ts - self.window_seconds
        while history and history[0] < cutoff:
            history.popleft()

        if len(history) >= self.flood_threshold:
            count = len(history)
            history.clear()
            alerts.append(
                Alert(
                    threat_type=ThreatType.BLE_FLOOD,
                    severity=Severity.MEDIUM,
                    title="BLE Advertisement Flood Detected",
                    description=(
                        f"BLE device {device_mac} emitted {count} advertising frames in <= {self.window_seconds}s, "
                        f"exceeding threshold of {self.flood_threshold}."
                    ),
                    source_interface=record.interface,
                    evidence={
                        "device_mac": device_mac,
                        "advertisement_count": count,
                        "window_seconds": self.window_seconds,
                        "rssi": rssi,
                        "timestamp": ts,
                        "adv_data": str(adv_data)[:100] if adv_data else None,
                    },
                    mitigation=(
                        "Inspect physical perimeter for Bluetooth jamming or spamming devices; "
                        "filter anomalous BLE advertising addresses at gateway."
                    ),
                    timestamp=ts,
                )
            )

        # 2. MAC address churning detection (rapid appearance of diverse MAC addresses)
        self.interface_history.append((ts, device_mac))
        while self.interface_history and self.interface_history[0][0] < cutoff:
            self.interface_history.popleft()

        # Count distinct MACs in window
        distinct_macs: Set[str] = {mac for _, mac in self.interface_history if mac != "00:00:00:00:00:00"}
        if len(distinct_macs) >= self.mac_churn_threshold:
            churn_count = len(distinct_macs)
            self.interface_history.clear()
            alerts.append(
                Alert(
                    threat_type=ThreatType.BLE_FLOOD,
                    severity=Severity.HIGH,
                    title="BLE MAC Address Churning Detected",
                    description=(
                        f"Detected {churn_count} distinct BLE MAC addresses within {self.window_seconds}s. "
                        "Indicates active BLE spoofing, tracking randomization attack, or BLE spam."
                    ),
                    source_interface=record.interface,
                    evidence={
                        "distinct_mac_count": churn_count,
                        "sample_macs": list(distinct_macs)[:5],
                        "window_seconds": self.window_seconds,
                        "timestamp": ts,
                    },
                    mitigation="Monitor Bluetooth channel activity; enforce BLE privacy resolve key (IRK) validation.",
                    timestamp=ts,
                )
            )

        return alerts

    def reset(self) -> None:
        """Clear all sliding window history."""
        self.adv_history.clear()
        self.interface_history.clear()
