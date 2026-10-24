"""
TCP and UDP Port Scan Detector
Monitors transport-layer connection attempts across a sliding time window to identify:
1. Vertical port scans (probing many ports on a single target IP).
2. Horizontal port sweeps (probing ports across multiple target IPs).
Corresponds to SRS REQ-F3-03 and GitHub Issue #17 (Test Case UT_F3_07).
"""

from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from .base import BaseDetector
from ..models import NormalizedRecord, Alert, ThreatType, Severity


class PortScanDetector(BaseDetector):
    """
    Pluggable detector for TCP/UDP port scans and sweeps.
    Maintains a sliding window of destination ports queried by each source IP.
    """

    def __init__(
        self,
        name: str = "port_scan_detector",
        enabled: bool = True,
        threshold: int = 15,
        window_seconds: float = 5.0,
        max_tracked_ips: int = 2000,
    ):
        super().__init__(name=name, enabled=enabled)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.max_tracked_ips = max_tracked_ips
        # Map: src_ip -> deque of (timestamp, dst_port, dst_ip, protocol)
        self.history: Dict[str, deque] = defaultdict(deque)

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """
        Inspect TCP and UDP records for port scan activity.
        Returns a list of Alert instances when threshold is reached.
        """
        if not self.enabled or record is None:
            return []

        # 1. Validate transport protocol (TCP/UDP)
        proto = (record.protocol or "").strip().upper()
        if proto not in ("TCP", "UDP"):
            return []

        # 2. Defensive checks: source IP and destination port must be present and valid
        if not record.src_ip or record.dst_port is None:
            return []

        try:
            dst_port = int(record.dst_port)
            if not (1 <= dst_port <= 65535):
                return []
        except (ValueError, TypeError):
            return []

        try:
            ts = float(record.timestamp)
        except (ValueError, TypeError):
            return []

        src_ip = record.src_ip.strip()
        dst_ip = (record.dst_ip or "unknown").strip()

        # 3. Sliding time window management
        attempts = self.history[src_ip]
        cutoff = ts - self.window_seconds

        # Evict expired records outside sliding window
        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()

        # Append current attempt
        attempts.append((ts, dst_port, dst_ip, proto))

        # 4. Count unique destination ports in current window
        unique_ports = {entry[1] for entry in attempts}

        alerts: List[Alert] = []
        if len(unique_ports) >= self.threshold:
            target_hosts = sorted({entry[2] for entry in attempts if entry[2] != "unknown"})
            protocols_seen = sorted({entry[3] for entry in attempts})
            proto_label = "/".join(protocols_seen)

            primary_target = target_hosts[0] if target_hosts else dst_ip
            target_summary = (
                primary_target
                if len(target_hosts) <= 1
                else f"{len(target_hosts)} hosts ({', '.join(target_hosts[:3])}...)"
            )

            sorted_ports = sorted(list(unique_ports))
            alert = Alert(
                threat_type=ThreatType.PORT_SCAN,
                severity=Severity.HIGH,
                title=f"{proto_label} Port Scan Detected",
                description=(
                    f"Host {src_ip} attempted connections across {len(unique_ports)} distinct "
                    f"destination ports on {target_summary} within {self.window_seconds}s "
                    f"(threshold: {self.threshold})."
                ),
                source_interface=record.interface or "unknown",
                evidence={
                    "detection_type": "PORT_SCAN",
                    "source_ip": src_ip,
                    "target_ip": primary_target,
                    "targeted_hosts": target_hosts,
                    "scanned_ports": sorted_ports,
                    "scanned_ports_sample": sorted_ports[:20],
                    "unique_port_count": len(unique_ports),
                    "protocol": proto_label,
                    "window_seconds": self.window_seconds,
                    "timestamp": ts,
                },
                mitigation=(
                    f"Inspect source host {src_ip} for port scanning utilities (nmap, masscan, zmap). "
                    f"Consider rate-limiting or blocking {src_ip} via host firewall or iptables."
                ),
                timestamp=ts,
            )
            alerts.append(alert)

            # Clear attempts to prevent alerting on every subsequent packet in the same sweep
            attempts.clear()

        # Periodic bounded memory cleanup if tracking table grows large
        if len(self.history) > self.max_tracked_ips:
            empty_keys = [k for k, v in self.history.items() if not v]
            for k in empty_keys:
                del self.history[k]

        return alerts

    def reset(self) -> None:
        """Clear all active connection history queues."""
        self.history.clear()
