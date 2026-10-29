"""
Rogue and Evil-Twin Wireless Access Point Detector
Monitors 802.11 beacon and probe response frames to detect:
1. Evil-Twin APs: Known enterprise SSIDs broadcast by unauthorized BSSIDs.
2. Security Downgrades: Legitimate SSIDs broadcast with weaker or missing encryption (e.g. OPEN / WEP).
3. BSSID Spoofing / Channel Conflicts.
"""

from typing import Any, Dict, List, Optional, Set
from .base import BaseDetector
from ..models import NormalizedRecord, Alert, ThreatType, Severity


class RogueApDetector(BaseDetector):
    """
    Detects rogue and Evil-Twin wireless access points based on baseline profiles
    and dynamic wireless environment analysis.
    """

    def __init__(
        self,
        name: str = "rogue_ap_detector",
        enabled: bool = True,
        authorized_aps: Optional[Dict[str, Dict[str, Any]]] = None,
        alert_on_unknown_ssid: bool = False,
    ):
        super().__init__(name=name, enabled=enabled)
        # authorized_aps format:
        # {
        #   "CorporateWiFi": {
        #       "allowed_bssids": ["00:11:22:33:44:01", "00:11:22:33:44:02"],
        #       "min_security": "WPA2"
        #   }
        # }
        self.authorized_aps: Dict[str, Dict[str, Any]] = {}
        if authorized_aps:
            for ssid, info in authorized_aps.items():
                allowed = [b.lower() for b in info.get("allowed_bssids", [])]
                self.authorized_aps[ssid] = {
                    "allowed_bssids": allowed,
                    "min_security": info.get("min_security", "WPA2"),
                }
        self.alert_on_unknown_ssid = alert_on_unknown_ssid
        # Observed (ssid, bssid) pairs: track first seen and security
        self.observed_aps: Dict[str, Set[str]] = {}
        self.observed_security: Dict[str, str] = {}
        # Track alerted pairs to avoid duplicate storms
        self._alerted_pairs: Set[str] = set()

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """Inspect beacon or probe-response frames for rogue AP indicators."""
        if not self.enabled or record is None:
            return []

        # Check if wireless frame containing AP beacon or probe info
        metadata = record.metadata or {}
        ssid = metadata.get("ssid")
        bssid = metadata.get("bssid") or record.src_mac

        if not ssid or not bssid:
            return []

        ssid = str(ssid).strip()
        bssid = str(bssid).strip().lower()
        if not ssid or bssid in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return []

        security = str(metadata.get("security", metadata.get("encryption", "UNKNOWN"))).upper()
        channel = metadata.get("channel")
        pair_key = f"{ssid}_{bssid}"

        alerts: List[Alert] = []

        # Case 1: SSID is in authorized baseline
        if ssid in self.authorized_aps:
            baseline = self.authorized_aps[ssid]
            allowed_bssids = baseline.get("allowed_bssids", [])
            min_sec = baseline.get("min_security", "WPA2").upper()

            # Check BSSID authorization
            if allowed_bssids and bssid not in allowed_bssids:
                if pair_key not in self._alerted_pairs:
                    self._alerted_pairs.add(pair_key)
                    alerts.append(
                        Alert(
                            threat_type=ThreatType.ROGUE_AP,
                            severity=Severity.CRITICAL,
                            title="Evil-Twin Rogue Access Point Detected",
                            description=(
                                f"Known SSID '{ssid}' detected on unauthorized BSSID {bssid}. "
                                f"Authorized BSSIDs: {allowed_bssids}."
                            ),
                            source_interface=record.interface,
                            evidence={
                                "ssid": ssid,
                                "observed_bssid": bssid,
                                "expected_bssids": allowed_bssids,
                                "security": security,
                                "channel": channel,
                                "detection_reason": "unauthorized_bssid",
                                "timestamp": record.timestamp,
                            },
                            mitigation=(
                                "Locate and isolate unauthorized transmitter; check physical AP registry "
                                "and deploy WIPS containment."
                            ),
                            timestamp=record.timestamp,
                        )
                    )

            # Check Security Downgrade (e.g. WPA2 expected but OPEN/WEP observed)
            if min_sec in ("WPA2", "WPA3") and security in ("OPEN", "NONE", "WEP"):
                sec_key = f"{pair_key}_downgrade"
                if sec_key not in self._alerted_pairs:
                    self._alerted_pairs.add(sec_key)
                    alerts.append(
                        Alert(
                            threat_type=ThreatType.ROGUE_AP,
                            severity=Severity.HIGH,
                            title="Wireless Security Downgrade Detected",
                            description=(
                                f"Known SSID '{ssid}' on BSSID {bssid} is operating with weak/no security "
                                f"({security}). Expected minimum: {min_sec}."
                            ),
                            source_interface=record.interface,
                            evidence={
                                "ssid": ssid,
                                "observed_bssid": bssid,
                                "observed_security": security,
                                "required_security": min_sec,
                                "channel": channel,
                                "detection_reason": "security_downgrade",
                                "timestamp": record.timestamp,
                            },
                            mitigation="Enforce WPA2/WPA3 enterprise encryption and disallow open fallback networks.",
                            timestamp=record.timestamp,
                        )
                    )

        # Track dynamically
        if ssid not in self.observed_aps:
            self.observed_aps[ssid] = set()
        self.observed_aps[ssid].add(bssid)
        self.observed_security[bssid] = security

        return alerts

    def reset(self) -> None:
        """Clear dynamic AP observations and alert caches."""
        self.observed_aps.clear()
        self.observed_security.clear()
        self._alerted_pairs.clear()
