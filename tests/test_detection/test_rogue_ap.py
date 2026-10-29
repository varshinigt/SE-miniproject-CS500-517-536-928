"""
Unit Tests for Rogue and Evil-Twin Wireless AP Detection (UT_F3_10)
Tests FR-F3-06 acceptance criteria:
1. Tracking SSID/BSSID pairs.
2. Detecting known SSID broadcast on unauthorized BSSID.
3. Detecting security downgrade (e.g. WPA2 expected, OPEN observed).
4. Alert deduplication and evidence completeness.
"""

import unittest
from src.detection.models import NormalizedRecord, ThreatType, Severity
from src.detection.rules.rogue_ap import RogueApDetector


class TestRogueApDetector(unittest.TestCase):

    def setUp(self):
        self.authorized = {
            "CorpSecure": {
                "allowed_bssids": ["00:11:22:33:44:01", "00:11:22:33:44:02"],
                "min_security": "WPA2",
            }
        }
        self.detector = RogueApDetector(authorized_aps=self.authorized)

    def test_authorized_ap_beacon_no_alert(self):
        """Legitimate beacon from authorized BSSID should generate no alerts."""
        rec = NormalizedRecord(
            timestamp=100.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="00:11:22:33:44:01",
            metadata={
                "ssid": "CorpSecure",
                "bssid": "00:11:22:33:44:01",
                "security": "WPA2",
                "channel": 6,
            },
        )
        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 0)

    def test_evil_twin_unauthorized_bssid_detected(self):
        """Known SSID broadcast from unauthorized BSSID triggers Evil-Twin alert."""
        rec = NormalizedRecord(
            timestamp=101.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="de:ad:be:ef:00:99",
            metadata={
                "ssid": "CorpSecure",
                "bssid": "de:ad:be:ef:00:99",
                "security": "WPA2",
                "channel": 1,
            },
        )
        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.ROGUE_AP)
        self.assertEqual(alert.severity, Severity.CRITICAL)
        self.assertIn("Evil-Twin", alert.title)
        self.assertEqual(alert.evidence["ssid"], "CorpSecure")
        self.assertEqual(alert.evidence["observed_bssid"], "de:ad:be:ef:00:99")
        self.assertEqual(alert.evidence["detection_reason"], "unauthorized_bssid")

    def test_security_downgrade_detected(self):
        """Authorized BSSID broadcasting OPEN network triggers Security Downgrade alert."""
        rec = NormalizedRecord(
            timestamp=102.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="00:11:22:33:44:01",
            metadata={
                "ssid": "CorpSecure",
                "bssid": "00:11:22:33:44:01",
                "security": "OPEN",
                "channel": 6,
            },
        )
        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.ROGUE_AP)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertIn("Downgrade", alert.title)
        self.assertEqual(alert.evidence["detection_reason"], "security_downgrade")

    def test_alert_deduplication_prevents_spam(self):
        """Repeated beacons from the same rogue AP do not create duplicate alert storms."""
        rec = NormalizedRecord(
            timestamp=100.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="de:ad:be:ef:00:99",
            metadata={
                "ssid": "CorpSecure",
                "bssid": "de:ad:be:ef:00:99",
                "security": "WPA2",
            },
        )
        alerts1 = self.detector.process_record(rec)
        self.assertEqual(len(alerts1), 1)

        # 10 identical subsequent beacon frames
        for i in range(10):
            rec_sub = NormalizedRecord(
                timestamp=100.1 + i * 0.1,
                interface="wlan0mon",
                link_type="WIFI",
                src_mac="de:ad:be:ef:00:99",
                metadata={
                    "ssid": "CorpSecure",
                    "bssid": "de:ad:be:ef:00:99",
                    "security": "WPA2",
                },
            )
            alerts_sub = self.detector.process_record(rec_sub)
            self.assertEqual(len(alerts_sub), 0)

    def test_reset_clears_alert_cache(self):
        """Reset clears alerted cache so rogue AP can alert again if seen in new session."""
        rec = NormalizedRecord(
            timestamp=100.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="de:ad:be:ef:00:99",
            metadata={
                "ssid": "CorpSecure",
                "bssid": "de:ad:be:ef:00:99",
                "security": "WPA2",
            },
        )
        self.detector.process_record(rec)
        self.detector.reset()

        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()
