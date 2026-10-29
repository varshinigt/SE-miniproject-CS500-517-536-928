"""
Unit Tests for WiFi Deauthentication and Disassociation Flood Detection (UT_F3_09)
Tests FR-F3-05 acceptance criteria:
1. Identifying deauth and disassociation management frames.
2. Generating alert when rate exceeds threshold.
3. Accurate evidence fields and sliding window expiration.
"""

import unittest
from src.detection.models import NormalizedRecord, ThreatType, Severity
from src.detection.rules.wifi_deauth import WifiDeauthDetector


class TestWifiDeauthDetector(unittest.TestCase):

    def setUp(self):
        self.detector = WifiDeauthDetector(
            deauth_threshold=5,
            window_seconds=2.0,
        )

    def test_benign_wifi_data_frames_no_alert(self):
        """Benign data frames should not trigger deauth alerts."""
        rec = NormalizedRecord(
            timestamp=100.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            metadata={"wifi_subtype": 0, "frame_type": "data"},
        )
        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 0)

    def test_sub_threshold_deauth_no_alert(self):
        """Deauth frames under threshold (4 frames < 5 threshold) should not alert."""
        for i in range(4):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.1,
                interface="wlan0mon",
                link_type="WIFI",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                metadata={"wifi_subtype": 12, "bssid": "00:11:22:33:44:55", "client_mac": "66:77:88:99:aa:bb"},
            )
            alerts = self.detector.process_record(rec)
            self.assertEqual(len(alerts), 0)

    def test_deauth_flood_threshold_exceeded(self):
        """Reaching threshold of 5 deauth frames triggers an alert."""
        alerts = []
        for i in range(5):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.1,
                interface="wlan0mon",
                link_type="WIFI",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                metadata={"wifi_subtype": 12, "bssid": "00:11:22:33:44:55", "client_mac": "66:77:88:99:aa:bb"},
            )
            res = self.detector.process_record(rec)
            alerts.extend(res)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.WIFI_DEAUTH)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertIn("Deauthentication", alert.title)
        self.assertEqual(alert.evidence["frame_count"], 5)
        self.assertEqual(alert.evidence["bssid"], "00:11:22:33:44:55")
        self.assertEqual(alert.evidence["client_mac"], "66:77:88:99:aa:bb")

    def test_disassociation_flood_detected(self):
        """Subtype 10 disassociation frame burst triggers an alert."""
        alerts = []
        for i in range(5):
            rec = NormalizedRecord(
                timestamp=200.0 + i * 0.1,
                interface="wlan0mon",
                link_type="WIFI",
                src_mac="aa:bb:cc:dd:ee:ff",
                dst_mac="11:22:33:44:55:66",
                metadata={"wifi_subtype": 10, "bssid": "aa:bb:cc:dd:ee:ff", "client_mac": "11:22:33:44:55:66"},
            )
            res = self.detector.process_record(rec)
            alerts.extend(res)

        self.assertEqual(len(alerts), 1)
        self.assertIn("Disassociation", alerts[0].title)

    def test_sliding_window_expiration(self):
        """Frames spaced further apart than window_seconds expire and do not alert."""
        # 4 frames in first second
        for i in range(4):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.1,
                interface="wlan0mon",
                link_type="WIFI",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                metadata={"wifi_subtype": 12},
            )
            self.detector.process_record(rec)

        # 5th frame arrives after window expired (window=2.0s, arrival at 105.0)
        late_rec = NormalizedRecord(
            timestamp=105.0,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            metadata={"wifi_subtype": 12},
        )
        alerts = self.detector.process_record(late_rec)
        self.assertEqual(len(alerts), 0)

    def test_reset_clears_history(self):
        """Reset clears state so count restarts."""
        for i in range(4):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.1,
                interface="wlan0mon",
                link_type="WIFI",
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:aa:bb",
                metadata={"wifi_subtype": 12},
            )
            self.detector.process_record(rec)

        self.detector.reset()

        # 1 more packet should not trigger threshold (would be 5 without reset)
        rec = NormalizedRecord(
            timestamp=100.5,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            metadata={"wifi_subtype": 12},
        )
        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
