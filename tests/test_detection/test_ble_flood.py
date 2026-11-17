"""
Unit Tests for BLE Advertisement Flood and MAC Churning Detection (UT_F3_11)
Tests FR-F3-07 acceptance criteria:
1. Tracking BLE advertisement count within sliding window.
2. Generating alert when advertisement rate exceeds threshold.
3. Detecting MAC address churning / randomization storms.
4. Handling missing/incomplete BLE fields safely.
"""

import unittest
from src.detection.models import NormalizedRecord, ThreatType, Severity
from src.detection.rules.ble_flood import BleFloodDetector


class TestBleFloodDetector(unittest.TestCase):

    def setUp(self):
        self.detector = BleFloodDetector(
            flood_threshold=10,
            window_seconds=3.0,
            mac_churn_threshold=5,
        )

    def test_benign_ble_traffic_no_alert(self):
        """Moderate BLE advertisements under threshold generate no alerts."""
        for i in range(5):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.5,
                interface="hci0",
                link_type="BLE",
                src_mac="aa:bb:cc:11:22:33",
                metadata={"rssi": -65, "adv_data": "020106"},
            )
            alerts = self.detector.process_record(rec)
            self.assertEqual(len(alerts), 0)

    def test_ble_flood_threshold_exceeded(self):
        """Single device sending >= 10 advertisements in 3 seconds triggers flood alert."""
        alerts = []
        for i in range(10):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.1,
                interface="hci0",
                link_type="BLE",
                src_mac="aa:bb:cc:11:22:33",
                metadata={"rssi": -50, "adv_data": "Apple AirTag Beacon"},
            )
            res = self.detector.process_record(rec)
            alerts.extend(res)

        self.assertTrue(len(alerts) >= 1)
        flood_alert = [a for a in alerts if "Flood" in a.title][0]
        self.assertEqual(flood_alert.threat_type, ThreatType.BLE_FLOOD)
        self.assertEqual(flood_alert.severity, Severity.MEDIUM)
        self.assertEqual(flood_alert.evidence["device_mac"], "aa:bb:cc:11:22:33")
        self.assertEqual(flood_alert.evidence["advertisement_count"], 10)

    def test_ble_mac_churning_detected(self):
        """Detect rapid appearance of 5 distinct randomized MAC addresses within window."""
        alerts = []
        for i in range(5):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.2,
                interface="hci0",
                link_type="BLE",
                src_mac=f"fa:ce:b0:0c:00:0{i}",
                metadata={"rssi": -70},
            )
            res = self.detector.process_record(rec)
            alerts.extend(res)

        churn_alerts = [a for a in alerts if "Churning" in a.title]
        self.assertEqual(len(churn_alerts), 1)
        alert = churn_alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.BLE_FLOOD)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.evidence["distinct_mac_count"], 5)

    def test_incomplete_ble_fields_handled_gracefully(self):
        """Missing RSSI, missing adv_data, or missing MAC should not crash."""
        rec = NormalizedRecord(
            timestamp=100.0,
            interface="hci0",
            link_type="BLE",
            src_mac=None,
            metadata=None,
        )
        try:
            alerts = self.detector.process_record(rec)
            self.assertEqual(len(alerts), 0)
        except Exception as e:
            self.fail(f"process_record crashed on incomplete BLE record: {e}")

    def test_reset_clears_ble_state(self):
        """Reset clears BLE queues."""
        for i in range(9):
            rec = NormalizedRecord(
                timestamp=100.0 + i * 0.1,
                interface="hci0",
                link_type="BLE",
                src_mac="aa:bb:cc:11:22:33",
            )
            self.detector.process_record(rec)

        self.detector.reset()

        # 1 more packet should not trigger threshold (would be 10 without reset)
        rec = NormalizedRecord(
            timestamp=100.9,
            interface="hci0",
            link_type="BLE",
            src_mac="aa:bb:cc:11:22:33",
        )
        alerts = self.detector.process_record(rec)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
