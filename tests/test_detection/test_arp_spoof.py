"""
Unit Tests for F3: ARP Spoofing Detector and Detection Engine
Corresponds to Jackfruit Phase-3 Test Cases (UT_F3_01 to UT_F3_06).
"""

import time
import unittest
from src.detection.models import NormalizedRecord, Severity, ThreatType, Alert
from src.detection.rules.arp_spoof import ArpSpoofDetector
from src.detection.engine import DetectionEngine


class TestArpSpoofDetector(unittest.TestCase):
    """Test suite for ARP Cache Poisoning and Reply Flood detection."""

    def setUp(self):
        """Set up fresh detector instance before each test."""
        self.detector = ArpSpoofDetector(
            flood_threshold=5,
            flood_window_seconds=3.0,
        )

    def test_normal_arp_traffic_produces_no_alerts(self):
        """UT_F3_01: Verify benign ARP traffic with consistent IP-MAC does not trigger alerts."""
        now = time.time()
        record1 = NormalizedRecord(
            timestamp=now,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.255",
            protocol="ARP",
            metadata={"arp_op": 1},  # Request
        )
        record2 = NormalizedRecord(
            timestamp=now + 0.1,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.100",
            protocol="ARP",
            metadata={"arp_op": 2},  # Reply
        )

        alerts1 = self.detector.process_record(record1)
        alerts2 = self.detector.process_record(record2)

        self.assertEqual(len(alerts1), 0)
        self.assertEqual(len(alerts2), 0)

    def test_arp_cache_poisoning_detected(self):
        """UT_F3_02: Verify that claiming an existing IP from a different MAC triggers CRITICAL alert."""
        now = time.time()
        legitimate_record = NormalizedRecord(
            timestamp=now,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            src_ip="192.168.1.1",
            protocol="ARP",
            metadata={"arp_op": 1},
        )
        # Establish baseline
        self.detector.process_record(legitimate_record)

        # Attacker spoofing the gateway IP 192.168.1.1 with their own MAC
        attacker_record = NormalizedRecord(
            timestamp=now + 1.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="de:ad:be:ef:aa:bb",
            src_ip="192.168.1.1",
            protocol="ARP",
            metadata={"arp_op": 2},
        )
        alerts = self.detector.process_record(attacker_record)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.ARP_SPOOFING)
        self.assertEqual(alert.severity, Severity.CRITICAL)
        self.assertIn("ARP Cache Poisoning Detected", alert.title)
        self.assertEqual(alert.evidence["claimed_ip"], "192.168.1.1")
        self.assertEqual(alert.evidence["original_mac"], "00:11:22:33:44:55")
        self.assertEqual(alert.evidence["spoofed_mac"], "de:ad:be:ef:aa:bb")

    def test_gratuitous_arp_reply_flood(self):
        """UT_F3_03: Rapid burst of 5+ ARP replies within 3s triggers HIGH alert."""
        now = time.time()
        all_alerts = []

        for i in range(5):
            record = NormalizedRecord(
                timestamp=now + (i * 0.2),  # 5 replies spaced 200ms apart
                interface="eth0",
                link_type="ETHERNET",
                src_mac="11:22:33:44:55:66",
                src_ip="192.168.1.50",
                protocol="ARP",
                metadata={"arp_op": 2},
            )
            alerts = self.detector.process_record(record)
            all_alerts.extend(alerts)

        self.assertEqual(len(all_alerts), 1)
        flood_alert = all_alerts[0]
        self.assertEqual(flood_alert.threat_type, ThreatType.ARP_SPOOFING)
        self.assertEqual(flood_alert.severity, Severity.HIGH)
        self.assertIn("ARP Reply Flood", flood_alert.title)
        self.assertEqual(flood_alert.evidence["reply_count"], 5)

    def test_arp_reply_flood_sliding_window_expiration(self):
        """UT_F3_03: Proves timestamps older than flood_window_seconds (3.0s) expire without alerting."""
        base_time = 1728087600.0
        all_alerts = []

        # Send 5 ARP replies, but spaced 1.0s apart (total span: 4.0s)
        # With a 3.0s window, earlier timestamps expire, keeping count <= 3, never reaching threshold 5.
        for i in range(5):
            record = NormalizedRecord(
                timestamp=base_time + (i * 1.0),
                interface="eth0",
                link_type="ETHERNET",
                src_mac="22:33:44:55:66:77",
                src_ip=f"192.168.1.{100 + i}",
                protocol="ARP",
                metadata={"arp_op": 2},
            )
            alerts = self.detector.process_record(record)
            all_alerts.extend(alerts)

        self.assertEqual(len(all_alerts), 0)

    def test_malformed_records_and_none_metadata_safety(self):
        """SEC-02: Safely handles None record, missing fields, or None metadata without raising exceptions."""
        self.assertEqual(self.detector.process_record(None), [])

        # Record with metadata explicitly set to None
        none_meta_record = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            src_ip="192.168.1.1",
            protocol="ARP",
            metadata=None,  # type: ignore
        )
        alerts = self.detector.process_record(none_meta_record)
        self.assertEqual(len(alerts), 0)

        # Record missing src_ip
        missing_ip_record = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            src_ip=None,
            protocol="ARP",
        )
        self.assertEqual(self.detector.process_record(missing_ip_record), [])

    def test_non_arp_traffic_ignored(self):
        """UT_F3_04: Non-ARP records (e.g. TCP, UDP, BLE) are safely ignored."""
        tcp_record = NormalizedRecord(
            timestamp=time.time(),
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="TCP",
            src_port=443,
            dst_port=54321,
        )
        alerts = self.detector.process_record(tcp_record)
        self.assertEqual(len(alerts), 0)

    def test_detection_engine_integration(self):
        """UT_F3_05: Verify DetectionEngine pipeline dispatches packets and calls alert callback."""
        callback_alerts = []

        def mock_callback(alert: Alert):
            callback_alerts.append(alert)

        engine = DetectionEngine(alert_callback=mock_callback)
        engine.register_rule(self.detector)

        self.assertIn("arp_spoof_detector", engine.get_registered_rules())

        # Baseline
        engine.process_record(NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="aa:bb:cc:00:00:01",
            src_ip="10.0.0.1",
            protocol="ARP",
            metadata={"arp_op": 1},
        ))

        # Attack
        attack_record = NormalizedRecord(
            timestamp=101.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="ff:ff:ff:99:99:99",
            src_ip="10.0.0.1",
            protocol="ARP",
            metadata={"arp_op": 2},
        )
        returned_alerts = engine.process_record(attack_record)

        self.assertEqual(len(returned_alerts), 1)
        self.assertEqual(len(engine.alerts_generated), 1)
        self.assertEqual(len(callback_alerts), 1)
        self.assertEqual(callback_alerts[0].title, returned_alerts[0].title)

    def test_reset_functionality(self):
        """UT_F3_06: Verify reset clears all internal state and binding tables."""
        record = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            src_ip="192.168.1.1",
            protocol="ARP",
        )
        self.detector.process_record(record)
        self.assertIn("192.168.1.1", self.detector.ip_mac_table)

        self.detector.reset()
        self.assertEqual(len(self.detector.ip_mac_table), 0)
        self.assertEqual(len(self.detector.reply_history), 0)


if __name__ == "__main__":
    unittest.main()
