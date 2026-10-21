"""
Unit Tests for F3 Port Scan Detector (TCP and UDP)
Corresponds to SRS REQ-F3-03 and GitHub Issue #17 (Test Case UT_F3_07).
Verifies detection of horizontal sweeps and vertical scans, sliding-window expiry,
duplicate port handling, protocol support, and malformed record safety.
"""

import time
import unittest
from src.detection.models import NormalizedRecord, ThreatType, Severity
from src.detection.rules.port_scan import PortScanDetector
from src.detection.engine import DetectionEngine


class TestPortScanDetector(unittest.TestCase):
    """Test suite for PortScanDetector rule."""

    def setUp(self):
        """Initialize fresh detector before each test."""
        # Default: 15 unique ports within 5.0s
        self.detector = PortScanDetector(
            threshold=15,
            window_seconds=5.0,
        )

    def test_tcp_vertical_port_scan_detected(self):
        """UT_F3_07: Rapid TCP SYN scan across 15 distinct ports triggers HIGH alert."""
        base_time = 1728087600.0
        alerts = []

        # Send probes to 15 distinct destination ports on a single target IP
        for port in range(1, 16):
            record = NormalizedRecord(
                timestamp=base_time + (port * 0.1),
                interface="eth0",
                link_type="ETHERNET",
                src_mac="aa:bb:cc:dd:ee:01",
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                protocol="TCP",
                src_port=40000 + port,
                dst_port=port,
            )
            result = self.detector.process_record(record)
            alerts.extend(result)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.PORT_SCAN)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertIn("TCP Port Scan Detected", alert.title)
        self.assertEqual(alert.evidence["source_ip"], "192.168.1.100")
        self.assertEqual(alert.evidence["target_ip"], "192.168.1.1")
        self.assertEqual(alert.evidence["unique_port_count"], 15)
        self.assertEqual(alert.evidence["protocol"], "TCP")
        self.assertEqual(len(alert.evidence["scanned_ports"]), 15)

    def test_udp_port_scan_detected(self):
        """UT_F3_07: Rapid UDP scan across 15 distinct ports triggers HIGH alert."""
        base_time = 1728087600.0
        alerts = []

        # Scan 15 UDP service ports (e.g., DNS, NTP, SNMP, etc.)
        for i, port in enumerate(range(1001, 1016)):
            record = NormalizedRecord(
                timestamp=base_time + (i * 0.15),
                interface="eth0",
                link_type="ETHERNET",
                src_ip="10.0.0.50",
                dst_ip="10.0.0.1",
                protocol="UDP",
                src_port=50000 + i,
                dst_port=port,
            )
            alerts.extend(self.detector.process_record(record))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_type, ThreatType.PORT_SCAN)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertIn("UDP Port Scan Detected", alert.title)
        self.assertEqual(alert.evidence["protocol"], "UDP")
        self.assertEqual(alert.evidence["unique_port_count"], 15)

    def test_duplicate_ports_do_not_trigger_false_positives(self):
        """Benign high-volume traffic to repeated ports (e.g., HTTP/HTTPS) does not alert."""
        base_time = 1728087600.0
        alerts = []

        # Simulate heavy web browsing: 50 requests alternating between ports 80 and 443
        for i in range(50):
            port = 443 if (i % 2 == 0) else 80
            record = NormalizedRecord(
                timestamp=base_time + (i * 0.05),
                interface="eth0",
                link_type="ETHERNET",
                src_ip="192.168.1.55",
                dst_ip="93.184.216.34",
                protocol="TCP",
                src_port=30000 + i,
                dst_port=port,
            )
            alerts.extend(self.detector.process_record(record))

        # Only 2 distinct ports observed, threshold is 15 -> 0 alerts
        self.assertEqual(len(alerts), 0)

    def test_threshold_boundary(self):
        """Verify strict threshold boundary (14 ports = no alert, 15th port = alert)."""
        base_time = 1728087600.0

        # Send 14 unique ports (below threshold of 15)
        for port in range(1, 15):
            record = NormalizedRecord(
                timestamp=base_time + (port * 0.1),
                interface="eth0",
                link_type="ETHERNET",
                src_ip="192.168.1.77",
                dst_ip="192.168.1.200",
                protocol="TCP",
                src_port=45000 + port,
                dst_port=port,
            )
            alerts = self.detector.process_record(record)
            self.assertEqual(len(alerts), 0)

        # 15th unique port arrives within the window
        probe_15 = NormalizedRecord(
            timestamp=base_time + 1.6,
            interface="eth0",
            link_type="ETHERNET",
            src_ip="192.168.1.77",
            dst_ip="192.168.1.200",
            protocol="TCP",
            src_port=45015,
            dst_port=15,
        )
        alerts_15 = self.detector.process_record(probe_15)
        self.assertEqual(len(alerts_15), 1)

    def test_sliding_window_expiration(self):
        """Probes spread out over time beyond the 5.0s window must not trigger an alert."""
        base_time = 1728087600.0
        alerts = []

        # 15 distinct ports, but each probe is spaced 1.0 second apart (total span: 14s)
        # In any 5.0s sliding window, there are at most 5-6 ports, well below threshold 15.
        for port in range(1, 16):
            record = NormalizedRecord(
                timestamp=base_time + (port * 1.0),
                interface="eth0",
                link_type="ETHERNET",
                src_ip="192.168.1.88",
                dst_ip="192.168.1.1",
                protocol="TCP",
                src_port=50000 + port,
                dst_port=port,
            )
            alerts.extend(self.detector.process_record(record))

        self.assertEqual(len(alerts), 0)

    def test_horizontal_sweep_across_multiple_hosts(self):
        """Horizontal sweep probing single or multiple ports across different destination IPs."""
        base_time = 1728087600.0
        alerts = []

        # Probing 15 different destination IPs on distinct ports
        for i in range(1, 16):
            record = NormalizedRecord(
                timestamp=base_time + (i * 0.1),
                interface="eth0",
                link_type="ETHERNET",
                src_ip="172.16.0.99",
                dst_ip=f"192.168.1.{i}",
                protocol="TCP",
                src_port=60000 + i,
                dst_port=8000 + i,
            )
            alerts.extend(self.detector.process_record(record))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.evidence["source_ip"], "172.16.0.99")
        self.assertGreaterEqual(len(alert.evidence["targeted_hosts"]), 10)

    def test_non_tcp_udp_traffic_ignored(self):
        """ARP, ICMP, DNS (non-TCP/UDP), or BLE packets must be ignored."""
        arp_record = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_ip="192.168.1.1",
            protocol="ARP",
            dst_port=80,
        )
        icmp_record = NormalizedRecord(
            timestamp=100.1,
            interface="eth0",
            link_type="ETHERNET",
            src_ip="192.168.1.1",
            protocol="ICMP",
            dst_port=80,
        )
        self.assertEqual(self.detector.process_record(arp_record), [])
        self.assertEqual(self.detector.process_record(icmp_record), [])

    def test_malformed_records_handled_defensively(self):
        """Defensive handling of None records, missing fields, or out-of-range ports."""
        self.assertEqual(self.detector.process_record(None), [])

        missing_src_ip = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_ip=None,
            dst_port=80,
            protocol="TCP",
        )
        self.assertEqual(self.detector.process_record(missing_src_ip), [])

        missing_port = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_ip="10.0.0.1",
            dst_port=None,
            protocol="TCP",
        )
        self.assertEqual(self.detector.process_record(missing_port), [])

        invalid_port = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_ip="10.0.0.1",
            dst_port=70000,  # Invalid port (> 65535)
            protocol="TCP",
        )
        self.assertEqual(self.detector.process_record(invalid_port), [])

    def test_configurable_threshold_and_window(self):
        """Verify detector honors custom threshold and window configurations."""
        custom_detector = PortScanDetector(threshold=3, window_seconds=1.0)
        base_time = 100.0

        for port in [21, 22, 23]:
            record = NormalizedRecord(
                timestamp=base_time + 0.1,
                interface="eth0",
                link_type="ETHERNET",
                src_ip="192.168.1.22",
                dst_port=port,
                protocol="TCP",
            )
            alerts = custom_detector.process_record(record)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence["unique_port_count"], 3)

    def test_reset_clears_history(self):
        """Verify reset() empties connection history queue."""
        record = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_ip="192.168.1.10",
            dst_port=80,
            protocol="TCP",
        )
        self.detector.process_record(record)
        self.assertIn("192.168.1.10", self.detector.history)

        self.detector.reset()
        self.assertEqual(len(self.detector.history), 0)

    def test_detection_engine_integration(self):
        """Verify PortScanDetector integrates seamlessly into DetectionEngine."""
        engine = DetectionEngine()
        engine.register_rule(self.detector)

        self.assertIn("port_scan_detector", engine.get_registered_rules())

        base_time = 100.0
        alerts = []
        for port in range(1, 16):
            record = NormalizedRecord(
                timestamp=base_time + (port * 0.1),
                interface="eth0",
                link_type="ETHERNET",
                src_ip="192.168.5.50",
                dst_ip="192.168.5.1",
                protocol="TCP",
                dst_port=port,
            )
            alerts.extend(engine.process_record(record))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(engine.alerts_generated), 1)


if __name__ == "__main__":
    unittest.main()
