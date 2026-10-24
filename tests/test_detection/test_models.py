"""
Unit Tests for F3 Data Models (NormalizedRecord and Alert Schema)
Corresponds to SRS REQ-F3-09 and Issue #14 (UT_F3_05).
"""

import json
import time
import unittest
import uuid
from src.detection.models import Severity, ThreatType, NormalizedRecord, Alert


class TestDetectionModels(unittest.TestCase):
    """Test suite for F3 data models and serialization contracts."""

    def test_severity_enum_values(self):
        """Verify standard severity level values and str comparability."""
        self.assertEqual(Severity.LOW.value, "LOW")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        # Ensure str comparability
        self.assertEqual(Severity.CRITICAL, "CRITICAL")

    def test_threat_type_enum_values(self):
        """Verify threat type enum values correspond to system specifications."""
        expected_threats = {
            "ARP_SPOOFING",
            "PORT_SCAN",
            "DNS_ANOMALY",
            "WIFI_DEAUTH",
            "ROGUE_AP",
            "BLE_FLOOD",
        }
        actual_threats = {t.value for t in ThreatType}
        self.assertTrue(expected_threats.issubset(actual_threats))

    def test_normalized_record_creation_and_defaults(self):
        """Verify NormalizedRecord instantiation, defaults, and type contract."""
        record = NormalizedRecord(
            timestamp=1728087600.0,
            interface="eth0",
            link_type="ETHERNET",
        )
        self.assertEqual(record.timestamp, 1728087600.0)
        self.assertEqual(record.interface, "eth0")
        self.assertEqual(record.link_type, "ETHERNET")
        self.assertIsNone(record.src_mac)
        self.assertIsNone(record.dst_mac)
        self.assertIsNone(record.src_ip)
        self.assertIsNone(record.dst_ip)
        self.assertIsNone(record.protocol)
        self.assertIsNone(record.src_port)
        self.assertIsNone(record.dst_port)
        self.assertEqual(record.payload_len, 0)
        self.assertEqual(record.metadata, {})

    def test_normalized_record_to_dict_and_json(self):
        """Verify NormalizedRecord.to_dict() produces valid JSON-serializable output."""
        record = NormalizedRecord(
            timestamp=1728087600.125,
            interface="wlan0mon",
            link_type="WIFI",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=54321,
            dst_port=80,
            payload_len=128,
            metadata={"wifi_subtype": 8, "rssi": -42},
        )
        data = record.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["src_port"], 54321)
        self.assertEqual(data["metadata"]["wifi_subtype"], 8)
        # Must be valid JSON
        json_str = json.dumps(data)
        self.assertIn("00:11:22:33:44:55", json_str)

    def test_alert_default_attributes(self):
        """Verify auto-generation of UUID alert_id and UTC epoch timestamp."""
        before = time.time()
        alert = Alert(
            threat_type=ThreatType.ARP_SPOOFING,
            severity=Severity.CRITICAL,
            title="ARP Cache Poisoning Detected",
            description="Conflicting MAC address observed for IP",
            source_interface="eth0",
            evidence={"claimed_ip": "192.168.1.1"},
            mitigation="Enable Dynamic ARP Inspection (DAI)",
        )
        after = time.time()

        # Validate UUIDv4 format
        parsed_uuid = uuid.UUID(alert.alert_id, version=4)
        self.assertEqual(str(parsed_uuid), alert.alert_id)

        # Validate epoch float timestamp within bounds
        self.assertGreaterEqual(alert.timestamp, before - 0.05)
        self.assertLessEqual(alert.timestamp, after + 0.05)

    def test_alert_custom_attributes(self):
        """Verify explicit alert_id and timestamp override default factories."""
        custom_id = "custom-alert-12345"
        custom_time = 1700000000.5
        alert = Alert(
            threat_type=ThreatType.PORT_SCAN,
            severity=Severity.HIGH,
            title="TCP Port Scan Detected",
            description="SYN scan detected across ports",
            source_interface="eth0",
            evidence={"ports": [22, 80, 443]},
            mitigation="Block source IP on firewall",
            timestamp=custom_time,
            alert_id=custom_id,
        )
        self.assertEqual(alert.alert_id, custom_id)
        self.assertEqual(alert.timestamp, custom_time)

    def test_alert_to_dict_matches_srs_schema(self):
        """Verify Alert.to_dict() matches SRS Table B.2 field layout."""
        alert = Alert(
            threat_type=ThreatType.ARP_SPOOFING,
            severity=Severity.CRITICAL,
            title="ARP Cache Poisoning Detected",
            description="Host claiming IP with conflicting MAC",
            source_interface="eth0",
            evidence={
                "claimed_ip": "192.168.1.1",
                "original_mac": "00:11:22:33:44:55",
                "spoofed_mac": "de:ad:be:ef:aa:bb",
            },
            mitigation="Enable Dynamic ARP Inspection (DAI)",
        )
        d = alert.to_dict()

        # Verify all mandatory schema keys exist
        required_keys = {
            "alert_id",
            "timestamp",
            "threat_type",
            "severity",
            "title",
            "description",
            "source_interface",
            "evidence",
            "mitigation",
        }
        self.assertTrue(required_keys.issubset(d.keys()))

        # Verify enum values serialized as strings
        self.assertEqual(d["threat_type"], "ARP_SPOOFING")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertIsInstance(d["timestamp"], float)
        self.assertIsInstance(d["evidence"], dict)

        # Verify JSON serializability
        serialized = json.dumps(d)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["alert_id"], alert.alert_id)
        self.assertEqual(deserialized["threat_type"], "ARP_SPOOFING")


if __name__ == "__main__":
    unittest.main()
