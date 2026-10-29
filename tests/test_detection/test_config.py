"""
Unit Tests for Dynamic Detection Configuration (UT_F3_12)
Tests FR-F3-08 acceptance criteria:
1. Dynamic threshold and window configuration.
2. Validation of invalid configuration values.
3. Fallback to defaults.
4. Runtime updates without interrupting pipeline.
"""

import json
import os
import tempfile
import unittest
from src.detection.config import (
    DetectionConfig,
    DEFAULT_CONFIG,
)
from src.detection.engine import DetectionEngine
from src.detection.models import NormalizedRecord


class TestDetectionConfig(unittest.TestCase):

    def test_default_config_valid(self):
        """Default configuration contains expected defaults and passes validation."""
        config = DetectionConfig()
        config.validate()
        self.assertEqual(config.arp.flood_threshold, 5)
        self.assertEqual(config.port_scan.port_threshold, 15)
        self.assertEqual(config.wifi_deauth.deauth_threshold, 10)
        self.assertEqual(config.ble_flood.flood_threshold, 20)

    def test_invalid_threshold_raises_value_error(self):
        """Zero or negative thresholds fail validation."""
        # ARP invalid values
        config = DetectionConfig()
        config.arp.flood_threshold = -1
        with self.assertRaises(ValueError):
            config.validate()

        config.arp.flood_threshold = 5
        config.arp.flood_window_seconds = 0
        with self.assertRaises(ValueError):
            config.validate()

        # Port scan invalid values
        config = DetectionConfig()
        config.port_scan.port_threshold = 0
        with self.assertRaises(ValueError):
            config.validate()

        config = DetectionConfig()
        config.port_scan.window_seconds = -2.0
        with self.assertRaises(ValueError):
            config.validate()

        config = DetectionConfig()
        config.port_scan.horizontal_host_threshold = 0
        with self.assertRaises(ValueError):
            config.validate()

        # WiFi deauth invalid values
        config = DetectionConfig()
        config.wifi_deauth.deauth_threshold = 0
        with self.assertRaises(ValueError):
            config.validate()

        config = DetectionConfig()
        config.wifi_deauth.window_seconds = -1
        with self.assertRaises(ValueError):
            config.validate()

        # Rogue AP invalid values
        config = DetectionConfig()
        config.rogue_ap.authorized_aps = "not_a_dict"  # type: ignore
        with self.assertRaises(ValueError):
            config.validate()

        # BLE flood invalid values
        config = DetectionConfig()
        config.ble_flood.flood_threshold = 0
        with self.assertRaises(ValueError):
            config.validate()

        config = DetectionConfig()
        config.ble_flood.window_seconds = -1.0
        with self.assertRaises(ValueError):
            config.validate()

        config = DetectionConfig()
        config.ble_flood.mac_churn_threshold = 0
        with self.assertRaises(ValueError):
            config.validate()

    def test_from_dict_and_to_dict_roundtrip(self):
        """Deserializing from dictionary and serializing back matches."""
        raw = {
            "arp": {"flood_threshold": 8, "flood_window_seconds": 4.5, "enabled": False},
            "port_scan": {"port_threshold": 25, "window_seconds": 10.0, "horizontal_host_threshold": 12},
            "wifi_deauth": {"deauth_threshold": 15, "window_seconds": 3.0, "enabled": True},
            "rogue_ap": {
                "authorized_aps": {"OfficeWiFi": {"allowed_bssids": ["00:11:22:33:44:55"]}},
                "alert_on_unknown_ssid": True,
                "enabled": True,
            },
            "ble_flood": {"flood_threshold": 30, "window_seconds": 5.0, "mac_churn_threshold": 15, "enabled": False},
        }
        cfg = DetectionConfig.from_dict(raw)
        self.assertEqual(cfg.arp.flood_threshold, 8)
        self.assertEqual(cfg.arp.flood_window_seconds, 4.5)
        self.assertFalse(cfg.arp.enabled)
        self.assertEqual(cfg.port_scan.port_threshold, 25)
        self.assertEqual(cfg.wifi_deauth.deauth_threshold, 15)
        self.assertEqual(cfg.ble_flood.mac_churn_threshold, 15)
        self.assertFalse(cfg.ble_flood.enabled)
        self.assertTrue(cfg.rogue_ap.alert_on_unknown_ssid)
        self.assertIn("OfficeWiFi", cfg.rogue_ap.authorized_aps)

        out_dict = cfg.to_dict()
        self.assertEqual(out_dict["arp"]["flood_threshold"], 8)

    def test_from_dict_non_dict_fallback(self):
        """Passing non-dict to from_dict falls back to defaults."""
        cfg = DetectionConfig.from_dict("not_a_dictionary")  # type: ignore
        self.assertEqual(cfg.arp.flood_threshold, DEFAULT_CONFIG.arp.flood_threshold)

    def test_load_from_json_file(self):
        """Loading configuration from JSON file."""
        data = {
            "arp": {"flood_threshold": 12},
            "wifi_deauth": {"deauth_threshold": 25},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            cfg = DetectionConfig.load_from_file(temp_path)
            self.assertEqual(cfg.arp.flood_threshold, 12)
            self.assertEqual(cfg.wifi_deauth.deauth_threshold, 25)
            # Unspecified values take defaults
            self.assertEqual(cfg.port_scan.port_threshold, 15)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_load_from_corrupted_json_file_uses_defaults(self):
        """Malformed JSON file gracefully logs and falls back to defaults."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("INVALID_JSON_CONTENT{{{")
            temp_path = f.name

        try:
            cfg = DetectionConfig.load_from_file(temp_path)
            self.assertEqual(cfg.arp.flood_threshold, DEFAULT_CONFIG.arp.flood_threshold)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_load_from_missing_file_uses_defaults(self):
        """Missing configuration file gracefully defaults without error."""
        cfg = DetectionConfig.load_from_file("non_existent_config_file_12345.json")
        self.assertEqual(cfg.arp.flood_threshold, DEFAULT_CONFIG.arp.flood_threshold)

    def test_dynamic_update_without_interrupting_engine(self):
        """Runtime updates modify engine config in-place."""
        engine = DetectionEngine()
        self.assertEqual(engine.config.arp.flood_threshold, 5)

        engine.config.update({"arp": {"flood_threshold": 20}})
        self.assertEqual(engine.config.arp.flood_threshold, 20)
        # Verify engine continues to process records smoothly
        rec = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="ARP",
        )
        alerts = engine.process_record(rec)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
