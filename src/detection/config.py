"""
Detection Engine Configuration Module
Provides centralized, validated, and dynamic threshold settings for all F3 detection rules.
Supports runtime updates without interrupting packet inspection (FR-F3-08).
"""

from dataclasses import dataclass, field
import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger("DetectionConfig")


@dataclass
class ArpRuleConfig:
    flood_threshold: int = 5
    flood_window_seconds: float = 3.0
    enabled: bool = True

    def validate(self) -> None:
        if self.flood_threshold <= 0:
            raise ValueError("ArpRuleConfig.flood_threshold must be positive")
        if self.flood_window_seconds <= 0:
            raise ValueError("ArpRuleConfig.flood_window_seconds must be positive")


@dataclass
class PortScanRuleConfig:
    port_threshold: int = 15
    window_seconds: float = 5.0
    horizontal_host_threshold: int = 10
    enabled: bool = True

    def validate(self) -> None:
        if self.port_threshold <= 0:
            raise ValueError("PortScanRuleConfig.port_threshold must be positive")
        if self.window_seconds <= 0:
            raise ValueError("PortScanRuleConfig.window_seconds must be positive")
        if self.horizontal_host_threshold <= 0:
            raise ValueError("PortScanRuleConfig.horizontal_host_threshold must be positive")


@dataclass
class WifiDeauthRuleConfig:
    deauth_threshold: int = 10
    window_seconds: float = 2.0
    enabled: bool = True

    def validate(self) -> None:
        if self.deauth_threshold <= 0:
            raise ValueError("WifiDeauthRuleConfig.deauth_threshold must be positive")
        if self.window_seconds <= 0:
            raise ValueError("WifiDeauthRuleConfig.window_seconds must be positive")


@dataclass
class RogueApRuleConfig:
    # Baseline of authorized SSIDs and their allowed BSSIDs / required security
    # e.g.: {"CorpNet": {"allowed_bssids": ["00:11:22:33:44:01"], "min_security": "WPA2"}}
    authorized_aps: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    alert_on_unknown_ssid: bool = False
    enabled: bool = True

    def validate(self) -> None:
        if not isinstance(self.authorized_aps, dict):
            raise ValueError("RogueApRuleConfig.authorized_aps must be a dictionary")


@dataclass
class BleFloodRuleConfig:
    flood_threshold: int = 20
    window_seconds: float = 3.0
    mac_churn_threshold: int = 10
    enabled: bool = True

    def validate(self) -> None:
        if self.flood_threshold <= 0:
            raise ValueError("BleFloodRuleConfig.flood_threshold must be positive")
        if self.window_seconds <= 0:
            raise ValueError("BleFloodRuleConfig.window_seconds must be positive")
        if self.mac_churn_threshold <= 0:
            raise ValueError("BleFloodRuleConfig.mac_churn_threshold must be positive")


@dataclass
class DetectionConfig:
    """Master configuration container for F3 detection rules."""
    arp: ArpRuleConfig = field(default_factory=ArpRuleConfig)
    port_scan: PortScanRuleConfig = field(default_factory=PortScanRuleConfig)
    wifi_deauth: WifiDeauthRuleConfig = field(default_factory=WifiDeauthRuleConfig)
    rogue_ap: RogueApRuleConfig = field(default_factory=RogueApRuleConfig)
    ble_flood: BleFloodRuleConfig = field(default_factory=BleFloodRuleConfig)

    def validate(self) -> None:
        """Validate all sub-configurations."""
        self.arp.validate()
        self.port_scan.validate()
        self.wifi_deauth.validate()
        self.rogue_ap.validate()
        self.ble_flood.validate()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionConfig":
        """Instantiate configuration from dictionary with graceful defaults."""
        config = cls()
        if not isinstance(data, dict):
            logger.warning("Configuration payload is not a dictionary; using defaults.")
            return config

        # ARP config
        arp_data = data.get("arp", {})
        if isinstance(arp_data, dict):
            if "flood_threshold" in arp_data:
                config.arp.flood_threshold = int(arp_data["flood_threshold"])
            if "flood_window_seconds" in arp_data:
                config.arp.flood_window_seconds = float(arp_data["flood_window_seconds"])
            if "enabled" in arp_data:
                config.arp.enabled = bool(arp_data["enabled"])

        # Port scan config
        ps_data = data.get("port_scan", {})
        if isinstance(ps_data, dict):
            if "port_threshold" in ps_data:
                config.port_scan.port_threshold = int(ps_data["port_threshold"])
            if "window_seconds" in ps_data:
                config.port_scan.window_seconds = float(ps_data["window_seconds"])
            if "horizontal_host_threshold" in ps_data:
                config.port_scan.horizontal_host_threshold = int(ps_data["horizontal_host_threshold"])
            if "enabled" in ps_data:
                config.port_scan.enabled = bool(ps_data["enabled"])

        # WiFi deauth config
        wifi_data = data.get("wifi_deauth", {})
        if isinstance(wifi_data, dict):
            if "deauth_threshold" in wifi_data:
                config.wifi_deauth.deauth_threshold = int(wifi_data["deauth_threshold"])
            if "window_seconds" in wifi_data:
                config.wifi_deauth.window_seconds = float(wifi_data["window_seconds"])
            if "enabled" in wifi_data:
                config.wifi_deauth.enabled = bool(wifi_data["enabled"])

        # Rogue AP config
        rogue_data = data.get("rogue_ap", {})
        if isinstance(rogue_data, dict):
            if "authorized_aps" in rogue_data and isinstance(rogue_data["authorized_aps"], dict):
                config.rogue_ap.authorized_aps = rogue_data["authorized_aps"]
            if "alert_on_unknown_ssid" in rogue_data:
                config.rogue_ap.alert_on_unknown_ssid = bool(rogue_data["alert_on_unknown_ssid"])
            if "enabled" in rogue_data:
                config.rogue_ap.enabled = bool(rogue_data["enabled"])

        # BLE flood config
        ble_data = data.get("ble_flood", {})
        if isinstance(ble_data, dict):
            if "flood_threshold" in ble_data:
                config.ble_flood.flood_threshold = int(ble_data["flood_threshold"])
            if "window_seconds" in ble_data:
                config.ble_flood.window_seconds = float(ble_data["window_seconds"])
            if "mac_churn_threshold" in ble_data:
                config.ble_flood.mac_churn_threshold = int(ble_data["mac_churn_threshold"])
            if "enabled" in ble_data:
                config.ble_flood.enabled = bool(ble_data["enabled"])

        config.validate()
        return config

    @classmethod
    def load_from_file(cls, filepath: str) -> "DetectionConfig":
        """Load configuration from JSON file. Falls back to defaults if not found or malformed."""
        if not os.path.isfile(filepath):
            logger.info(f"Config file not found at {filepath}, using default configuration.")
            return cls()

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to parse config file {filepath}: {e}. Using defaults.")
            return cls()

    def update(self, new_settings: Dict[str, Any]) -> None:
        """Dynamically update configuration values without replacing object reference."""
        temp = self.from_dict(new_settings)
        self.arp = temp.arp
        self.port_scan = temp.port_scan
        self.wifi_deauth = temp.wifi_deauth
        self.rogue_ap = temp.rogue_ap
        self.ble_flood = temp.ble_flood
        logger.info("Detection configuration updated dynamically.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "arp": {
                "flood_threshold": self.arp.flood_threshold,
                "flood_window_seconds": self.arp.flood_window_seconds,
                "enabled": self.arp.enabled,
            },
            "port_scan": {
                "port_threshold": self.port_scan.port_threshold,
                "window_seconds": self.port_scan.window_seconds,
                "horizontal_host_threshold": self.port_scan.horizontal_host_threshold,
                "enabled": self.port_scan.enabled,
            },
            "wifi_deauth": {
                "deauth_threshold": self.wifi_deauth.deauth_threshold,
                "window_seconds": self.wifi_deauth.window_seconds,
                "enabled": self.wifi_deauth.enabled,
            },
            "rogue_ap": {
                "authorized_aps": self.rogue_ap.authorized_aps,
                "alert_on_unknown_ssid": self.rogue_ap.alert_on_unknown_ssid,
                "enabled": self.rogue_ap.enabled,
            },
            "ble_flood": {
                "flood_threshold": self.ble_flood.flood_threshold,
                "window_seconds": self.ble_flood.window_seconds,
                "mac_churn_threshold": self.ble_flood.mac_churn_threshold,
                "enabled": self.ble_flood.enabled,
            },
        }


DEFAULT_CONFIG = DetectionConfig()
