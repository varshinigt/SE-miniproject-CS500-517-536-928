"""
Detection Engine
Central coordinator that receives normalized records, executes all registered
threat detection rules, and aggregates generated alerts.
Hardened against malformed, corrupted, and fuzzed packet inputs (SEC-02).
"""

import logging
import math
from typing import Any, Callable, Dict, List, Optional
from .models import NormalizedRecord, Alert
from .rules.base import BaseDetector
from .config import DetectionConfig

logger = logging.getLogger("DetectionEngine")


class DetectionEngine:
    """
    Pluggable rule coordinator for Pocket Packet Sniffer (F3).
    Follows Observer / Pipeline pattern to dispatch packet stream to active detectors.
    Features robust input sanitization and error isolation (SEC-02).
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[Alert], None]] = None,
        config: Optional[DetectionConfig] = None,
    ):
        self._rules: List[BaseDetector] = []
        self._alert_callback = alert_callback
        self.config: DetectionConfig = config or DetectionConfig()
        self.alerts_generated: List[Alert] = []
        self.total_processed: int = 0
        self.malformed_dropped: int = 0

    def register_rule(self, rule: BaseDetector) -> None:
        """Register a new threat detector into the processing pipeline."""
        if not isinstance(rule, BaseDetector):
            raise TypeError(f"Rule must inherit from BaseDetector, got {type(rule)}")
        # If a rule with this name is already registered, replace it
        self._rules = [r for r in self._rules if r.name != rule.name]
        self._rules.append(rule)
        logger.info(f"Registered detection rule: {rule.name}")

    def get_registered_rules(self) -> List[str]:
        """Return names of all currently registered rules."""
        return [rule.name for rule in self._rules if rule.enabled]

    def get_rule(self, name: str) -> Optional[BaseDetector]:
        """Retrieve a registered rule instance by its unique name."""
        for rule in self._rules:
            if rule.name == name:
                return rule
        return None

    def unregister_rule(self, name: str) -> bool:
        """Remove a rule by name. Returns True if removed, False if not found."""
        initial_len = len(self._rules)
        self._rules = [rule for rule in self._rules if rule.name != name]
        return len(self._rules) < initial_len

    def validate_record(self, record: Any) -> bool:
        """
        Validate packet record schema and boundaries against fuzzed or malformed data (SEC-02).
        Returns True if the record is safe for inspection, False otherwise.
        """
        if not isinstance(record, NormalizedRecord):
            logger.warning("Rejected non-NormalizedRecord instance.")
            return False

        # Validate timestamp
        if not isinstance(record.timestamp, (int, float)):
            logger.warning("Rejected record with non-numeric timestamp.")
            return False
        if math.isnan(record.timestamp) or math.isinf(record.timestamp) or record.timestamp < 0:
            logger.warning("Rejected record with NaN, infinite, or negative timestamp.")
            return False
        if record.timestamp > 4_000_000_000:  # Far beyond year 2096
            logger.warning("Rejected record with absurdly futuristic timestamp.")
            return False

        # Validate interface name
        if not isinstance(record.interface, str) or len(record.interface) > 64:
            logger.warning("Rejected record with invalid or excessively long interface name.")
            return False

        # Validate link_type
        if not isinstance(record.link_type, str) or len(record.link_type) > 32:
            logger.warning("Rejected record with invalid link_type.")
            return False

        # Validate payload length bounds (max 65535 for standard IP, up to 1MB for jumbo/aggregate)
        if not isinstance(record.payload_len, int) or record.payload_len < 0 or record.payload_len > 1_048_576:
            logger.warning("Rejected record with out-of-bounds payload length.")
            return False

        # Validate port ranges if present
        for port_field, port_val in (("src_port", record.src_port), ("dst_port", record.dst_port)):
            if port_val is not None:
                if not isinstance(port_val, int) or port_val < 0 or port_val > 65535:
                    logger.warning(f"Rejected record with out-of-range {port_field}: {port_val}")
                    return False

        # Validate metadata type
        if record.metadata is not None and not isinstance(record.metadata, dict):
            logger.warning("Rejected record with non-dictionary metadata.")
            return False

        return True

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """
        Feed a single normalized packet record to all enabled detectors.
        Hardened against malformed inputs and detector runtime exceptions.
        """
        if record is None:
            return []

        # Validate incoming record schema (SEC-02)
        if not self.validate_record(record):
            self.malformed_dropped += 1
            return []

        self.total_processed += 1
        new_alerts: List[Alert] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            try:
                rule_alerts = rule.process_record(record)
                if rule_alerts:
                    for alert in rule_alerts:
                        new_alerts.append(alert)
                        self.alerts_generated.append(alert)
                        if self._alert_callback:
                            try:
                                self._alert_callback(alert)
                            except Exception as cb_err:
                                logger.error(
                                    f"Error in alert callback for rule {rule.name}: {cb_err}",
                                    exc_info=False,
                                )
            except Exception as e:
                # Log error safely without leaking sensitive payload bytes (SEC-02)
                logger.error(
                    f"Error executing rule '{rule.name}' on {record.interface} packet: {type(e).__name__}",
                    exc_info=False,
                )

        return new_alerts

    def process_records(self, records: List[NormalizedRecord]) -> List[Alert]:
        """
        Feed a batch/stream of normalized records sequentially through the pipeline.
        Returns combined list of all alerts generated during the run.
        """
        batch_alerts: List[Alert] = []
        for record in records:
            batch_alerts.extend(self.process_record(record))
        return batch_alerts

    def get_stats(self) -> Dict[str, Any]:
        """Return engine processing and hardening statistics."""
        return {
            "total_processed": self.total_processed,
            "malformed_dropped": self.malformed_dropped,
            "total_alerts": len(self.alerts_generated),
            "active_rules": len([r for r in self._rules if r.enabled]),
        }

    def reset(self) -> None:
        """Reset internal alert history and clear state of all registered rules."""
        self.alerts_generated.clear()
        self.total_processed = 0
        self.malformed_dropped = 0
        for rule in self._rules:
            rule.reset()
