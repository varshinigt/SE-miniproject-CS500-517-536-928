"""
Detection Engine
Central coordinator that receives normalized records, executes all registered
threat detection rules, and aggregates generated alerts.
"""

import logging
from typing import Callable, List, Optional
from .models import NormalizedRecord, Alert
from .rules.base import BaseDetector

logger = logging.getLogger("DetectionEngine")


class DetectionEngine:
    """
    Pluggable rule coordinator for Pocket Packet Sniffer (F3).
    Follows Observer / Pipeline pattern to dispatch packet stream to active detectors.
    """

    def __init__(self, alert_callback: Optional[Callable[[Alert], None]] = None):
        self._rules: List[BaseDetector] = []
        self._alert_callback = alert_callback
        self.alerts_generated: List[Alert] = []

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

    def process_record(self, record: Optional[NormalizedRecord]) -> List[Alert]:
        """
        Feed a single normalized packet record to all enabled detectors.
        Returns list of newly generated alerts for this record.
        """
        if record is None:
            return []

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
                                    exc_info=True,
                                )
            except Exception as e:
                logger.error(f"Error executing rule {rule.name}: {e}", exc_info=True)

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

    def reset(self) -> None:
        """Reset internal alert history and clear state of all registered rules."""
        self.alerts_generated.clear()
        for rule in self._rules:
            rule.reset()
