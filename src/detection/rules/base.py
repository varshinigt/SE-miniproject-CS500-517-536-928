"""
Base Detector Abstract Class
All threat detection rules must inherit from BaseDetector.
This follows the Open/Closed Principle (OCP) and Strategy Pattern,
allowing new threat signatures to be plugged into the engine dynamically.
"""

from abc import ABC, abstractmethod
from typing import List
from ..models import NormalizedRecord, Alert


class BaseDetector(ABC):
    """Abstract Base Class for all pluggable threat detectors."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def process_record(self, record: NormalizedRecord) -> List[Alert]:
        """
        Inspect a single normalized packet record.
        Returns a list of Alert instances if an attack/anomaly is detected.
        Returns an empty list [] if the traffic is benign.
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset internal detection state (used for testing or window expiration)."""
        pass
