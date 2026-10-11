"""
Pluggable detection rules package.
"""

from .base import BaseDetector
from .arp_spoof import ArpSpoofDetector

__all__ = ["BaseDetector", "ArpSpoofDetector"]
