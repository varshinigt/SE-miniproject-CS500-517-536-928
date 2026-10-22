
from abc import ABC, abstractmethod
from typing import Any

from src.common.models import NormalizedRecord


class ProtocolParser(ABC):
    """Base interface for pluggable protocol parsers."""

    @abstractmethod
    def can_parse(self, packet: Any) -> bool:
        """Return True if this parser supports the packet."""
        raise NotImplementedError

    @abstractmethod
    def parse(
        self, packet: Any, interface: str = "unknown"
    ) -> NormalizedRecord:
        """Parse a supported packet into a normalized record."""
        raise NotImplementedError
