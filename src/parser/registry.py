import logging
import time
from typing import Any

from src.common.models import NormalizedRecord
from src.parser.base import ProtocolParser

logger = logging.getLogger(__name__)


def _safe_fallback(
    packet: Any, interface: str = "unknown"
) -> NormalizedRecord:
    """Return a minimal safe record when no parser matches or parsing fails."""
    try:
        length = len(packet)
    except Exception:
        length = 0

    try:
        timestamp = float(getattr(packet, "time", time.time()))
    except (TypeError, ValueError, AttributeError):
        timestamp = time.time()

    return NormalizedRecord(
        timestamp=timestamp,
        interface=interface,
        link_type="UNKNOWN",
        length=length,
    )


class ParserRegistry:
    """Ordered registry of ProtocolParser instances with safe dispatch."""

    def __init__(self) -> None:
        self._parsers: list[ProtocolParser] = []

    def register(self, parser: ProtocolParser) -> None:
        """Append a parser to the end of the dispatch chain."""
        if not isinstance(parser, ProtocolParser):
            raise TypeError(f"Expected ProtocolParser, got {type(parser)}")
        self._parsers.append(parser)

    def dispatch(
        self, packet: Any, interface: str = "unknown"
    ) -> NormalizedRecord:
        """Find a matching parser and isolate parser exceptions."""
        for parser in self._parsers:
            try:
                if not parser.can_parse(packet):
                    continue

                return parser.parse(packet, interface)

            except Exception as exc:
                logger.error(
                    "Parser %s failed on %s: %s",
                    type(parser).__name__,
                    interface,
                    exc,
                    exc_info=True,
                )
                return _safe_fallback(packet, interface)

        logger.debug(
            "No parser matched packet on %s; returning safe fallback",
            interface,
        )
        return _safe_fallback(packet, interface)

    def registered_parsers(self) -> list[str]:
        """Return class names of registered parsers in dispatch order."""
        return [type(parser).__name__ for parser in self._parsers]


from src.parser.protocol_parser import (  # noqa: E402
    ScapyBLEParser,
    ScapyProtocolParser,
    ScapyWiFiParser,
)

_registry = ParserRegistry()
_registry.register(ScapyWiFiParser())
_registry.register(ScapyBLEParser())
_registry.register(ScapyProtocolParser())