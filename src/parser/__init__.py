"""
F2: Protocol Parsing and Storage (Owner: Tejaswini R Pujar)
Public API for the parser package.
"""
from src.parser.base import ProtocolParser
from src.parser.registry import ParserRegistry, _registry, _safe_fallback


def parse_packet(packet, interface: str = "unknown"):
    """Public parse_packet via the shared registry."""
    return _registry.dispatch(packet, interface)


__all__ = [
    "ProtocolParser",
    "ParserRegistry",
    "_registry",
    "_safe_fallback",
    "parse_packet",
]
