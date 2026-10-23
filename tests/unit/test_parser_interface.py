
import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from src.parser.protocol_parser import ScapyProtocolParser, parse_packet

from src.common.models import NormalizedRecord
from src.parser.base import ProtocolParser


class DummyParser(ProtocolParser):
    """Minimal implementation used to test the interface."""

    def can_parse(self, packet):
        return True

    def parse(self, packet, interface="unknown"):
        return NormalizedRecord(
            timestamp=1.0,
            interface=interface,
            link_type="Test",
            protocol="TEST",
        )


def test_protocol_parser_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ProtocolParser()


def test_concrete_parser_implements_interface():
    parser = DummyParser()

    assert parser.can_parse(object()) is True


def test_concrete_parser_returns_normalized_record():
    parser = DummyParser()

    record = parser.parse(object(), interface="test0")

    assert isinstance(record, NormalizedRecord)
    assert record.interface == "test0"
    assert record.protocol == "TEST"


def test_scapy_parser_accepts_supported_packet():
    parser = ScapyProtocolParser()
    packet = Ether() / IP() / TCP()

    assert parser.can_parse(packet) is True

    record = parser.parse(packet, interface="test0")
    assert record.protocol == "TCP"
    assert record.interface == "test0"


def test_parse_packet_wrapper_remains_compatible():
    packet = Ether() / IP() / TCP()

    record = parse_packet(packet, interface="test0")

    assert record.protocol == "TCP"
    assert record.interface == "test0"
