import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from src.common.models import NormalizedRecord
from src.parser.base import ProtocolParser
from src.parser.protocol_parser import ScapyProtocolParser, parse_packet
from src.parser.registry import ParserRegistry


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


def test_registry_register_and_list_parsers():
    registry = ParserRegistry()
    registry.register(DummyParser())
    assert registry.registered_parsers() == ["DummyParser"]

    with pytest.raises(TypeError):
        registry.register("not_a_parser")


def test_registry_dispatch_checks_can_parse_first():
    registry = ParserRegistry()

    class RejectingParser(ProtocolParser):
        def can_parse(self, packet):
            return False

        def parse(self, packet, interface="unknown"):
            raise AssertionError(
                "parse should not be called when can_parse is False"
            )

    registry.register(RejectingParser())
    record = registry.dispatch(object(), interface="test_iface")
    assert record.link_type == "UNKNOWN"
    assert record.interface == "test_iface"


def test_registry_dispatch_first_match_wins():
    registry = ParserRegistry()

    class FirstParser(ProtocolParser):
        def can_parse(self, packet):
            return True

        def parse(self, packet, interface="unknown"):
            return NormalizedRecord(
                timestamp=1.0,
                interface=interface,
                link_type="FIRST",
                protocol="FIRST",
            )

    class SecondParser(ProtocolParser):
        def can_parse(self, packet):
            return True

        def parse(self, packet, interface="unknown"):
            raise AssertionError("SecondParser should not be called")

    registry.register(FirstParser())
    registry.register(SecondParser())

    record = registry.dispatch(object(), interface="test_iface")
    assert record.link_type == "FIRST"
    assert record.protocol == "FIRST"


def test_registry_dispatch_fallback_on_no_match():
    registry = ParserRegistry()
    record = registry.dispatch(object(), interface="unknown_iface")
    assert record.link_type == "UNKNOWN"
    assert record.interface == "unknown_iface"


def test_registry_dispatch_isolates_parse_exception():
    registry = ParserRegistry()

    class CrashingParser(ProtocolParser):
        def can_parse(self, packet):
            return True

        def parse(self, packet, interface="unknown"):
            raise RuntimeError("Unexpected dissector crash!")

    registry.register(CrashingParser())
    record = registry.dispatch(object(), interface="crash_iface")
    assert record.link_type == "UNKNOWN"
    assert record.interface == "crash_iface"


def test_both_parse_packet_import_paths_use_registry():
    from src.parser import parse_packet as init_parse
    from src.parser.protocol_parser import parse_packet as pp_parse

    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=80, dport=8080)
    )
    rec1 = init_parse(packet, interface="eth0")
    rec2 = pp_parse(packet, interface="eth0")

    assert rec1.protocol == "TCP"
    assert rec2.protocol == "TCP"
    assert rec1.src_port == rec2.src_port == 80
    assert rec1.dst_port == rec2.dst_port == 8080
    assert rec1.link_type == rec2.link_type == "ETHERNET"
