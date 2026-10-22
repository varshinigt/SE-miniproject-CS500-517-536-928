from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from src.parser.protocol_parser import parse_packet


def test_parse_ethernet_tcp_packet():
    packet = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=80)
    )

    record = parse_packet(packet, interface="eth0")

    assert record.protocol == "TCP"
    assert record.src_mac == "00:11:22:33:44:55"
    assert record.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "192.168.1.20"
    assert record.src_port == 12345
    assert record.dst_port == 80
    assert record.interface == "eth0"


def test_parse_udp_packet():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
        sport=5353, dport=53
    )

    record = parse_packet(packet)

    assert record.protocol == "UDP"
    assert record.src_port == 5353
    assert record.dst_port == 53


def test_parse_arp_packet():
    packet = Ether() / ARP(
        op=2,
        hwsrc="00:11:22:33:44:55",
        hwdst="aa:bb:cc:dd:ee:ff",
        psrc="192.168.1.10",
        pdst="192.168.1.1",
    )

    record = parse_packet(packet)

    assert record.protocol == "ARP"
    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "192.168.1.1"
    assert record.details["operation"] == 2


def test_record_converts_to_dictionary():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()

    record = parse_packet(packet)
    data = record.to_dict()

    assert data["protocol"] == "TCP"
    assert data["length"] == len(packet)


def test_parse_plain_ip_packet():
    packet = IP(src="192.168.1.1", dst="192.168.1.2")

    record = parse_packet(packet)

    assert record.link_type == "Non-Ethernet"
    assert record.protocol == "IP"
    assert record.src_ip == "192.168.1.1"
    assert record.dst_ip == "192.168.1.2"


def test_parse_ipv6_packet():
    packet = Ether() / IPv6(
        src="2001:db8::1",
        dst="2001:db8::2",
    )

    record = parse_packet(packet)

    assert record.link_type == "Ethernet"
    assert record.protocol == "IPv6"
    assert record.src_ip == "2001:db8::1"
    assert record.dst_ip == "2001:db8::2"


def test_parse_unknown_protocol_packet():
    packet = Ether() / Raw(load=b"test")

    record = parse_packet(packet)

    assert record.link_type == "Ethernet"
    assert record.protocol == "UNKNOWN"
    assert record.src_ip is None
    assert record.dst_ip is None
