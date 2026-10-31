from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

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
    assert record.details["arp_op"] == 2


def test_record_converts_to_dictionary():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()

    record = parse_packet(packet)
    data = record.to_dict()

    assert data["protocol"] == "TCP"
    assert data["payload_len"] == len(packet)


def test_parse_plain_ip_packet():
    packet = IP(src="192.168.1.1", dst="192.168.1.2")

    record = parse_packet(packet)

    assert record.link_type == "UNKNOWN"
    assert record.protocol == "IP"
    assert record.src_ip == "192.168.1.1"
    assert record.dst_ip == "192.168.1.2"


def test_parse_ipv6_packet():
    packet = Ether() / IPv6(
        src="2001:db8::1",
        dst="2001:db8::2",
    )

    record = parse_packet(packet)

    assert record.link_type == "ETHERNET"
    assert record.protocol == "IPv6"
    assert record.src_ip == "2001:db8::1"
    assert record.dst_ip == "2001:db8::2"


def test_parse_unknown_protocol_packet():
    packet = Ether() / Raw(load=b"test")

    record = parse_packet(packet)

    assert record.link_type == "ETHERNET"
    assert record.protocol == "UNKNOWN"
    assert record.src_ip is None
    assert record.dst_ip is None


def test_parse_ethernet_link_type_uppercase():
    packet = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=80)
    )
    record = parse_packet(packet)
    assert record.link_type == "ETHERNET"


def test_parse_dns_query_over_udp():
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qr=0, qd=DNSQR(qname="test.com"))
    )
    record = parse_packet(packet)
    assert record.protocol == "DNS"
    assert record.src_port == 12345
    assert record.dst_port == 53
    assert record.details["qr"] == 0
    assert record.details["qname"] == "test.com."
    assert record.details["qtype"] == 1


def test_parse_dns_response_over_udp():
    packet = (
        Ether()
        / IP(src="8.8.8.8", dst="10.0.0.1")
        / UDP(sport=53, dport=12345)
        / DNS(
            qr=1,
            rcode=0,
            qd=DNSQR(qname="test.com"),
            an=DNSRR(rrname="test.com", rdata="93.184.216.34"),
        )
    )
    record = parse_packet(packet)
    assert record.protocol == "DNS"
    assert record.details["qr"] == 1
    assert record.details["rcode"] == 0


def test_parse_dns_over_tcp():
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / TCP(sport=54321, dport=53)
        / DNS(rd=1, qr=0, qd=DNSQR(qname="test.com"))
    )
    record = parse_packet(packet)
    assert record.protocol == "DNS"
    assert record.src_port == 54321
    assert record.dst_port == 53


def test_malformed_raw_bytes_no_exception():
    packet = Raw(b"\xff\xfe\x00\x01")
    record = parse_packet(packet)
    assert record is not None
    assert record.link_type == "UNKNOWN"
    assert record.protocol == "UNKNOWN"


def test_payload_len_property_matches_length():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
    record = parse_packet(packet)
    assert record.payload_len == record.length
    assert record.payload_len == len(packet)


def test_metadata_property_matches_details():
    packet = Ether() / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1")
    record = parse_packet(packet)
    assert record.metadata == record.details
    assert record.metadata["arp_op"] == 1

    # Verify auto-initialization and mutation persistence
    record.metadata["custom_key"] = "custom_val"
    assert record.details["custom_key"] == "custom_val"


def test_to_dict_emits_srs_keys():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
    record = parse_packet(packet)
    d = record.to_dict()
    assert "payload_len" in d
    assert "metadata" in d
    assert "length" not in d
    assert "details" not in d
