
import time
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from src.common.models import NormalizedRecord
from src.parser.base import ProtocolParser


class ScapyProtocolParser(ProtocolParser):
    """Pluggable parser for supported Scapy packets."""

    def can_parse(self, packet: Any) -> bool:
        """Return True if the packet has a supported protocol layer."""
        return any(
            layer in packet
            for layer in (ARP, IP, IPv6)
        )

    def parse(
        self, packet: Any, interface: str = "unknown"
    ) -> NormalizedRecord:
        """Decode a Scapy packet into a normalized record."""
        timestamp = float(getattr(packet, "time", time.time()))
        record = NormalizedRecord(
            timestamp=timestamp,
            interface=interface,
            link_type="UNKNOWN",
            length=len(packet),
        )

        if Ether in packet:
            ether = packet[Ether]
            record.link_type = "Ethernet"
            record.src_mac = ether.src
            record.dst_mac = ether.dst
        else:
            record.link_type = "Non-Ethernet"

        if ARP in packet:
            arp = packet[ARP]
            record.protocol = "ARP"
            record.src_ip = arp.psrc or None
            record.dst_ip = arp.pdst or None
            record.details = {
                "operation": int(arp.op),
                "sender_mac": arp.hwsrc,
                "target_mac": arp.hwdst,
            }
        elif IP in packet:
            ip = packet[IP]
            record.src_ip = ip.src
            record.dst_ip = ip.dst

            if TCP in packet:
                tcp = packet[TCP]
                record.protocol = "TCP"
                record.src_port = int(tcp.sport)
                record.dst_port = int(tcp.dport)
            elif UDP in packet:
                udp = packet[UDP]
                record.protocol = "UDP"
                record.src_port = int(udp.sport)
                record.dst_port = int(udp.dport)
            else:
                record.protocol = "IP"
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            record.src_ip = ipv6.src
            record.dst_ip = ipv6.dst
            record.protocol = "IPv6"

        return record


_default_parser = ScapyProtocolParser()


def parse_packet(
    packet: Any, interface: str = "unknown"
) -> NormalizedRecord:
    """Backward-compatible wrapper for the existing parser function."""
    return _default_parser.parse(packet, interface)
