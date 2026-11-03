import logging
import time
from typing import Any

from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from src.common.models import NormalizedRecord
from src.parser.base import ProtocolParser

logger = logging.getLogger(__name__)


def _safe_fallback(
    packet: Any, interface: str = "unknown"
) -> NormalizedRecord:
    """Return a minimal safe record when no parser matches or parse fails."""
    return NormalizedRecord(
        timestamp=float(getattr(packet, "time", time.time())),
        interface=interface,
        link_type="UNKNOWN",
        length=len(packet) if hasattr(packet, "__len__") else 0,
    )


class ScapyProtocolParser(ProtocolParser):
    """Pluggable parser for supported Scapy Ethernet and L3/L4 packets."""

    def can_parse(self, packet: Any) -> bool:
        """Return True if the packet has a supported protocol layer."""
        return any(
            layer in packet
            for layer in (Ether, ARP, IP, IPv6)
        )

    def parse(
        self, packet: Any, interface: str = "unknown"
    ) -> NormalizedRecord:
        """Decode a Scapy packet into a normalized record."""
        try:
            timestamp = float(getattr(packet, "time", time.time()))
            record = NormalizedRecord(
                timestamp=timestamp,
                interface=interface,
                link_type="UNKNOWN",
                length=len(packet) if hasattr(packet, "__len__") else 0,
            )

            if Ether in packet:
                ether = packet[Ether]
                record.link_type = "ETHERNET"
                record.src_mac = ether.src
                record.dst_mac = ether.dst

            if ARP in packet:
                arp = packet[ARP]
                record.protocol = "ARP"
                record.src_ip = arp.psrc or None
                record.dst_ip = arp.pdst or None
                record.details = {
                    "arp_op": int(arp.op),
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

                if DNS in packet:
                    dns = packet[DNS]
                    record.protocol = "DNS"
                    dns_meta: dict[str, Any] = {
                        "qr": int(dns.qr),
                        "rcode": int(dns.rcode),
                    }
                    if DNSQR in packet and dns.qd is not None:
                        qname = dns[DNSQR].qname
                        if isinstance(qname, bytes):
                            dns_meta["qname"] = qname.decode(errors="replace")
                        else:
                            dns_meta["qname"] = str(qname)
                        dns_meta["qtype"] = int(dns[DNSQR].qtype)
                    record.details = {**(record.details or {}), **dns_meta}

            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                record.src_ip = ipv6.src
                record.dst_ip = ipv6.dst
                record.protocol = "IPv6"

                if TCP in packet:
                    tcp = packet[TCP]
                    record.src_port = int(tcp.sport)
                    record.dst_port = int(tcp.dport)
                elif UDP in packet:
                    udp = packet[UDP]
                    record.src_port = int(udp.sport)
                    record.dst_port = int(udp.dport)

                if DNS in packet:
                    dns = packet[DNS]
                    record.protocol = "DNS"
                    dns_meta = {
                        "qr": int(dns.qr),
                        "rcode": int(dns.rcode),
                    }
                    if DNSQR in packet and dns.qd is not None:
                        qname = dns[DNSQR].qname
                        if isinstance(qname, bytes):
                            dns_meta["qname"] = qname.decode(errors="replace")
                        else:
                            dns_meta["qname"] = str(qname)
                        dns_meta["qtype"] = int(dns[DNSQR].qtype)
                    record.details = {**(record.details or {}), **dns_meta}

            return record
        except Exception as exc:
            logger.warning(
                "ScapyProtocolParser failed on %s: %s", interface, exc
            )
            return _safe_fallback(packet, interface)


class ScapyWiFiParser(ProtocolParser):
    """Parser for IEEE 802.11 monitor-mode frames (Dot11 Scapy layer)."""

    def can_parse(self, packet: Any) -> bool:
        """Return True if the packet is an 802.11 Wi-Fi frame."""
        return Dot11 in packet

    def parse(
        self, packet: Any, interface: str = "unknown"
    ) -> NormalizedRecord:
        """Decode an 802.11 frame across 4 ToDS/FromDS address combinations."""
        try:
            dot11 = packet[Dot11]
            to_ds = "to_DS" in dot11.FCfield
            from_ds = "from_DS" in dot11.FCfield

            if not to_ds and not from_ds:
                # IBSS / ad-hoc / management: DA=addr1, SA=addr2, BSSID=addr3
                src_mac, dst_mac, bssid = dot11.addr2, dot11.addr1, dot11.addr3
            elif to_ds and not from_ds:
                # STA -> AP (upstream): BSSID=addr1, SA=addr2, DA=addr3
                src_mac, dst_mac, bssid = dot11.addr2, dot11.addr3, dot11.addr1
            elif from_ds and not to_ds:
                # AP -> STA (downstream): DA=addr1, BSSID=addr2, SA=addr3
                src_mac, dst_mac, bssid = dot11.addr3, dot11.addr1, dot11.addr2
            else:
                # WDS / 4-address: RA=addr1, TA=addr2, DA=addr3, SA=addr4
                src_mac = getattr(dot11, "addr4", None)
                dst_mac = dot11.addr3
                bssid = None

            meta: dict[str, Any] = {
                "wifi_subtype": int(dot11.subtype),
                "wifi_type": int(dot11.type),
                "bssid": bssid,
                "wifi_tods": int(bool(to_ds)),
                "wifi_fromds": int(bool(from_ds)),
            }

            record = NormalizedRecord(
                timestamp=float(getattr(packet, "time", time.time())),
                interface=interface,
                link_type="WIFI",
                src_mac=src_mac,
                dst_mac=dst_mac,
                length=len(packet) if hasattr(packet, "__len__") else 0,
                details=meta,
            )

            # Check for encapsulated L3/L4 payload
            if IP in packet:
                ip = packet[IP]
                record.src_ip = ip.src
                record.dst_ip = ip.dst
                if TCP in packet:
                    record.protocol = "TCP"
                    record.src_port = int(packet[TCP].sport)
                    record.dst_port = int(packet[TCP].dport)
                elif UDP in packet:
                    record.protocol = "UDP"
                    record.src_port = int(packet[UDP].sport)
                    record.dst_port = int(packet[UDP].dport)
                else:
                    record.protocol = "IP"
            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                record.src_ip = ipv6.src
                record.dst_ip = ipv6.dst
                if TCP in packet:
                    record.protocol = "TCP"
                    record.src_port = int(packet[TCP].sport)
                    record.dst_port = int(packet[TCP].dport)
                elif UDP in packet:
                    record.protocol = "UDP"
                    record.src_port = int(packet[UDP].sport)
                    record.dst_port = int(packet[UDP].dport)
                else:
                    record.protocol = "IPv6"
            else:
                record.protocol = "802.11"

            return record
        except Exception as exc:
            logger.warning("ScapyWiFiParser failed on %s: %s", interface, exc)
            return _safe_fallback(packet, interface)


class ScapyBLEParser(ProtocolParser):
    """Parser for BLE advertisement frames (Scapy BTLE layer)."""

    def can_parse(self, packet: Any) -> bool:
        """Return True if the packet is a Bluetooth Low Energy frame."""
        return BTLE in packet

    def parse(
        self, packet: Any, interface: str = "unknown"
    ) -> NormalizedRecord:
        """Decode a BLE advertisement frame."""
        try:
            btle = packet[BTLE]
            meta: dict[str, Any] = {"access_addr": hex(btle.access_addr)}

            src_mac = None
            if BTLE_ADV in packet:
                adv = packet[BTLE_ADV]
                meta["ble_adv_type"] = int(adv.PDU_type)
            if BTLE_ADV_IND in packet:
                src_mac = packet[BTLE_ADV_IND].AdvA

            return NormalizedRecord(
                timestamp=float(getattr(packet, "time", time.time())),
                interface=interface,
                link_type="BLE",
                src_mac=src_mac,
                protocol="BLE",
                length=len(packet) if hasattr(packet, "__len__") else 0,
                details=meta,
            )
        except Exception as exc:
            logger.warning("ScapyBLEParser failed on %s: %s", interface, exc)
            return _safe_fallback(packet, interface)


_default_parser = ScapyProtocolParser()


def parse_packet(
    packet: Any, interface: str = "unknown"
) -> NormalizedRecord:
    """Backward-compatible entry point delegating to parser."""
    try:
        from src.parser.registry import _registry
        return _registry.dispatch(packet, interface)
    except ImportError:
        return _default_parser.parse(packet, interface)
