from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from src.parser.protocol_parser import ScapyBLEParser, ScapyWiFiParser


def test_wifi_can_parse_dot11_returns_true():
    parser = ScapyWiFiParser()
    pkt = Dot11()
    assert parser.can_parse(pkt) is True


def test_wifi_cannot_parse_ethernet():
    parser = ScapyWiFiParser()
    pkt = Ether() / IP() / TCP()
    assert parser.can_parse(pkt) is False


def test_wifi_link_type_is_wifi():
    parser = ScapyWiFiParser()
    pkt = Dot11(
        addr1="11:11:11:11:11:11",
        addr2="22:22:22:22:22:22",
        addr3="33:33:33:33:33:33",
    )
    record = parser.parse(pkt, interface="wlan0mon")
    assert record.link_type == "WIFI"
    assert record.interface == "wlan0mon"


def test_wifi_ibss_mac_extraction():
    parser = ScapyWiFiParser()
    pkt = Dot11(
        FCfield=0x00,
        addr1="11:11:11:11:11:11",
        addr2="22:22:22:22:22:22",
        addr3="33:33:33:33:33:33",
    )
    record = parser.parse(pkt)
    assert record.src_mac == "22:22:22:22:22:22"
    assert record.dst_mac == "11:11:11:11:11:11"
    assert record.metadata["bssid"] == "33:33:33:33:33:33"


def test_wifi_sta_to_ap_mac_extraction():
    parser = ScapyWiFiParser()
    pkt = Dot11(
        FCfield=0x01,
        addr1="11:11:11:11:11:11",
        addr2="22:22:22:22:22:22",
        addr3="33:33:33:33:33:33",
    )
    record = parser.parse(pkt)
    assert record.src_mac == "22:22:22:22:22:22"
    assert record.dst_mac == "33:33:33:33:33:33"
    assert record.metadata["bssid"] == "11:11:11:11:11:11"


def test_wifi_ap_to_sta_mac_extraction():
    parser = ScapyWiFiParser()
    pkt = Dot11(
        FCfield=0x02,
        addr1="11:11:11:11:11:11",
        addr2="22:22:22:22:22:22",
        addr3="33:33:33:33:33:33",
    )
    record = parser.parse(pkt)
    assert record.src_mac == "33:33:33:33:33:33"
    assert record.dst_mac == "11:11:11:11:11:11"
    assert record.metadata["bssid"] == "22:22:22:22:22:22"


def test_wifi_wds_mac_extraction():
    parser = ScapyWiFiParser()
    raw_wds = (
        b"\x08\x03\x00\x00"
        + b"\x11" * 6
        + b"\x22" * 6
        + b"\x33" * 6
        + b"\x00\x00"
        + b"\x44" * 6
    )
    pkt = Dot11(raw_wds)
    record = parser.parse(pkt)
    assert record.src_mac == "44:44:44:44:44:44"
    assert record.dst_mac == "33:33:33:33:33:33"
    assert record.metadata["bssid"] is None


def test_wifi_wds_missing_addr4_handled_safely():
    parser = ScapyWiFiParser()
    pkt = Dot11(
        FCfield=0x03,
        addr1="11:11:11:11:11:11",
        addr2="22:22:22:22:22:22",
        addr3="33:33:33:33:33:33",
    )
    record = parser.parse(pkt)
    assert record.src_mac is None
    assert record.dst_mac == "33:33:33:33:33:33"
    assert record.metadata["bssid"] is None


def test_wifi_ip_sublayer_decoded():
    parser = ScapyWiFiParser()
    pkt = (
        Dot11(
            FCfield=0x02,
            addr1="11:11:11:11:11:11",
            addr2="22:22:22:22:22:22",
            addr3="33:33:33:33:33:33",
        )
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
    )
    record = parser.parse(pkt)
    assert record.link_type == "WIFI"
    assert record.protocol == "TCP"
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.src_port == 1234
    assert record.dst_port == 80


def test_ble_can_parse_btle_returns_true():
    parser = ScapyBLEParser()
    pkt = BTLE() / BTLE_ADV() / BTLE_ADV_IND(AdvA="aa:bb:cc:dd:ee:ff")
    assert parser.can_parse(pkt) is True


def test_ble_cannot_parse_ethernet():
    parser = ScapyBLEParser()
    pkt = Ether() / IP()
    assert parser.can_parse(pkt) is False


def test_ble_link_type_and_mac_extraction():
    parser = ScapyBLEParser()
    pkt = (
        BTLE(access_addr=0x8E89BED6)
        / BTLE_ADV()
        / BTLE_ADV_IND(AdvA="aa:bb:cc:dd:ee:ff")
    )
    record = parser.parse(pkt, interface="hci0")
    assert record.link_type == "BLE"
    assert record.interface == "hci0"
    assert record.protocol == "BLE"
    assert record.src_mac == "aa:bb:cc:dd:ee:ff"


def test_ble_metadata_fields_populated():
    parser = ScapyBLEParser()
    pkt = (
        BTLE(access_addr=0x8E89BED6)
        / BTLE_ADV()
        / BTLE_ADV_IND(AdvA="aa:bb:cc:dd:ee:ff")
    )
    record = parser.parse(pkt)
    assert record.metadata["ble_adv_type"] == 0
    assert record.metadata["access_addr"] == "0x8e89bed6"
