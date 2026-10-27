"""Unit tests for F1 Ethernet capture (UT_F1_01, UT_F1_02)."""

import pytest
from scapy.layers.l2 import Ether

from src.capture import ethernet
from src.capture.ethernet import CaptureError, EthernetCapture

real_interface_exists = ethernet.interface_exists


class FakeSniffer:
    """Stands in for scapy.sniff so tests need no root or real NIC."""

    def __init__(self, packets=(), error=None):
        self.packets = list(packets)
        self.error = error
        self.kwargs = None

    def __call__(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        for packet in self.packets:
            kwargs["prn"](packet)
            if kwargs["stop_filter"](packet):
                break


@pytest.fixture(autouse=True)
def eth0_exists(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: True)


def make_frames(count):
    return [Ether(src="aa:aa:aa:aa:aa:01", dst="ff:ff:ff:ff:ff:ff")] * count


def test_capture_enables_promiscuous_mode_on_interface():
    sniffer = FakeSniffer()
    EthernetCapture("eth0", sniffer=sniffer).start()
    assert sniffer.kwargs["promisc"] is True
    assert sniffer.kwargs["iface"] == "eth0"
    assert sniffer.kwargs["store"] is False


def test_capture_passes_each_frame_with_interface_name():
    received = []
    sniffer = FakeSniffer(make_frames(3))
    capture = EthernetCapture(
        "eth0", handler=lambda p, i: received.append((p, i)), sniffer=sniffer
    )
    total = capture.start()
    assert total == 3
    assert len(received) == 3
    assert all(iface == "eth0" for _, iface in received)


def test_capture_works_without_handler():
    capture = EthernetCapture("eth0", sniffer=FakeSniffer(make_frames(2)))
    assert capture.start() == 2


def test_stop_ends_capture_loop():
    holder = {}

    def handler(packet, iface):
        holder["capture"].stop()

    capture = EthernetCapture(
        "eth0", handler=handler, sniffer=FakeSniffer(make_frames(5))
    )
    holder["capture"] = capture
    assert capture.start() == 1


def test_bpf_filter_is_forwarded():
    sniffer = FakeSniffer()
    EthernetCapture("eth0", sniffer=sniffer, bpf_filter="arp").start()
    assert sniffer.kwargs["filter"] == "arp"


def test_missing_interface_raises_capture_error(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: False)
    sniffer = FakeSniffer()
    with pytest.raises(CaptureError, match="not found"):
        EthernetCapture("eth9", sniffer=sniffer).start()
    assert sniffer.kwargs is None


def test_permission_denied_raises_capture_error():
    sniffer = FakeSniffer(error=PermissionError())
    with pytest.raises(CaptureError, match="Permission denied"):
        EthernetCapture("eth0", sniffer=sniffer).start()


def test_interface_exists_detects_loopback():
    assert real_interface_exists("lo0") or real_interface_exists("lo")
    assert not real_interface_exists("definitely-not-a-nic")
