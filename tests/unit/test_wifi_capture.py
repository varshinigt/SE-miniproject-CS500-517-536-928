"""Unit tests for F1 WiFi monitor mode capture and channel hopping (UT_F1_02, TC-F1-02)."""

import time
import pytest
from scapy.layers.dot11 import Dot11

from src.capture import ethernet
from src.capture.ethernet import CaptureError
from src.capture.wifi import WiFiCapture, set_interface_channel


class FakeSniffer:
    """Stands in for scapy.sniff so tests need no root, real WiFi NIC or monitor mode."""

    def __init__(self, packets=(), error=None, delay=0.0):
        self.packets = list(packets)
        self.error = error
        self.delay = delay
        self.kwargs = None

    def __call__(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        if self.delay > 0:
            time.sleep(self.delay)
        for packet in self.packets:
            kwargs["prn"](packet)
            if kwargs["stop_filter"](packet):
                break


@pytest.fixture(autouse=True)
def wlan0mon_exists(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: True)


def make_dot11_frames(count):
    return [
        Dot11(
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
    ] * count


def test_wifi_capture_defaults():
    capture = WiFiCapture("wlan0mon")
    assert capture.interface == "wlan0mon"
    assert capture.channels == list(range(1, 14))
    assert capture.hop_interval == 0.25
    assert capture.current_channel == 1


def test_wifi_capture_invalid_parameters():
    with pytest.raises(ValueError, match="hop_interval must be positive"):
        WiFiCapture(hop_interval=0)

    with pytest.raises(ValueError, match="queue_size must be positive"):
        WiFiCapture(queue_size=-1)


def test_wifi_capture_hops_channels():
    switched_channels = []

    def mock_channel_setter(iface, ch):
        switched_channels.append((iface, ch))
        return True

    capture = WiFiCapture(
        interface="wlan0mon",
        channels=[1, 6, 11],
        hop_interval=0.05,
        channel_setter=mock_channel_setter,
        sniffer=FakeSniffer(delay=0.18),
    )

    capture.start()
    assert len(switched_channels) >= 2
    assert all(iface == "wlan0mon" for iface, _ in switched_channels)
    visited = [ch for _, ch in switched_channels]
    assert 1 in visited


def test_wifi_capture_forwards_packets_to_handler():
    received = []
    frames = make_dot11_frames(4)
    sniffer = FakeSniffer(frames)

    capture = WiFiCapture(
        interface="wlan0mon",
        channels=[6],
        handler=lambda p, iface: received.append((p, iface)),
        sniffer=sniffer,
    )

    total = capture.start()
    assert total == 4
    assert len(received) == 4
    assert all(iface == "wlan0mon" for _, iface in received)
    assert sniffer.kwargs["store"] is False


def test_wifi_capture_without_handler():
    frames = make_dot11_frames(3)
    capture = WiFiCapture("wlan0mon", channels=[1], sniffer=FakeSniffer(frames))
    assert capture.start() == 3


def test_wifi_capture_stop_ends_capture():
    holder = {}

    def handler(packet, iface):
        holder["capture"].stop()

    capture = WiFiCapture(
        interface="wlan0mon",
        channels=[1, 6],
        hop_interval=0.05,
        handler=handler,
        sniffer=FakeSniffer(make_dot11_frames(5)),
    )
    holder["capture"] = capture
    assert capture.start() == 1


def test_wifi_capture_missing_interface_raises_capture_error(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: False)
    capture = WiFiCapture("wlan99mon", sniffer=FakeSniffer())
    with pytest.raises(CaptureError, match="not found"):
        capture.start()


def test_wifi_capture_permission_denied_raises_capture_error():
    sniffer = FakeSniffer(error=PermissionError("Need root"))
    capture = WiFiCapture("wlan0mon", channels=[1], sniffer=sniffer)
    with pytest.raises(CaptureError, match="Permission denied"):
        capture.start()


def test_wifi_capture_async_processing_queue():
    received = []
    frames = make_dot11_frames(5)

    capture = WiFiCapture(
        interface="wlan0mon",
        channels=[1],
        handler=lambda p, iface: received.append(p),
        sniffer=FakeSniffer(frames),
        async_processing=True,
        queue_size=20,
    )

    total = capture.start()
    assert total == 5
    assert len(received) == 5
    assert capture.processed == 5
    assert capture.queue_dropped == 0
    assert capture.queue_depth == 0


def test_set_interface_channel_helper(monkeypatch):
    calls = []

    class DummyCompletedProcess:
        def __init__(self, returncode):
            self.returncode = returncode

    def fake_subprocess_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "iw":
            return DummyCompletedProcess(0)
        return DummyCompletedProcess(1)

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)
    assert set_interface_channel("wlan0mon", 6) is True
    assert len(calls) == 1
    assert calls[0] == ["iw", "dev", "wlan0mon", "set", "channel", "6"]


def test_set_interface_channel_fallback_to_iwconfig(monkeypatch):
    calls = []

    class DummyCompletedProcess:
        def __init__(self, returncode):
            self.returncode = returncode

    def fake_subprocess_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "iw":
            raise FileNotFoundError("iw not installed")
        if cmd[0] == "iwconfig":
            return DummyCompletedProcess(0)
        return DummyCompletedProcess(1)

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)
    assert set_interface_channel("wlan0mon", 11) is True
    assert len(calls) == 2
    assert calls[1] == ["iwconfig", "wlan0mon", "channel", "11"]


def test_set_interface_channel_failure(monkeypatch):
    def fake_subprocess_run(cmd, **kwargs):
        raise PermissionError("not permitted")

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)
    assert set_interface_channel("wlan0mon", 1) is False
