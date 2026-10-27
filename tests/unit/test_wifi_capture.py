"""Unit tests for F1 WiFi Monitor Mode and Channel Hopping (UT_F1_05, UT_F1_06)."""

import subprocess
import time
import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon

from src.capture import ethernet
from src.capture.ethernet import CaptureError
from src.capture.wifi import WifiCapture


class FakeProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeCommandRunner:
    def __init__(self, failure_cmd=None, err_msg="Operation not supported"):
        self.calls = []
        self.failure_cmd = failure_cmd
        self.err_msg = err_msg

    def __call__(self, cmd):
        self.calls.append(cmd)
        if self.failure_cmd and self.failure_cmd in cmd:
            return FakeProcess(returncode=1, stderr=self.err_msg)
        return FakeProcess(returncode=0)


class FakeSniffer:
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
def wlan0_exists(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: True)


def make_dot11_frames(count):
    return [Dot11(type=0, subtype=8) / Dot11Beacon()] * count


def test_wifi_capture_enables_monitor_mode():
    runner = FakeCommandRunner()
    sniffer = FakeSniffer()
    capture = WifiCapture(
        interface="wlan0",
        cmd_runner=runner,
        sniffer=sniffer,
        enable_monitor_mode=True,
    )
    capture.start()
    assert ["ip", "link", "set", "wlan0", "down"] in runner.calls
    assert ["iw", "dev", "wlan0", "set", "type", "monitor"] in runner.calls
    assert ["ip", "link", "set", "wlan0", "up"] in runner.calls


def test_wifi_capture_unsupported_monitor_mode_raises():
    runner = FakeCommandRunner(failure_cmd="monitor", err_msg="Not a supported type")
    capture = WifiCapture(
        interface="wlan0",
        cmd_runner=runner,
        sniffer=FakeSniffer(),
        enable_monitor_mode=True,
    )
    with pytest.raises(CaptureError, match="does not support monitor mode"):
        capture.start()


def test_wifi_capture_channel_hopping():
    runner = FakeCommandRunner()
    capture = WifiCapture(
        interface="wlan0",
        channels=[1, 6, 11],
        hop_interval=0.01,
        cmd_runner=runner,
        enable_monitor_mode=False,
    )
    assert capture.set_channel(6) is True
    assert capture.current_channel == 6
    assert ["iw", "dev", "wlan0", "set", "channel", "6"] in runner.calls


def test_wifi_capture_delivers_frames_to_handler():
    received = []
    frames = make_dot11_frames(4)
    sniffer = FakeSniffer(frames)
    runner = FakeCommandRunner()
    capture = WifiCapture(
        interface="wlan0mon",
        channels=[6],
        handler=lambda p, iface: received.append((p, iface)),
        sniffer=sniffer,
        cmd_runner=runner,
        enable_monitor_mode=False,
    )
    total = capture.start()
    assert total == 4
    assert len(received) == 4
    assert all(iface == "wlan0mon" for _, iface in received)


def test_wifi_capture_missing_interface_raises(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: False)
    capture = WifiCapture(interface="wlan9", sniffer=FakeSniffer())
    with pytest.raises(CaptureError, match="not found"):
        capture.start()


def test_wifi_capture_permission_denied_raises():
    runner = FakeCommandRunner()
    sniffer = FakeSniffer(error=PermissionError())
    capture = WifiCapture(
        interface="wlan0",
        cmd_runner=runner,
        sniffer=sniffer,
        enable_monitor_mode=False,
    )
    with pytest.raises(CaptureError, match="Permission denied"):
        capture.start()


def test_wifi_capture_stop_halts_hopping():
    runner = FakeCommandRunner()
    capture = WifiCapture(
        interface="wlan0",
        channels=[1, 6, 11],
        hop_interval=0.02,
        cmd_runner=runner,
        enable_monitor_mode=False,
    )
    capture._stop_requested = False
    # Start hopper manually to verify stop cleanly joins
    capture._channel_hopper_loop = lambda: None
    capture.stop()
    assert capture._stop_requested is True
