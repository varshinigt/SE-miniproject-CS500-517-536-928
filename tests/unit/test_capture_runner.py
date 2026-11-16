"""Unit tests for the F1 capture service runner (NFR-PORT-01)."""

import threading

import pytest
from scapy.layers.dot11 import Dot11
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from src.capture.ble import BLECapture
from src.capture.esp32 import DEFAULT_PORT, ESP32Capture
from src.capture.ethernet import CaptureError, EthernetCapture
from src.capture.runner import (
    CaptureRunner,
    CaptureSource,
    build_sources,
    esp32_writer,
    main,
    parse_args,
    session_writer,
)
from src.capture.session import PcapSession
from src.capture.wifi import WiFiCapture


class FakeCapture:
    """Stands in for a capture engine: blocks until stop(), or fails at once."""

    def __init__(self, fail=False):
        self.fail = fail
        self.started = threading.Event()
        self._stopped = threading.Event()
        self.stop_calls = 0

    def start(self):
        self.started.set()
        if self.fail:
            raise CaptureError("interface not found")
        self._stopped.wait(5)
        return 0

    def stop(self):
        self.stop_calls += 1
        self._stopped.set()


def make_source(tmp_path, name, fail=False):
    return CaptureSource(name, FakeCapture(fail=fail), PcapSession(str(tmp_path), prefix=name))


# --- argument parsing -------------------------------------------------------

def test_parse_args_requires_a_source():
    with pytest.raises(SystemExit):
        parse_args([])


def test_parse_args_esp32_flag_defaults_to_port_5555():
    args = parse_args(["--esp32"])
    assert args.esp32 == DEFAULT_PORT == 5555


def test_parse_args_esp32_custom_port_and_rotation_defaults():
    args = parse_args(["--esp32", "6000", "--ethernet", "eth0"])
    assert args.esp32 == 6000
    assert args.ethernet == "eth0"
    assert args.max_mb == 50
    assert args.max_minutes == 15


def test_parse_args_rejects_non_positive_rotation():
    with pytest.raises(SystemExit):
        parse_args(["--ethernet", "eth0", "--max-mb", "0"])


# --- building sources -------------------------------------------------------

def test_build_sources_creates_one_engine_and_session_per_source(tmp_path):
    args = parse_args([
        "--ethernet", "eth0", "--wifi", "wlan0mon", "--ble", "hci0", "--esp32",
        "--output-dir", str(tmp_path), "--max-mb", "2", "--max-minutes", "1",
    ])
    sources = build_sources(args)

    assert [s.name for s in sources] == ["ethernet", "wifi", "ble", "esp32"]
    assert isinstance(sources[0].capture, EthernetCapture)
    assert isinstance(sources[1].capture, WiFiCapture)
    assert isinstance(sources[2].capture, BLECapture)
    assert isinstance(sources[3].capture, ESP32Capture)
    assert sources[3].capture.port == DEFAULT_PORT
    for source in sources:
        assert source.capture.async_processing is True
        assert source.session.max_bytes == 2 * 1024 * 1024
        assert source.session.max_seconds == 60
    assert sources[0].session.prefix == "eth_eth0"


def test_build_sources_only_includes_requested_sources(tmp_path):
    sources = build_sources(parse_args(["--ble", "hci1", "--output-dir", str(tmp_path)]))
    assert [s.name for s in sources] == ["ble"]
    assert sources[0].capture.hci_device == "hci1"


# --- packet handlers --------------------------------------------------------

def test_session_writer_records_packets(tmp_path):
    session = PcapSession(str(tmp_path))
    session_writer(session)(Ether() / b"hello", "eth0")
    session.close()

    packets = rdpcap(session.files[0])
    assert len(packets) == 1
    assert bytes(packets[0]).endswith(b"hello")


def test_esp32_writer_stores_raw_bytes_as_80211_frames(tmp_path):
    session = PcapSession(str(tmp_path))
    frame = bytes(Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff"))
    esp32_writer(session)(frame, "esp32")
    session.close()

    packets = rdpcap(session.files[0])
    assert len(packets) == 1
    assert packets[0].haslayer(Dot11)
    assert bytes(packets[0]) == frame


# --- runner -----------------------------------------------------------------

def test_runner_requires_sources():
    with pytest.raises(ValueError):
        CaptureRunner([])


def test_runner_runs_until_stopped(tmp_path):
    sources = [make_source(tmp_path, "a"), make_source(tmp_path, "b")]
    runner = CaptureRunner(sources, poll_interval=0.01)
    result = {}
    thread = threading.Thread(target=lambda: result.update(code=runner.run()))
    thread.start()

    for source in sources:
        assert source.capture.started.wait(2)
    runner.stop()
    thread.join(5)

    assert not thread.is_alive()
    assert result["code"] == 0
    assert all(s.capture.stop_calls >= 1 for s in sources)


def test_runner_keeps_running_when_one_source_fails(tmp_path):
    good = make_source(tmp_path, "good")
    bad = make_source(tmp_path, "bad", fail=True)
    runner = CaptureRunner([good, bad], poll_interval=0.01)
    result = {}
    thread = threading.Thread(target=lambda: result.update(code=runner.run()))
    thread.start()

    assert good.capture.started.wait(2)
    assert bad.capture.started.wait(2)
    assert thread.is_alive()
    runner.stop()
    thread.join(5)

    assert result["code"] == 0
    assert isinstance(bad.error, CaptureError)
    assert good.error is None


def test_runner_exits_non_zero_when_every_source_fails(tmp_path):
    sources = [make_source(tmp_path, "a", fail=True), make_source(tmp_path, "b", fail=True)]
    assert CaptureRunner(sources, poll_interval=0.01).run() == 1


def test_main_exits_non_zero_without_hardware(tmp_path):
    # No interface with this name exists, so the only source fails at once.
    code = main(["--ethernet", "pps-missing0", "--output-dir", str(tmp_path)])
    assert code == 1


def test_module_entry_point_runs_main(monkeypatch):
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", ["src.capture", "--help"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("src.capture", run_name="__main__")
    assert exc.value.code == 0
