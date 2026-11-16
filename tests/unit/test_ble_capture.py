"""Unit tests for F1 Bluetooth Low Energy capture (UT_F1_03, TC-F1-03)."""

import pytest
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND, BTLE_ADV_NONCONN_IND

from src.capture import ble
from src.capture.ble import BLECapture, hci_device_exists
from src.capture.ethernet import CaptureError


class FakeSniffer:
    """Stands in for scapy.sniff so tests need no root or Bluetooth hardware."""

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
def hci0_exists(monkeypatch):
    monkeypatch.setattr(ble, "hci_device_exists", lambda name: True)


def make_ble_advertisements():
    return [
        BTLE() / BTLE_ADV() / BTLE_ADV_IND(AdvA="aa:bb:cc:dd:ee:01"),
        BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA="aa:bb:cc:dd:ee:02"),
    ]


def test_ble_capture_defaults():
    capture = BLECapture("hci0")
    assert capture.hci_device == "hci0"
    assert capture.captured == 0
    assert capture.queue_size == 1000


def test_ble_capture_invalid_parameters():
    with pytest.raises(ValueError, match="queue_size must be positive"):
        BLECapture(queue_size=0)


def test_ble_capture_forwards_advertisements_to_handler():
    received = []
    packets = make_ble_advertisements()
    sniffer = FakeSniffer(packets)

    capture = BLECapture(
        hci_device="hci0",
        handler=lambda p, dev: received.append((p, dev)),
        sniffer=sniffer,
    )

    total = capture.start()
    assert total == 2
    assert len(received) == 2
    assert all(dev == "hci0" for _, dev in received)
    assert sniffer.kwargs["store"] is False


def test_ble_capture_without_handler():
    packets = make_ble_advertisements()
    capture = BLECapture("hci0", sniffer=FakeSniffer(packets))
    assert capture.start() == 2


def test_ble_capture_stop_ends_capture():
    holder = {}

    def handler(packet, dev):
        holder["capture"].stop()

    capture = BLECapture(
        hci_device="hci0",
        handler=handler,
        sniffer=FakeSniffer(make_ble_advertisements()),
    )
    holder["capture"] = capture
    assert capture.start() == 1


def test_ble_capture_missing_device_raises_capture_error(monkeypatch):
    monkeypatch.setattr(ble, "hci_device_exists", lambda name: False)
    capture = BLECapture("hci9", sniffer=FakeSniffer())
    with pytest.raises(CaptureError, match="not found"):
        capture.start()


def test_ble_capture_permission_denied_raises_capture_error():
    sniffer = FakeSniffer(error=PermissionError("Need CAP_NET_ADMIN"))
    capture = BLECapture("hci0", sniffer=sniffer)
    with pytest.raises(CaptureError, match="Permission denied"):
        capture.start()


def test_ble_capture_async_processing_queue():
    received = []
    packets = make_ble_advertisements()

    capture = BLECapture(
        hci_device="hci0",
        handler=lambda p, dev: received.append(p),
        sniffer=FakeSniffer(packets),
        async_processing=True,
        queue_size=10,
    )

    total = capture.start()
    assert total == 2
    assert len(received) == 2
    assert capture.processed == 2
    assert capture.queue_dropped == 0
    assert capture.queue_depth == 0


def test_hci_device_exists_helper(tmp_path):
    sysfs = tmp_path / "sys_bluetooth"
    sysfs.mkdir()
    (sysfs / "hci0").mkdir()

    assert hci_device_exists("hci0", sysfs_root=str(sysfs)) is True
    assert hci_device_exists("hci1", sysfs_root=str(sysfs)) is False
