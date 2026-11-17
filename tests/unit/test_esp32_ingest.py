"""Unit tests for F1 remote ESP32 sniffer UDP ingestion (UT_F1_04, TC-F1-04)."""

import socket
import struct
import threading
import time
import pytest

from src.capture.esp32 import (
    ESP32Capture,
    ESP32_MAGIC,
    HEADER_FORMAT,
    parse_esp32_datagram,
)
from src.capture.ethernet import CaptureError


def build_esp32_packet(rssi: int, channel: int, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, ESP32_MAGIC, rssi, channel, len(payload))
    return header + payload


def test_parse_esp32_datagram_valid():
    payload = b"\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff"
    data = build_esp32_packet(rssi=-65, channel=11, payload=payload)

    metadata, extracted_payload = parse_esp32_datagram(data)
    assert metadata["rssi"] == -65
    assert metadata["channel"] == 11
    assert metadata["payload_len"] == len(payload)
    assert metadata["source"] == "esp32"
    assert extracted_payload == payload


def test_parse_esp32_datagram_too_short():
    with pytest.raises(ValueError, match="Datagram too short"):
        parse_esp32_datagram(b"ESP1")


def test_parse_esp32_datagram_invalid_magic():
    bad_header = struct.pack(HEADER_FORMAT, b"XYZ1", -50, 6, 10)
    with pytest.raises(ValueError, match="Invalid ESP32 probe magic"):
        parse_esp32_datagram(bad_header + b"1234567890")


def test_parse_esp32_datagram_truncated_payload():
    header = struct.pack(HEADER_FORMAT, ESP32_MAGIC, -40, 1, 20)
    with pytest.raises(ValueError, match="Truncated payload"):
        parse_esp32_datagram(header + b"only_10_by")


def test_esp32_capture_validation():
    with pytest.raises(ValueError, match="queue_size must be positive"):
        ESP32Capture(queue_size=0)

    with pytest.raises(ValueError, match="Invalid port"):
        ESP32Capture(port=70000)


def test_esp32_capture_ingests_datagrams_over_udp():
    received = []
    capture = ESP32Capture(
        host="127.0.0.1",
        port=0,
        handler=lambda p, iface: received.append((p, iface)),
    )

    def sender():
        assert capture._ready.wait(timeout=2.0)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        p1 = build_esp32_packet(-50, 1, b"frame_one")
        p2 = build_esp32_packet(-70, 6, b"frame_two")
        time.sleep(0.02)
        client.sendto(p1, ("127.0.0.1", capture.port))
        time.sleep(0.02)
        client.sendto(p2, ("127.0.0.1", capture.port))
        client.close()

    t = threading.Thread(target=sender, daemon=True)
    t.start()

    total = capture.start(max_packets=2, timeout=2.0)
    t.join(timeout=1.0)

    assert total == 2
    assert len(received) == 2
    assert received[0] == (b"frame_one", "esp32")
    assert received[1] == (b"frame_two", "esp32")
    assert capture.malformed == 0


def test_esp32_capture_defensive_against_malformed_packets():
    received = []
    capture = ESP32Capture(
        host="127.0.0.1",
        port=0,
        handler=lambda p, iface: received.append(p),
    )

    def sender():
        assert capture._ready.wait(timeout=2.0)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Send garbage / truncated datagrams
        client.sendto(b"garbagetruncated", ("127.0.0.1", capture.port))
        client.sendto(b"short", ("127.0.0.1", capture.port))
        time.sleep(0.02)
        # Send valid datagram
        valid = build_esp32_packet(-60, 6, b"valid_frame")
        client.sendto(valid, ("127.0.0.1", capture.port))
        client.close()

    t = threading.Thread(target=sender, daemon=True)
    t.start()

    total = capture.start(max_packets=1, timeout=2.0)
    t.join(timeout=1.0)

    assert total == 1
    assert len(received) == 1
    assert received[0] == b"valid_frame"
    assert capture.malformed >= 2


def test_esp32_capture_bind_error(monkeypatch):
    def fake_socket(*args, **kwargs):
        raise OSError("Address already in use")

    monkeypatch.setattr("socket.socket", fake_socket)
    capture = ESP32Capture(port=5555)
    with pytest.raises(CaptureError, match="Failed to bind"):
        capture.start()


def test_esp32_capture_async_processing_queue():
    received = []
    capture = ESP32Capture(
        host="127.0.0.1",
        port=0,
        handler=lambda p, iface: received.append(p),
        async_processing=True,
        queue_size=20,
    )

    def sender():
        assert capture._ready.wait(timeout=2.0)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        p = build_esp32_packet(-55, 11, b"async_frame")
        time.sleep(0.02)
        client.sendto(p, ("127.0.0.1", capture.port))
        client.close()

    t = threading.Thread(target=sender, daemon=True)
    t.start()

    total = capture.start(max_packets=1, timeout=2.0)
    t.join(timeout=1.0)

    assert total == 1
    assert len(received) == 1
    assert capture.processed == 1
    assert capture.queue_dropped == 0
    assert capture.queue_depth == 0
