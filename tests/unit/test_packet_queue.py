
"""Tests for bounded asynchronous packet processing."""

import threading

import pytest

from src.capture.packet_queue import PacketProcessingQueue


def test_queue_processes_submitted_packets():
    received = []
    queue = PacketProcessingQueue(
        lambda packet, interface: received.append((packet, interface))
    )

    queue.submit("packet1", "eth0")
    queue.submit("packet2", "eth0")
    queue.close()

    assert received == [("packet1", "eth0"), ("packet2", "eth0")]
    assert queue.processed == 2
    assert queue.dropped == 0


def test_queue_drops_packets_when_full():
    entered = threading.Event()
    release = threading.Event()

    def slow_handler(packet, interface):
        entered.set()
        release.wait(timeout=2)

    queue = PacketProcessingQueue(slow_handler, maxsize=1)

    assert queue.submit("packet1", "eth0")
    assert entered.wait(timeout=2)

    assert queue.submit("packet2", "eth0")
    assert not queue.submit("packet3", "eth0")
    assert queue.dropped == 1
    assert queue.queue_depth == 1

    release.set()
    queue.close()

    assert queue.processed == 2
    assert queue.dropped == 1


def test_queue_continues_after_handler_error():
    received = []

    def handler(packet, interface):
        if packet == "bad":
            raise ValueError("invalid packet")
        received.append(packet)

    queue = PacketProcessingQueue(handler)
    queue.submit("bad", "eth0")
    queue.submit("good", "eth0")
    queue.close()

    assert received == ["good"]
    assert queue.errors == 1
    assert queue.processed == 1


def test_queue_rejects_nonpositive_capacity():
    with pytest.raises(ValueError):
        PacketProcessingQueue(lambda packet, interface: None, maxsize=0)


def test_queue_rejects_submissions_after_close():
    queue = PacketProcessingQueue(lambda packet, interface: None)
    queue.close()

    assert queue.submit("packet", "eth0") is False


def test_start_after_close_raises_error():
    queue = PacketProcessingQueue(lambda packet, interface: None)
    queue.close()

    with pytest.raises(RuntimeError, match="already closed"):
        queue.start()


def test_close_before_start_does_not_crash():
    queue = PacketProcessingQueue(lambda packet, interface: None)

    queue.close()

    assert queue.queue_depth == 0


def test_start_called_twice_does_not_restart_worker():
    queue = PacketProcessingQueue(lambda packet, interface: None)

    queue.start()
    worker = queue._worker

    queue.start()

    assert queue._worker is worker
    assert queue._worker.is_alive()

    queue.close()


def test_close_called_twice_does_not_crash():
    queue = PacketProcessingQueue(lambda packet, interface: None)

    queue.submit("packet", "eth0")
    queue.close()
    queue.close()

    assert queue.processed == 1
    assert queue.submit("another", "eth0") is False


def test_close_without_wait_stops_worker():
    queue = PacketProcessingQueue(lambda packet, interface: None)

    queue.submit("packet", "eth0")
    queue.close(wait=False)

    queue._worker.join(timeout=2)

    assert not queue._worker.is_alive()
    assert queue.submit("another", "eth0") is False
