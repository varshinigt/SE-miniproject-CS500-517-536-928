"""Performance benchmark for bounded packet processing."""

import time

from src.capture.packet_queue import PacketProcessingQueue


def test_packet_queue_throughput():
    packet_count = 5000
    received = []

    def handler(packet, interface):
        received.append(packet)

    packet_queue = PacketProcessingQueue(
        handler,
        maxsize=packet_count,
    )

    start_time = time.perf_counter()

    for packet_id in range(packet_count):
        assert packet_queue.submit(packet_id, "eth0")

    packet_queue.close(wait=True)

    elapsed = time.perf_counter() - start_time
    throughput = packet_queue.processed / elapsed

    print(f"\nPackets submitted: {packet_count}")
    print(f"Packets processed: {packet_queue.processed}")
    print(f"Packets dropped: {packet_queue.dropped}")
    print(f"Processing errors: {packet_queue.errors}")
    print(f"Elapsed time: {elapsed:.4f} seconds")
    print(f"Throughput: {throughput:.2f} packets/second")

    assert packet_queue.processed == packet_count
    assert packet_queue.dropped == 0
    assert packet_queue.errors == 0
    assert len(received) == packet_count
    assert packet_queue.queue_depth == 0