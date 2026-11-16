
"""Bounded asynchronous packet-processing queue for NFR-PERF-02."""

import logging
import queue
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

PacketHandler = Callable[[Any, str], None]


class PacketProcessingQueue:
    """Process captured packets in a worker without blocking capture."""

    def __init__(
        self,
        handler: PacketHandler,
        maxsize: int = 1000,
    ) -> None:
        if maxsize <= 0:
            raise ValueError("maxsize must be positive")

        self.handler = handler
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self.processed = 0
        self.dropped = 0
        self.errors = 0
        self._lock = threading.Lock()
        self._worker = threading.Thread(
            target=self._process,
            name="packet-processing-worker",
            daemon=True,
        )
        self._started = False
        self._closed = False

    @property
    def queue_depth(self) -> int:
        """Number of packets currently waiting for processing."""
        return self._queue.qsize()

    def start(self) -> None:
        """Start the background processing worker."""
        if self._closed:
            raise RuntimeError("Queue is already closed")
        if not self._started:
            self._worker.start()
            self._started = True

    def submit(self, packet: Any, interface: str) -> bool:
        """Enqueue a packet without blocking. Return False if full."""
        if self._closed:
            return False

        if not self._started:
            self.start()

        try:
            self._queue.put_nowait((packet, interface))
            return True
        except queue.Full:
            with self._lock:
                self.dropped += 1
            return False

    def _process(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return

                packet, interface = item
                try:
                    self.handler(packet, interface)
                    with self._lock:
                        self.processed += 1
                except Exception:
                    with self._lock:
                        self.errors += 1
                    logger.exception("Packet processing failed")
            finally:
                self._queue.task_done()

    def close(self, wait: bool = True) -> None:
        """Stop accepting packets and drain pending packets."""
        if self._closed:
            return

        self._closed = True

        if not self._started:
            return

        if wait:
            self._queue.join()

        self._queue.put(None)

        if wait:
            self._worker.join()
