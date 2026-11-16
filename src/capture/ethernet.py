
"""
F1: Promiscuous Ethernet capture (REQ-F1-01).

Supports synchronous packet handling and optional bounded asynchronous
processing to prevent slow handlers from blocking packet capture.
"""

import logging
import socket
from typing import Any, Callable, Optional

from scapy.all import sniff

from src.capture.stats import CaptureStats, StatsTracker
from src.capture.packet_queue import PacketProcessingQueue

logger = logging.getLogger(__name__)

PacketHandler = Callable[[Any, str], None]


class CaptureError(Exception):
    """Raised when capture cannot start (missing interface, no permission)."""


def interface_exists(interface: str) -> bool:
    """Return True if the OS knows about the given network interface."""
    return interface in {name for _, name in socket.if_nameindex()}


class EthernetCapture:
    """Promiscuous-mode capture on a single Ethernet interface."""

    def __init__(
        self,
        interface: str = "eth0",
        handler: Optional[PacketHandler] = None,
        sniffer: Callable[..., Any] = sniff,
        bpf_filter: Optional[str] = None,
        async_processing: bool = False,
        queue_size: int = 1000,
    ) -> None:
        self.interface = interface
        self.handler = handler
        self.bpf_filter = bpf_filter
        self._sniffer = sniffer
        self._stop_requested = False
        self.captured = 0
        self.stats: Optional[CaptureStats] = None
        self.async_processing = async_processing
        self.queue_size = queue_size
        self.processing_queue: Optional[PacketProcessingQueue] = None

        if queue_size <= 0:
            raise ValueError("queue_size must be positive")

    @property
    def queue_depth(self) -> int:
        return (
            self.processing_queue.queue_depth
            if self.processing_queue is not None else 0
        )

    @property
    def queue_dropped(self) -> int:
        return (
            self.processing_queue.dropped
            if self.processing_queue is not None else 0
        )

    @property
    def processed(self) -> int:
        return (
            self.processing_queue.processed
            if self.processing_queue is not None else 0
        )

    @property
    def processing_errors(self) -> int:
        return (
            self.processing_queue.errors
            if self.processing_queue is not None else 0
        )

    def _on_packet(self, packet: Any) -> None:
        self.captured += 1

        if self.handler is None:
            return

        if self.processing_queue is not None:
            self.processing_queue.submit(packet, self.interface)
        else:
            self.handler(packet, self.interface)

    def stop(self) -> None:
        """Ask the capture loop to finish after the current packet."""
        self._stop_requested = True

    def start(self) -> int:
        """Capture until stop() is called. Returns packets captured."""
        if not interface_exists(self.interface):
            logger.error("Interface %s does not exist", self.interface)
            raise CaptureError(f"Interface {self.interface} not found")

        self._stop_requested = False
        self.captured = 0
        self.processing_queue = None

        tracker = StatsTracker(self.interface)
        tracker.start()

        if self.async_processing and self.handler is not None:
            self.processing_queue = PacketProcessingQueue(
                self.handler,
                maxsize=self.queue_size,
            )
            self.processing_queue.start()

        logger.info("Starting promiscuous capture on %s", self.interface)

        try:
            self._sniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                promisc=True,
                filter=self.bpf_filter,
                stop_filter=lambda _packet: self._stop_requested,
            )
        except PermissionError as exc:
            logger.error("Permission denied capturing on %s", self.interface)
            raise CaptureError(
                f"Permission denied on {self.interface} (run with root)"
            ) from exc
        finally:
            if self.processing_queue is not None:
                self.processing_queue.close(wait=True)

        self.stats = tracker.finish(self.captured)
        logger.info("Capture stopped: %s", self.stats.summary())

        if self.processing_queue is not None:
            logger.info(
                "Processing summary: processed=%d dropped=%d errors=%d",
                self.processed,
                self.queue_dropped,
                self.processing_errors,
            )

        return self.captured
