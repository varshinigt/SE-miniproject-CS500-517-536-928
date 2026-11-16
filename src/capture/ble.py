"""
F1: Bluetooth Low Energy advertisement capture (REQ-F1-03).

Captures BLE advertisement frames (such as ADV_IND and ADV_NONCONN_IND)
via Linux BlueZ HCI interfaces (default hci0) and passes normalized or
raw frames to the downstream pipeline.
"""

import logging
import os
from typing import Any, Callable, Optional

from scapy.all import sniff

from src.capture.ethernet import CaptureError, PacketHandler
from src.capture.packet_queue import PacketProcessingQueue
from src.capture.stats import CaptureStats, StatsTracker

logger = logging.getLogger(__name__)

SYSFS_BLUETOOTH = "/sys/class/bluetooth"


def hci_device_exists(device: str, sysfs_root: str = SYSFS_BLUETOOTH) -> bool:
    """Return True if the operating system reports the given Bluetooth HCI device.

    Checks ``/sys/class/bluetooth/<device>`` on Linux systems, or accepts
    standard hci0 device names in development/test harnesses.
    """
    path = os.path.join(sysfs_root, device)
    if os.path.exists(path):
        return True
    return False


class BLECapture:
    """Bluetooth Low Energy advertisement sniffer via BlueZ HCI sockets."""

    def __init__(
        self,
        hci_device: str = "hci0",
        handler: Optional[PacketHandler] = None,
        sniffer: Callable[..., Any] = sniff,
        bpf_filter: Optional[str] = None,
        async_processing: bool = False,
        queue_size: int = 1000,
    ) -> None:
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")

        self.hci_device = hci_device
        self.handler = handler
        self.bpf_filter = bpf_filter
        self.async_processing = async_processing
        self.queue_size = queue_size
        self._sniffer = sniffer

        self._stop_requested = False
        self.captured = 0
        self.stats: Optional[CaptureStats] = None
        self.processing_queue: Optional[PacketProcessingQueue] = None

    @property
    def queue_depth(self) -> int:
        return (
            self.processing_queue.queue_depth
            if self.processing_queue is not None
            else 0
        )

    @property
    def queue_dropped(self) -> int:
        return (
            self.processing_queue.dropped
            if self.processing_queue is not None
            else 0
        )

    @property
    def processed(self) -> int:
        return (
            self.processing_queue.processed
            if self.processing_queue is not None
            else 0
        )

    @property
    def processing_errors(self) -> int:
        return (
            self.processing_queue.errors
            if self.processing_queue is not None
            else 0
        )

    def _on_packet(self, packet: Any) -> None:
        self.captured += 1
        if self.handler is None:
            return

        if self.processing_queue is not None:
            self.processing_queue.submit(packet, self.hci_device)
        else:
            self.handler(packet, self.hci_device)

    def stop(self) -> None:
        """Request the capture loop to finish after the current packet."""
        self._stop_requested = True

    def start(self) -> int:
        """Start capturing BLE advertisements until stop() is called.

        Raises:
            CaptureError: If the HCI adapter is missing or unprivileged.
        """
        if not hci_device_exists(self.hci_device):
            logger.error("HCI device %s does not exist", self.hci_device)
            raise CaptureError(f"HCI device {self.hci_device} not found")

        self._stop_requested = False
        self.captured = 0
        self.processing_queue = None

        tracker = StatsTracker(self.hci_device)
        tracker.start()

        if self.async_processing and self.handler is not None:
            self.processing_queue = PacketProcessingQueue(
                self.handler,
                maxsize=self.queue_size,
            )
            self.processing_queue.start()

        logger.info("Starting BLE capture on %s", self.hci_device)
        try:
            self._sniffer(
                iface=self.hci_device,
                prn=self._on_packet,
                store=False,
                filter=self.bpf_filter,
                stop_filter=lambda _packet: self._stop_requested,
            )
        except PermissionError as exc:
            logger.error("Permission denied capturing on %s", self.hci_device)
            raise CaptureError(
                f"Permission denied on {self.hci_device} (run with root)"
            ) from exc
        finally:
            if self.processing_queue is not None:
                self.processing_queue.close(wait=True)

        self.stats = tracker.finish(self.captured)
        logger.info("BLE capture stopped: %s", self.stats.summary())
        return self.captured
