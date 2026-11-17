"""
F1: WiFi 802.11 monitor mode capture and channel hopping (REQ-F1-02).

Enables promiscuous frame sniffing across 2.4 GHz channels 1 through 13
at a configurable hop frequency (default 250 ms), streaming raw 802.11 frames
to the downstream parser or PCAP session recorder.
"""

import itertools
import logging
import subprocess  # nosec B404
import threading
from typing import Any, Callable, List, Optional

from scapy.all import sniff

from src.capture import ethernet
from src.capture.ethernet import CaptureError, PacketHandler
from src.capture.packet_queue import PacketProcessingQueue
from src.capture.stats import CaptureStats, StatsTracker

logger = logging.getLogger(__name__)

interface_exists = ethernet.interface_exists

DEFAULT_CHANNELS: List[int] = list(range(1, 14))
DEFAULT_HOP_INTERVAL: float = 0.25  # 250 milliseconds


def set_interface_channel(interface: str, channel: int) -> bool:
    """Set the 2.4 GHz channel of a wireless monitor interface using system utilities.

    Attempts ``iw dev <iface> set channel <ch>`` first, falling back to
    ``iwconfig <iface> channel <ch>``. Returns True on success, False on error.
    """
    for cmd in (
        ["iw", "dev", interface, "set", "channel", str(channel)],
        ["iwconfig", interface, "channel", str(channel)],
    ):
        try:
            res = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                check=False,
                timeout=2,
            )
            if res.returncode == 0:
                return True
        except (FileNotFoundError, PermissionError, subprocess.SubprocessError):
            continue
    return False


class WiFiCapture:
    """Promiscuous 802.11 monitor-mode capture with background channel hopping."""

    def __init__(
        self,
        interface: str = "wlan0mon",
        channels: Optional[List[int]] = None,
        hop_interval: float = DEFAULT_HOP_INTERVAL,
        handler: Optional[PacketHandler] = None,
        sniffer: Callable[..., Any] = sniff,
        channel_setter: Optional[Callable[[str, int], bool]] = None,
        bpf_filter: Optional[str] = None,
        async_processing: bool = False,
        queue_size: int = 1000,
    ) -> None:
        if hop_interval <= 0:
            raise ValueError("hop_interval must be positive")
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")

        self.interface = interface
        self.channels = list(channels) if channels is not None else list(DEFAULT_CHANNELS)
        self.hop_interval = hop_interval
        self.handler = handler
        self.bpf_filter = bpf_filter
        self.async_processing = async_processing
        self.queue_size = queue_size
        self._sniffer = sniffer
        self._channel_setter = channel_setter or set_interface_channel

        self._stop_requested = False
        self._stop_hopper = threading.Event()
        self._hopper_thread: Optional[threading.Thread] = None

        self.captured = 0
        self.current_channel: int = self.channels[0] if self.channels else 1
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

    def set_channel(self, channel: int) -> bool:
        """Switch the wireless interface to the specified channel."""
        success = self._channel_setter(self.interface, channel)
        if success:
            self.current_channel = channel
            logger.debug("Switched %s to channel %d", self.interface, channel)
        return success

    def _channel_hopper_loop(self) -> None:
        """Background thread worker to rotate 2.4 GHz channels at configured interval."""
        channel_cycle = itertools.cycle(self.channels)
        while not self._stop_hopper.is_set():
            ch = next(channel_cycle)
            try:
                self.set_channel(ch)
            except Exception as e:
                logger.debug("Failed setting channel %d on %s: %s", ch, self.interface, e)
            if self._stop_hopper.wait(timeout=self.hop_interval):
                break

    def _on_packet(self, packet: Any) -> None:
        self.captured += 1
        if self.handler is None:
            return

        if self.processing_queue is not None:
            self.processing_queue.submit(packet, self.interface)
        else:
            self.handler(packet, self.interface)

    def stop(self) -> None:
        """Request both the sniffer loop and channel hopper thread to stop."""
        self._stop_requested = True
        self._stop_hopper.set()

    def start(self) -> int:
        """Start channel hopping and capture 802.11 frames until stop() is called.

        Raises:
            CaptureError: If interface is missing or process lacks permissions.
        """
        if not ethernet.interface_exists(self.interface):
            logger.error("Interface %s does not exist", self.interface)
            raise CaptureError(f"Interface {self.interface} not found")

        self._stop_requested = False
        self._stop_hopper.clear()
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

        if len(self.channels) > 1 and self.hop_interval > 0:
            self._hopper_thread = threading.Thread(
                target=self._channel_hopper_loop,
                name=f"wifi-hopper-{self.interface}",
                daemon=True,
            )
            self._hopper_thread.start()
            logger.info(
                "Started channel hopping on %s across channels %s (interval=%.2fs)",
                self.interface,
                self.channels,
                self.hop_interval,
            )

        logger.info("Starting WiFi monitor capture on %s", self.interface)
        try:
            self._sniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                filter=self.bpf_filter,
                stop_filter=lambda _packet: self._stop_requested,
            )
        except PermissionError as exc:
            logger.error("Permission denied capturing on %s", self.interface)
            raise CaptureError(
                f"Permission denied on {self.interface} (run with root)"
            ) from exc
        finally:
            self.stop()
            if self._hopper_thread is not None and self._hopper_thread.is_alive():
                self._hopper_thread.join(timeout=2.0)
                self._hopper_thread = None

            if self.processing_queue is not None:
                self.processing_queue.close(wait=True)

        self.stats = tracker.finish(self.captured)
        logger.info("WiFi capture stopped: %s", self.stats.summary())
        return self.captured
