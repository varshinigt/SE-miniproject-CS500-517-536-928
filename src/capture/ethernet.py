"""
F1: Promiscuous Ethernet capture (REQ-F1-01).

Captures every frame seen on a wired interface and hands each one to a
callback (normally the F2 parser) together with the interface name.
"""

import logging
import socket
from typing import Any, Callable, Optional

from scapy.all import sniff

from src.capture.stats import CaptureStats, StatsTracker

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
    ) -> None:
        self.interface = interface
        self.handler = handler
        self.bpf_filter = bpf_filter
        self._sniffer = sniffer
        self._stop_requested = False
        self.captured = 0
        self.stats: Optional[CaptureStats] = None

    def _on_packet(self, packet: Any) -> None:
        self.captured += 1
        if self.handler is not None:
            self.handler(packet, self.interface)

    def stop(self) -> None:
        """Ask the capture loop to finish after the current packet."""
        self._stop_requested = True

    def start(self) -> int:
        """Capture until stop() is called. Returns the packets captured.

        Raises CaptureError if the interface is missing or the process
        is not allowed to open it, instead of crashing with a traceback.
        """
        if not interface_exists(self.interface):
            logger.error("Interface %s does not exist", self.interface)
            raise CaptureError(f"Interface {self.interface} not found")

        self._stop_requested = False
        self.captured = 0
        tracker = StatsTracker(self.interface)
        tracker.start()
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
        self.stats = tracker.finish(self.captured)
        logger.info("Capture stopped: %s", self.stats.summary())
        return self.captured
