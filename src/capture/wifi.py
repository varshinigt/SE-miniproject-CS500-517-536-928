"""
F1: WiFi 802.11 Monitor Mode Capture and Channel Hopping (REQ-F1-02).

Configures wireless interfaces into monitor mode, performs background
channel hopping across 2.4 GHz channels (1-11), and captures 802.11
management, control, and data frames.
"""

import logging
import subprocess
import threading
import time
from typing import Any, Callable, List, Optional

from scapy.all import sniff

from src.capture import ethernet
from src.capture.ethernet import CaptureError

logger = logging.getLogger(__name__)

PacketHandler = Callable[[Any, str], None]
CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def default_command_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    """Executes a system shell command safely."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )


class WifiCapture:
    """Captures 802.11 wireless frames in monitor mode with channel hopping."""

    def __init__(
        self,
        interface: str = "wlan0",
        channels: Optional[List[int]] = None,
        hop_interval: float = 0.25,
        handler: Optional[PacketHandler] = None,
        sniffer: Callable[..., Any] = sniff,
        cmd_runner: CommandRunner = default_command_runner,
        enable_monitor_mode: bool = True,
    ) -> None:
        self.interface = interface
        self.channels = channels or list(range(1, 12))
        self.hop_interval = hop_interval
        self.handler = handler
        self._sniffer = sniffer
        self._cmd_runner = cmd_runner
        self.enable_monitor_mode = enable_monitor_mode

        self.current_channel = self.channels[0] if self.channels else 1
        self._stop_requested = False
        self._hopper_thread: Optional[threading.Thread] = None
        self.captured = 0

    def enable_monitor(self) -> None:
        """Puts the wireless adapter into monitor mode using iw/ip."""
        logger.info("Enabling monitor mode on interface %s", self.interface)
        # Attempt standard Linux monitor mode activation
        res_down = self._cmd_runner(["ip", "link", "set", self.interface, "down"])
        res_mode = self._cmd_runner(["iw", "dev", self.interface, "set", "type", "monitor"])
        res_up = self._cmd_runner(["ip", "link", "set", self.interface, "up"])

        if res_mode.returncode != 0:
            err_msg = res_mode.stderr.strip() or "Unknown error"
            logger.error("Failed to enable monitor mode on %s: %s", self.interface, err_msg)
            raise CaptureError(
                f"Interface {self.interface} does not support monitor mode: {err_msg}"
            )

    def set_channel(self, channel: int) -> bool:
        """Sets the operating WiFi channel using iw."""
        res = self._cmd_runner(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if res.returncode == 0:
            self.current_channel = channel
            return True
        logger.debug(
            "Failed to set channel %d on %s: %s", channel, self.interface, res.stderr.strip()
        )
        return False

    def _channel_hopper_loop(self) -> None:
        """Background loop hopping through channels at hop_interval."""
        idx = 0
        while not self._stop_requested:
            if self.channels:
                idx = (idx + 1) % len(self.channels)
                target_channel = self.channels[idx]
                self.set_channel(target_channel)
            time.sleep(self.hop_interval)

    def _on_packet(self, packet: Any) -> None:
        self.captured += 1
        if self.handler is not None:
            self.handler(packet, self.interface)

    def stop(self) -> None:
        """Stops the packet capture and channel hopping loop."""
        self._stop_requested = True
        if self._hopper_thread and self._hopper_thread.is_alive():
            self._hopper_thread.join(timeout=1.0)

    def start(self) -> int:
        """Starts monitor mode, background channel hopper, and sniffer.

        Returns total packets captured.
        """
        if not ethernet.interface_exists(self.interface):
            logger.error("Wireless interface %s does not exist", self.interface)
            raise CaptureError(f"Interface {self.interface} not found")

        if self.enable_monitor_mode:
            self.enable_monitor()

        self._stop_requested = False
        self.captured = 0

        # Start channel hopper thread if multiple channels are configured
        if len(self.channels) > 1:
            self._hopper_thread = threading.Thread(
                target=self._channel_hopper_loop,
                daemon=True,
                name=f"WifiHopper-{self.interface}",
            )
            self._hopper_thread.start()

        logger.info("Starting WiFi 802.11 capture on %s", self.interface)
        try:
            self._sniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _packet: self._stop_requested,
            )
        except PermissionError as exc:
            logger.error("Permission denied capturing on %s", self.interface)
            raise CaptureError(
                f"Permission denied on {self.interface} (run with root)"
            ) from exc
        finally:
            self.stop()

        logger.info("WiFi capture on %s stopped, %d packets", self.interface, self.captured)
        return self.captured
