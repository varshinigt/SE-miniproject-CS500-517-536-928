"""
F1: PCAP session recording, rotation and replay (REQ-F1-05).

Saves captured packets to timestamped .pcap files, starts a new file when
the size or duration limit is reached, and can replay a saved file back
into the parser so the system can be demonstrated without live traffic.
"""

import logging
import os
import time
from datetime import datetime
from typing import Any, Callable, List, Optional

from scapy.utils import PcapReader, PcapWriter

logger = logging.getLogger(__name__)

PCAP_GLOBAL_HEADER_BYTES = 24
PCAP_RECORD_HEADER_BYTES = 16

DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_SECONDS = 15 * 60  # 15 minutes


class PcapSession:
    """Writes packets to PCAP files and rotates them by size or time."""

    def __init__(
        self,
        output_dir: str,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_seconds: float = DEFAULT_MAX_SECONDS,
        prefix: str = "capture",
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_bytes <= 0 or max_seconds <= 0:
            raise ValueError("max_bytes and max_seconds must be positive")
        self.output_dir = output_dir
        self.max_bytes = max_bytes
        self.max_seconds = max_seconds
        self.prefix = prefix
        self._clock = clock
        self._writer: Optional[PcapWriter] = None
        self._file_bytes = 0
        self._file_started = 0.0
        self._file_index = 0
        self.files: List[str] = []
        self.packets_written = 0
        os.makedirs(output_dir, exist_ok=True)

    def _new_filename(self) -> str:
        stamp = datetime.fromtimestamp(self._clock()).strftime("%Y%m%d_%H%M%S")
        self._file_index += 1
        name = f"{self.prefix}_{stamp}_{self._file_index:03d}.pcap"
        return os.path.join(self.output_dir, name)

    def _open_new_file(self) -> None:
        self._close_current()
        path = self._new_filename()
        self._writer = PcapWriter(path, sync=True)
        self._file_bytes = PCAP_GLOBAL_HEADER_BYTES
        self._file_started = self._clock()
        self.files.append(path)
        logger.info("Started PCAP file %s", path)

    def _close_current(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    def _needs_rotation(self, packet_bytes: int) -> bool:
        if self._writer is None:
            return True
        too_big = self._file_bytes + packet_bytes > self.max_bytes
        too_old = self._clock() - self._file_started >= self.max_seconds
        # never rotate an empty file, otherwise one huge packet loops forever
        has_packets = self._file_bytes > PCAP_GLOBAL_HEADER_BYTES
        return has_packets and (too_big or too_old)

    def write(self, packet: Any) -> None:
        """Append one packet, rotating to a new file first if needed."""
        packet_bytes = PCAP_RECORD_HEADER_BYTES + len(packet)
        if self._writer is None or self._needs_rotation(packet_bytes):
            self._open_new_file()
        self._writer.write(packet)
        self._file_bytes += packet_bytes
        self.packets_written += 1

    def close(self) -> None:
        """Finish the current file."""
        self._close_current()

    def __enter__(self) -> "PcapSession":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


def replay_pcap(
    path: str,
    handler: Callable[[Any, str], None],
    interface: str = "replay",
) -> int:
    """Feed every packet of a saved PCAP to handler, in original order.

    Returns the number of packets delivered. Raises FileNotFoundError if
    the file does not exist.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"PCAP file not found: {path}")
    count = 0
    with PcapReader(path) as reader:
        for packet in reader:
            handler(packet, interface)
            count += 1
    logger.info("Replayed %d packets from %s", count, path)
    return count
