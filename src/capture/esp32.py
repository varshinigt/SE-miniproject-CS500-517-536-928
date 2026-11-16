"""
F1: Remote ESP32 sniffer probe frame ingestion over UDP (REQ-F1-04).

Listens on UDP port 5555 to ingest raw wireless 802.11 frames forwarded
by external ESP32 microcontroller sniffer nodes, stripping header metadata
(RSSI, channel, length) and dispatching payload frames to the pipeline.
"""

import logging
import select
import socket
import struct
import threading
from typing import Any, Dict, Optional, Tuple

from src.capture.ethernet import CaptureError, PacketHandler
from src.capture.packet_queue import PacketProcessingQueue
from src.capture.stats import CaptureStats, StatsTracker

logger = logging.getLogger(__name__)

DEFAULT_PORT = 5555
DEFAULT_HOST = "0.0.0.0"  # nosec B104

# Header structure: Magic (4B), RSSI (int8), Channel (uint8), Payload Length (uint16)
ESP32_MAGIC = b"ESP1"
HEADER_FORMAT = "!4sbBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 8 bytes


def parse_esp32_datagram(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """Parse an incoming ESP32 UDP sniffer datagram into metadata and raw frame.

    Raises:
        ValueError: If datagram is truncated, missing magic, or length mismatches.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Datagram too short: expected at least {HEADER_SIZE} bytes, got {len(data)}"
        )

    magic, rssi, channel, payload_len = struct.unpack_from(HEADER_FORMAT, data, 0)
    if magic != ESP32_MAGIC:
        raise ValueError(f"Invalid ESP32 probe magic: {magic!r}")

    payload = data[HEADER_SIZE:]
    if len(payload) < payload_len:
        raise ValueError(
            f"Truncated payload: header claims {payload_len} bytes, but received {len(payload)}"
        )

    metadata = {
        "rssi": int(rssi),
        "channel": int(channel),
        "payload_len": int(payload_len),
        "source": "esp32",
    }
    return metadata, payload[:payload_len]


class ESP32Capture:
    """UDP ingestion worker capturing forwarded frames from remote ESP32 sniffer nodes."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        handler: Optional[PacketHandler] = None,
        async_processing: bool = False,
        queue_size: int = 1000,
    ) -> None:
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        if not (0 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        self.host = host
        self.port = port
        self.handler = handler
        self.async_processing = async_processing
        self.queue_size = queue_size

        self._stop_requested = False
        self._ready = threading.Event()
        self._socket: Optional[socket.socket] = None
        self._worker_thread: Optional[threading.Thread] = None

        self.captured = 0
        self.malformed = 0
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

    def _on_packet(self, payload: bytes, metadata: Dict[str, Any]) -> None:
        self.captured += 1
        if self.handler is None:
            return

        if self.processing_queue is not None:
            self.processing_queue.submit(payload, "esp32")
        else:
            self.handler(payload, "esp32")

    def stop(self) -> None:
        """Stop receiving datagrams and shut down socket."""
        self._stop_requested = True
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as exc:
                logger.debug("Error closing UDP socket: %s", exc)

    def start(
        self,
        max_packets: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> int:
        """Listen on the configured UDP port and ingest frames.

        Args:
            max_packets: Optional maximum number of valid packets to ingest before exiting.
            timeout: Optional maximum seconds to listen before exiting.

        Returns:
            Total count of successfully parsed packets.
        """
        import time

        self._stop_requested = False
        self._ready.clear()
        self.captured = 0
        self.malformed = 0
        self.processing_queue = None

        tracker = StatsTracker(f"udp/{self.port}")
        tracker.start()

        if self.async_processing and self.handler is not None:
            self.processing_queue = PacketProcessingQueue(
                self.handler,
                maxsize=self.queue_size,
            )
            self.processing_queue.start()

        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self.host, self.port))
            self.port = self._socket.getsockname()[1]
            self._socket.settimeout(0.5)
            self._ready.set()
            logger.info("ESP32 UDP ingestion listening on %s:%d", self.host, self.port)
        except PermissionError as exc:
            self._ready.set()
            raise CaptureError(
                f"Permission denied binding to {self.host}:{self.port}"
            ) from exc
        except OSError as exc:
            self._ready.set()
            raise CaptureError(
                f"Failed to bind {self.host}:{self.port}: {exc}"
            ) from exc

        start_time = time.monotonic()
        try:
            while not self._stop_requested:
                if max_packets is not None and self.captured >= max_packets:
                    break
                if timeout is not None and (time.monotonic() - start_time) >= timeout:
                    break

                try:
                    rlist, _, _ = select.select([self._socket], [], [], 0.2)
                    if not rlist or self._stop_requested:
                        continue
                    data, addr = self._socket.recvfrom(65535)
                except (socket.timeout, OSError):
                    continue

                try:
                    metadata, payload = parse_esp32_datagram(data)
                    metadata["remote_ip"] = addr[0]
                    metadata["remote_port"] = addr[1]
                    self._on_packet(payload, metadata)
                except ValueError as err:
                    self.malformed += 1
                    logger.debug("Rejected malformed ESP32 probe datagram: %s", err)
                    continue
        finally:
            self.stop()
            if self.processing_queue is not None:
                self.processing_queue.close(wait=True)

        self.stats = tracker.finish(self.captured)
        logger.info(
            "ESP32 ingestion stopped: captured=%d malformed=%d",
            self.captured,
            self.malformed,
        )
        return self.captured


# Backward-compatible alias
ESP32Receiver = ESP32Capture
