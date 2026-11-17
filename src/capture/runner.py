"""
F1: Capture service runner (NFR-PORT-01).

Starts one or more capture sources (Ethernet, WiFi, BLE, ESP32) in background
threads and records each one into its own rotating PCAP session. This is the
entry point the systemd unit and the docker-compose ``capture`` service run:

    python -m src.capture --ethernet eth0 --esp32 --output-dir data/pcaps

A source whose interface is missing is logged and skipped, so the service
keeps capturing on whatever hardware is present. If no source can run, the
process exits with a non-zero code so systemd restarts it.
"""

import argparse
import logging
import signal
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Sequence

from scapy.layers.dot11 import Dot11

from src.capture.ble import BLECapture
from src.capture.esp32 import DEFAULT_PORT, ESP32Capture
from src.capture.ethernet import EthernetCapture
from src.capture.session import DEFAULT_MAX_BYTES, DEFAULT_MAX_SECONDS, PcapSession
from src.capture.wifi import WiFiCapture

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = "data/pcaps"


@dataclass
class CaptureSource:
    """One capture engine together with the PCAP session it records into."""

    name: str
    capture: Any
    session: PcapSession
    error: Optional[BaseException] = None
    thread: Optional[threading.Thread] = field(default=None, repr=False)


def session_writer(session: PcapSession) -> Callable[[Any, str], None]:
    """Handler that writes captured scapy packets straight into a session."""

    def _write(packet: Any, _interface: str) -> None:
        session.write(packet)

    return _write


def esp32_writer(session: PcapSession) -> Callable[[Any, str], None]:
    """Handler for ESP32 payloads, which arrive as raw 802.11 frame bytes.

    Wrapping them in a Dot11 layer makes the PCAP use the 802.11 link type,
    so Wireshark and the parser decode them as WiFi frames.
    """

    def _write(payload: bytes, _interface: str) -> None:
        session.write(Dot11(payload))

    return _write


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.capture",
        description="Run Pocket Packet Sniffer capture sources and record PCAP sessions.",
    )
    parser.add_argument("--ethernet", metavar="IFACE", help="Ethernet interface, e.g. eth0")
    parser.add_argument("--wifi", metavar="IFACE", help="Monitor-mode interface, e.g. wlan0mon")
    parser.add_argument("--ble", metavar="HCI", help="BlueZ HCI device, e.g. hci0")
    parser.add_argument(
        "--esp32",
        metavar="PORT",
        type=int,
        nargs="?",
        const=DEFAULT_PORT,
        help=f"Listen for ESP32 sniffer probes on this UDP port (default {DEFAULT_PORT})",
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for PCAP files")
    parser.add_argument(
        "--max-mb",
        type=float,
        default=DEFAULT_MAX_BYTES / (1024 * 1024),
        help="Rotate a PCAP file after this many megabytes (default 50)",
    )
    parser.add_argument(
        "--max-minutes",
        type=float,
        default=DEFAULT_MAX_SECONDS / 60,
        help="Rotate a PCAP file after this many minutes (default 15)",
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level (default INFO)")
    args = parser.parse_args(argv)

    if not (args.ethernet or args.wifi or args.ble or args.esp32 is not None):
        parser.error("choose at least one source: --ethernet, --wifi, --ble or --esp32")
    if args.max_mb <= 0 or args.max_minutes <= 0:
        parser.error("--max-mb and --max-minutes must be positive")
    return args


def build_sources(args: argparse.Namespace) -> List[CaptureSource]:
    """Create a capture engine and PCAP session for each requested source."""
    max_bytes = int(args.max_mb * 1024 * 1024)
    max_seconds = args.max_minutes * 60

    def new_session(prefix: str) -> PcapSession:
        return PcapSession(
            args.output_dir,
            max_bytes=max_bytes,
            max_seconds=max_seconds,
            prefix=prefix,
        )

    sources: List[CaptureSource] = []
    if args.ethernet:
        session = new_session(f"eth_{args.ethernet}")
        capture = EthernetCapture(
            args.ethernet, handler=session_writer(session), async_processing=True
        )
        sources.append(CaptureSource("ethernet", capture, session))
    if args.wifi:
        session = new_session(f"wifi_{args.wifi}")
        capture = WiFiCapture(
            args.wifi, handler=session_writer(session), async_processing=True
        )
        sources.append(CaptureSource("wifi", capture, session))
    if args.ble:
        session = new_session(f"ble_{args.ble}")
        capture = BLECapture(
            args.ble, handler=session_writer(session), async_processing=True
        )
        sources.append(CaptureSource("ble", capture, session))
    if args.esp32 is not None:
        session = new_session("esp32")
        capture = ESP32Capture(
            port=args.esp32, handler=esp32_writer(session), async_processing=True
        )
        sources.append(CaptureSource("esp32", capture, session))
    return sources


class CaptureRunner:
    """Runs capture sources in threads until stopped or until all have exited."""

    def __init__(self, sources: List[CaptureSource], poll_interval: float = 1.0) -> None:
        if not sources:
            raise ValueError("at least one capture source is required")
        self.sources = sources
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()

    def _run_source(self, source: CaptureSource) -> None:
        try:
            source.capture.start()
        except Exception as exc:  # one broken source must not stop the others
            source.error = exc
            logger.error("Capture source %s stopped: %s", source.name, exc)

    def stop(self, *_signal_args: Any) -> None:
        """Ask every source to stop. Safe to use as a signal handler."""
        self._stop_event.set()
        for source in self.sources:
            source.capture.stop()

    def run(self) -> int:
        """Start all sources and block until stopped. Returns a process exit code."""
        for source in self.sources:
            source.thread = threading.Thread(
                target=self._run_source,
                args=(source,),
                name=f"capture-{source.name}",
                daemon=True,
            )
            source.thread.start()
            logger.info("Started capture source %s", source.name)

        while not self._stop_event.is_set():
            if not any(s.thread.is_alive() for s in self.sources):
                break
            self._stop_event.wait(self.poll_interval)

        self.stop()
        for source in self.sources:
            source.thread.join(timeout=5)
            source.session.close()
            logger.info(
                "Source %s finished: %d packets written to %d file(s)",
                source.name,
                source.session.packets_written,
                len(source.session.files),
            )

        if all(s.error is not None for s in self.sources):
            logger.error("No capture source could run")
            return 1
        return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    runner = CaptureRunner(build_sources(args))
    signal.signal(signal.SIGTERM, runner.stop)
    signal.signal(signal.SIGINT, runner.stop)
    return runner.run()
