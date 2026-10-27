"""
F1: Capture statistics for lossless-capture measurement (NFR-PERF-01).

Tracks how many packets a session captured and how many the kernel
dropped, so each session can report both numbers when it ends.
"""

import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

SYSFS_NET = "/sys/class/net"


def read_rx_dropped(interface: str, sysfs_root: str = SYSFS_NET) -> Optional[int]:
    """Return the NIC's cumulative rx drop counter, or None if unavailable.

    The counter only exists on Linux (e.g. the Raspberry Pi); on other
    systems callers should treat the drop count as unknown.
    """
    base = os.path.join(sysfs_root, interface, "statistics")
    total = 0
    found = False
    for counter in ("rx_dropped", "rx_missed_errors", "rx_fifo_errors"):
        try:
            with open(os.path.join(base, counter), encoding="ascii") as handle:
                total += int(handle.read().strip())
                found = True
        except (OSError, ValueError):
            continue
    return total if found else None


@dataclass
class CaptureStats:
    """Result of one capture session."""

    interface: str
    captured: int
    dropped: Optional[int]
    duration: float

    @property
    def rate(self) -> float:
        """Average captured packets per second."""
        return self.captured / self.duration if self.duration > 0 else 0.0

    def summary(self) -> str:
        dropped = "unknown" if self.dropped is None else str(self.dropped)
        return (
            f"interface={self.interface} captured={self.captured} "
            f"dropped={dropped} duration={self.duration:.1f}s "
            f"rate={self.rate:.1f} pps"
        )


class StatsTracker:
    """Measures captured and dropped packets between start() and finish()."""

    def __init__(
        self,
        interface: str,
        drop_reader: Callable[[str], Optional[int]] = read_rx_dropped,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interface = interface
        self._drop_reader = drop_reader
        self._clock = clock
        self._start_time = 0.0
        self._start_drops: Optional[int] = None

    def start(self) -> None:
        self._start_time = self._clock()
        self._start_drops = self._drop_reader(self.interface)

    def finish(self, captured: int) -> CaptureStats:
        end_drops = self._drop_reader(self.interface)
        if self._start_drops is None or end_drops is None:
            dropped = None
        else:
            dropped = max(end_drops - self._start_drops, 0)
        return CaptureStats(
            interface=self.interface,
            captured=captured,
            dropped=dropped,
            duration=self._clock() - self._start_time,
        )
