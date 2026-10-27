"""Capture benchmark for PT_F1_01 / NFR-PERF-01.

Run on the Raspberry Pi while a traffic generator sends packets at the
target rate, e.g.:

    sudo python scripts/capture_benchmark.py --interface eth0 --duration 60

Prints captured and dropped packet counts and whether the run met the
lossless target. Exit code 0 means PASS, 1 means FAIL.
"""

import argparse
import logging
import sys
import threading

from src.capture.ethernet import CaptureError, EthernetCapture


def run_benchmark(interface: str, duration: float, min_rate: float) -> int:
    capture = EthernetCapture(interface)
    timer = threading.Timer(duration, capture.stop)
    timer.start()
    try:
        # stop() is only noticed when the next frame arrives, so the
        # traffic generator must keep sending until the run ends
        capture.start()
    except CaptureError as exc:
        print(f"ERROR: {exc}")
        return 2
    finally:
        timer.cancel()

    stats = capture.stats
    print(stats.summary())
    lossless = stats.dropped == 0
    fast_enough = stats.rate >= min_rate
    print(f"zero drops: {'PASS' if lossless else 'FAIL'}")
    print(f"rate >= {min_rate:g} pps: {'PASS' if fast_enough else 'FAIL'}")
    return 0 if lossless and fast_enough else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--min-rate", type=float, default=1000.0)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    return run_benchmark(args.interface, args.duration, args.min_rate)


if __name__ == "__main__":
    sys.exit(main())
