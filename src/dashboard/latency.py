"""Measures how long a new packet takes to appear on the dashboard stream.

Requirement NFR-PERF-03 asks for sub-second dashboard latency. This tool writes
a marker packet into the database the dashboard reads, then times how long it
takes to arrive on the ``/ws/live`` WebSocket, which is the same path the
browser uses. The marker rows are removed afterwards.

Usage (dashboard running with the same database):
    python -m src.dashboard.latency --samples 20 --report docs/Latency_Report.md
"""
import argparse
import json
import platform
import statistics
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, List

from . import db

LIMIT_MS = 1000.0
PROBE_PREFIX = "latency-probe-"


def percentile(values: List[float], pct: float) -> float:
    """Nearest-rank percentile of a non-empty list."""
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))  # ceil without importing math
    return ordered[int(rank) - 1]


def summarize(samples_ms: List[float], limit_ms: float = LIMIT_MS) -> dict:
    return {
        "samples": len(samples_ms),
        "min_ms": min(samples_ms),
        "mean_ms": statistics.mean(samples_ms),
        "median_ms": statistics.median(samples_ms),
        "p95_ms": percentile(samples_ms, 95),
        "max_ms": max(samples_ms),
        "limit_ms": limit_ms,
        "passed": percentile(samples_ms, 95) < limit_ms,
    }


def _insert_probe(db_path: str, marker: str) -> None:
    with db.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO packets (ts, src, dst, protocol, length, info) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), marker, "latency-probe-sink", "TCP", 64, "latency probe"),
        )


def _remove_probes(db_path: str) -> None:
    with db.connect(db_path) as conn:
        conn.execute("DELETE FROM packets WHERE src LIKE ?", (PROBE_PREFIX + "%",))


def measure(connect: Callable, db_path: str, samples: int = 20, timeout: float = 5.0) -> List[float]:
    """Return one latency in milliseconds per sample.

    ``connect`` returns a context manager whose object has ``receive_json()``.
    """
    token = uuid.uuid4().hex[:8]
    results: List[float] = []
    db.init_db(db_path)
    try:
        with connect() as stream:
            stream.receive_json()  # wait for the first snapshot so the stream is running
            for i in range(samples):
                marker = f"{PROBE_PREFIX}{token}-{i}"
                started = time.perf_counter()
                _insert_probe(db_path, marker)
                while True:
                    message = stream.receive_json()
                    if any(p["src"] == marker for p in message["packets"]):
                        results.append((time.perf_counter() - started) * 1000)
                        break
                    if time.perf_counter() - started > timeout:
                        raise TimeoutError(f"probe {marker} did not reach the stream within {timeout}s")
                time.sleep(0.05 * (i % 7))  # vary the phase against the push cycle
    finally:
        _remove_probes(db_path)
    return results


def render_report(summary: dict, push_interval_note: str) -> str:
    verdict = "PASS" if summary["passed"] else "FAIL"
    return "\n".join(
        [
            "# Dashboard Latency Report (NFR-PERF-03)",
            "",
            f"Measured on {datetime.now():%Y-%m-%d %H:%M} with {platform.system()} {platform.machine()}, "
            f"Python {platform.python_version()}.",
            "",
            "Method: a marker packet is written to the database and timed until it arrives on the",
            "`/ws/live` WebSocket, the same stream the browser uses. " + push_interval_note,
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| Samples | {summary['samples']} |",
            f"| Minimum | {summary['min_ms']:.0f} ms |",
            f"| Mean | {summary['mean_ms']:.0f} ms |",
            f"| Median | {summary['median_ms']:.0f} ms |",
            f"| 95th percentile | {summary['p95_ms']:.0f} ms |",
            f"| Maximum | {summary['max_ms']:.0f} ms |",
            f"| Requirement | 95th percentile under {summary['limit_ms']:.0f} ms |",
            f"| Result | **{verdict}** |",
            "",
        ]
    )


@contextmanager
def _websocket_stream(url: str):
    """Adapter that gives the ``websockets`` client a ``receive_json()`` method."""
    from websockets.sync.client import connect as ws_connect

    with ws_connect(url) as ws:

        class Stream:
            @staticmethod
            def receive_json():
                return json.loads(ws.recv(timeout=10))

        yield Stream()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Measure dashboard WebSocket latency")
    parser.add_argument("--url", default="ws://127.0.0.1:8000/ws/live", help="dashboard stream URL")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH, help="database file the dashboard reads")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--report", help="write a Markdown report to this path")
    args = parser.parse_args(argv)

    samples = measure(lambda: _websocket_stream(args.url), args.db, samples=args.samples)
    summary = summarize(samples)
    report = render_report(summary, "The server pushes a snapshot every 0.5 seconds.")
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(report)
    print(report)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
