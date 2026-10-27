"""Unit tests for capture statistics (PT_F1_01 support)."""

import pytest

from src.capture import ethernet
from src.capture.ethernet import EthernetCapture
from src.capture.stats import CaptureStats, StatsTracker, read_rx_dropped


def write_counters(root, interface, **counters):
    stats_dir = root / interface / "statistics"
    stats_dir.mkdir(parents=True)
    for name, value in counters.items():
        (stats_dir / name).write_text(f"{value}\n")


def test_read_rx_dropped_sums_available_counters(tmp_path):
    write_counters(
        tmp_path, "eth0", rx_dropped=3, rx_missed_errors=2, rx_fifo_errors=1
    )
    assert read_rx_dropped("eth0", sysfs_root=str(tmp_path)) == 6


def test_read_rx_dropped_returns_none_when_unavailable(tmp_path):
    assert read_rx_dropped("eth0", sysfs_root=str(tmp_path)) is None


def test_read_rx_dropped_ignores_bad_counter_value(tmp_path):
    write_counters(tmp_path, "eth0", rx_dropped="oops", rx_missed_errors=4)
    assert read_rx_dropped("eth0", sysfs_root=str(tmp_path)) == 4


def test_tracker_reports_drops_during_session():
    readings = iter([10, 14])
    clock = iter([100.0, 160.0])
    tracker = StatsTracker(
        "eth0", drop_reader=lambda _: next(readings), clock=lambda: next(clock)
    )
    tracker.start()
    stats = tracker.finish(captured=60000)
    assert stats.dropped == 4
    assert stats.captured == 60000
    assert stats.duration == 60.0
    assert stats.rate == 1000.0


def test_tracker_reports_zero_drops():
    tracker = StatsTracker("eth0", drop_reader=lambda _: 5)
    tracker.start()
    assert tracker.finish(captured=10).dropped == 0


def test_tracker_drop_count_unknown_without_counters():
    tracker = StatsTracker("eth0", drop_reader=lambda _: None)
    tracker.start()
    assert tracker.finish(captured=10).dropped is None


def test_tracker_never_reports_negative_drops():
    readings = iter([9, 2])  # counter reset mid-session
    tracker = StatsTracker("eth0", drop_reader=lambda _: next(readings))
    tracker.start()
    assert tracker.finish(captured=1).dropped == 0


def test_rate_is_zero_for_zero_duration():
    assert CaptureStats("eth0", 5, 0, 0.0).rate == 0.0


@pytest.mark.parametrize(
    "dropped,expected", [(0, "dropped=0"), (None, "dropped=unknown")]
)
def test_summary_reports_captured_and_dropped(dropped, expected):
    text = CaptureStats("eth0", 120, dropped, 2.0).summary()
    assert "captured=120" in text
    assert expected in text
    assert "rate=60.0 pps" in text


def test_ethernet_capture_exposes_stats_after_session(monkeypatch):
    monkeypatch.setattr(ethernet, "interface_exists", lambda name: True)

    def fake_sniffer(**kwargs):
        for _ in range(4):
            kwargs["prn"](object())

    capture = EthernetCapture("eth0", sniffer=fake_sniffer)
    assert capture.stats is None
    capture.start()
    assert capture.stats.captured == 4
    assert capture.stats.interface == "eth0"
