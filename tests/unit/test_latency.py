import pytest
from fastapi.testclient import TestClient

from src.dashboard import db, latency
from src.dashboard.app import create_app


def test_percentile_uses_nearest_rank():
    values = list(range(1, 101))

    assert latency.percentile(values, 95) == 95
    assert latency.percentile(values, 100) == 100
    assert latency.percentile([7], 95) == 7


def test_summarize_passes_when_p95_under_limit():
    summary = latency.summarize([100.0, 200.0, 300.0], limit_ms=1000)

    assert summary["samples"] == 3
    assert summary["min_ms"] == 100.0
    assert summary["median_ms"] == 200.0
    assert summary["max_ms"] == 300.0
    assert summary["passed"] is True


def test_summarize_fails_when_p95_over_limit():
    assert latency.summarize([100.0, 2000.0], limit_ms=1000)["passed"] is False


def test_measure_times_probe_through_websocket(db_path):
    with TestClient(create_app(db_path, push_interval=0.02)) as client:
        samples = latency.measure(lambda: client.websocket_connect("/ws/live"), db_path, samples=4)

    assert len(samples) == 4
    assert all(0 <= s < 1000 for s in samples)


def test_measure_removes_probe_rows(db_path):
    with TestClient(create_app(db_path, push_interval=0.02)) as client:
        latency.measure(lambda: client.websocket_connect("/ws/live"), db_path, samples=2)

    with db.connect(db_path) as conn:
        left = conn.execute("SELECT COUNT(*) FROM packets WHERE src LIKE 'latency-probe-%'").fetchone()[0]
    assert left == 0


def test_measure_times_out_if_probe_never_arrives(db_path):
    class SilentStream:
        def receive_json(self):
            return {"packets": []}

    class Connection:
        def __enter__(self):
            return SilentStream()

        def __exit__(self, *exc):
            return False

    with pytest.raises(TimeoutError):
        latency.measure(Connection, db_path, samples=1, timeout=0.05)


def test_render_report_contains_verdict_and_numbers():
    report = latency.render_report(latency.summarize([120.0, 180.0, 240.0]), "Push every 0.5 s.")

    assert "NFR-PERF-03" in report
    assert "| Samples | 3 |" in report
    assert "**PASS**" in report
    assert "Push every 0.5 s." in report


def test_main_writes_report_and_returns_zero(db_path, tmp_path, monkeypatch):
    with TestClient(create_app(db_path, push_interval=0.02)) as client:
        monkeypatch.setattr(latency, "_websocket_stream", lambda url: client.websocket_connect("/ws/live"))
        report_path = tmp_path / "out" / "report.md"

        exit_code = latency.main(["--db", db_path, "--samples", "3", "--report", str(report_path)])

    assert exit_code == 0
    assert "**PASS**" in report_path.read_text()
