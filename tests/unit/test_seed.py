import sys

import pytest

from src.dashboard import db, seed


def count_rows(db_path, table):
    with db.connect(db_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_seed_inserts_requested_rows(db_path):
    seed.seed(db_path, packets=5, alerts=2)

    assert count_rows(db_path, "packets") == 5
    assert count_rows(db_path, "alerts") == 2


def test_random_packet_has_valid_shape():
    ts, src, dst, protocol, length, info = seed.random_packet(123.0)

    assert ts == 123.0
    assert src != dst
    assert protocol in seed.PROTOCOLS
    assert 40 <= length <= 1500
    assert protocol in info


def test_run_live_adds_packets_and_periodic_alerts(db_path, monkeypatch):
    calls = {"n": 0}

    def fake_sleep(_seconds):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt  # stop the endless loop after 3 packets

    monkeypatch.setattr(seed.time, "sleep", fake_sleep)

    with pytest.raises(KeyboardInterrupt):
        seed.run_live(db_path, interval=0, alert_every=2)

    assert count_rows(db_path, "packets") == 3
    assert count_rows(db_path, "alerts") == 1  # one alert, after the 2nd packet


def test_main_seeds_database(db_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["seed", "--db", db_path])

    seed.main()

    assert "Seeded demo data" in capsys.readouterr().out
    assert count_rows(db_path, "packets") == 50
    assert count_rows(db_path, "alerts") == 4


def test_main_live_flag_starts_live_mode(db_path, monkeypatch):
    started = {}
    monkeypatch.setattr(seed, "run_live", lambda path: started.setdefault("db", path))
    monkeypatch.setattr(sys, "argv", ["seed", "--db", db_path, "--live"])

    seed.main()

    assert started["db"] == db_path
