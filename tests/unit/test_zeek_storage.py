
import json

from src.common.zeek_models import ZeekEvent
from src.storage.sqlite_store import SQLiteStore


def test_save_and_get_zeek_event(tmp_path):
    db_path = tmp_path / "zeek.db"

    with SQLiteStore(db_path) as store:
        event = ZeekEvent(
            timestamp=1000.5,
            log_type="conn",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=5000,
            dst_port=443,
            protocol="tcp",
            uid="C123",
            metadata={"conn_state": "SF", "service": "https"},
        )

        event_id = store.save_zeek_event(event)
        result = store.get_zeek_event(event_id)

        assert result is not None
        assert result["timestamp"] == 1000.5
        assert result["log_type"] == "conn"
        assert result["src_ip"] == "192.168.1.10"
        assert result["dst_ip"] == "192.168.1.20"
        assert result["src_port"] == 5000
        assert result["dst_port"] == 443
        assert result["protocol"] == "tcp"
        assert result["uid"] == "C123"
        assert result["metadata"]["conn_state"] == "SF"
        assert result["metadata"]["service"] == "https"


def test_get_nonexistent_zeek_event_returns_none(tmp_path):
    with SQLiteStore(tmp_path / "zeek.db") as store:
        assert store.get_zeek_event(999) is None


def test_list_zeek_events(tmp_path):
    with SQLiteStore(tmp_path / "zeek.db") as store:
        store.save_zeek_event(
            ZeekEvent(
                timestamp=1000.0,
                log_type="conn",
                uid="C1",
            )
        )
        store.save_zeek_event(
            ZeekEvent(
                timestamp=1001.0,
                log_type="dns",
                uid="D1",
                metadata={"query": "example.com"},
            )
        )
        store.save_zeek_event(
            ZeekEvent(
                timestamp=1002.0,
                log_type="conn",
                uid="C2",
            )
        )

        events = store.list_zeek_events()

        assert len(events) == 3
        assert events[0]["timestamp"] == 1002.0
        assert events[1]["timestamp"] == 1001.0


def test_filter_zeek_events_by_log_type(tmp_path):
    with SQLiteStore(tmp_path / "zeek.db") as store:
        store.save_zeek_event(
            ZeekEvent(timestamp=1000.0, log_type="conn", uid="C1")
        )
        store.save_zeek_event(
            ZeekEvent(timestamp=1001.0, log_type="dns", uid="D1")
        )
        store.save_zeek_event(
            ZeekEvent(timestamp=1002.0, log_type="conn", uid="C2")
        )

        events = store.list_zeek_events(log_type="conn")

        assert len(events) == 2
        assert all(event["log_type"] == "conn" for event in events)


def test_zeek_event_limit(tmp_path):
    with SQLiteStore(tmp_path / "zeek.db") as store:
        for index in range(5):
            store.save_zeek_event(
                ZeekEvent(
                    timestamp=float(index),
                    log_type="conn",
                    uid=f"C{index}",
                )
            )

        events = store.list_zeek_events(limit=2)

        assert len(events) == 2
        assert events[0]["timestamp"] == 4.0


def test_empty_metadata_is_preserved(tmp_path):
    with SQLiteStore(tmp_path / "zeek.db") as store:
        event_id = store.save_zeek_event(
            ZeekEvent(timestamp=1000.0, log_type="conn")
        )

        result = store.get_zeek_event(event_id)

        assert result is not None
        assert result["metadata"] == {}
