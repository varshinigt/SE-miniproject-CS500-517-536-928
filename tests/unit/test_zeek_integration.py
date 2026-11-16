
import json
import threading
import time

from src.parser.zeek_ingest import ingest_file, follow_and_store
from src.storage.sqlite_store import SQLiteStore


def test_recorded_zeek_file_to_sqlite(tmp_path):
    log_file = tmp_path / "conn.log"
    db_path = tmp_path / "zeek.db"

    records = [
        {
            "ts": 1000.0,
            "_path": "conn",
            "uid": "C1",
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "8.8.8.8",
            "proto": "udp",
            "conn_state": "SF",
        },
        {
            "ts": 1001.0,
            "_path": "dns",
            "uid": "D1",
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "8.8.8.8",
            "query": "example.com",
        },
    ]

    log_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    with SQLiteStore(db_path) as store:
        saved_count = ingest_file(log_file, store)

        assert saved_count == 2

        events = store.list_zeek_events()

        assert len(events) == 2
        assert events[0]["log_type"] == "dns"
        assert events[0]["metadata"]["query"] == "example.com"
        assert events[1]["log_type"] == "conn"
        assert events[1]["metadata"]["conn_state"] == "SF"


def test_recorded_zeek_file_with_invalid_record(tmp_path):
    log_file = tmp_path / "conn.log"

    records = [
        json.dumps({"ts": 1000.0, "_path": "conn"}),
        '{"ts": invalid}',
        json.dumps({"ts": 1001.0, "_path": "conn"}),
    ]

    log_file.write_text("\n".join(records) + "\n", encoding="utf-8")

    with SQLiteStore(tmp_path / "zeek.db") as store:
        saved_count = ingest_file(log_file, store)

        assert saved_count == 2
        assert len(store.list_zeek_events()) == 2


def test_live_zeek_file_to_sqlite(tmp_path):
    log_file = tmp_path / "conn.log"
    log_file.write_text("", encoding="utf-8")

    stop_event = threading.Event()
    db_path = tmp_path / "zeek.db"
    result = {}

    def run_ingestion():
        with SQLiteStore(db_path) as store:
            result["count"] = follow_and_store(
                log_file,
                store,
                stop_event,
                poll_interval=0.02,
            )

    worker = threading.Thread(target=run_ingestion)
    worker.start()

    time.sleep(0.1)

    with log_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps({
            "ts": 1000.0,
            "_path": "conn",
            "uid": "C1",
        }) + "\n")

        file.write(json.dumps({
            "ts": 1001.0,
            "_path": "dns",
            "uid": "D1",
        }) + "\n")

    time.sleep(0.3)
    stop_event.set()
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert result["count"] == 2

    with SQLiteStore(db_path) as store:
        events = store.list_zeek_events()
        assert len(events) == 2
        assert {event["log_type"] for event in events} == {
            "conn", "dns"
        }
