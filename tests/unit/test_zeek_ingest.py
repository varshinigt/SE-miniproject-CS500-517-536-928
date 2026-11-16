
import json
import threading
import time
import pytest

from src.parser.zeek_ingest import ZeekLogParser


def test_parse_json_conn_event():
    parser = ZeekLogParser()

    event = parser.parse_line(json.dumps({
        "ts": 1000.5,
        "_path": "conn",
        "uid": "C123",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 5000,
        "id.resp_h": "192.168.1.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "conn_state": "SF",
    }))

    assert event is not None
    assert event.log_type == "conn"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.20"
    assert event.src_port == 5000
    assert event.dst_port == 443
    assert event.protocol == "tcp"
    assert event.uid == "C123"
    assert event.metadata["conn_state"] == "SF"


def test_parse_json_dns_event():
    parser = ZeekLogParser()

    event = parser.parse_line(json.dumps({
        "ts": 1001.0,
        "_path": "dns",
        "uid": "D123",
        "id.orig_h": "192.168.1.10",
        "id.resp_h": "8.8.8.8",
        "proto": "udp",
        "query": "example.com",
        "qtype_name": "A",
    }))

    assert event is not None
    assert event.log_type == "dns"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "8.8.8.8"
    assert event.metadata["query"] == "example.com"


def test_parse_tsv_event():
    parser = ZeekLogParser()

    parser.parse_line("#separator \\x09")
    parser.parse_line("#path conn")
    parser.parse_line(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
        "id.resp_h\tid.resp_p\tproto"
    )

    event = parser.parse_line(
        "1000.5\tC123\t192.168.1.10\t5000\t"
        "192.168.1.20\t443\ttcp"
    )

    assert event is not None
    assert event.log_type == "conn"
    assert event.src_ip == "192.168.1.10"
    assert event.src_port == 5000
    assert event.dst_port == 443
    assert event.protocol == "tcp"


def test_missing_optional_fields_are_handled():
    parser = ZeekLogParser()

    event = parser.parse_line(json.dumps({
        "ts": 1000.0,
        "_path": "conn",
    }))

    assert event is not None
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.src_port is None
    assert event.dst_port is None


def test_malformed_json_is_skipped():
    parser = ZeekLogParser()

    event = parser.parse_line('{"ts": invalid}')

    assert event is None
    assert len(parser.errors) == 1


def test_missing_timestamp_is_skipped():
    parser = ZeekLogParser()

    event = parser.parse_line(json.dumps({
        "_path": "conn",
        "uid": "C123",
    }))

    assert event is None
    assert "Missing timestamp" in parser.errors[0]


def test_read_file_returns_valid_events(tmp_path):
    log_file = tmp_path / "conn.log"

    records = [
        json.dumps({"ts": 1000.0, "_path": "conn"}),
        "malformed record",
        json.dumps({"ts": 1001.0, "_path": "conn"}),
    ]

    log_file.write_text("\n".join(records) + "\n", encoding="utf-8")

    parser = ZeekLogParser()
    events = list(parser.read_file(log_file))

    assert len(events) == 2
    assert events[0].timestamp == 1000.0
    assert events[1].timestamp == 1001.0
    assert len(parser.errors) == 1


def test_follow_file_reads_new_records(tmp_path):
    log_file = tmp_path / "conn.log"
    log_file.write_text("", encoding="utf-8")

    stop_event = threading.Event()
    parser = ZeekLogParser()
    received = []

    def consume():
        for event in parser.follow_file(
            log_file, stop_event, poll_interval=0.02
        ):
            received.append(event)
            if len(received) >= 2:
                stop_event.set()

    worker = threading.Thread(target=consume)
    worker.start()

    time.sleep(0.1)

    with log_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps({
            "ts": 1000.0, "_path": "conn"
        }) + "\n")
        file.flush()

        file.write(json.dumps({
            "ts": 1001.0, "_path": "dns"
        }) + "\n")
        file.flush()

    worker.join(timeout=3)
    stop_event.set()

    assert not worker.is_alive()
    assert len(received) == 2
    assert received[0].log_type == "conn"
    assert received[1].log_type == "dns"
def test_follow_file_rejects_nonpositive_poll_interval(tmp_path):
    from src.parser.zeek_ingest import ZeekLogParser

    log_file = tmp_path / "conn.log"
    log_file.write_text("", encoding="utf-8")

    parser = ZeekLogParser()

    with pytest.raises(ValueError, match="poll_interval must be positive"):
        list(parser.follow_file(log_file, poll_interval=0))
