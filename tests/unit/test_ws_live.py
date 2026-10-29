import time

from fastapi.testclient import TestClient

from src.dashboard import db
from src.dashboard.app import create_app


def _client(db_path):
    return TestClient(create_app(db_path, push_interval=0.02))


def test_ws_pushes_snapshot_with_all_sections(db_path):
    with _client(db_path) as client:
        with client.websocket_connect("/ws/live") as ws:
            message = ws.receive_json()

    assert set(message) == {"ts", "packets", "alerts", "stats", "devices"}
    assert message["packets"] == []
    assert message["stats"]["total"] == 0


def test_ws_pushes_new_data_without_reconnecting(db_path):
    with _client(db_path) as client:
        with client.websocket_connect("/ws/live") as ws:
            assert ws.receive_json()["packets"] == []
            with db.connect(db_path) as conn:
                conn.execute(
                    "INSERT INTO packets (ts, src, dst, protocol, length, info) VALUES (?,?,?,?,?,?)",
                    (time.time(), "10.0.0.1", "10.0.0.2", "TCP", 60, "x"),
                )
            for _ in range(50):
                message = ws.receive_json()
                if message["packets"]:
                    break

    assert message["packets"][0]["src"] == "10.0.0.1"
    assert message["stats"]["by_protocol"] == {"TCP": 1}
    assert {d["ip"] for d in message["devices"]} == {"10.0.0.1", "10.0.0.2"}


def test_ws_includes_alerts(db_path):
    db.init_db(db_path)
    with db.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO alerts (ts, severity, rule, description) VALUES (?,?,?,?)",
            (time.time(), "high", "ARP spoofing", "bad"),
        )
    with _client(db_path) as client:
        with client.websocket_connect("/ws/live") as ws:
            message = ws.receive_json()

    assert message["alerts"][0]["rule"] == "ARP spoofing"


def test_ws_applies_packet_filters(db_path):
    db.init_db(db_path)
    now = time.time()
    with db.connect(db_path) as conn:
        for proto in ("TCP", "DNS"):
            conn.execute(
                "INSERT INTO packets (ts, src, dst, protocol, length, info) VALUES (?,?,?,?,?,?)",
                (now, "10.0.0.1", "10.0.0.2", proto, 60, ""),
            )
    with _client(db_path) as client:
        with client.websocket_connect("/ws/live?protocol=dns") as ws:
            message = ws.receive_json()

    assert [p["protocol"] for p in message["packets"]] == ["DNS"]
    assert message["stats"]["total"] == 2  # chart and inventory stay unfiltered


def test_ws_streams_repeatedly(db_path):
    with _client(db_path) as client:
        with client.websocket_connect("/ws/live") as ws:
            first = ws.receive_json()["ts"]
            second = ws.receive_json()["ts"]

    assert second > first
