

from src.common.models import NormalizedRecord
from src.storage.sqlite_store import SQLiteStore


def make_record(**overrides):
    values = {
        "timestamp": 1000.0,
        "interface": "eth0",
        "link_type": "Ethernet",
        "src_mac": "00:11:22:33:44:55",
        "dst_mac": "AA:BB:CC:DD:EE:FF",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "protocol": "TCP",
        "src_port": 5000,
        "dst_port": 443,
        "length": 64,
        "details": {"flags": "S"},
    }
    values.update(overrides)
    return NormalizedRecord(**values)


def test_save_and_retrieve_packet(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as store:
        packet_id = store.save_packet(make_record())
        packet = store.get_packet(packet_id)

        assert packet is not None
        assert packet["src_ip"] == "192.168.1.10"
        assert packet["protocol"] == "TCP"
        assert packet["details"] == '{"flags": "S"}'


def test_packet_persists_after_reopening_database(tmp_path):
    db_path = tmp_path / "test.db"

    with SQLiteStore(db_path) as store:
        packet_id = store.save_packet(make_record())

    with SQLiteStore(db_path) as store:
        assert store.get_packet(packet_id)["dst_port"] == 443


def test_update_connection_counts_packets(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as store:
        store.update_connection(make_record(timestamp=1000.0))
        store.update_connection(make_record(timestamp=1005.0))

        row = store.connection.execute(
            "SELECT * FROM connections"
        ).fetchone()

        assert row["packet_count"] == 2
        assert row["first_seen"] == 1000.0
        assert row["last_seen"] == 1005.0


def test_non_tcp_udp_packet_does_not_create_connection(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as store:
        store.update_connection(make_record(protocol="ARP"))

        count = store.connection.execute(
            "SELECT COUNT(*) FROM connections"
        ).fetchone()[0]

        assert count == 0


def test_create_and_finish_session(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as store:
        session_id = store.create_session(
            "eth0", 1000.0, {"capture": "test"}
        )
        store.finish_session(session_id, 1100.0, 25)

        row = store.connection.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()

        assert row["interface"] == "eth0"
        assert row["end_time"] == 1100.0
        assert row["packet_count"] == 25
        assert row["metadata"] == '{"capture": "test"}'


def test_required_packet_indexes_exist(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as store:
        indexes = {
            row["name"]
            for row in store.connection.execute(
                "PRAGMA index_list(packets)"
            ).fetchall()
        }

        assert "idx_packets_src_ip" in indexes
        assert "idx_packets_dst_ip" in indexes
        assert "idx_packets_src_mac" in indexes
        assert "idx_packets_dst_mac" in indexes
        assert "idx_packets_timestamp" in indexes


def test_list_packets_returns_newest_first(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as store:
        store.save_packet(make_record(timestamp=1000.0))
        store.save_packet(make_record(timestamp=2000.0))

        packets = store.list_packets()

        assert len(packets) == 2
        assert packets[0]["timestamp"] == 2000.0
        assert packets[1]["timestamp"] == 1000.0
