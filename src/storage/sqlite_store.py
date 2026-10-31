
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.common.models import NormalizedRecord


class SQLiteStore:
    """Persist normalized packets, connections, and capture sessions."""

    def __init__(self, db_path: str | Path = "packets.db") -> None:
        self.db_path = str(db_path)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        """Create storage tables and indexes if they do not exist."""
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    interface TEXT NOT NULL,
                    link_type TEXT NOT NULL,
                    src_mac TEXT,
                    dst_mac TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    length INTEGER NOT NULL,
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    packet_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE (src_ip, dst_ip, src_port, dst_port, protocol)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    interface TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_packets_src_ip
                    ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_packets_dst_ip
                    ON packets(dst_ip);
                CREATE INDEX IF NOT EXISTS idx_packets_src_mac
                    ON packets(src_mac);
                CREATE INDEX IF NOT EXISTS idx_packets_dst_mac
                    ON packets(dst_mac);
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp
                    ON packets(timestamp);
                """
            )

    def save_packet(self, record: NormalizedRecord) -> int:
        """Save a normalized packet and return its database ID."""
        data = asdict(record)
        details = data["details"]

        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO packets (
                    timestamp, interface, link_type,
                    src_mac, dst_mac, src_ip, dst_ip,
                    protocol, src_port, dst_port, length, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["timestamp"],
                    data["interface"],
                    data["link_type"],
                    data["src_mac"],
                    data["dst_mac"],
                    data["src_ip"],
                    data["dst_ip"],
                    data["protocol"] or "UNKNOWN",
                    data["src_port"],
                    data["dst_port"],
                    data["length"],
                    json.dumps(details) if details is not None else None,
                ),
            )

        return int(cursor.lastrowid)

    def get_packet(self, packet_id: int) -> dict[str, Any] | None:
        """Retrieve one packet by ID."""
        row = self.connection.execute(
            "SELECT * FROM packets WHERE id = ?", (packet_id,)
        ).fetchone()

        if row is not None:
            return dict(row)
        return None

    def list_packets(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent packets, newest first."""
        rows = self.connection.execute(
            "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    def update_connection(self, record: NormalizedRecord) -> None:
        """Insert or update a connection summary from a TCP/UDP packet."""
        if record.protocol not in {"TCP", "UDP"}:
            return

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO connections (
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    first_seen, last_seen, packet_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol)
                DO UPDATE SET
                    last_seen = excluded.last_seen,
                    packet_count = connections.packet_count + 1
                """,
                (
                    record.src_ip,
                    record.dst_ip,
                    record.src_port,
                    record.dst_port,
                    record.protocol,
                    record.timestamp,
                    record.timestamp,
                ),
            )

    def create_session(
        self,
        interface: str,
        start_time: float,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Create a capture session and return its ID."""
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO sessions (interface, start_time, metadata)
                VALUES (?, ?, ?)
                """,
                (
                    interface,
                    start_time,
                    json.dumps(metadata) if metadata is not None else None,
                ),
            )

        return int(cursor.lastrowid)

    def finish_session(
        self,
        session_id: int,
        end_time: float,
        packet_count: int,
    ) -> None:
        """Record the end time and packet count for a session."""
        with self.connection:
            self.connection.execute(
                """
                UPDATE sessions
                SET end_time = ?, packet_count = ?
                WHERE id = ?
                """,
                (end_time, packet_count, session_id),
            )

    def close(self) -> None:
        """Close the SQLite connection."""
        self.connection.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc_value: Any,
        traceback: Any,
    ) -> None:
        self.close()
