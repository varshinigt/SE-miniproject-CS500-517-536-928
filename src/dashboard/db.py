"""SQLite access layer for the dashboard module (F4).

The dashboard only reads from the database that the parser (F2) and the
detection engine (F3) write to. Keeping connection and schema handling here
means a schema change only touches this file and the route queries.
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = os.environ.get("PPS_DB_PATH", "data/sniffer.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL    NOT NULL,
    src      TEXT    NOT NULL,
    dst      TEXT    NOT NULL,
    protocol TEXT    NOT NULL,
    length   INTEGER NOT NULL DEFAULT 0,
    info     TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    severity    TEXT NOT NULL,
    rule        TEXT NOT NULL,
    description TEXT NOT NULL
);
"""


def init_db(db_path):
    """Create the database file and tables if they do not exist yet."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def connect(db_path):
    """Open a connection that returns dict-like rows and always closes it."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
