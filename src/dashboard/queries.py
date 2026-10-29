"""Shared read queries used by the REST routes and the WebSocket stream."""
from typing import List, Optional

from . import db


def _like_pattern(text: str) -> str:
    """Turn user text into a LIKE pattern that matches it literally anywhere."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


PACKET_QUERY = r"""
SELECT id, ts, src, dst, protocol, length, info FROM packets
WHERE (:protocol IS NULL OR UPPER(protocol) = UPPER(:protocol))
  AND (:host IS NULL OR src = :host OR dst = :host)
  AND (:pattern IS NULL
       OR src LIKE :pattern ESCAPE '\'
       OR dst LIKE :pattern ESCAPE '\'
       OR protocol LIKE :pattern ESCAPE '\'
       OR info LIKE :pattern ESCAPE '\')
ORDER BY ts DESC, id DESC
LIMIT :limit
"""


def fetch_packets(
    db_path: str,
    limit: int = 100,
    protocol: Optional[str] = None,
    host: Optional[str] = None,
    q: Optional[str] = None,
) -> List[dict]:
    """Latest packets, newest first, optionally filtered.

    protocol: exact protocol name, case-insensitive (for example "dns")
    host:     exact address that is either the source or the destination
    q:        free text matched anywhere in source, destination, protocol or info

    The SQL is fixed text; every filter is passed as a bound parameter.
    """
    params = {
        "protocol": protocol or None,
        "host": host or None,
        "pattern": _like_pattern(q) if q else None,
        "limit": limit,
    }
    with db.connect(db_path) as conn:
        return [dict(row) for row in conn.execute(PACKET_QUERY, params).fetchall()]



def fetch_alerts(db_path: str, limit: int = 100) -> List[dict]:
    """Latest alerts, newest first."""
    with db.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, ts, severity, rule, description "
            "FROM alerts ORDER BY ts DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
