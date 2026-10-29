"""Shared read queries used by the REST routes and the WebSocket stream."""
import time
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


def fetch_stats(db_path: str, window: int = 60) -> dict:
    """Count packets per protocol seen in the last ``window`` seconds."""
    since = time.time() - window
    with db.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT protocol, COUNT(*) AS n FROM packets WHERE ts >= ? "
            "GROUP BY protocol ORDER BY n DESC, protocol",
            (since,),
        ).fetchall()
    by_protocol = {row["protocol"]: row["n"] for row in rows}
    return {"window": window, "total": sum(by_protocol.values()), "by_protocol": by_protocol}


DEVICE_QUERY = """
SELECT ip,
       SUM(sent)      AS sent,
       SUM(received)  AS received,
       SUM(bytes)     AS bytes,
       MAX(last_seen) AS last_seen,
       GROUP_CONCAT(DISTINCT protocol) AS protocols
FROM (
    SELECT src AS ip, 1 AS sent, 0 AS received, length AS bytes, ts AS last_seen, protocol
    FROM packets WHERE ts >= ?
    UNION ALL
    SELECT dst AS ip, 0 AS sent, 1 AS received, length AS bytes, ts AS last_seen, protocol
    FROM packets WHERE ts >= ?
)
GROUP BY ip
ORDER BY last_seen DESC, ip
LIMIT ?
"""


def fetch_devices(db_path: str, window: int = 300, limit: int = 50) -> List[dict]:
    """Hosts that sent or received packets in the last ``window`` seconds, most recent first."""
    since = time.time() - window
    with db.connect(db_path) as conn:
        rows = conn.execute(DEVICE_QUERY, (since, since, limit)).fetchall()
    return [
        {
            "ip": row["ip"],
            "packets": row["sent"] + row["received"],
            "sent": row["sent"],
            "received": row["received"],
            "bytes": row["bytes"],
            "last_seen": row["last_seen"],
            "protocols": sorted((row["protocols"] or "").split(",")),
        }
        for row in rows
    ]
