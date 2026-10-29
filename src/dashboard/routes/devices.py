"""GET /devices: inventory of hosts seen in recent traffic."""
import time
from typing import List

from fastapi import APIRouter, Query, Request

from .. import db

router = APIRouter()

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


@router.get("/devices")
def list_devices(
    request: Request,
    window: int = Query(300, ge=1, le=86400),
    limit: int = Query(50, ge=1, le=500),
) -> List[dict]:
    """Hosts that sent or received packets in the last ``window`` seconds, most recent first."""
    since = time.time() - window
    with db.connect(request.app.state.db_path) as conn:
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
