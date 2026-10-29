"""GET /stats: packet counts per protocol, used by the dashboard chart."""
import time

from fastapi import APIRouter, Query, Request

from .. import db

router = APIRouter()


@router.get("/stats")
def packet_stats(request: Request, window: int = Query(60, ge=1, le=86400)) -> dict:
    """Count packets per protocol seen in the last ``window`` seconds."""
    since = time.time() - window
    with db.connect(request.app.state.db_path) as conn:
        rows = conn.execute(
            "SELECT protocol, COUNT(*) AS n FROM packets WHERE ts >= ? "
            "GROUP BY protocol ORDER BY n DESC, protocol",
            (since,),
        ).fetchall()
    by_protocol = {row["protocol"]: row["n"] for row in rows}
    return {"window": window, "total": sum(by_protocol.values()), "by_protocol": by_protocol}
