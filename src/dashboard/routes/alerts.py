"""GET /alerts: alerts raised by the detection engine, newest first."""
from typing import List

from fastapi import APIRouter, Query, Request

from .. import db

router = APIRouter()


@router.get("/alerts")
def list_alerts(request: Request, limit: int = Query(100, ge=1, le=1000)) -> List[dict]:
    with db.connect(request.app.state.db_path) as conn:
        rows = conn.execute(
            "SELECT id, ts, severity, rule, description "
            "FROM alerts ORDER BY ts DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
