"""GET /packets: latest captured packets, newest first."""
from typing import List

from fastapi import APIRouter, Query, Request

from .. import db

router = APIRouter()


@router.get("/packets")
def list_packets(request: Request, limit: int = Query(100, ge=1, le=1000)) -> List[dict]:
    with db.connect(request.app.state.db_path) as conn:
        rows = conn.execute(
            "SELECT id, ts, src, dst, protocol, length, info "
            "FROM packets ORDER BY ts DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
