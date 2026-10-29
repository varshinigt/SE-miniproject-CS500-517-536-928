"""GET /alerts: alerts raised by the detection engine, newest first."""
from typing import List

from fastapi import APIRouter, Query, Request

from .. import queries

router = APIRouter()


@router.get("/alerts")
def list_alerts(request: Request, limit: int = Query(100, ge=1, le=1000)) -> List[dict]:
    return queries.fetch_alerts(request.app.state.db_path, limit=limit)
