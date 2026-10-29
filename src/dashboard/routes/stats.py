"""GET /stats: packet counts per protocol, used by the dashboard chart."""
from fastapi import APIRouter, Query, Request

from .. import queries

router = APIRouter()


@router.get("/stats")
def packet_stats(request: Request, window: int = Query(60, ge=1, le=86400)) -> dict:
    """Count packets per protocol seen in the last ``window`` seconds."""
    return queries.fetch_stats(request.app.state.db_path, window=window)
