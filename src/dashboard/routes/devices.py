"""GET /devices: inventory of hosts seen in recent traffic."""
from typing import List

from fastapi import APIRouter, Query, Request

from .. import queries

router = APIRouter()


@router.get("/devices")
def list_devices(
    request: Request,
    window: int = Query(300, ge=1, le=86400),
    limit: int = Query(50, ge=1, le=500),
) -> List[dict]:
    """Hosts that sent or received packets in the last ``window`` seconds, most recent first."""
    return queries.fetch_devices(request.app.state.db_path, window=window, limit=limit)
