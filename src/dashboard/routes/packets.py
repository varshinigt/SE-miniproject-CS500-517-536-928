"""GET /packets: latest captured packets, newest first, with optional filters."""
from typing import List, Optional

from fastapi import APIRouter, Query, Request

from .. import queries

router = APIRouter()


@router.get("/packets")
def list_packets(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    protocol: Optional[str] = Query(None, max_length=20),
    host: Optional[str] = Query(None, max_length=64),
    q: Optional[str] = Query(None, max_length=100),
) -> List[dict]:
    return queries.fetch_packets(
        request.app.state.db_path, limit=limit, protocol=protocol, host=host, q=q
    )
