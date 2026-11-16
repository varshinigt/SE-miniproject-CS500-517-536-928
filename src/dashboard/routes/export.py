"""GET /export/packets and /export/alerts: download captured data as CSV or JSON."""
import csv
import io
import json
from typing import List, Optional

from fastapi import APIRouter, Query, Request, Response

from .. import queries

router = APIRouter(prefix="/export")

PACKET_COLUMNS = ["id", "ts", "src", "dst", "protocol", "length", "info"]
ALERT_COLUMNS = ["id", "ts", "severity", "rule", "description"]
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value):
    """Stop spreadsheet programs from running captured text as a formula."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def _to_csv(rows: List[dict], columns: List[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_safe_cell(row[column]) for column in columns])
    return buffer.getvalue()


def _download(rows: List[dict], columns: List[str], fmt: str, name: str) -> Response:
    if fmt == "json":
        body, media_type = json.dumps(rows, indent=2), "application/json"
    else:
        body, media_type = _to_csv(rows, columns), "text/csv"
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{name}.{fmt}"'},
    )


@router.get("/packets")
def export_packets(
    request: Request,
    format: str = Query("csv", pattern="^(csv|json)$"),
    limit: int = Query(10000, ge=1, le=100000),
    protocol: Optional[str] = Query(None, max_length=20),
    host: Optional[str] = Query(None, max_length=64),
    q: Optional[str] = Query(None, max_length=100),
) -> Response:
    """Export packets (newest first) using the same filters as /packets."""
    rows = queries.fetch_packets(
        request.app.state.db_path, limit=limit, protocol=protocol, host=host, q=q
    )
    return _download(rows, PACKET_COLUMNS, format, "packets")


@router.get("/alerts")
def export_alerts(
    request: Request,
    format: str = Query("csv", pattern="^(csv|json)$"),
    limit: int = Query(10000, ge=1, le=100000),
) -> Response:
    rows = queries.fetch_alerts(request.app.state.db_path, limit=limit)
    return _download(rows, ALERT_COLUMNS, format, "alerts")
