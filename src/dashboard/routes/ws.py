"""WS /ws/live: pushes a fresh snapshot of the dashboard data to the browser.

The page opens one WebSocket and receives packets, alerts, protocol counts and
the device inventory in a single message, instead of polling four endpoints.
Packet filters use the same query parameters as ``GET /packets``.
"""
import asyncio
import time
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import queries

router = APIRouter()

PACKET_LIMIT = 50
ALERT_LIMIT = 20


def build_snapshot(
    db_path: str,
    protocol: Optional[str] = None,
    host: Optional[str] = None,
    q: Optional[str] = None,
) -> dict:
    return {
        "ts": time.time(),
        "packets": queries.fetch_packets(db_path, limit=PACKET_LIMIT, protocol=protocol, host=host, q=q),
        "alerts": queries.fetch_alerts(db_path, limit=ALERT_LIMIT),
        "stats": queries.fetch_stats(db_path, window=60),
        "devices": queries.fetch_devices(db_path, window=300, limit=50),
    }


@router.websocket("/ws/live")
async def live(
    websocket: WebSocket,
    protocol: Optional[str] = None,
    host: Optional[str] = None,
    q: Optional[str] = None,
):
    await websocket.accept()
    db_path = websocket.app.state.db_path
    interval = websocket.app.state.push_interval
    try:
        while True:
            snapshot = await asyncio.to_thread(build_snapshot, db_path, protocol, host, q)
            await websocket.send_json(snapshot)
            await asyncio.sleep(interval)
    except (WebSocketDisconnect, RuntimeError):
        # The browser went away; nothing left to push to.
        return
