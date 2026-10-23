"""Health check used by the dashboard, CI and deployment scripts."""
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}
