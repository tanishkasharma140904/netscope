from fastapi import APIRouter
from backend.api.schemas.models import StatsResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/stats", response_model=StatsResponse)
def read_stats():
    """Get live packet counters and total bandwidth data."""
    return engine_bridge.get_stats()
