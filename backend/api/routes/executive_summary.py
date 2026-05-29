from fastapi import APIRouter
from backend.api.schemas.models import ExecutiveSummaryResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/executive-summary", response_model=ExecutiveSummaryResponse)
def read_executive_summary():
    """Get high-level summary of active hosts, sessions, threat posture, and network health."""
    return engine_bridge.get_executive_summary()
