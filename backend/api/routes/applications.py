from fastapi import APIRouter
from backend.api.schemas.models import ApplicationsResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/applications", response_model=ApplicationsResponse)
def read_applications():
    """Get application-level traffic statistics sorted by dominance, including percentages."""
    return engine_bridge.get_applications()
