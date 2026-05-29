from fastapi import APIRouter
from backend.api.schemas.models import TopTalkersResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/top-talkers", response_model=TopTalkersResponse)
def read_top_talkers():
    """Get the top 10 most active IP addresses in the network."""
    return engine_bridge.get_top_talkers()
