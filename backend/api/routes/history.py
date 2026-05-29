# =============================================================
#   NetScope AI — Historical API Routes
#   Endpoints for retrieving database snapshots and alerts
# =============================================================

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from backend.database.database import get_db
from backend.database import crud
from backend.api.schemas.models import (
    StatsHistoryEntry,
    AlertHistoryEntry,
    ThreatHistoryEntry,
    SessionHistoryEntry,
    HostHistoryEntry
)

router = APIRouter(prefix="/history", tags=["Historical Analytics"])

@router.get("/stats", response_model=List[StatsHistoryEntry])
def read_stats_history(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieve historical protocol statistics snapshots (newest first)."""
    return crud.get_stats_snapshots(db, limit=limit)


@router.get("/alerts", response_model=List[AlertHistoryEntry])
def read_alerts_history(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieve triggered security alerts history (newest first)."""
    return crud.get_alerts(db, limit=limit)


@router.get("/threats", response_model=List[ThreatHistoryEntry])
def read_threats_history(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieve historical threat assessments and platform score snapshots (newest first)."""
    return crud.get_threats(db, limit=limit)


@router.get("/sessions", response_model=List[SessionHistoryEntry])
def read_sessions_history(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieve captured session logs (newest first)."""
    return crud.get_sessions(db, limit=limit)


@router.get("/hosts", response_model=List[HostHistoryEntry])
def read_hosts_history(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieve registered network hosts inventory history (newest first)."""
    return crud.get_hosts(db, limit=limit)
