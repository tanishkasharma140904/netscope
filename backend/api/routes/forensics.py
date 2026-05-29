import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database.database import SessionLocal
from backend.database import crud
from backend.api.services import engine_bridge

router = APIRouter()

# Dependency to get SQLite DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/forensics/snapshot")
def capture_snapshot(snapshot_name: str = "Manual Forensic Capture", db: Session = Depends(get_db)):
    """Captures a forensic snapshot of the current live telemetry state and commits it to SQLite database."""
    try:
        # 1. Fetch live sniffer telemetry from the engine bridge
        live_threats = engine_bridge.get_threats()
        live_inventory = engine_bridge.get_inventory()
        live_sessions = engine_bridge.get_sessions()
        live_stats = engine_bridge.get_stats()

        # 2. Serialize objects to JSON strings
        threats_json = json.dumps(live_threats)
        hosts_json = json.dumps(live_inventory)
        sessions_json = json.dumps(live_sessions)
        stats_json = json.dumps(live_stats)

        # 3. Create record in SQLite db
        db_snapshot = crud.create_forensic_snapshot(
            db=db,
            snapshot_name=snapshot_name,
            threats_json=threats_json,
            hosts_json=hosts_json,
            sessions_json=sessions_json,
            stats_json=stats_json
        )

        return {
            "status": "success",
            "message": "Forensic snapshot captured successfully",
            "snapshot_id": db_snapshot.id,
            "snapshot_name": db_snapshot.snapshot_name,
            "timestamp": db_snapshot.timestamp
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to capture forensic snapshot: {str(e)}")

@router.get("/forensics/snapshot")
def list_snapshots(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieves all historical manual forensic snapshots captured by CISO analysts."""
    try:
        snapshots = crud.get_forensic_snapshots(db=db, limit=limit)
        return [
            {
                "id": s.id,
                "snapshot_name": s.snapshot_name,
                "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "threats": json.loads(s.threats_json) if s.threats_json else {},
                "hosts": json.loads(s.hosts_json) if s.hosts_json else {},
                "sessions": json.loads(s.sessions_json) if s.sessions_json else {},
                "stats": json.loads(s.stats_json) if s.stats_json else {}
            }
            for s in snapshots
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list forensic snapshots: {str(e)}")
