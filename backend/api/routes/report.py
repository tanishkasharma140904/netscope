import os
from datetime import datetime
from fastapi import APIRouter, HTTPException
from backend.api.schemas.models import ReportResponse
from backend.api.services import engine_bridge

router = APIRouter()

REPORT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "phase1", "reports", "final_report.txt")
)

@router.get("/report", response_model=ReportResponse)
def read_executive_report():
    """Retrieve full human-readable executive security report and its last update timestamp."""
    if not os.path.exists(REPORT_PATH):
        try:
            res = engine_bridge.generate_report_now()
            return ReportResponse(timestamp=res["timestamp"], content=res["content"])
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

    try:
        mtime = os.path.getmtime(REPORT_PATH)
        timestamp_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        with open(REPORT_PATH, "r") as f:
            content = f.read()
        return ReportResponse(timestamp=timestamp_str, content=content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {str(e)}")

@router.post("/report/generate", response_model=ReportResponse)
def generate_executive_report():
    """Triggers the Scapy engine to write the latest real telemetry into reports/final_report.txt."""
    try:
        res = engine_bridge.generate_report_now()
        return ReportResponse(timestamp=res["timestamp"], content=res["content"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
