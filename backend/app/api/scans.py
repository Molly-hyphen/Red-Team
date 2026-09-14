import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.orchestrator.orchestrator import orchestrator
from app.state.scan_state import ScanState

router = APIRouter(prefix="/scans", tags=["scans"])

class CreateScanRequest(BaseModel):
    target: str
    mode: str = "black_box" # black_box, grey_box, white_box
    instruction: Optional[str] = ""
    scope: Optional[Dict[str, Any]] = None

@router.post("")
async def create_scan(req: CreateScanRequest):
    scan_id = str(uuid.uuid4())
    state = await orchestrator.start_scan(
        scan_id=scan_id,
        target=req.target,
        mode=req.mode,
        scope_definition=req.scope,
        instruction=req.instruction
    )
    return {
        "scan_id": scan_id,
        "status": "started",
        "target": req.target,
        "mode": req.mode
    }

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    state = orchestrator.get_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": state.scan_id,
        "target": state.target,
        "mode": state.mode,
        "total_findings": len(state.validated_findings),
        "total_endpoints": len(state.endpoints),
        "technologies": state.technologies,
        "total_tool_calls": state.total_tool_calls
    }

@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str):
    success = await orchestrator.stop_scan(scan_id)
    return {"scan_id": scan_id, "stopped": success}

@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    state = orchestrator.get_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [f.model_dump() for f in state.validated_findings]
