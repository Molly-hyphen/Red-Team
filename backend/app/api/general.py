import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from app.events.event_bus import event_bus
from app.orchestrator.orchestrator import orchestrator
from app.reports.report_generator import ReportGenerator

router = APIRouter(tags=["general_api"])

@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    for scan_id, state in orchestrator._scan_states.items():
        for f in state.findings:
            if f.id == finding_id:
                return f.model_dump()
    raise HTTPException(status_code=404, detail="Finding not found")

@router.get("/scans/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json"):
    state = orchestrator.get_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == "markdown":
        return PlainTextResponse(ReportGenerator.generate_markdown_report(state))
    elif format == "html":
        return HTMLResponse(ReportGenerator.generate_html_report(state))
    else:
        return JSONResponse(ReportGenerator.generate_json_report(state))

@router.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    queue = event_bus.subscribe_scan(scan_id)
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event.model_dump())
    except WebSocketDisconnect:
        event_bus.unsubscribe_scan(scan_id, queue)
    except Exception:
        event_bus.unsubscribe_scan(scan_id, queue)
