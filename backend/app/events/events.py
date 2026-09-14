from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class EventType(str, Enum):
    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_STOPPED = "scan.stopped"
    
    # Agent lifecycle
    AGENT_CREATED = "agent.created"
    AGENT_STARTED = "agent.started"
    AGENT_PROGRESS = "agent.progress"
    AGENT_TASK_UPDATE = "agent.task_update"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    AGENT_TERMINATED = "agent.terminated"
    
    # Tool execution
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_BLOCKED = "tool.blocked"
    
    # Discoveries & Attack surface
    ASSET_DISCOVERED = "asset.discovered"
    ENDPOINT_DISCOVERED = "endpoint.discovered"
    
    # Findings & Validation
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_VALIDATION_STARTED = "finding.validation_started"
    FINDING_VALIDATED = "finding.validated"
    FINDING_REJECTED = "finding.rejected"
    FINDING_DUPLICATE = "finding.duplicate"
    
    # Report
    REPORT_GENERATED = "report.generated"

class ScanEventMessage(BaseModel):
    scan_id: str
    event_type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    payload: Dict[str, Any] = Field(default_factory=dict)
