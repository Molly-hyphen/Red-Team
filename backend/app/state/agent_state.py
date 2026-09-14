import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class AgentState(BaseModel):
    agent_id: str
    scan_id: str
    parent_agent_id: Optional[str] = None
    role: str
    objective: str
    status: str = "idle" # idle, running, completed, failed, terminated
    current_task: str = ""
    
    iterations: int = 0
    max_iterations: int = 15
    tokens_used: int = 0
    cost_usd: float = 0.0
    
    findings_discovered_ids: List[str] = Field(default_factory=list)
    observations: List[Dict[str, Any]] = Field(default_factory=list)
    tool_history: List[Dict[str, Any]] = Field(default_factory=list)
    
    start_time: float = Field(default_factory=time.time)
    end_time: Optional[float] = None
