import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.scope.validator import validate_action_scope

class ToolObservation(BaseModel):
    tool: str
    target: str
    status: str # "success", "failed", "blocked_by_scope"
    status_code: Optional[int] = None
    duration_ms: int = 0
    data: Dict[str, Any] = Field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)

class SecurityTool(ABC):
    name: str = "base_tool"
    description: str = "Base security testing tool"
    category: str = "general" # "recon", "web", "api", "source", "validation"

    @abstractmethod
    async def execute(self, params: Dict[str, Any], scope_def: Dict[str, Any]) -> ToolObservation:
        """Execute the tool with given parameters after validating scope."""
        pass

    def check_scope(self, target: str, scope_def: Dict[str, Any]) -> tuple[bool, str]:
        """Verify target against authorized scope before doing network or fs operations."""
        return validate_action_scope(scope_def, target)
