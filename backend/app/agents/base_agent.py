import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from app.events.event_bus import event_bus
from app.events.events import ScanEventMessage, EventType
from app.llm import get_llm_provider
from app.llm.base_provider import BaseLLMProvider
from app.skills.registry import skill_registry
from app.state.agent_state import AgentState
from app.state.memory import AgentMemory
from app.state.scan_state import ScanState
from app.tools import tool_registry

class BaseAgent(ABC):
    role: str = "BaseAgent"

    def __init__(
        self,
        agent_id: Optional[str] = None,
        scan_id: str = "",
        parent_agent_id: Optional[str] = None,
        objective: str = "",
        max_iterations: int = 10,
        llm_provider: Optional[BaseLLMProvider] = None
    ):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.scan_id = scan_id
        self.parent_agent_id = parent_agent_id
        self.objective = objective
        self.max_iterations = max_iterations
        self.llm = llm_provider or get_llm_provider()
        self.memory = AgentMemory()
        
        self.state = AgentState(
            agent_id=self.agent_id,
            scan_id=self.scan_id,
            parent_agent_id=self.parent_agent_id,
            role=self.role,
            objective=self.objective,
            max_iterations=self.max_iterations,
            status="idle"
        )

    async def emit_event(self, event_type: EventType, payload: Dict[str, Any]):
        event_payload = {
            "agent_id": self.agent_id,
            "role": self.role,
            "parent_agent_id": self.parent_agent_id,
            **payload
        }
        await event_bus.publish(ScanEventMessage(
            scan_id=self.scan_id,
            event_type=event_type,
            payload=event_payload
        ))

    async def execute_tool(self, tool_name: str, params: Dict[str, Any], scan_state: ScanState) -> Dict[str, Any]:
        """Executes a security tool via the tool registry with full event logging."""
        tool = tool_registry.get_tool(tool_name)
        if not tool:
            return {"status": "failed", "error": f"Tool '{tool_name}' not found."}

        target_dest = params.get("url") or params.get("path") or params.get("target") or scan_state.target
        
        # Tool start event
        await self.emit_event(EventType.TOOL_STARTED, {
            "tool_name": tool_name,
            "target": target_dest,
            "params": params
        })

        obs = await tool.execute(params, scan_state.scope_definition)
        scan_state.total_tool_calls += 1

        # Record in memory
        self.memory.record_observation(obs.model_dump())
        self.state.observations.append(obs.model_dump())
        self.state.tool_history.append({
            "tool": tool_name,
            "status": obs.status,
            "duration_ms": obs.duration_ms,
            "raw_output": obs.raw_output
        })

        # Tool complete event
        await self.emit_event(EventType.TOOL_COMPLETED, {
            "tool_name": tool_name,
            "target": target_dest,
            "status": obs.status,
            "status_code": obs.status_code,
            "duration_ms": obs.duration_ms,
            "data": obs.data,
            "error": obs.error
        })

        return obs.model_dump()

    @abstractmethod
    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        """Core execution loop of the specialized agent."""
        pass
