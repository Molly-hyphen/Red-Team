from typing import Dict, List, Any
from app.state.agent_state import AgentState

class AgentManager:
    def __init__(self):
        self._agents: Dict[str, AgentState] = {}

    def register_agent(self, state: AgentState):
        self._agents[state.agent_id] = state

    def get_agents_for_scan(self, scan_id: str) -> List[AgentState]:
        return [a for a in self._agents.values() if a.scan_id == scan_id]

    def get_agent(self, agent_id: str) -> AgentState:
        return self._agents.get(agent_id)

agent_manager = AgentManager()
