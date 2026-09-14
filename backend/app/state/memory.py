from typing import Any, Dict, List
from collections import deque

class AgentMemory:
    """
    Manages bounded short-term observation memory and structured discoveries.
    Avoids prompt overflow by storing only recent observations and key discoveries.
    """
    def __init__(self, max_observations: int = 10):
        self.observations = deque(maxlen=max_observations)
        self.discoveries: List[Dict[str, Any]] = []

    def record_observation(self, observation: Dict[str, Any]):
        self.observations.append(observation)

    def record_discovery(self, discovery_type: str, data: Dict[str, Any]):
        self.discoveries.append({
            "type": discovery_type,
            "data": data
        })

    def get_summary(self) -> str:
        recent_obs = [f"[{o.get('tool', 'tool')}] {o.get('raw_output', '')}" for o in self.observations]
        return "\n".join(recent_obs[-5:]) if recent_obs else "No prior observations."
