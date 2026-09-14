import asyncio
from typing import Dict, Any, Optional
from app.agents.root_agent import RootAgent
from app.state.scan_state import ScanState

class ScanOrchestrator:
    def __init__(self):
        self._active_scans: Dict[str, asyncio.Task] = {}
        self._scan_states: Dict[str, ScanState] = {}

    def get_state(self, scan_id: str) -> Optional[ScanState]:
        return self._scan_states.get(scan_id)

    async def start_scan(
        self,
        scan_id: str,
        target: str,
        mode: str = "black_box",
        scope_definition: Optional[Dict[str, Any]] = None,
        instruction: str = ""
    ) -> ScanState:
        """Initializes and runs autonomous pentest in background task."""
        state = ScanState(
            scan_id=scan_id,
            target=target,
            mode=mode,
            scope_definition=scope_definition or {
                "allowed_domains": ["localhost", "127.0.0.1", "demo-target"],
                "allowed_urls": [target],
                "allowed_ports": [80, 443, 3000, 5000, 8000, 8080],
                "allowed_local_paths": ["./demo-target", "./"]
            }
        )
        self._scan_states[scan_id] = state

        root_agent = RootAgent(scan_id=scan_id)
        task = asyncio.create_task(root_agent.run(state))
        self._active_scans[scan_id] = task
        return state

    async def stop_scan(self, scan_id: str) -> bool:
        if scan_id in self._active_scans:
            task = self._active_scans[scan_id]
            task.cancel()
            del self._active_scans[scan_id]
            return True
        return False

orchestrator = ScanOrchestrator()
