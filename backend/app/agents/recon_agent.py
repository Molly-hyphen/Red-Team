import asyncio
from typing import Any, Dict
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.state.scan_state import ScanState

class ReconAgent(BaseAgent):
    role = "ReconAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Starting reconnaissance & tech discovery"})
        
        # 1. Tech fingerprinting & route probing
        self.state.current_task = f"Fingerprinting {scan_state.target} and probing common security routes"
        await self.emit_event(EventType.AGENT_PROGRESS, {"progress": 25, "current_task": self.state.current_task})
        
        obs = await self.execute_tool("recon_discovery", {
            "url": scan_state.target,
            "scan_ports": True,
            "probe_endpoints": True
        }, scan_state)

        data = obs.get("data", {})
        discovered_endpoints = data.get("discovered_endpoints", [])
        technologies = data.get("technologies", [])
        missing_headers = data.get("missing_security_headers", [])

        # Update global scan state
        for tech in technologies:
            if tech not in scan_state.technologies:
                scan_state.technologies.append(tech)
                await self.emit_event(EventType.ASSET_DISCOVERED, {"asset_type": "technology", "value": tech})

        for ep in discovered_endpoints:
            ep_url = ep.get("url") or ep.get("path")
            scan_state.add_endpoint(ep_url, source_agent="ReconAgent")
            await self.emit_event(EventType.ENDPOINT_DISCOVERED, {
                "url": ep_url,
                "status_code": ep.get("status_code"),
                "content_type": ep.get("content_type")
            })

        # 2. Browser DOM inspection for forms and inputs
        self.state.current_task = "Inspecting DOM for interactive input vectors"
        await self.emit_event(EventType.AGENT_PROGRESS, {"progress": 70, "current_task": self.state.current_task})
        
        dom_obs = await self.execute_tool("browser_dom_inspector", {
            "url": scan_state.target
        }, scan_state)

        self.state.status = "completed"
        self.state.current_task = "Reconnaissance completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {
            "status": "completed",
            "summary": f"Discovered {len(discovered_endpoints)} endpoints, {len(technologies)} technologies."
        })

        return {
            "discovered_endpoints": discovered_endpoints,
            "technologies": technologies,
            "missing_security_headers": missing_headers
        }
