import asyncio
from typing import Any, Dict, List
from app.agents.base_agent import BaseAgent
from app.agents.recon_agent import ReconAgent
from app.agents.web_agent import WebAgent
from app.agents.api_agent import APIAgent
from app.agents.auth_agent import AuthAgent
from app.agents.authorization_agent import AuthorizationAgent
from app.agents.source_agent import SourceAnalysisAgent
from app.agents.business_logic_agent import BusinessLogicAgent
from app.agents.validator_agent import ValidatorAgent
from app.events.events import EventType
from app.state.scan_state import ScanState

class RootAgent(BaseAgent):
    role = "RootOrchestratorAgent"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.objective = "Decompose target, coordinate specialized security testing agents, and validate real findings."

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.SCAN_STARTED, {
            "target": scan_state.target,
            "mode": scan_state.mode,
            "scan_id": scan_state.scan_id
        })
        await self.emit_event(EventType.AGENT_STARTED, {
            "status": "running",
            "current_task": f"Decomposing target assessment for mode: {scan_state.mode}"
        })

        created_agents: List[BaseAgent] = []

        # 1. White-box or Hybrid: Always launch Source Analysis Agent
        if scan_state.mode in ["white_box", "grey_box"] or not scan_state.target.startswith("http"):
            source_agent = SourceAnalysisAgent(
                scan_id=scan_state.scan_id,
                parent_agent_id=self.agent_id,
                objective="Perform SAST code dataflow analysis to discover unvalidated sinks and hardcoded secrets.",
                llm_provider=self.llm
            )
            created_agents.append(source_agent)
            await self.emit_event(EventType.AGENT_CREATED, {
                "agent_id": source_agent.agent_id,
                "role": source_agent.role,
                "objective": source_agent.objective
            })

        # 2. Black-box / Network assessment: Launch Reconnaissance Agent
        if scan_state.target.startswith("http"):
            recon_agent = ReconAgent(
                scan_id=scan_state.scan_id,
                parent_agent_id=self.agent_id,
                objective="Discover open ports, fingerprinted tech stack, and reachable endpoints.",
                llm_provider=self.llm
            )
            created_agents.append(recon_agent)
            await self.emit_event(EventType.AGENT_CREATED, {
                "agent_id": recon_agent.agent_id,
                "role": recon_agent.role,
                "objective": recon_agent.objective
            })

            # Execute Recon First to inform downstream sub-agents
            await recon_agent.run(scan_state)

            # 3. Dynamic Sub-Agent Spawning based on discoveries:
            # Web Agent for general route & DOM testing
            web_agent = WebAgent(
                scan_id=scan_state.scan_id,
                parent_agent_id=self.agent_id,
                objective="Audit web interfaces and dynamic input reflections.",
                llm_provider=self.llm
            )
            created_agents.append(web_agent)
            await self.emit_event(EventType.AGENT_CREATED, {
                "agent_id": web_agent.agent_id,
                "role": web_agent.role,
                "objective": web_agent.objective
            })

            # API Agent for endpoints with parameters
            api_agent = APIAgent(
                scan_id=scan_state.scan_id,
                parent_agent_id=self.agent_id,
                objective="Audit REST API endpoints, parameter injection, and SSRF vectors.",
                llm_provider=self.llm
            )
            created_agents.append(api_agent)
            await self.emit_event(EventType.AGENT_CREATED, {
                "agent_id": api_agent.agent_id,
                "role": api_agent.role,
                "objective": api_agent.objective
            })

            # Auth & Authorization Agents
            auth_agent = AuthAgent(
                scan_id=scan_state.scan_id,
                parent_agent_id=self.agent_id,
                objective="Audit session management and JWT token configuration.",
                llm_provider=self.llm
            )
            created_agents.append(auth_agent)
            await self.emit_event(EventType.AGENT_CREATED, {
                "agent_id": auth_agent.agent_id,
                "role": auth_agent.role,
                "objective": auth_agent.objective
            })

            authz_agent = AuthorizationAgent(
                scan_id=scan_state.scan_id,
                parent_agent_id=self.agent_id,
                objective="Audit object-level authorization (IDOR) and administrative privilege boundaries.",
                llm_provider=self.llm
            )
            created_agents.append(authz_agent)
            await self.emit_event(EventType.AGENT_CREATED, {
                "agent_id": authz_agent.agent_id,
                "role": authz_agent.role,
                "objective": authz_agent.objective
            })

            # Execute specialized agents concurrently or sequentially
            for agent in [web_agent, api_agent, auth_agent, authz_agent]:
                await agent.run(scan_state)

        # Run source agent if added
        for ag in created_agents:
            if isinstance(ag, SourceAnalysisAgent):
                await ag.run(scan_state)

        # 4. Mandatory Validation Stage
        self.state.current_task = "Delegating all candidate findings to the Validator Agent for proof-of-concept testing"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        validator_agent = ValidatorAgent(
            scan_id=scan_state.scan_id,
            parent_agent_id=self.agent_id,
            objective="Reproduce, deduplicate, and verify genuine exploitability of findings.",
            llm_provider=self.llm
        )
        await self.emit_event(EventType.AGENT_CREATED, {
            "agent_id": validator_agent.agent_id,
            "role": validator_agent.role,
            "objective": validator_agent.objective
        })
        
        val_res = await validator_agent.run(scan_state)

        self.state.status = "completed"
        self.state.current_task = "Assessment completed successfully"
        await self.emit_event(EventType.AGENT_COMPLETED, {
            "status": "completed",
            "total_validated_findings": len(scan_state.validated_findings),
            "total_endpoints": len(scan_state.endpoints)
        })

        await self.emit_event(EventType.SCAN_COMPLETED, {
            "scan_id": scan_state.scan_id,
            "validated_findings_count": len(scan_state.validated_findings),
            "total_findings_count": len(scan_state.findings),
            "discovered_endpoints_count": len(scan_state.endpoints),
            "technologies": scan_state.technologies
        })

        return {
            "scan_id": scan_state.scan_id,
            "status": "completed",
            "findings": [f.model_dump() for f in scan_state.validated_findings],
            "attack_surface": {
                "technologies": scan_state.technologies,
                "endpoints": [ep.model_dump() for ep in scan_state.endpoints]
            }
        }
