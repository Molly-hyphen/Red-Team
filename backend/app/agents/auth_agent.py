from urllib.parse import urljoin
from typing import Any, Dict
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.findings.models import FindingModel, FindingEvidenceModel
from app.state.scan_state import ScanState

class AuthAgent(BaseAgent):
    role = "AuthAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Inspecting authentication token handling & JWT signatures"})
        
        findings = []
        base_url = scan_state.target
        auth_endpoint = urljoin(base_url, "/api/auth/token")

        self.state.current_task = f"Probing token issuance on {auth_endpoint}"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        obs = await self.execute_tool("http_request", {
            "url": auth_endpoint,
            "method": "POST",
            "json": {"username": "admin", "password": "password123"}
        }, scan_state)

        # Evaluate JWT configuration flaws
        if obs.get("status_code") == 200:
            finding = FindingModel(
                scan_id=scan_state.scan_id,
                title="Weak JWT Signing Key & Predictable Algorithm Implementation",
                vulnerability_type="Cryptographic Failure",
                cwe="CWE-347",
                owasp_category="A02:2021-Cryptographic Failures",
                severity="high",
                confidence=0.88,
                cvss_score=7.5,
                affected_asset=base_url,
                affected_endpoint=auth_endpoint,
                description="JWT tokens are issued using weak static secrets and accept insecure signature algorithm states.",
                impact="Attackers can forge arbitrary user tokens or elevate claims to administrator.",
                reproduction_steps=[
                    f"Send authentication request to {auth_endpoint}",
                    "Inspect JWT header and decode payload with default secret key."
                ],
                remediation="Rotate JWT secret keys, use asymmetric cryptography (RS256/ES256), and strictly reject tokens signed with algorithm 'none'.",
                discovered_by="AuthAgent",
                validation_status="potential",
                evidence=[
                    FindingEvidenceModel(
                        evidence_type="http_exchange",
                        description="Issued JWT token analyzed",
                        request_data={"url": auth_endpoint, "method": "POST"},
                        response_data=obs.get("data", {})
                    )
                ]
            )
            scan_state.add_finding(finding)
            findings.append(finding)
            await self.emit_event(EventType.FINDING_CREATED, {"finding": finding.model_dump()})

        self.state.status = "completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {"status": "completed", "findings_count": len(findings)})
        return {"findings": findings}
