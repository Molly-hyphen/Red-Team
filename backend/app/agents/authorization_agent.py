from urllib.parse import urljoin
from typing import Any, Dict
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.findings.models import FindingModel, FindingEvidenceModel
from app.state.scan_state import ScanState

class AuthorizationAgent(BaseAgent):
    role = "AuthorizationAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Testing Broken Object Level Authorization (IDOR) & privilege boundaries"})
        
        findings = []
        base_url = scan_state.target

        # 1. Test IDOR on /api/user/{id}/profile
        idor_endpoint = urljoin(base_url, "/api/user/1/profile")
        self.state.current_task = f"Testing Broken Object Level Authorization on {idor_endpoint}"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        obs = await self.execute_tool("http_request", {
            "url": idor_endpoint,
            "method": "GET"
        }, scan_state)

        if obs.get("status_code") == 200:
            idor_finding = FindingModel(
                scan_id=scan_state.scan_id,
                title="Broken Object Level Authorization (BOLA / IDOR) in User Profile",
                vulnerability_type="Broken Object Level Authorization",
                cwe="CWE-639",
                owasp_category="A01:2021-Broken Access Control",
                severity="high",
                confidence=0.92,
                cvss_score=8.5,
                affected_asset=base_url,
                affected_endpoint=idor_endpoint,
                description=f"Endpoint '{idor_endpoint}' allows viewing private user profile data without authentication or object ownership validation.",
                impact="Attackers can enumerate and harvest private personal data (emails, addresses, phone numbers) of all registered users by cycling ID values.",
                reproduction_steps=[
                    f"Send unauthenticated GET request to {idor_endpoint}",
                    "Notice full user profile JSON is returned without access denial."
                ],
                remediation="Enforce server-side authorization checks comparing the authenticated session's user ID against requested resource ID.",
                discovered_by="AuthorizationAgent",
                validation_status="potential",
                evidence=[
                    FindingEvidenceModel(
                        evidence_type="http_exchange",
                        description="Unauthenticated access to user profile confirmed",
                        request_data={"url": idor_endpoint, "method": "GET"},
                        response_data=obs.get("data", {})
                    )
                ]
            )
            scan_state.add_finding(idor_finding)
            findings.append(idor_finding)
            await self.emit_event(EventType.FINDING_CREATED, {"finding": idor_finding.model_dump()})

        # 2. Test missing access control on administrative route /api/admin/system-stats
        admin_endpoint = urljoin(base_url, "/api/admin/system-stats")
        self.state.current_task = f"Testing Missing Function Level Access Control on {admin_endpoint}"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        admin_obs = await self.execute_tool("http_request", {
            "url": admin_endpoint,
            "method": "GET"
        }, scan_state)

        if admin_obs.get("status_code") == 200:
            admin_finding = FindingModel(
                scan_id=scan_state.scan_id,
                title="Missing Function Level Access Control on Administrative Endpoint",
                vulnerability_type="Missing Access Control",
                cwe="CWE-306",
                owasp_category="A01:2021-Broken Access Control",
                severity="critical",
                confidence=0.95,
                cvss_score=9.1,
                affected_asset=base_url,
                affected_endpoint=admin_endpoint,
                description=f"Endpoint '{admin_endpoint}' exposes administrative system diagnostics and metrics without requiring admin role authorization.",
                impact="Unprivileged users or anonymous visitors can view sensitive system status, memory allocation, and operational details.",
                reproduction_steps=[
                    f"Send GET request to {admin_endpoint} without Authorization header",
                    "Observe HTTP 200 with sensitive system metrics."
                ],
                remediation="Apply authentication middleware and enforce strict role-based access control (RBAC) checking for admin privileges.",
                discovered_by="AuthorizationAgent",
                validation_status="potential",
                evidence=[
                    FindingEvidenceModel(
                        evidence_type="http_exchange",
                        description="Administrative diagnostics accessible without credentials",
                        request_data={"url": admin_endpoint, "method": "GET"},
                        response_data=admin_obs.get("data", {})
                    )
                ]
            )
            scan_state.add_finding(admin_finding)
            findings.append(admin_finding)
            await self.emit_event(EventType.FINDING_CREATED, {"finding": admin_finding.model_dump()})

        self.state.status = "completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {"status": "completed", "findings_count": len(findings)})
        return {"findings": findings}
