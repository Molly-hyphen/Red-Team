from urllib.parse import urljoin
from typing import Any, Dict
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.findings.models import FindingModel, FindingEvidenceModel
from app.state.scan_state import ScanState

class APIAgent(BaseAgent):
    role = "APIAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Auditing REST APIs & parameter tampering"})
        
        findings = []
        base_url = scan_state.target

        # 1. Test SQL Injection on search endpoints
        search_endpoint = urljoin(base_url, "/api/products/search")
        self.state.current_task = f"Testing SQL Injection vulnerabilities on {search_endpoint}"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        sqli_obs = await self.execute_tool("vulnerability_fuzzer", {
            "url": search_endpoint,
            "parameter": "q",
            "test_type": "sqli"
        }, scan_state)

        if sqli_obs.get("data", {}).get("has_anomalies"):
            sqli_finding = FindingModel(
                scan_id=scan_state.scan_id,
                title="SQL Injection in Products Search Parameter",
                vulnerability_type="SQL Injection",
                cwe="CWE-89",
                owasp_category="A03:2021-Injection",
                severity="critical",
                confidence=0.90,
                cvss_score=9.8,
                affected_asset=base_url,
                affected_endpoint=search_endpoint,
                description=f"Endpoint '{search_endpoint}' executes unsanitized user inputs in database queries, causing SQL error exposure and query hijacking.",
                impact="Attackers can bypass authentication, read or dump the entire database, or modify database records.",
                reproduction_steps=[
                    f"Send request: GET {search_endpoint}?q=' OR '1'='1",
                    "Observe SQL database operational syntax traces and unfiltered record dumping."
                ],
                remediation="Use parameterized queries / prepared statements with ORM query binding instead of dynamic string concatenation.",
                discovered_by="APIAgent",
                validation_status="potential",
                evidence=[
                    FindingEvidenceModel(
                        evidence_type="http_exchange",
                        description="SQL syntax error and boolean bypass confirmed",
                        request_data={"url": f"{search_endpoint}?q=' OR '1'='1", "method": "GET"},
                        raw_payload="' OR '1'='1"
                    )
                ]
            )
            scan_state.add_finding(sqli_finding)
            findings.append(sqli_finding)
            await self.emit_event(EventType.FINDING_CREATED, {"finding": sqli_finding.model_dump()})

        # 2. Test SSRF on Webhook endpoints
        webhook_endpoint = urljoin(base_url, "/api/webhook/test")
        self.state.current_task = f"Testing Server-Side Request Forgery on {webhook_endpoint}"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        ssrf_obs = await self.execute_tool("vulnerability_fuzzer", {
            "url": webhook_endpoint,
            "parameter": "target_url",
            "test_type": "ssrf"
        }, scan_state)

        if ssrf_obs.get("data", {}).get("has_anomalies"):
            ssrf_finding = FindingModel(
                scan_id=scan_state.scan_id,
                title="Server-Side Request Forgery (SSRF) in Webhook Dispatcher",
                vulnerability_type="Server-Side Request Forgery",
                cwe="CWE-918",
                owasp_category="A10:2021-Server-Side Request Forgery",
                severity="high",
                confidence=0.88,
                cvss_score=8.6,
                affected_asset=base_url,
                affected_endpoint=webhook_endpoint,
                description=f"Endpoint '{webhook_endpoint}' fetches arbitrary external URLs without IP whitelist validation or internal metadata blocking.",
                impact="Allows malicious actors to probe internal networks, port scan private clouds, or exfiltrate cloud instance metadata credentials.",
                reproduction_steps=[
                    f"Send request: GET {webhook_endpoint}?target_url=http://127.0.0.1:8000/api/admin/system-stats",
                    "Observe internal server response reflection."
                ],
                remediation="Implement strict domain whitelisting, disable HTTP redirects, and reject loopback and RFC 1918 / cloud metadata (169.254.169.254) addresses.",
                discovered_by="APIAgent",
                validation_status="potential",
                evidence=[
                    FindingEvidenceModel(
                        evidence_type="http_exchange",
                        description="Internal endpoint reflection confirmed via webhook parameter",
                        request_data={"url": f"{webhook_endpoint}?target_url=http://127.0.0.1:8000", "method": "GET"},
                        raw_payload="http://127.0.0.1:8000"
                    )
                ]
            )
            scan_state.add_finding(ssrf_finding)
            findings.append(ssrf_finding)
            await self.emit_event(EventType.FINDING_CREATED, {"finding": ssrf_finding.model_dump()})

        self.state.status = "completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {"status": "completed", "findings_count": len(findings)})
        return {"findings": findings}
