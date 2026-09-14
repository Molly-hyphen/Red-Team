from typing import Any, Dict
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.findings.models import FindingModel, FindingEvidenceModel
from app.state.scan_state import ScanState

class WebAgent(BaseAgent):
    role = "WebAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Analyzing web application inputs & reflection"})
        
        discovered_findings = []

        # Test endpoints discovered during recon
        target_endpoints = [ep.url for ep in scan_state.endpoints if ep.url.startswith("http")]
        if not target_endpoints:
            target_endpoints = [scan_state.target]

        for ep in target_endpoints[:6]: # Test top endpoints
            # 1. Test XSS on parameter fields
            self.state.current_task = f"Testing XSS & input reflection on {ep}"
            await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
            
            fuzz_obs = await self.execute_tool("vulnerability_fuzzer", {
                "url": ep,
                "parameter": "message",
                "test_type": "xss"
            }, scan_state)

            fuzz_data = fuzz_obs.get("data", {})
            if fuzz_data.get("has_anomalies"):
                finding = FindingModel(
                    scan_id=scan_id_val := scan_state.scan_id,
                    title="Reflected Cross-Site Scripting (XSS) in Parameter",
                    vulnerability_type="Cross-Site Scripting",
                    cwe="CWE-79",
                    owasp_category="A03:2021-Injection",
                    severity="medium",
                    confidence=0.85,
                    cvss_score=6.1,
                    affected_asset=scan_state.target,
                    affected_endpoint=ep,
                    description=f"Endpoint '{ep}' unsafely reflects user-supplied script tags in HTTP responses without sanitization.",
                    impact="An attacker can execute arbitrary script in the victim's browser context, potentially stealing session tokens or manipulating DOM.",
                    reproduction_steps=[
                        f"Send GET request to {ep}?message=<script>alert(1)</script>",
                        "Observe unescaped script tag returned in response payload."
                    ],
                    remediation="Apply context-aware output encoding (e.g. HTML entity encoding) before rendering dynamic inputs.",
                    discovered_by="WebAgent",
                    validation_status="potential",
                    evidence=[
                        FindingEvidenceModel(
                            evidence_type="http_exchange",
                            description="Unescaped payload reflection detected",
                            request_data={"url": f"{ep}?message=<script>alert(1)</script>", "method": "GET"},
                            raw_payload="<script>alert(1)</script>"
                        )
                    ]
                )
                scan_state.add_finding(finding)
                discovered_findings.append(finding)
                await self.emit_event(EventType.FINDING_CREATED, {"finding": finding.model_dump()})

        self.state.status = "completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {
            "status": "completed",
            "findings_count": len(discovered_findings)
        })

        return {"findings": discovered_findings}
