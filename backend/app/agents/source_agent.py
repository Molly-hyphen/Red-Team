from typing import Any, Dict
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.findings.models import FindingModel, FindingEvidenceModel
from app.findings.severity import SeverityCalculator
from app.state.scan_state import ScanState

class SourceAnalysisAgent(BaseAgent):
    role = "SourceAnalysisAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Performing white-box Static Analysis (SAST)"})
        
        target_path = scan_state.target if not scan_state.target.startswith("http") else "./demo-target"
        
        self.state.current_task = f"Analyzing source code directory: {target_path}"
        await self.emit_event(EventType.AGENT_PROGRESS, {"current_task": self.state.current_task})
        
        sast_obs = await self.execute_tool("source_code_sast", {
            "path": target_path
        }, scan_state)

        data = sast_obs.get("data", {})
        code_findings = data.get("findings", [])
        created_findings = []

        for item in code_findings:
            enriched = SeverityCalculator.enrich_finding(item.get("cwe", ""))
            finding = FindingModel(
                scan_id=scan_state.scan_id,
                title=item.get("title", "Code Security Vulnerability"),
                vulnerability_type=item.get("pattern_id", "Static Vulnerability"),
                cwe=item.get("cwe", ""),
                owasp_category=enriched.get("owasp", ""),
                severity=item.get("severity", "medium"),
                confidence=0.95,
                cvss_score=enriched.get("cvss", 7.0),
                affected_asset=item.get("file", target_path),
                affected_endpoint=f"file://{item.get('file')}:{item.get('line_number')}",
                source_locations=[{
                    "file": item.get("file"),
                    "line_number": item.get("line_number"),
                    "snippet": item.get("code_snippet")
                }],
                description=f"Static code analysis detected dangerous pattern '{item.get('title')}' at line {item.get('line_number')}.",
                impact="May lead to remote code execution, database compromise, or secret exposure depending on sink trigger.",
                reproduction_steps=[
                    f"Inspect source file {item.get('file')} at line {item.get('line_number')}",
                    f"Code: {item.get('code_snippet')}"
                ],
                remediation="Refactor the vulnerable code construct to avoid unvalidated user interpolation into execution sinks.",
                discovered_by="SourceAnalysisAgent",
                validation_status="potential",
                evidence=[
                    FindingEvidenceModel(
                        evidence_type="code_snippet",
                        description=f"Source code finding in {item.get('file')}:{item.get('line_number')}",
                        raw_payload=item.get("code_snippet")
                    )
                ]
            )
            scan_state.add_finding(finding)
            created_findings.append(finding)
            await self.emit_event(EventType.FINDING_CREATED, {"finding": finding.model_dump()})

        self.state.status = "completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {"status": "completed", "findings_count": len(created_findings)})
        return {"findings": created_findings}
