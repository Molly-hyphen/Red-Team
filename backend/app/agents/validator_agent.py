from typing import Any, Dict, List
from app.agents.base_agent import BaseAgent
from app.events.events import EventType
from app.findings.deduplicator import FindingDeduplicator
from app.findings.validator import FindingValidator
from app.state.scan_state import ScanState

class ValidatorAgent(BaseAgent):
    role = "ValidatorAgent"

    async def run(self, scan_state: ScanState) -> Dict[str, Any]:
        self.state.status = "running"
        await self.emit_event(EventType.AGENT_STARTED, {"status": "running", "current_task": "Validating potential vulnerability hypotheses"})
        
        deduped_findings = []
        validated_count = 0
        rejected_count = 0
        
        # 1. Deduplication pass
        for f in scan_state.findings:
            is_dup, existing = FindingDeduplicator.is_duplicate(f, deduped_findings)
            if is_dup and existing:
                FindingDeduplicator.merge_findings(existing, f)
                await self.emit_event(EventType.FINDING_DUPLICATE, {"duplicate_id": f.id, "primary_id": existing.id})
            else:
                deduped_findings.append(f)

        # 2. Reproduction and proof-of-concept verification
        for idx, finding in enumerate(deduped_findings):
            self.state.current_task = f"Attempting controlled reproduction of: {finding.title}"
            await self.emit_event(EventType.AGENT_PROGRESS, {
                "progress": int((idx + 1) / len(deduped_findings) * 100),
                "current_task": self.state.current_task
            })
            await self.emit_event(EventType.FINDING_VALIDATION_STARTED, {"finding_id": finding.id, "title": finding.title})

            is_valid, updated_finding = await FindingValidator.validate_finding(finding, scan_state.scope_definition)
            
            if is_valid:
                validated_count += 1
                await self.emit_event(EventType.FINDING_VALIDATED, {"finding": updated_finding.model_dump()})
            else:
                rejected_count += 1
                await self.emit_event(EventType.FINDING_REJECTED, {
                    "finding_id": updated_finding.id,
                    "reason": updated_finding.validation_notes
                })

        # Update validated list in scan_state
        scan_state.validated_findings = [f for f in deduped_findings if f.validation_status == "validated"]
        scan_state.findings = deduped_findings

        self.state.status = "completed"
        await self.emit_event(EventType.AGENT_COMPLETED, {
            "status": "completed",
            "validated_findings": validated_count,
            "rejected_findings": rejected_count
        })

        return {
            "validated_findings": [f.model_dump() for f in scan_state.validated_findings],
            "total_validated": validated_count,
            "total_rejected": rejected_count
        }
