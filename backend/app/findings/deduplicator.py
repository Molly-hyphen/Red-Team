from typing import List, Optional
from app.findings.models import FindingModel

class FindingDeduplicator:
    @staticmethod
    def is_duplicate(candidate: FindingModel, existing_findings: List[FindingModel]) -> tuple[bool, Optional[FindingModel]]:
        """
        Determines if a finding is a duplicate by comparing:
        1. Normalized endpoint / affected asset
        2. Vulnerability class / CWE
        3. Source file and line (for whitebox)
        """
        for existing in existing_findings:
            # 1. Match by endpoint and vulnerability type
            same_endpoint = (
                candidate.affected_endpoint.strip().lower() == existing.affected_endpoint.strip().lower()
                and candidate.affected_endpoint != ""
            )
            same_vuln = candidate.vulnerability_type.strip().lower() == existing.vulnerability_type.strip().lower()

            if same_endpoint and same_vuln:
                return True, existing

            # 2. Match by source location
            if candidate.source_locations and existing.source_locations:
                c_loc = candidate.source_locations[0]
                e_loc = existing.source_locations[0]
                if (
                    c_loc.get("file") == e_loc.get("file")
                    and abs(c_loc.get("line_number", 0) - e_loc.get("line_number", 0)) <= 3
                    and same_vuln
                ):
                    return True, existing

        return False, None

    @staticmethod
    def merge_findings(primary: FindingModel, duplicate: FindingModel) -> FindingModel:
        """Merges evidence and updates confidence when duplicates occur."""
        for ev in duplicate.evidence:
            primary.evidence.append(ev)
        primary.confidence = min(1.0, primary.confidence + 0.1)
        return primary
