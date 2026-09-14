import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class FindingEvidenceModel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: str = "http_exchange" # http_exchange, code_snippet, screenshot, terminal
    description: str = ""
    request_data: Dict[str, Any] = Field(default_factory=dict)
    response_data: Dict[str, Any] = Field(default_factory=dict)
    raw_payload: str = ""
    screenshot_url: str = ""

class FindingModel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    title: str
    vulnerability_type: str
    cwe: str = ""
    owasp_category: str = ""
    severity: str = "medium" # critical, high, medium, low, info
    confidence: float = 0.8
    cvss_score: float = 5.0
    
    affected_asset: str
    affected_endpoint: str = ""
    source_locations: List[Dict[str, Any]] = Field(default_factory=list)
    
    description: str
    impact: str = ""
    reproduction_steps: List[str] = Field(default_factory=list)
    remediation: str = ""
    
    validation_status: str = "potential" # potential, investigating, validated, rejected, duplicate
    validation_notes: str = ""
    discovered_by: str = "WebAgent"
    validated_by: str = ""
    
    evidence: List[FindingEvidenceModel] = Field(default_factory=list)
