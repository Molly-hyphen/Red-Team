from typing import Any, Dict, List, Set
from pydantic import BaseModel, Field
from app.findings.models import FindingModel

class DiscoveredEndpoint(BaseModel):
    url: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    auth_required: bool = False
    source_agent: str = "recon"
    confidence: float = 1.0

class ScanState(BaseModel):
    scan_id: str
    target: str
    mode: str = "black_box"
    scope_definition: Dict[str, Any] = Field(default_factory=dict)
    
    # Live aggregated knowledge
    technologies: List[str] = Field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = Field(default_factory=list)
    parameters: Dict[str, List[str]] = Field(default_factory=dict) # endpoint -> [params]
    discovered_assets: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Findings repository
    findings: List[FindingModel] = Field(default_factory=list)
    validated_findings: List[FindingModel] = Field(default_factory=list)
    
    # Execution metrics
    total_tokens: int = 0
    total_tool_calls: int = 0
    start_time: float = 0.0
    
    def add_endpoint(self, url: str, method: str = "GET", source_agent: str = "recon"):
        for ep in self.endpoints:
            if ep.url == url and ep.method == method:
                return
        self.endpoints.append(DiscoveredEndpoint(url=url, method=method, source_agent=source_agent))

    def add_finding(self, finding: FindingModel):
        self.findings.append(finding)
        if finding.validation_status == "validated":
            self.validated_findings.append(finding)
