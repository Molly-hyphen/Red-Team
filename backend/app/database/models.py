import uuid
from datetime import datetime
from enum import Enum
from sqlalchemy import (
    Column, String, Text, Integer, Float, Boolean, DateTime,
    ForeignKey, JSON
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def generate_uuid() -> str:
    return str(uuid.uuid4())

class ScanStatus(str, Enum):
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"

class TargetMode(str, Enum):
    BLACK_BOX = "black_box"
    GREY_BOX = "grey_box"
    WHITE_BOX = "white_box"

class TargetType(str, Enum):
    WEB_URL = "web_url"
    API_ENDPOINT = "api_endpoint"
    OPENAPI_SPEC = "openapi_spec"
    POSTMAN_COLLECTION = "postman_collection"
    LOCAL_DIRECTORY = "local_directory"
    GITHUB_REPO = "github_repo"
    MULTI_TARGET = "multi_target"

class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingValidationStatus(str, Enum):
    POTENTIAL = "potential"
    INVESTIGATING = "investigating"
    VALIDATED = "validated"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    FIXED = "fixed"
    REOPENED = "reopened"

class FindingStatusEnum(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"
    NOT_FOUND = "NOT_FOUND"

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    target_type = Column(String(50), default=TargetType.WEB_URL.value)
    location = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    versions = relationship("ProjectVersion", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project")

class ProjectVersion(Base):
    __tablename__ = "project_versions"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    project_hash = Column(String(64), nullable=False, index=True) # SHA-256
    source_files_count = Column(Integer, default=0)
    metadata_info = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    project = relationship("Project", back_populates="versions")
    scans = relationship("Scan", back_populates="version")

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    target_type = Column(String(50), default=TargetType.WEB_URL.value)
    mode = Column(String(50), default=TargetMode.BLACK_BOX.value)
    location = Column(Text, nullable=False) # URL or path
    scope_definition = Column(JSON, default=dict) # allowed/excluded domains, IPs, paths
    credentials = Column(JSON, default=dict) # Auth tokens or test accounts if greybox
    metadata_info = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True)
    version_id = Column(String(36), ForeignKey("project_versions.id"), nullable=True)
    project_hash = Column(String(64), nullable=True)
    
    status = Column(String(50), default=ScanStatus.PENDING.value)
    mode = Column(String(50), default=TargetMode.BLACK_BOX.value)
    instruction = Column(Text, default="")
    config = Column(JSON, default=dict)
    
    # Progress & Metrics
    progress_percentage = Column(Float, default=0.0)
    total_tokens_used = Column(Integer, default=0)
    estimated_cost_usd = Column(Float, default=0.0)
    total_tool_calls = Column(Integer, default=0)
    
    # Attack surface stats
    discovered_assets_count = Column(Integer, default=0)
    discovered_endpoints_count = Column(Integer, default=0)
    
    # Findings summary count
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    target = relationship("Target", back_populates="scans")
    project = relationship("Project", back_populates="scans")
    version = relationship("ProjectVersion", back_populates="scans")
    agents = relationship("Agent", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    observations_list = relationship("ObservationModel", back_populates="scan", cascade="all, delete-orphan")
    hypotheses_list = relationship("HypothesisModel", back_populates="scan", cascade="all, delete-orphan")
    validations_list = relationship("ValidationRecordModel", back_populates="scan", cascade="all, delete-orphan")
    agent_runs_list = relationship("AgentRunModel", back_populates="scan", cascade="all, delete-orphan")

class ObservationModel(Base):
    __tablename__ = "observations"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    agent_id = Column(String(36), nullable=False)
    category = Column(String(100), nullable=False)
    target_location = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    raw_data = Column(JSON, default=dict)
    evidence_snippet = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="observations_list")

class HypothesisModel(Base):
    __tablename__ = "hypotheses"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    test_id = Column(String(100), nullable=False)
    capability_id = Column(String(100), nullable=False)
    suspected_flaw = Column(Text, nullable=False)
    target_location = Column(Text, nullable=False)
    confidence = Column(Float, default=0.5)
    rationale = Column(Text, default="")
    validation_strategy = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="hypotheses_list")

class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    parent_agent_id = Column(String(36), ForeignKey("agents.id"), nullable=True)
    role = Column(String(100), nullable=False) # RootAgent, ReconAgent, WebAgent, APIAgent, etc.
    objective = Column(Text, nullable=False)
    status = Column(String(50), default=AgentStatus.IDLE.value)
    current_task = Column(Text, default="")
    
    iterations = Column(Integer, default=0)
    max_iterations = Column(Integer, default=15)
    tokens_used = Column(Integer, default=0)
    cost_usd = Column(Float, default=0.0)
    
    observations = Column(JSON, default=list)
    state_data = Column(JSON, default=dict)
    
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="agents")
    parent = relationship("Agent", remote_side=[id], backref="sub_agents")
    tasks = relationship("AgentTask", back_populates="agent", cascade="all, delete-orphan")
    tool_calls = relationship("ToolCall", back_populates="agent", cascade="all, delete-orphan")

class AgentTask(Base):
    __tablename__ = "agent_tasks"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(50), default="pending") # pending, in_progress, completed, failed
    result = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    agent = relationship("Agent", back_populates="tasks")

class ToolCall(Base):
    __tablename__ = "tool_calls"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    target_destination = Column(Text, nullable=False)
    input_parameters = Column(JSON, default=dict)
    
    # Execution info
    status = Column(String(50), default="executing") # executing, success, failed, blocked_by_scope
    status_code = Column(Integer, nullable=True)
    duration_ms = Column(Integer, default=0)
    output_result = Column(JSON, default=dict)
    raw_output = Column(Text, default="")
    error_message = Column(Text, default="")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", back_populates="tool_calls")

class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    asset_type = Column(String(50), nullable=False) # endpoint, subdomain, parameter, tech, file, port
    value = Column(Text, nullable=False)
    details = Column(JSON, default=dict)
    discovered_by_agent = Column(String(100), default="recon")
    confidence = Column(Float, default=1.0)
    created_at = Column(DateTime, default=datetime.utcnow)

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    project_id = Column(String(36), nullable=True)
    version_id = Column(String(36), nullable=True)
    project_hash = Column(String(64), nullable=True)
    finding_hash = Column(String(64), nullable=True, index=True) # SHA-256 deterministic fingerprint
    
    title = Column(String(255), nullable=False)
    vulnerability_type = Column(String(100), nullable=False) # SQL Injection, IDOR, SSRF, XSS, etc.
    cwe = Column(String(50), default="")
    owasp_category = Column(String(100), default="")
    
    severity = Column(String(50), default=FindingSeverity.MEDIUM.value)
    confidence = Column(Float, default=0.8)
    cvss_score = Column(Float, default=5.0)
    status = Column(String(50), default=FindingStatusEnum.POTENTIAL.value) # CONFIRMED, POTENTIAL, INCONCLUSIVE, REJECTED, NOT_FOUND
    
    affected_asset = Column(Text, nullable=False)
    affected_endpoint = Column(Text, default="")
    file = Column(Text, default="")
    line = Column(Integer, nullable=True)
    endpoint = Column(Text, default="")
    parameter = Column(String(255), default="")
    sink = Column(Text, default="")
    source_locations = Column(JSON, default=list)
    
    description = Column(Text, nullable=False)
    impact = Column(Text, default="")
    reproduction_steps = Column(JSON, default=list)
    remediation = Column(Text, default="")
    
    validation_status = Column(String(50), default=FindingValidationStatus.POTENTIAL.value)
    validation_notes = Column(Text, default="")
    discovered_by = Column(String(100), default="WebAgent")
    validated_by = Column(String(100), default="")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    validations = relationship("ValidationRecordModel", back_populates="finding", cascade="all, delete-orphan")

class ValidationRecordModel(Base):
    __tablename__ = "validations"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=True)
    hypothesis_id = Column(String(100), nullable=True)
    validation_method = Column(String(100), nullable=False) # static_taint_proof, safe_dynamic_poc, auth_cross_tenant_test
    validation_status = Column(String(50), default=FindingStatusEnum.POTENTIAL.value)
    evidence_ids = Column(JSON, default=list)
    rationale = Column(Text, default="")
    steps_executed = Column(JSON, default=list)
    is_reproducible = Column(Boolean, default=False)
    notes = Column(Text, default="")
    validated_by_agent = Column(String(100), default="ValidatorEngine")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="validations_list")
    finding = relationship("Finding", back_populates="validations")

class AgentRunModel(Base):
    __tablename__ = "agent_runs"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    agent_name = Column(String(100), nullable=False)
    capability_id = Column(String(100), nullable=False)
    capability_name = Column(String(255), nullable=False)
    status = Column(String(50), default="completed")
    findings_generated_count = Column(Integer, default=0)
    hypotheses_count = Column(Integer, default=0)
    observations_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    scan = relationship("Scan", back_populates="agent_runs_list")

class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)
    evidence_type = Column(String(50), nullable=False) # http_exchange, code_snippet, terminal_output, screenshot
    description = Column(Text, default="")
    
    request_data = Column(JSON, default=dict)
    response_data = Column(JSON, default=dict)
    raw_payload = Column(Text, default="")
    screenshot_url = Column(Text, default="")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    finding = relationship("Finding", back_populates="evidence")

class ScanEvent(Base):
    __tablename__ = "scan_events"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    event_type = Column(String(100), nullable=False) # scan.started, agent.created, tool.completed, etc.
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="events")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    summary = Column(Text, default="")
    content_html = Column(Text, default="")
    content_markdown = Column(Text, default="")
    content_json = Column(JSON, default=dict)
    content_sarif = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="reports")
