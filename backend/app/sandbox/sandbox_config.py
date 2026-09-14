import os
from pydantic import BaseModel, Field
from typing import List, Dict

class SandboxConfig(BaseModel):
    mode: str = Field(default="local_isolated", description="'docker' or 'local_isolated'")
    image_name: str = Field(default="aegis-sandbox:latest")
    cpu_limit: float = Field(default=2.0)
    memory_limit: str = Field(default="1g")
    timeout_seconds: int = Field(default=30)
    network_mode: str = Field(default="bridge")
    allowed_binaries: List[str] = Field(default_factory=lambda: [
        "curl", "nmap", "nikto", "semgrep", "nuclei", "python3", "pytest", "node"
    ])
