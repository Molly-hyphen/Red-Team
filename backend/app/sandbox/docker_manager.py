import shutil
import asyncio
from typing import Optional, Dict, Any
from app.sandbox.sandbox_config import SandboxConfig
from app.sandbox.container import SandboxContainer, ExecutionResult

class DockerSandboxManager:
    """
    Manages isolated containerized sandbox environments for tool execution.
    Gracefully falls back to local isolated process sandbox if Docker daemon is not accessible.
    """
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.has_docker = shutil.which("docker") is not None
        self.local_sandbox = SandboxContainer(self.config)

    async def run_tool(self, command: str, target: str, env_vars: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> ExecutionResult:
        # If Docker is available and configured
        if self.config.mode == "docker" and self.has_docker:
            docker_cmd = (
                f"docker run --rm --network {self.config.network_mode} "
                f"--memory {self.config.memory_limit} --cpus {self.config.cpu_limit} "
                f"{self.config.image_name} {command}"
            )
            return await self.local_sandbox.execute_command(docker_cmd, timeout=timeout)
        else:
            # Local isolated runner
            return await self.local_sandbox.execute_command(command, timeout=timeout)

docker_sandbox = DockerSandboxManager()
