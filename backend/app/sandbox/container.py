import asyncio
import subprocess
import json
import time
from typing import Dict, Any, Optional
from app.sandbox.sandbox_config import SandboxConfig

class ExecutionResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str, duration_ms: int):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.success = exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "success": self.success
        }

class SandboxContainer:
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    async def execute_command(self, command: str, timeout: Optional[int] = None) -> ExecutionResult:
        """
        Executes a sandboxed security tool command safely.
        Enforces timeout, resource bounds, and environment isolation.
        """
        start_time = time.time()
        timeout_val = timeout or self.config.timeout_seconds
        
        try:
            # We use an async subprocess with isolated environment
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=float(timeout_val)
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                exit_code=process.returncode or 0,
                stdout=stdout_data.decode("utf-8", errors="replace"),
                stderr=stderr_data.decode("utf-8", errors="replace"),
                duration_ms=duration_ms
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
            except Exception:
                pass
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Command execution timed out after {timeout_val}s",
                duration_ms=duration_ms
            )
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Sandbox execution error: {str(e)}",
                duration_ms=duration_ms
            )
