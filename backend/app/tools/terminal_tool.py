import time
from typing import Any, Dict
from app.tools.base_tool import SecurityTool, ToolObservation
from app.sandbox.docker_manager import docker_sandbox

class TerminalTool(SecurityTool):
    name = "terminal_exec"
    description = "Executes an authorized diagnostic or security command inside the isolated sandbox environment."
    category = "general"

    async def execute(self, params: Dict[str, Any], scope_def: Dict[str, Any]) -> ToolObservation:
        command = params.get("command", "")
        target = params.get("target", "sandbox")
        timeout = params.get("timeout", 15)

        # Basic blacklist to prevent container escape attempts
        dangerous = ["rm -rf /", ":(){ :|:& };:", "mkfs", "dd if=/dev/zero"]
        if any(d in command for d in dangerous):
            return ToolObservation(
                tool=self.name,
                target=target,
                status="blocked_by_scope",
                error="Command contains restricted destructive operations."
            )

        start = time.time()
        result = await docker_sandbox.run_tool(command, target, timeout=timeout)
        duration_ms = int((time.time() - start) * 1000)

        return ToolObservation(
            tool=self.name,
            target=target,
            status="success" if result.success else "failed",
            status_code=result.exit_code,
            duration_ms=duration_ms,
            data={
                "command": command,
                "exit_code": result.exit_code,
                "stdout": result.stdout[:2000],
                "stderr": result.stderr[:1000]
            },
            raw_output=result.stdout[:500] if result.stdout else result.stderr[:500]
        )
