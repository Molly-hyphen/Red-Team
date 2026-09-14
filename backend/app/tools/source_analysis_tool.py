import os
import re
import time
from typing import Any, Dict, List
from app.tools.base_tool import SecurityTool, ToolObservation

PATTERNS = [
    {
        "id": "HARDCODED_SECRET",
        "title": "Hardcoded Secret / API Key / JWT Secret",
        "regex": r"""(?i)(api[_-]?key|secret[_-]?key|jwt[_-]?secret|password|auth[_-]?token)\s*=\s*['"][a-zA-Z0-9_\-\.]{8,}['"]""",
        "severity": "high",
        "cwe": "CWE-798"
    },
    {
        "id": "RAW_SQL_CONCAT",
        "title": "Unsafe SQL String Concatenation / SQL Injection Sink",
        "regex": r"""(?i)(cursor\.execute|db\.query|sequelize\.query|SELECT\s+.*FROM)\s*\(\s*f?["'].*?(\+|%|\{|\$).*?["']""",
        "severity": "critical",
        "cwe": "CWE-89"
    },
    {
        "id": "UNSAFE_EVAL_EXEC",
        "title": "Dangerous Dynamic Code Execution (eval/exec)",
        "regex": r"""\b(eval|exec|os\.system|child_process\.exec)\s*\(""",
        "severity": "critical",
        "cwe": "CWE-94"
    },
    {
        "id": "PATH_TRAVERSAL_SINK",
        "title": "Unsanitized File Read / Path Traversal Sink",
        "regex": r"""(open\s*\(\s*f?["'].*?(\+|\{)|fs\.readFileSync\s*\()""",
        "severity": "high",
        "cwe": "CWE-22"
    },
    {
        "id": "INSECURE_JWT_VERIFICATION",
        "title": "Insecure JWT Verification / Missing Secret Enforcement",
        "regex": r"""(jwt\.decode\s*\(.*?verify=False|algorithms\s*=\s*\[['"]none['"]\])""",
        "severity": "high",
        "cwe": "CWE-347"
    }
]

class SourceAnalysisTool(SecurityTool):
    name = "source_code_sast"
    description = "Performs Static Application Security Testing (SAST) on local code directories to detect SQL injections, secrets, command execution, path traversal, and auth flaws."
    category = "source"

    async def execute(self, params: Dict[str, Any], scope_def: Dict[str, Any]) -> ToolObservation:
        target_dir = params.get("path", "./demo-target")
        max_files = int(params.get("max_files", 100))

        allowed, reason = self.check_scope(target_dir, scope_def)
        if not allowed:
            return ToolObservation(
                tool=self.name,
                target=target_dir,
                status="blocked_by_scope",
                error=f"Scope violation: {reason}"
            )

        start = time.time()
        findings = []
        files_scanned = 0

        if not os.path.exists(target_dir):
            return ToolObservation(
                tool=self.name,
                target=target_dir,
                status="failed",
                error=f"Directory or file does not exist: {target_dir}"
            )

        for root, dirs, files in os.walk(target_dir):
            # Skip node_modules, .git, venv
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", "__pycache__", "dist", ".next"]]
            for file in files:
                if files_scanned >= max_files:
                    break
                if not file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".env", ".yaml", ".yml")):
                    continue

                filepath = os.path.join(root, file)
                files_scanned += 1

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    for idx, line in enumerate(lines, 1):
                        for pattern in PATTERNS:
                            if re.search(pattern["regex"], line):
                                findings.append({
                                    "pattern_id": pattern["id"],
                                    "title": pattern["title"],
                                    "severity": pattern["severity"],
                                    "cwe": pattern["cwe"],
                                    "file": filepath,
                                    "line_number": idx,
                                    "code_snippet": line.strip()[:200]
                                })
                except Exception:
                    pass

        duration_ms = int((time.time() - start) * 1000)
        return ToolObservation(
            tool=self.name,
            target=target_dir,
            status="success",
            duration_ms=duration_ms,
            data={
                "target_directory": target_dir,
                "files_scanned": files_scanned,
                "issues_found": len(findings),
                "findings": findings
            },
            raw_output=f"SAST analysis scanned {files_scanned} files in {target_dir}. Found {len(findings)} potential code risks."
        )
