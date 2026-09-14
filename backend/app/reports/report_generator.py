import json
from datetime import datetime
from typing import Dict, Any, List
from app.state.scan_state import ScanState

class ReportGenerator:
    @staticmethod
    def generate_json_report(scan_state: ScanState) -> Dict[str, Any]:
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in scan_state.validated_findings:
            sev = f.severity.lower()
            if sev in severity_dist:
                severity_dist[sev] += 1

        return {
            "metadata": {
                "scan_id": scan_state.scan_id,
                "target": scan_state.target,
                "mode": scan_state.mode,
                "generated_at": datetime.utcnow().isoformat(),
                "tool_version": "AegisPentest 1.0.0"
            },
            "summary": {
                "total_findings": len(scan_state.validated_findings),
                "severity_distribution": severity_dist,
                "technologies_discovered": scan_state.technologies,
                "endpoints_audited": len(scan_state.endpoints)
            },
            "findings": [f.model_dump() for f in scan_state.validated_findings],
            "attack_surface": {
                "endpoints": [ep.model_dump() for ep in scan_state.endpoints],
                "technologies": scan_state.technologies
            }
        }

    @staticmethod
    def generate_markdown_report(scan_state: ScanState) -> str:
        rep = ReportGenerator.generate_json_report(scan_state)
        lines = [
            f"# Autonomous AI Penetration Testing Report",
            f"**Target**: `{scan_state.target}`  ",
            f"**Mode**: `{scan_state.mode}`  ",
            f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Scan ID**: `{scan_state.scan_id}`  \n",
            "---",
            "## 1. Executive Summary",
            f"An automated penetration test was conducted against **{scan_state.target}** using autonomous specialized AI agents with pre-flight scope enforcement and empirical proof-of-concept validation.",
            f"- **Total Confirmed Findings**: {len(scan_state.validated_findings)}",
            f"- **Critical**: {rep['summary']['severity_distribution']['critical']} | **High**: {rep['summary']['severity_distribution']['high']} | **Medium**: {rep['summary']['severity_distribution']['medium']} | **Low**: {rep['summary']['severity_distribution']['low']}\n",
            "## 2. Attack Surface Discovered",
            f"- **Technologies**: {', '.join(scan_state.technologies) if scan_state.technologies else 'Standard Web'}",
            f"- **Total Reachable Endpoints**: {len(scan_state.endpoints)}\n"
        ]

        lines.append("## 3. Verified Security Findings\n")
        if not scan_state.validated_findings:
            lines.append("*No high-confidence vulnerabilities were verified during this assessment.*")
        else:
            for idx, f in enumerate(scan_state.validated_findings, 1):
                lines.extend([
                    f"### {idx}. [{f.severity.upper()}] {f.title}",
                    f"- **Vulnerability Class**: {f.vulnerability_type} ({f.cwe})",
                    f"- **OWASP Category**: {f.owasp_category}",
                    f"- **CVSS Score**: {f.cvss_score}",
                    f"- **Affected Asset**: `{f.affected_endpoint or f.affected_asset}`",
                    f"- **Validation Status**: {f.validation_status.upper()} (Validated by: {f.validated_by or 'ValidatorAgent'})\n",
                    f"**Description**:\n{f.description}\n",
                    f"**Impact**:\n{f.impact}\n",
                    "**Reproduction Steps**:"
                ])
                for step in f.reproduction_steps:
                    lines.append(f"1. {step}")
                lines.extend([
                    f"\n**Remediation Guidance**:\n{f.remediation}\n",
                    "---"
                ])

        return "\n".join(lines)

    @staticmethod
    def generate_html_report(scan_state: ScanState) -> str:
        md = ReportGenerator.generate_markdown_report(scan_state)
        # HTML template
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Penetration Testing Report - {scan_state.target}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #f8fafc; }}
    .card {{ background: white; border-radius: 12px; padding: 32px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }}
    h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 12px; text-transform: uppercase; }}
    .badge-critical {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
    .badge-high {{ background: #fff7ed; color: #ea580c; border: 1px solid #ffedd5; }}
    pre {{ background: #0f172a; color: #f8fafc; padding: 14px; border-radius: 8px; overflow-x: auto; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>AegisAI Security Assessment Report</h1>
    <p><strong>Target:</strong> {scan_state.target} | <strong>Mode:</strong> {scan_state.mode}</p>
    <hr/>
    <pre>{md}</pre>
  </div>
</body>
</html>"""
