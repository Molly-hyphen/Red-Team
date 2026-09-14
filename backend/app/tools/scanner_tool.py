import time
import httpx
from typing import Any, Dict, List
from app.tools.base_tool import SecurityTool, ToolObservation

class ScannerTool(SecurityTool):
    name = "vulnerability_fuzzer"
    description = "Executes structured security payload probes against parameters (SQL Injection, XSS, SSRF, IDOR, Path Traversal) and analyzes server response anomalies."
    category = "scanning"

    async def execute(self, params: Dict[str, Any], scope_def: Dict[str, Any]) -> ToolObservation:
        url = params.get("url", "")
        method = params.get("method", "GET").upper()
        target_param = params.get("parameter", "")
        test_type = params.get("test_type", "sqli") # sqli, xss, ssrf, path_traversal, idor, auth_bypass
        custom_payload = params.get("custom_payload")
        headers = params.get("headers", {})

        allowed, reason = self.check_scope(url, scope_def)
        if not allowed:
            return ToolObservation(
                tool=self.name,
                target=url,
                status="blocked_by_scope",
                error=f"Scope violation: {reason}"
            )

        start = time.time()
        results = []

        # Determine payloads based on test type
        payloads = []
        if custom_payload:
            payloads.append(custom_payload)
        elif test_type == "sqli":
            payloads = ["' OR '1'='1", "1' ORDER BY 1--+", "' UNION SELECT NULL, version(), NULL--", "admin'--"]
        elif test_type == "xss":
            payloads = ['<script>alert("xss")</script>', '"><img src=x onerror=alert(1)>', '"><svg/onload=alert(1)>']
        elif test_type == "path_traversal":
            payloads = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "../../../../app/config.json"]
        elif test_type == "ssrf":
            payloads = ["http://127.0.0.1:8000/api/admin", "http://169.254.169.254/latest/meta-data/"]
        elif test_type == "idor":
            payloads = ["1", "2", "3", "admin", "9999"]
        else:
            payloads = ["test"]

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            for payload in payloads:
                try:
                    req_params = {}
                    req_json = {}
                    if method == "GET":
                        req_params = {target_param: payload} if target_param else {}
                    else:
                        req_json = {target_param: payload} if target_param else {}

                    resp = await client.request(
                        method=method,
                        url=url,
                        params=req_params,
                        json=req_json if method != "GET" else None,
                        headers=headers
                    )

                    body = resp.text
                    anomaly = False
                    anomaly_reason = ""

                    # Detection heuristics
                    if test_type == "sqli" and any(err in body.lower() for err in ["syntax error", "sqlite3.operationalerror", "mysql", "postgresql", "sql state", "unclosed quotation mark"]):
                        anomaly = True
                        anomaly_reason = "Database syntax/error trace leaked in response body."
                    elif test_type == "xss" and payload in body:
                        anomaly = True
                        anomaly_reason = "Unescaped raw XSS payload reflected directly in HTML/JSON response."
                    elif test_type == "path_traversal" and any(indicator in body for indicator in ["root:x:0:0", "[extensions]", "database_url", "secret_key"]):
                        anomaly = True
                        anomaly_reason = "System file or internal configuration contents leaked."
                    elif test_type == "idor" and resp.status_code == 200 and len(body) > 10:
                        anomaly = True
                        anomaly_reason = "Object data returned without ownership verification."
                    elif test_type == "ssrf" and (resp.status_code == 200 or "metadata" in body.lower()):
                        anomaly = True
                        anomaly_reason = "Server reached internal endpoint / reflected internal response."

                    results.append({
                        "payload": payload,
                        "status_code": resp.status_code,
                        "anomaly_detected": anomaly,
                        "anomaly_reason": anomaly_reason,
                        "response_preview": body[:500],
                        "headers": dict(resp.headers)
                    })
                except Exception as e:
                    results.append({
                        "payload": payload,
                        "error": str(e),
                        "anomaly_detected": False
                    })

        duration_ms = int((time.time() - start) * 1000)
        has_anomalies = any(r.get("anomaly_detected") for r in results)

        return ToolObservation(
            tool=self.name,
            target=url,
            status="success",
            duration_ms=duration_ms,
            data={
                "url": url,
                "parameter": target_param,
                "test_type": test_type,
                "probes_executed": len(results),
                "has_anomalies": has_anomalies,
                "results": results
            },
            raw_output=f"Fuzzer tested {len(results)} payloads on '{target_param}'. Anomalies detected: {has_anomalies}"
        )
