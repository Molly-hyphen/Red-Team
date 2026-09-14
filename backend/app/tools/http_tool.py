import time
import httpx
from typing import Any, Dict, Optional
from app.tools.base_tool import SecurityTool, ToolObservation

class HTTPTool(SecurityTool):
    name = "http_request"
    description = "Executes an HTTP/HTTPS request (GET, POST, PUT, DELETE, PATCH, OPTIONS) and records full headers, status, response body, latency, and cookies."
    category = "web"

    async def execute(self, params: Dict[str, Any], scope_def: Dict[str, Any]) -> ToolObservation:
        url = params.get("url", "")
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        data = params.get("data")
        json_data = params.get("json")
        timeout = float(params.get("timeout", 15.0))
        allow_redirects = params.get("allow_redirects", True)

        # 1. Mandatory Scope Enforcement
        allowed, reason = self.check_scope(url, scope_def)
        if not allowed:
            return ToolObservation(
                tool=self.name,
                target=url,
                status="blocked_by_scope",
                error=f"Scope violation: {reason}"
            )

        start = time.time()
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=allow_redirects) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    json=json_data,
                    timeout=timeout
                )
                
                duration_ms = int((time.time() - start) * 1000)
                
                # Format response body preview safely
                body_text = response.text[:4000] if response.text else ""
                
                return ToolObservation(
                    tool=self.name,
                    target=url,
                    status="success",
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    data={
                        "method": method,
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "cookies": dict(response.cookies),
                        "body_preview": body_text,
                        "body_length": len(response.text or ""),
                        "content_type": response.headers.get("content-type", "")
                    },
                    raw_output=f"{method} {url} -> HTTP {response.status_code} ({duration_ms}ms)"
                )
        except httpx.RequestError as e:
            duration_ms = int((time.time() - start) * 1000)
            return ToolObservation(
                tool=self.name,
                target=url,
                status="failed",
                duration_ms=duration_ms,
                error=f"Network request failed: {str(e)}"
            )
        except Exception as e:
            duration_ms = int((time.time() - start) * 1000)
            return ToolObservation(
                tool=self.name,
                target=url,
                status="failed",
                duration_ms=duration_ms,
                error=f"Unexpected error: {str(e)}"
            )
