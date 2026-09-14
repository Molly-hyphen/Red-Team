import asyncio
import socket
import time
import httpx
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List
from app.tools.base_tool import SecurityTool, ToolObservation

COMMON_DISCOVERY_PATHS = [
    "/", "/api", "/api/v1", "/swagger", "/swagger.json", "/openapi.json", "/docs",
    "/api/docs", "/admin", "/login", "/auth", "/api/auth/token", "/api/user",
    "/api/users", "/api/profile", "/api/products", "/api/products/search",
    "/api/feedback", "/api/logs/view", "/api/webhook/test", "/api/admin/system-stats",
    "/robots.txt", "/sitemap.xml", "/health", "/metrics", "/.env", "/config.json"
]

COMMON_PORTS = [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]

class ReconTool(SecurityTool):
    name = "recon_discovery"
    description = "Performs technology fingerprinting, security headers analysis, port scanning, and route/endpoint discovery on an authorized target."
    category = "recon"

    async def execute(self, params: Dict[str, Any], scope_def: Dict[str, Any]) -> ToolObservation:
        base_url = params.get("url", "")
        scan_ports = params.get("scan_ports", False)
        probe_endpoints = params.get("probe_endpoints", True)

        allowed, reason = self.check_scope(base_url, scope_def)
        if not allowed:
            return ToolObservation(
                tool=self.name,
                target=base_url,
                status="blocked_by_scope",
                error=f"Scope violation: {reason}"
            )

        start = time.time()
        discovered_routes = []
        open_ports = []
        technologies = []
        missing_security_headers = []
        
        parsed = urlparse(base_url if "://" in base_url else f"http://{base_url}")
        host = parsed.hostname or "localhost"

        # 1. Port scanning (if requested)
        if scan_ports and host:
            for port in COMMON_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    res = sock.connect_ex((host, port))
                    if res == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass

        # 2. Tech Fingerprinting & Security Headers
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            try:
                resp = await client.get(base_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                server = headers.get("server", "")
                powered_by = headers.get("x-powered-by", "")

                if "express" in powered_by.lower() or "express" in server.lower():
                    technologies.append("Express.js")
                if "fastapi" in server.lower() or "uvicorn" in server.lower():
                    technologies.append("FastAPI / Uvicorn")
                if "gunicorn" in server.lower() or "django" in server.lower():
                    technologies.append("Python / Django")
                if "nginx" in server.lower():
                    technologies.append("Nginx")
                if "react" in resp.text.lower():
                    technologies.append("React Frontend")
                if "swagger" in resp.text.lower() or "openapi" in resp.text.lower():
                    technologies.append("Swagger/OpenAPI Documentation")

                # Header security evaluation
                required_headers = [
                    "x-frame-options", "x-content-type-options", "strict-transport-security",
                    "content-security-policy", "x-xss-protection"
                ]
                for req_h in required_headers:
                    if req_h not in headers:
                        missing_security_headers.append(req_h)

                discovered_routes.append({
                    "path": parsed.path or "/",
                    "status_code": resp.status_code,
                    "content_type": headers.get("content-type", "")
                })
            except Exception:
                pass

            # 3. Endpoint discovery probing
            if probe_endpoints:
                for path in COMMON_DISCOVERY_PATHS:
                    target_url = urljoin(base_url, path)
                    # Verify scope for each probe
                    probe_allowed, _ = self.check_scope(target_url, scope_def)
                    if not probe_allowed:
                        continue

                    try:
                        probe_resp = await client.get(target_url, timeout=3.0)
                        if probe_resp.status_code in [200, 201, 301, 302, 401, 403, 405]:
                            discovered_routes.append({
                                "path": path,
                                "url": target_url,
                                "status_code": probe_resp.status_code,
                                "content_type": probe_resp.headers.get("content-type", ""),
                                "body_length": len(probe_resp.text or "")
                            })
                    except Exception:
                        pass

        duration_ms = int((time.time() - start) * 1000)
        return ToolObservation(
            tool=self.name,
            target=base_url,
            status="success",
            duration_ms=duration_ms,
            data={
                "base_url": base_url,
                "host": host,
                "open_ports": open_ports,
                "technologies": list(set(technologies)),
                "discovered_endpoints": discovered_routes,
                "missing_security_headers": missing_security_headers,
                "total_routes_found": len(discovered_routes)
            },
            raw_output=f"Recon completed for {base_url}: {len(discovered_routes)} endpoints, {len(technologies)} technologies detected."
        )
