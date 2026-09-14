import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

class ScopeDefinition:
    def __init__(self, raw_scope: Dict[str, Any]):
        self.allowed_domains: List[str] = raw_scope.get("allowed_domains", [])
        self.allowed_ips: List[str] = raw_scope.get("allowed_ips", [])
        self.allowed_urls: List[str] = raw_scope.get("allowed_urls", [])
        self.allowed_ports: List[int] = raw_scope.get("allowed_ports", [80, 443, 3000, 5000, 8000, 8080, 8443, 8888])
        self.excluded_paths: List[str] = raw_scope.get("excluded_paths", ["/logout", "/delete-account", "/admin/drop-db", "/reset-password"])
        self.excluded_domains: List[str] = raw_scope.get("excluded_domains", ["google.com", "github.com", "facebook.com", "twitter.com"])
        self.allowed_local_paths: List[str] = raw_scope.get("allowed_local_paths", ["./demo-target", "./sandbox", "/app/demo-target", "./"])
        self.include_subdomains: bool = raw_scope.get("include_subdomains", False)

class ScopeManager:
    def __init__(self, scope: ScopeDefinition):
        self.scope = scope

    def is_target_allowed(self, target: str) -> Tuple[bool, str]:
        """
        Validates if a target (URL, hostname, IP, or file path) is strictly inside authorized scope.
        Returns (is_allowed: bool, reason: str)
        """
        if not target or not isinstance(target, str):
            return False, "Target is empty or invalid"

        target = target.strip()

        # Check local file path
        if target.startswith("/") or target.startswith("./") or target.startswith("../") or "\\" in target:
            for allowed_path in self.scope.allowed_local_paths:
                if target.startswith(allowed_path) or allowed_path in target:
                    return True, f"Local path {target} is inside authorized scope ({allowed_path})"
            # Allow common demo target paths
            if "demo-target" in target or "sandbox" in target:
                return True, "Path is part of authorized demo target"
            return False, f"Local path {target} is outside authorized local directories"

        # Check URL or hostname
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path

        if not hostname:
            return False, f"Could not determine hostname from target: {target}"

        # 1. Check excluded paths
        for excl in self.scope.excluded_paths:
            if path and path.startswith(excl):
                return False, f"Path '{path}' is explicitly excluded from scan scope"

        # 2. Check excluded domains
        for excl_dom in self.scope.excluded_domains:
            if hostname == excl_dom or hostname.endswith(f".{excl_dom}"):
                return False, f"Domain '{hostname}' is explicitly in excluded list"

        # 3. Check allowed ports
        if port not in self.scope.allowed_ports:
            return False, f"Port {port} is not in authorized ports list ({self.scope.allowed_ports})"

        # 4. Check localhost / private addresses if allowed
        if hostname in ["localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "demo-target"]:
            return True, f"Target '{hostname}' is an authorized local/container test instance"

        # 5. Check allowed IPs / CIDRs
        try:
            ip_obj = ipaddress.ip_address(hostname)
            for allowed_ip in self.scope.allowed_ips:
                try:
                    if "/" in allowed_ip:
                        if ip_obj in ipaddress.ip_network(allowed_ip, strict=False):
                            return True, f"IP {hostname} matches authorized CIDR {allowed_ip}"
                    else:
                        if ip_obj == ipaddress.ip_address(allowed_ip):
                            return True, f"IP {hostname} matches authorized IP"
                except ValueError:
                    continue
        except ValueError:
            pass # Not an IP address, proceed to domain check

        # 6. Check allowed URLs
        for allowed_url in self.scope.allowed_urls:
            if target.startswith(allowed_url):
                return True, f"Target matches authorized base URL: {allowed_url}"

        # 7. Check allowed domains
        for allowed_dom in self.scope.allowed_domains:
            if hostname == allowed_dom:
                return True, f"Hostname '{hostname}' matches authorized domain"
            if self.scope.include_subdomains and hostname.endswith(f".{allowed_dom}"):
                return True, f"Subdomain '{hostname}' matches wildcard scope for '{allowed_dom}'"

        return False, f"Destination '{hostname}' is not present in authorized target scope"
