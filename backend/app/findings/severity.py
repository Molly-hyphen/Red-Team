from typing import Dict, Any

SEVERITY_MAPPINGS = {
    "CWE-89": {"severity": "critical", "cvss": 9.8, "owasp": "A03:2021-Injection"},
    "CWE-79": {"severity": "medium", "cvss": 6.1, "owasp": "A03:2021-Injection"},
    "CWE-22": {"severity": "high", "cvss": 7.5, "owasp": "A01:2021-Broken Access Control"},
    "CWE-639": {"severity": "high", "cvss": 8.5, "owasp": "A01:2021-Broken Access Control"},
    "CWE-918": {"severity": "high", "cvss": 8.6, "owasp": "A10:2021-Server-Side Request Forgery"},
    "CWE-798": {"severity": "high", "cvss": 7.5, "owasp": "A07:2021-Identification and Authentication Failures"},
    "CWE-347": {"severity": "high", "cvss": 7.5, "owasp": "A02:2021-Cryptographic Failures"},
    "CWE-306": {"severity": "critical", "cvss": 9.1, "owasp": "A07:2021-Identification and Authentication Failures"},
    "CWE-94": {"severity": "critical", "cvss": 9.8, "owasp": "A03:2021-Injection"}
}

class SeverityCalculator:
    @staticmethod
    def enrich_finding(cwe: str) -> Dict[str, Any]:
        return SEVERITY_MAPPINGS.get(cwe, {
            "severity": "medium",
            "cvss": 5.5,
            "owasp": "A04:2021-Insecure Design"
        })
