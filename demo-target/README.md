# Authorized Vulnerable Demo Target

This service is a safe, intentionally vulnerable local application designed specifically for validating AegisPentest autonomous agent testing workflows.

## Included Test Scenarios:
1. **SQL Injection (CWE-89)** on `GET /api/products/search?q=`
2. **Broken Object Level Authorization / IDOR (CWE-639)** on `GET /api/user/{id}/profile`
3. **Reflected Cross-Site Scripting / XSS (CWE-79)** on `GET /api/feedback?message=`
4. **Missing Function Level Access Control (CWE-306)** on `GET /api/admin/system-stats`
5. **Insecure Cryptographic Token / JWT (CWE-347)** on `POST /api/auth/token`
6. **Server-Side Request Forgery / SSRF (CWE-918)** on `GET /api/webhook/test?target_url=`
7. **Path Traversal (CWE-22)** on `GET /api/logs/view?file=`
8. **Hardcoded Secrets (CWE-798)** in `config.dev.json`
