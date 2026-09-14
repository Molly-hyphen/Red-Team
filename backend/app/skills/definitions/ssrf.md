# Security Skill: Server-Side Request Forgery (SSRF)

## Objectives
- Identify endpoints accepting arbitrary external URLs (webhooks, avatar importers, proxy relays).

## Testing Methodology
1. Inject loopback IPs: `http://127.0.0.1:8000/api/admin`, `http://localhost:3000`.
2. Inject cloud metadata IPs: `http://169.254.169.254/latest/meta-data/`.
3. Analyze status code and response body to confirm server-side HTTP request dispatch.
