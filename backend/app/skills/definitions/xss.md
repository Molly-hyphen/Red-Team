# Security Skill: Cross-Site Scripting (XSS)

## Objectives
- Detect Reflected and Stored Cross-Site Scripting vulnerabilities.

## Testing Methodology
1. Inject benign script tags: `<script>alert("xss")</script>`, `"><img src=x onerror=alert(1)>`.
2. Inspect server response: Check if `<` and `>` are reflected unencoded in HTML context with `text/html` Content-Type.
3. Validate DOM sinks and CSP header defenses.
