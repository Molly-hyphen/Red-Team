# Security Skill: Authentication Testing

## Objectives
- Evaluate login endpoints, session cookies, and JWT token structures.
- Detect weak hashing algorithms, predictable tokens, lack of brute force protection, and missing HttpOnly/Secure flags.

## Testing Methodology
1. **Endpoint Discovery**: Locate `/login`, `/auth/token`, `/api/v1/auth`, `/oauth/token`.
2. **JWT Inspection**:
   - Check algorithm header for `none` or `HS256` with weak key.
   - Verify expiration (`exp`), subject (`sub`), and role claims.
3. **Session Cookie Analysis**:
   - Verify `HttpOnly`, `Secure`, `SameSite` flags.
4. **Credential Stuffing / Rate Limiting**:
   - Observe response delays and HTTP 429 status codes under repeated requests.
