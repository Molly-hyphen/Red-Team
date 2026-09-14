# Security Skill: Broken Object Level Authorization (BOLA / IDOR)

## Objectives
- Detect Insecure Direct Object References where user A accesses records of user B by manipulating record IDs.
- Verify role boundaries between ordinary users and administrative interfaces.

## Testing Methodology
1. Identify object identifiers in URLs (e.g., `/api/user/{id}/profile`, `/api/orders/{order_id}`).
2. Test sequential integers (`1`, `2`, `3`) or alternate GUIDs across authenticated tokens.
3. Compare responses: If HTTP 200 and unredacted confidential data is returned without authorization match, flag as BOLA/IDOR.
4. Test administrative routes without headers (`/api/admin/system-stats`).
