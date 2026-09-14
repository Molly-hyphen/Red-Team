# Security Skill: SQL & Command Injection

## Objectives
- Detect unsanitized user inputs interpolated into database queries or shell execution strings.

## Testing Methodology
1. Inject Boolean payloads: `' OR '1'='1`, `admin'--`, `' OR 1=1 #`.
2. Observe error messages: Look for SQLite, Postgres, MySQL error signatures.
3. Check union-based extraction: `' UNION SELECT 1, sqlite_version(), 3--`.
4. Validate in White-Box: Trace source variables to `db.query()`, `cursor.execute()`, or `f"SELECT ... {user_input}"`.
