import sqlite3
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request

DATABASE_FILE = "demo.db"

def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS products")
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT)")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT, secret_note TEXT)")
    
    c.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", [
        (1, "Enterprise Firewall Gateway", 1299.99, "Next-gen network filtering appliance"),
        (2, "Hardware Security Key", 49.99, "FIDO2 U2F authentication token"),
        (3, "Encrypted Storage Drive", 199.99, "Hardware AES-256 encrypted flash disk")
    ])
    
    c.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", [
        (1, "alice_admin", "alice@enterprise-corp.internal", "admin", "Admin master password recovery token: SEC-ADMIN-9921"),
        (2, "bob_user", "bob@enterprise-corp.internal", "user", "Standard user financial record SSN: 000-12-3456"),
        (3, "charlie_guest", "charlie@enterprise-corp.internal", "guest", "Guest temporary pin: 1234")
    ])
    conn.commit()
    conn.close()

class VulnerableHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _send_html(self, html_content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # 1. Root info
        if path == "/" or path == "/health":
            self._send_json({
                "app": "Aegis Authorized Vulnerable Demo Target",
                "version": "1.0-vulnerable",
                "endpoints": [
                    "/api/products/search?q=",
                    "/api/user/{id}/profile",
                    "/api/feedback?message=",
                    "/api/admin/system-stats",
                    "/api/webhook/test?target_url=",
                    "/api/logs/view?file=",
                    "/api/auth/token",
                    "/openapi.json"
                ]
            })

        # 2. VULNERABILITY: SQL Injection in Products Search
        elif path == "/api/products/search":
            q = qs.get("q", [""])[0]
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            try:
                # Intentional flaw: raw string concatenation into query
                query_str = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%'"
                cursor.execute(query_str)
                rows = cursor.fetchall()
                results = [{"id": r[0], "name": r[1], "price": r[2], "description": r[3]} for r in rows]
                self._send_json({"query": query_str, "results": results})
            except Exception as e:
                self._send_json({"error": f"sqlite3.OperationalError: {str(e)}", "query": query_str}, status=500)
            finally:
                conn.close()

        # 3. VULNERABILITY: IDOR on User Profile
        elif path.startswith("/api/user/") and path.endswith("/profile"):
            user_id = path.split("/")[3]
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, role, secret_note FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                self._send_json({
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "role": row[3],
                    "private_data": row[4]
                })
            else:
                self._send_json({"error": "User not found"}, status=404)

        # 4. VULNERABILITY: Reflected XSS
        elif path == "/api/feedback":
            message = qs.get("message", ["Hello"])[0]
            # Intentional flaw: unescaped HTML reflection
            html_resp = f"<html><body><h2>User Feedback Submitted:</h2><p>{message}</p></body></html>"
            self._send_html(html_resp)

        # 5. VULNERABILITY: Missing Access Control on Administrative Endpoint
        elif path == "/api/admin/system-stats":
            self._send_json({
                "system": "Linux 5.15-enterprise-cloud",
                "admin_authenticated": False,
                "note": "UNPROTECTED ADMIN ENDPOINT - Leaking internal memory and telemetry",
                "active_db_connections": 14,
                "master_key_hash": "e99a18c428cb38d5f260853678922e03"
            })

        # 6. VULNERABILITY: SSRF
        elif path == "/api/webhook/test":
            target_url = qs.get("target_url", ["http://127.0.0.1:8000"])[0]
            try:
                req = urllib.request.Request(target_url, headers={'User-Agent': 'Aegis-Webhook-Tester/1.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = resp.read().decode('utf-8', errors='replace')
                    self._send_json({"status": "dispatched", "target_url": target_url, "reflected_response": data[:300]})
            except Exception as e:
                self._send_json({"status": "failed", "target_url": target_url, "error": str(e)}, status=502)

        # 7. VULNERABILITY: Path Traversal
        elif path == "/api/logs/view":
            filename = qs.get("file", ["app.log"])[0]
            try:
                with open(filename, "r") as f:
                    content = f.read()
                self._send_json({"file": filename, "content": content[:1000]})
            except Exception as e:
                self._send_json({"error": f"Cannot read file: {e}"}, status=400)

        # 8. OpenAPI Specification
        elif path == "/openapi.json":
            self._send_json({
                "openapi": "3.0.0",
                "info": {"title": "Authorized Vulnerable Demo Target", "version": "1.0.0"},
                "paths": {
                    "/api/products/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
                    "/api/user/{id}/profile": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
                    "/api/feedback": {"get": {"parameters": [{"name": "message", "in": "query"}]}},
                    "/api/admin/system-stats": {"get": {}},
                    "/api/webhook/test": {"get": {"parameters": [{"name": "target_url", "in": "query"}]}}
                }
            })

        else:
            self._send_json({"error": "Endpoint not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/token":
            # Insecure JWT token issuance with static weak secret
            self._send_json({
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIEFkbWluIiwicm9sZSI6ImFkbWluIn0.weak_signature_key_12345",
                "token_type": "bearer",
                "expires_in": 86400
            })
        else:
            self._send_json({"error": "Method not allowed"}, status=405)

def run(port=8080):
    init_db()
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, VulnerableHandler)
    print(f"[*] Authorized Vulnerable Demo Target active on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run(8080)
