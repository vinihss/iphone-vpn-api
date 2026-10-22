#!/usr/bin/env python3
"""Small standard-library REST API for a-Shell / Python."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import shlex
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB_PATH = DATA / "api.sqlite3"
TOKEN_PATH = DATA / "token.txt"
MAX_BODY = 1024 * 1024
MAX_OUTPUT = 64 * 1024
DEFAULT_TIMEOUT = 15

def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH), timeout=10)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            base_url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            path TEXT NOT NULL DEFAULT '/',
            headers_json TEXT NOT NULL DEFAULT '{}',
            timeout INTEGER NOT NULL DEFAULT 10,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            script TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            command TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            resource_id TEXT,
            ok INTEGER NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        """)
    if not TOKEN_PATH.exists():
        token = secrets.token_urlsafe(40)
        TOKEN_PATH.write_text(token + "\n", encoding="utf-8")
        try:
            TOKEN_PATH.chmod(0o600)
        except OSError:
            pass
        print("Credencial inicial criada em:", TOKEN_PATH)
        print("TOKEN:", token)
        print("Guarde o token; não o compartilhe.")

def get_token():
    if not TOKEN_PATH.exists():
        raise RuntimeError("Credencial ausente. Execute: python3 api.py init")
    return TOKEN_PATH.read_text(encoding="utf-8").strip()

def rotate_token():
    DATA.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(40)
    tmp = TOKEN_PATH.with_suffix(".tmp")
    tmp.write_text(token + "\n", encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(TOKEN_PATH)
    print("Nova credencial gerada. A credencial anterior foi invalidada.")
    print("TOKEN:", token)
    print("Armazene-a em local seguro.")

def jsonable(row):
    if row is None:
        return None
    out = dict(row)
    if "headers_json" in out:
        out["headers"] = json.loads(out.pop("headers_json"))
    for key in ("enabled",):
        if key in out:
            out[key] = bool(out[key])
    return out

def audit(action, resource, resource_id=None, ok=True, detail=""):
    try:
        with connect() as db:
            db.execute("INSERT INTO audit(ts,action,resource,resource_id,ok,detail) VALUES(?,?,?,?,?,?)",
                       (int(time.time()), action, resource, str(resource_id) if resource_id is not None else None,
                        int(bool(ok)), str(detail)[:500]))
    except Exception:
        pass

def run_shell(command, timeout=DEFAULT_TIMEOUT):
    """Execute via sh if the host environment provides it."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command/script deve ser uma string não vazia")
    # This is intentionally an explicit shell executor, not a sandbox.
    proc = subprocess.run(
        ["/bin/sh", "-c", command],
        capture_output=True, text=True, timeout=max(1, min(int(timeout), 60))
    )
    stdout = proc.stdout[-MAX_OUTPUT:]
    stderr = proc.stderr[-MAX_OUTPUT:]
    return {"exit_code": proc.returncode, "stdout": stdout, "stderr": stderr}

def call_service(item, body=None):
    base = item["base_url"].rstrip("/")
    path = item.get("path") or "/"
    # Reject credentials in URLs and non-HTTP schemes.
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("base_url deve ser uma URL HTTP(S) válida sem credenciais embutidas")
    url = base + (path if path.startswith("/") else "/" + path)
    headers = item.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("headers deve ser um objeto JSON")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={**headers, "Accept": "application/json"},
                                 method=item.get("method", "GET").upper())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=max(1, min(int(item.get("timeout", 10)), 30))) as response:
            raw = response.read(MAX_OUTPUT)
            return {"status": response.status, "headers": dict(response.headers),
                    "body": raw.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read(MAX_OUTPUT).decode("utf-8", errors="replace")}
    except urllib.error.URLError as exc:
        raise RuntimeError("Falha ao acessar serviço: " + str(exc.reason))

class Handler(BaseHTTPRequestHandler):
    server_version = "iPhoneVPNAPI/1.0"

    def log_message(self, fmt, *args):
        # Keep request logs minimal; do not log auth headers.
        print("%s - %s" % (self.client_address[0], fmt % args))

    def send_json(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Content-Length inválido")
        if length < 0 or length > MAX_BODY:
            raise ValueError("Corpo excede o limite de 1 MiB")
        if length == 0:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            raise ValueError("JSON inválido")
        if not isinstance(value, dict):
            raise ValueError("O corpo JSON deve ser um objeto")
        return value

    def authorized(self):
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer "):
            return False
        try:
            return hmac.compare_digest(supplied[7:].strip(), get_token())
        except Exception:
            return False

    def route(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/api/v1/health" and self.command == "GET":
            return self.send_json(200, {"ok": True, "service": "iphone-vpn-api"})
        if not path.startswith("/api/v1/"):
            return self.send_json(404, {"error": "not_found"})
        if not self.authorized():
            return self.send_json(401, {"error": "unauthorized", "message": "Use Authorization: Bearer <token>"})
        try:
            data = self.read_json() if self.command in ("POST", "PATCH", "PUT") else {}
            parts = path[len("/api/v1/"):].split("/")
            if parts[0] == "service":
                self.handle_crud("services", parts[1:], data, service=True)
            elif parts[0] == "command":
                self.handle_crud("commands", parts[1:], data)
            elif parts[0] == "toolbox":
                self.handle_tools(parts[1:], data)
            else:
                self.send_json(404, {"error": "not_found"})
        except ValueError as exc:
            self.send_json(400, {"error": "bad_request", "message": str(exc)})
        except subprocess.TimeoutExpired:
            self.send_json(408, {"error": "execution_timeout"})
        except Exception as exc:
            self.send_json(500, {"error": "internal_error", "message": str(exc)})

    def handle_crud(self, table, parts, data, service=False):
        singular = "service" if service else "command"
        if not parts or parts == [""]:
            return self.send_json(404, {"error": "not_found"})
        if parts[0] == "add" and self.command == "POST":
            if service:
                name, base_url = data.get("name"), data.get("base_url")
                if not name or not base_url: raise ValueError("name e base_url são obrigatórios")
                method = str(data.get("method", "GET")).upper()
                if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    raise ValueError("method inválido")
                headers = data.get("headers", {})
                if not isinstance(headers, dict): raise ValueError("headers deve ser objeto")
                vals = (name, base_url, method, data.get("path", "/"), json.dumps(headers),
                        int(data.get("timeout", 10)), int(time.time()))
                sql = "INSERT INTO services(name,base_url,method,path,headers_json,timeout,created_at) VALUES(?,?,?,?,?,?,?)"
            else:
                name, script = data.get("name"), data.get("script")
                if not name or not script: raise ValueError("name e script são obrigatórios")
                vals = (name, script, data.get("description", ""), int(bool(data.get("enabled", True))), int(time.time()))
                sql = "INSERT INTO commands(name,script,description,enabled,created_at) VALUES(?,?,?,?,?)"
            with connect() as db:
                cur = db.execute(sql, vals)
                row = db.execute(f"SELECT * FROM {table} WHERE id=?", (cur.lastrowid,)).fetchone()
            audit("create", singular, row["id"])
            return self.send_json(201, jsonable(row))
        if parts[0] == "list" and self.command == "GET":
            with connect() as db:
                rows = db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            return self.send_json(200, [jsonable(r) for r in rows])
        try:
            rid = int(parts[0])
        except ValueError:
            return self.send_json(404, {"error": "not_found"})
        if len(parts) == 2 and parts[1] == "run" and self.command == "POST":
            with connect() as db:
                row = db.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()
            if not row: return self.send_json(404, {"error": "not_found"})
            if service:
                result = call_service(jsonable(row), data)
            else:
                if not row["enabled"]: return self.send_json(409, {"error": "disabled"})
                result = run_shell(row["script"])
            audit("run", singular, rid, True, "exit/status")
            return self.send_json(200, result)
        if len(parts) != 1:
            return self.send_json(404, {"error": "not_found"})
        with connect() as db:
            row = db.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()
            if not row: return self.send_json(404, {"error": "not_found"})
            if self.command == "GET":
                return self.send_json(200, jsonable(row))
            if self.command == "DELETE":
                db.execute(f"DELETE FROM {table} WHERE id=?", (rid,))
                audit("delete", singular, rid)
                return self.send_json(200, {"deleted": True, "id": rid})
            if self.command == "PATCH":
                allowed = ({"name","base_url","method","path","headers","timeout"} if service
                           else {"name","script","description","enabled"})
                changes = {k:v for k,v in data.items() if k in allowed}
                if not changes: raise ValueError("Nenhum campo editável informado")
                if service and "headers" in changes:
                    if not isinstance(changes["headers"], dict): raise ValueError("headers deve ser objeto")
                    changes["headers_json"] = json.dumps(changes.pop("headers"))
                if "enabled" in changes: changes["enabled"] = int(bool(changes["enabled"]))
                cols = ",".join(k+"=?" for k in changes)
                with connect() as db:
                    db.execute(f"UPDATE {table} SET {cols} WHERE id=?", (*changes.values(), rid))
                    updated = db.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()
                audit("update", singular, rid)
                return self.send_json(200, jsonable(updated))
        self.send_json(405, {"error": "method_not_allowed"})

    def handle_tools(self, parts, data):
        if parts == ["exec"] and self.command == "POST":
            command = data.get("command")
            if not isinstance(command, str) or not command.strip():
                raise ValueError("command é obrigatório")
            result = run_shell(command, data.get("timeout", DEFAULT_TIMEOUT))
            audit("exec", "toolbox", None, result["exit_code"] == 0, "one-shot")
            return self.send_json(200, result)
        # CRUD for reusable tools
        if parts == ["add"] and self.command == "POST":
            name, command = data.get("name"), data.get("command")
            if not name or not command: raise ValueError("name e command são obrigatórios")
            with connect() as db:
                cur = db.execute("INSERT INTO tools(name,command,description,enabled,created_at) VALUES(?,?,?,?,?)",
                    (name, command, data.get("description",""), int(bool(data.get("enabled", True))), int(time.time())))
                row = db.execute("SELECT * FROM tools WHERE id=?", (cur.lastrowid,)).fetchone()
            audit("create", "tool", row["id"])
            return self.send_json(201, dict(row))
        if parts == ["list"] and self.command == "GET":
            with connect() as db: rows = db.execute("SELECT * FROM tools ORDER BY id").fetchall()
            return self.send_json(200, [dict(r) for r in rows])
        try: tid = int(parts[0])
        except (ValueError, IndexError): return self.send_json(404, {"error":"not_found"})
        if len(parts) == 2 and parts[1] == "run" and self.command == "POST":
            with connect() as db: row = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
            if not row: return self.send_json(404, {"error":"not_found"})
            if not row["enabled"]: return self.send_json(409, {"error":"disabled"})
            result = run_shell(row["command"], data.get("timeout", DEFAULT_TIMEOUT))
            audit("run", "tool", tid, result["exit_code"] == 0)
            return self.send_json(200, result)
        if len(parts) != 1: return self.send_json(404, {"error":"not_found"})
        with connect() as db: row = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
        if not row: return self.send_json(404, {"error":"not_found"})
        if self.command == "GET": return self.send_json(200, dict(row))
        if self.command == "DELETE":
            with connect() as db: db.execute("DELETE FROM tools WHERE id=?", (tid,))
            audit("delete", "tool", tid)
            return self.send_json(200, {"deleted":True, "id":tid})
        if self.command == "PATCH":
            changes = {k:v for k,v in data.items() if k in {"name","command","description","enabled"}}
            if not changes: raise ValueError("Nenhum campo editável informado")
            if "enabled" in changes: changes["enabled"] = int(bool(changes["enabled"]))
            with connect() as db:
                db.execute("UPDATE tools SET "+",".join(k+"=?" for k in changes)+" WHERE id=?",
                           (*changes.values(), tid))
                updated = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
            audit("update", "tool", tid)
            return self.send_json(200, dict(updated))
        self.send_json(405, {"error":"method_not_allowed"})

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = route

def main():
    parser = argparse.ArgumentParser(description="iPhone VPN REST API")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init")
    sub.add_parser("rotate-token")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.action == "init":
        init_db()
        print("Banco inicializado:", DB_PATH)
    elif args.action == "rotate-token":
        init_db()
        rotate_token()
    elif args.action == "serve":
        init_db()
        get_token()
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        print(f"API escutando em http://{args.host}:{args.port}/api/v1")
        print("Use apenas em rede confiável/Tailscale; Ctrl+C para encerrar.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nEncerrando...")
        finally:
            server.server_close()

if __name__ == "__main__":
    main()
