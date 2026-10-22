#!/usr/bin/env python3
"""iPhone VPN API: utilitários de CLI para a-Shell + servidor REST opcional.

Somente biblioteca padrão. O modo padrão é o CLI (sobe, executa e encerra),
porque o iOS encerra processos em segundo plano. O servidor HTTP continua
disponível sob `serve` para uso em VPS/tailnet.
"""
import argparse
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
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

# Códigos de saída do modo CLI.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2       # uso inválido (argparse)
EXIT_DISABLED = 3    # registro existe, mas está desativado
EXIT_TIMEOUT = 124   # tempo limite de execução (convenção do coreutils)
EXIT_INTERRUPTED = 130  # interrompido pelo usuário (128 + SIGINT)

SERVICE_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

def die(message, code=EXIT_ERROR):
    """Encerra com uma mensagem de erro em stderr (a saída útil fica em stdout)."""
    print("Erro:", message, file=sys.stderr)
    sys.exit(code)

def print_json(payload):
    print(json.dumps(payload, ensure_ascii=False, indent=2))

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

# ---------------------------------------------------------------------------
# Regras de negócio compartilhadas entre o modo CLI e o servidor HTTP.
# ---------------------------------------------------------------------------

def _insert(table, sql, vals, name):
    """Insere e devolve a linha criada; nome duplicado vira ValueError."""
    try:
        with connect() as db:
            cur = db.execute(sql, vals)
            row = db.execute(f"SELECT * FROM {table} WHERE id=?", (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        raise ValueError(f"Já existe um registro chamado '{name}'")
    return row

def validate_base_url(base_url):
    """Mesma regra usada na execução: só HTTP(S) e sem credenciais na URL."""
    parsed = urlparse(str(base_url).rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("base_url deve ser uma URL HTTP(S) válida sem credenciais embutidas")
    return base_url

def create_service(data):
    name, base_url = data.get("name"), data.get("base_url")
    if not name or not base_url:
        raise ValueError("name e base_url são obrigatórios")
    validate_base_url(base_url)
    method = str(data.get("method", "GET")).upper()
    if method not in SERVICE_METHODS:
        raise ValueError("method inválido")
    headers = data.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("headers deve ser objeto")
    timeout = int(data.get("timeout", 10))
    if timeout < 1:
        raise ValueError("timeout deve ser >= 1")
    vals = (name, base_url, method, data.get("path", "/"), json.dumps(headers), timeout, int(time.time()))
    sql = "INSERT INTO services(name,base_url,method,path,headers_json,timeout,created_at) VALUES(?,?,?,?,?,?,?)"
    return _insert("services", sql, vals, name)

def create_command(data):
    name, script = data.get("name"), data.get("script")
    if not name or not script:
        raise ValueError("name e script são obrigatórios")
    vals = (name, script, data.get("description", ""), int(bool(data.get("enabled", True))), int(time.time()))
    sql = "INSERT INTO commands(name,script,description,enabled,created_at) VALUES(?,?,?,?,?)"
    return _insert("commands", sql, vals, name)

def create_tool(data):
    name, command = data.get("name"), data.get("command")
    if not name or not command:
        raise ValueError("name e command são obrigatórios")
    vals = (name, command, data.get("description", ""), int(bool(data.get("enabled", True))), int(time.time()))
    sql = "INSERT INTO tools(name,command,description,enabled,created_at) VALUES(?,?,?,?,?)"
    return _insert("tools", sql, vals, name)

def allowed_fields(kind):
    if kind == "service":
        return {"name", "base_url", "method", "path", "headers", "timeout"}
    if kind == "toolbox":
        return {"name", "command", "description", "enabled"}
    return {"name", "script", "description", "enabled"}

def normalize_changes(kind, data):
    """Filtra e normaliza campos editáveis (PATCH do HTTP / update do CLI)."""
    changes = {k: v for k, v in data.items() if k in allowed_fields(kind)}
    if not changes:
        raise ValueError("Nenhum campo editável informado")
    if kind == "service":
        if "base_url" in changes:
            validate_base_url(changes["base_url"])
        if "method" in changes:
            method = str(changes["method"]).upper()
            if method not in SERVICE_METHODS:
                raise ValueError("method inválido")
            changes["method"] = method
        if "timeout" in changes:
            changes["timeout"] = int(changes["timeout"])
            if changes["timeout"] < 1:
                raise ValueError("timeout deve ser >= 1")
        if "headers" in changes:
            if not isinstance(changes["headers"], dict):
                raise ValueError("headers deve ser objeto")
            changes["headers_json"] = json.dumps(changes.pop("headers"))
    if "enabled" in changes:
        changes["enabled"] = int(bool(changes["enabled"]))
    return changes

def update_row(table, rid, changes):
    cols = ",".join(k + "=?" for k in changes)
    with connect() as db:
        db.execute(f"UPDATE {table} SET {cols} WHERE id=?", (*changes.values(), rid))
        return db.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()

def shell_binary():
    """Shell usado nos scripts. No a-Shell o `sh` pode não estar em /bin/sh.

    Defina IPHONE_VPN_API_SHELL para forçar um caminho/binário específico.
    """
    override = os.environ.get("IPHONE_VPN_API_SHELL", "").strip()
    if override:
        return override
    return shutil.which("sh") or "/bin/sh"

def run_shell(command, timeout=DEFAULT_TIMEOUT):
    """Execute via sh if the host environment provides it."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command/script deve ser uma string não vazia")
    # This is intentionally an explicit shell executor, not a sandbox.
    proc = subprocess.run(
        [shell_binary(), "-c", command],
        capture_output=True, text=True, timeout=max(1, min(int(timeout), 60))
    )
    stdout = proc.stdout[-MAX_OUTPUT:]
    stderr = proc.stderr[-MAX_OUTPUT:]
    return {"exit_code": proc.returncode, "stdout": stdout, "stderr": stderr}

def run_shell_stream(command, timeout=DEFAULT_TIMEOUT):
    """Executa deixando a saída fluir direto para o terminal (modo CLI).

    Devolve o código de saída: o do script, 124 em timeout ou 130 em Ctrl+C.
    Sinais viram 128+sinal, como faz o shell.
    """
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command/script deve ser uma string não vazia")
    limit = max(1, min(int(timeout), 60))
    try:
        proc = subprocess.Popen([shell_binary(), "-c", command])
    except OSError as exc:
        raise RuntimeError(f"shell indisponível ({shell_binary()}): {exc}")
    try:
        code = proc.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        print(f"Tempo limite de {limit}s atingido; processo encerrado.", file=sys.stderr)
        return EXIT_TIMEOUT
    except KeyboardInterrupt:
        proc.kill()
        proc.wait()
        print("\nInterrompido.", file=sys.stderr)
        return EXIT_INTERRUPTED
    return code if code >= 0 else 128 + (-code)

def call_service(item, body=None):
    base = item["base_url"].rstrip("/")
    path = item.get("path") or "/"
    # Reject credentials in URLs and non-HTTP schemes.
    validate_base_url(base)
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
            row = create_service(data) if service else create_command(data)
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
                changes = normalize_changes("service" if service else "command", data)
                updated = update_row(table, rid, changes)
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
            row = create_tool(data)
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
            changes = normalize_changes("toolbox", data)
            updated = update_row("tools", tid, changes)
            audit("update", "tool", tid)
            return self.send_json(200, dict(updated))
        self.send_json(405, {"error":"method_not_allowed"})

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = route

# ---------------------------------------------------------------------------
# Modo CLI (padrão): sobe, executa e encerra — não depende de processo vivo.
# ---------------------------------------------------------------------------

KINDS = {
    "command": {"table": "commands", "label": "Comando", "audit": "command"},
    "service": {"table": "services", "label": "Service", "audit": "service"},
    "toolbox": {"table": "tools", "label": "Tool", "audit": "tool"},
}
CREATORS = {"command": create_command, "service": create_service, "toolbox": create_tool}

def table_of(kind):
    return KINDS[kind]["table"]

def fetch_row(kind, rid):
    with connect() as db:
        return db.execute(f"SELECT * FROM {table_of(kind)} WHERE id=?", (rid,)).fetchone()

def require_row(kind, rid):
    row = fetch_row(kind, rid)
    if row is None:
        die(f"{KINDS[kind]['label']} ID {rid} não encontrado.")
    return row

def cli_init():
    init_db()
    print("Banco de dados inicializado com sucesso.")
    print("Banco:", DB_PATH)
    print("Token:", TOKEN_PATH)

def cli_exec(script, timeout):
    """Executa no shell com saída ao vivo e devolve o código de saída."""
    try:
        return run_shell_stream(script, timeout)
    except (RuntimeError, ValueError) as exc:
        die(str(exc))

def cli_run_command(rid, timeout=DEFAULT_TIMEOUT):
    """POST /api/v1/command/{id}/run em forma de CLI."""
    item = jsonable(require_row("command", rid))
    if not item["enabled"]:
        die(f"Comando '{item['name']}' está desativado.", EXIT_DISABLED)
    print(f"Executando comando '{item['name']}' (id={item['id']}): {item['script']}", file=sys.stderr)
    sys.exit(cli_exec(item["script"], timeout))

def cli_toolbox_exec(command, timeout=DEFAULT_TIMEOUT):
    """POST /api/v1/toolbox/exec em forma de CLI."""
    if not isinstance(command, str) or not command.strip():
        die("command não pode ser vazio")
    print(f"Executando comando: {command}", file=sys.stderr)
    sys.exit(cli_exec(command, timeout))

def parse_headers(pairs):
    """Converte ['Chave: valor', 'Outra=1'] em dict de headers."""
    headers = {}
    for pair in pairs or []:
        sep = ":" if ":" in pair else ("=" if "=" in pair else None)
        if sep is None:
            die(f"Header inválido (use 'Chave: valor'): {pair}")
        key, value = pair.split(sep, 1)
        if not key.strip():
            die(f"Header sem nome: {pair}")
        headers[key.strip()] = value.strip()
    return headers

def _flat(text, limit=60):
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"

def _list_headers(kind):
    if kind == "service":
        return ["ID", "NOME", "MÉTODO", "URL", "TIMEOUT"]
    if kind == "toolbox":
        return ["ID", "NOME", "ATIVO", "COMANDO"]
    return ["ID", "NOME", "ATIVO", "SCRIPT"]

def _list_columns(kind, item):
    if kind == "service":
        path = item["path"] or "/"
        if not path.startswith("/"):
            path = "/" + path
        return [item["id"], item["name"], item["method"], item["base_url"].rstrip("/") + path, item["timeout"]]
    if kind == "toolbox":
        return [item["id"], item["name"], "sim" if item["enabled"] else "não", _flat(item["command"])]
    return [item["id"], item["name"], "sim" if item["enabled"] else "não", _flat(item["script"])]

def cli_list(kind, as_json=False):
    with connect() as db:
        rows = [jsonable(r) for r in db.execute(f"SELECT * FROM {table_of(kind)} ORDER BY id").fetchall()]
    if as_json:
        print_json(rows)
        return
    if not rows:
        print("(nenhum registro)")
        return
    headers = _list_headers(kind)
    data = [_list_columns(kind, item) for item in rows]
    widths = []
    for i, head in enumerate(headers):
        width = len(head)
        for row in data:
            width = max(width, len(str(row[i])))
        widths.append(width)
    print("  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in data:
        print("  ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers))))

def cli_show(kind, rid):
    print_json(jsonable(require_row(kind, rid)))

def cli_delete(kind, rid):
    require_row(kind, rid)
    with connect() as db:
        db.execute(f"DELETE FROM {table_of(kind)} WHERE id=?", (rid,))
    audit("delete", KINDS[kind]["audit"], rid)
    print(f"{KINDS[kind]['label']} ID {rid} removido.")

def cli_add(kind, data):
    try:
        row = CREATORS[kind](data)
    except ValueError as exc:
        die(str(exc))
    audit("create", KINDS[kind]["audit"], row["id"])
    print_json(jsonable(row))

def cli_update(kind, rid, changes):
    require_row(kind, rid)
    try:
        normalized = normalize_changes(kind, changes)
    except ValueError as exc:
        die(str(exc))
    row = update_row(table_of(kind), rid, normalized)
    audit("update", KINDS[kind]["audit"], rid)
    print_json(jsonable(row))

def cli_set_enabled(kind, rid, enabled):
    require_row(kind, rid)
    row = update_row(table_of(kind), rid, {"enabled": int(bool(enabled))})
    audit("update", KINDS[kind]["audit"], rid)
    print(f"{KINDS[kind]['label']} ID {row['id']} {'ativado' if enabled else 'desativado'}.")

def cli_run(kind, rid, body=None, timeout=DEFAULT_TIMEOUT):
    if kind == "command":
        cli_run_command(rid, timeout)          # encerra o processo aqui
    if kind == "toolbox":
        item = jsonable(require_row("toolbox", rid))
        if not item["enabled"]:
            die(f"Tool '{item['name']}' está desativada.", EXIT_DISABLED)
        print(f"Executando tool '{item['name']}' (id={item['id']}): {item['command']}", file=sys.stderr)
        sys.exit(cli_exec(item["command"], timeout))
    payload = None
    if body:
        try:
            payload = json.loads(body)
        except ValueError:
            die("body deve ser um JSON válido")
    item = jsonable(require_row("service", rid))
    try:
        result = call_service(item, payload)
    except (ValueError, RuntimeError) as exc:
        die(str(exc))
    print(f"HTTP {result['status']}", file=sys.stderr)
    out = result.get("body") or ""
    if out:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    sys.exit(EXIT_OK if result["status"] < 400 else EXIT_ERROR)

# ---------------------------------------------------------------------------
# Linha de comando (argparse)
# ---------------------------------------------------------------------------

def _enabled_flag(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--enabled", dest="enabled", action="store_true", help="Ativa o registro")
    group.add_argument("--disabled", dest="enabled", action="store_false", help="Desativa o registro")
    parser.set_defaults(enabled=None)

def add_kind_parsers(sub, kind, help_text):
    parser = sub.add_parser(kind, help=help_text, description=help_text)
    actions = parser.add_subparsers(dest="item_action", required=True)

    listing = actions.add_parser("list", help="Lista os registros")
    listing.add_argument("--json", action="store_true", help="Saída em JSON")

    show = actions.add_parser("show", help="Mostra um registro em JSON")
    show.add_argument("id", type=int)

    delete = actions.add_parser("delete", help="Remove um registro")
    delete.add_argument("id", type=int)

    add = actions.add_parser("add", help="Cria um registro")
    run = actions.add_parser("run", help="Executa um registro")
    upd = actions.add_parser("update", help="Altera campos de um registro")
    for target in (run, upd):
        target.add_argument("id", type=int)

    if kind != "service":
        # services não têm coluna enabled; só command e toolbox têm.
        for name, text in (("enable", "Ativa o registro"), ("disable", "Desativa o registro")):
            toggle = actions.add_parser(name, help=text)
            toggle.add_argument("id", type=int)

    if kind == "service":
        run.add_argument("body", nargs="?", help="JSON do corpo da requisição")
        add.add_argument("name")
        add.add_argument("base_url", help="Ex.: http://100.64.0.10:8080")
        add.add_argument("--method", default="GET", type=str.upper, choices=list(SERVICE_METHODS))
        add.add_argument("--path", default="/")
        add.add_argument("--header", action="append", default=[], metavar="CHAVE: VALOR",
                         help="Repetível")
        add.add_argument("--timeout", type=int, default=10, help="Timeout em segundos")
        upd.add_argument("--name")
        upd.add_argument("--base-url")
        upd.add_argument("--method", type=str.upper, choices=list(SERVICE_METHODS))
        upd.add_argument("--path")
        upd.add_argument("--header", action="append", default=[], metavar="CHAVE: VALOR",
                         help="Repetível; faz merge nos headers já cadastrados")
        upd.add_argument("--timeout", type=int, help="Timeout em segundos")
    else:
        run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout em segundos")
        add.add_argument("name")
        add.add_argument("--description", default="")
        add.add_argument("--disabled", action="store_true", help="Cria já desativado")
        upd.add_argument("--name")
        upd.add_argument("--description")
        _enabled_flag(upd)
        if kind == "command":
            add.add_argument("script", help='Script shell, ex.: "pwd && ls"')
            upd.add_argument("--script")
        else:
            add.add_argument("command", help='Comando shell, ex.: "df -h"')
            upd.add_argument("--command")

def build_add_data(kind, args):
    if kind == "service":
        return {"name": args.name, "base_url": args.base_url, "method": args.method,
                "path": args.path, "timeout": args.timeout, "headers": parse_headers(args.header)}
    if kind == "command":
        return {"name": args.name, "script": args.script, "description": args.description,
                "enabled": not args.disabled}
    return {"name": args.name, "command": args.command, "description": args.description,
            "enabled": not args.disabled}

def build_update_changes(kind, args):
    if kind == "service":
        fields = {"name": args.name, "base_url": args.base_url, "method": args.method,
                  "path": args.path, "timeout": args.timeout}
    elif kind == "command":
        fields = {"name": args.name, "script": args.script, "description": args.description,
                  "enabled": args.enabled}
    else:
        fields = {"name": args.name, "command": args.command, "description": args.description,
                  "enabled": args.enabled}
    changes = {k: v for k, v in fields.items() if v is not None}
    if kind == "service" and args.header:
        current = jsonable(require_row(kind, args.id))
        merged = dict(current.get("headers") or {})
        merged.update(parse_headers(args.header))
        changes["headers"] = merged
    return changes

def build_parser():
    parser = argparse.ArgumentParser(
        prog="api.py",
        description="iPhone VPN API — utilitários de CLI para a-Shell (servidor HTTP opcional).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""exemplos:
  python3 api.py init
  python3 api.py run-command 1
  python3 api.py toolbox-exec "df -h"
  python3 api.py command add listar "pwd && ls"
  python3 api.py service add vps http://100.64.0.10:8080 --path /health
  python3 api.py service run 1

códigos de saída: 0 ok, 1 erro, 2 uso inválido, 3 registro desativado,
124 timeout, 130 interrompido; caso contrário, o código do script executado.""")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init", help="Cria data/api.sqlite3 e o token inicial (idempotente)")
    sub.add_parser("rotate-token", help="Gera um novo token e invalida o anterior")

    serve = sub.add_parser("serve", help="Sobe o servidor HTTP opcional (VPS/tailnet)")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8765)

    run = sub.add_parser("run-command", help="Executa um command cadastrado pelo ID")
    run.add_argument("id", type=int)
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout em segundos")

    raw = sub.add_parser("toolbox-exec", help="Executa uma string de comando arbitrária")
    raw.add_argument("command")
    raw.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout em segundos")

    add_kind_parsers(sub, "command", "Gerencia commands (scripts shell cadastrados)")
    add_kind_parsers(sub, "service", "Gerencia services (chamadas HTTP a outros sistemas)")
    add_kind_parsers(sub, "toolbox", "Gerencia tools reutilizáveis da toolbox")
    return parser

def serve(host, port):
    init_db()
    get_token()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"API escutando em http://{host}:{port}/api/v1")
    print("Use apenas em rede confiável/Tailscale; Ctrl+C para encerrar.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        server.server_close()

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        parser.print_help()
        return EXIT_OK
    args = parser.parse_args(argv)
    action = args.action
    if action == "init":
        cli_init()
    elif action == "rotate-token":
        init_db()
        rotate_token()
    elif action == "serve":
        serve(args.host, args.port)
    elif action == "run-command":
        cli_run_command(args.id, args.timeout)
    elif action == "toolbox-exec":
        cli_toolbox_exec(args.command, args.timeout)
    else:
        kind, step = action, args.item_action
        if step == "list":
            cli_list(kind, args.json)
        elif step == "show":
            cli_show(kind, args.id)
        elif step == "delete":
            cli_delete(kind, args.id)
        elif step == "add":
            cli_add(kind, build_add_data(kind, args))
        elif step == "update":
            cli_update(kind, args.id, build_update_changes(kind, args))
        elif step in ("enable", "disable"):
            cli_set_enabled(kind, args.id, step == "enable")
        else:
            cli_run(kind, args.id, getattr(args, "body", None),
                    getattr(args, "timeout", DEFAULT_TIMEOUT))
    return EXIT_OK

if __name__ == "__main__":
    sys.exit(main())
