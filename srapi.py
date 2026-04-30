#!/root/srtunnel/venv/bin/python

import sys, json, os, shutil, subprocess
sys.path.insert(0, "/root/srtunnel")

from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, Body
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
from helpers.auth import verify_linux_login, create_token, get_current_user, store_token, revoke_token, list_tokens
from helpers import core, dns, xray2 as xray, files
from helpers import ssh
from helpers import monitor
from helpers import speedtest as st
from helpers import services as svc_helper
import yaml, secrets, logging, traceback, time

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("srapi")

def load_config():
    path = Path("/root/srtunnel/config.yaml")
    if not path.exists():
        raise RuntimeError(f"Missing config file: {path}")
    app = (yaml.safe_load(path.read_text()) or {}).get("telegram_bot", {})
    return {
        "DB_FILE":          app.get("db_file", "users.db"),
        "CONFIG_FILE":      app.get("config_file", "./zivpn.json"),
        "DEFAULT_PASSWORD": app.get("default_password", "123"),
        "DOMAIN":           app.get("domain", ""),
        "DNSTT":            app.get("dnstt", ""),
        "KEY":              app.get("slowdnskey", ""),
        "IFACE":            app.get("interface", "eth0"),
        "CF_TOKEN":         app.get("cf_token", ""),
        "CF_ZONE":          app.get("cf_zone", ""),
        "CF_ROOT_DOMAIN":   app.get("cf_root_domain", ""),
        "XRAY_INBOUND_TAG": app.get("xray_inbound_tag", "xray-vless"),
        "XRAY_CONFIG":      app.get("xray_config", "./root/srtunnel/xray.json"),
        "XRAY_API_PORT":    app.get("xray_api_port", 10085),
        "XRAY_BINARY":      app.get("xray_binary", "/root/srtunnel/xray"),
    }

cfg = load_config()


def run_launch_commands():
    """Run manager.launch_commands from config.yaml once at startup."""
    path = Path("/root/srtunnel/config.yaml")
    if not path.exists():
        return
    block = (yaml.safe_load(path.read_text()) or {}).get("manager", {})
    for cmd in (block.get("launch_commands") or []):
        try:
            subprocess.run(cmd, shell=True, check=True)
            logger.info("launch_command ok: %s", cmd)
        except subprocess.CalledProcessError as e:
            logger.warning("launch_command failed: %s — %s", cmd, e)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("srapi starting up")
    run_launch_commands()
    logger.info("skipping old sync (XUI panel enabled)")
    # sync disabled - old xray code is incompatible with XUI panel
    yield
    logger.info("srapi shutting down")

app = FastAPI(lifespan=lifespan)

core.init(cfg)
dns.init(cfg)
core.init_db()
svc_helper.watcher.start()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request/response logging middleware ───────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        logger.error(
            "UNHANDLED  %s %s — %.1fms — %s: %s\n%s",
            request.method, request.url.path,
            elapsed,
            type(exc).__name__, exc,
            traceback.format_exc(),
        )
        raise
    elapsed = (time.perf_counter() - start) * 1000
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    logger.log(
        level,
        "%s  %s %s — %.1fms",
        response.status_code, request.method, request.url.path, elapsed,
    )
    return response

# ── Global exception handlers ─────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    logger.warning(
        "422 VALIDATION  %s %s — %s",
        request.method, request.url.path, exc.errors(),
    )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    level = logging.WARNING if exc.status_code < 500 else logging.ERROR
    logger.log(
        level,
        "%s HTTP  %s %s — %s",
        exc.status_code, request.method, request.url.path, exc.detail,
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(
        "500 UNHANDLED  %s %s — %s: %s\n%s",
        request.method, request.url.path,
        type(exc).__name__, exc,
        traceback.format_exc(),
    )
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(exc).__name__}: {exc}"})


SCOPE_FILE      = Path("/root/srtunnel/helpers/scope.json")
SERVERLIST_FILE = Path("/root/srtunnel/helpers/serverlist.json")

def load_scope():
    if SCOPE_FILE.exists():
        return json.loads(SCOPE_FILE.read_text())
    return {}

def save_scope(data):
    SCOPE_FILE.write_text(json.dumps(data, indent=2))

def load_serverlist():
    if SERVERLIST_FILE.exists():
        return json.loads(SERVERLIST_FILE.read_text())
    return []

def save_serverlist(data):
    SERVERLIST_FILE.write_text(json.dumps(data, indent=2))


# ── Models ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str
    label:    Optional[str] = None

class ScopeRequest(BaseModel):
    max_users:       Optional[int]  = None
    default_expiry:  Optional[int]  = None
    max_expiry:      Optional[int]  = None
    max_connections: Optional[int]  = None
    services:        Optional[Dict[str, bool]] = None

class CreateUserRequest(BaseModel):
    username:   str
    password:   Optional[str] = None
    days:       Optional[int] = None
    temporary:  Optional[bool] = False
    max_logins: Optional[int] = None
    services:   Optional[list[str]] = None
    xray_inbounds: Optional[list[str]] = None

class PasswordRequest(BaseModel):
    password: Optional[str] = None

class ExpiryRequest(BaseModel):
    days:   int
    extend: Optional[bool] = False

class MaxLoginsRequest(BaseModel):
    max_logins: Optional[int] = None

class ServerEntry(BaseModel):
    id:    str
    name:  str
    url:   str
    token: Optional[str] = None

class ServerListRequest(BaseModel):
    servers: list[ServerEntry]

class DnsRecordRequest(BaseModel):
    type:    str
    name:    str
    value:   str
    proxied: Optional[bool] = False

class XrayUserRequest(BaseModel):
    username: str
    password: Optional[str] = None
    uid: Optional[str] = None
    flow: Optional[str] = None
    alter_id: Optional[int] = 0


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/login")
def login(data: LoginRequest):
    if not verify_linux_login(data.username, data.password):
        logger.warning("Failed login attempt for user: %s", data.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    label = data.label or f"dashboard-{secrets.token_hex(4)}"
    token = create_token(data.username)
    store_token(token, data.username, label)
    logger.info("Login success: user=%s label=%s", data.username, label)
    return {"token": token}

@app.get("/api/me")
def me(user: str = Depends(get_current_user)):
    return {"user": user}


# ── Token management ──────────────────────────────────────────────────────────

class RevokeRequest(BaseModel):
    token: str

@app.get("/api/tokens")
def get_tokens(user: str = Depends(get_current_user)):
    return list_tokens()

@app.delete("/api/tokens")
def delete_token(data: RevokeRequest, user: str = Depends(get_current_user)):
    if not revoke_token(data.token):
        raise HTTPException(status_code=404, detail="Token not found")
    logger.info("Token revoked by %s", user)
    return {"status": "revoked"}


# ── Scope ─────────────────────────────────────────────────────────────────────

@app.get("/api/scope")
def get_scope(user: str = Depends(get_current_user)):
    return load_scope()

@app.post("/api/scope")
def set_scope(data: ScopeRequest, user: str = Depends(get_current_user)):
    save_scope(data.dict())
    logger.info("Scope updated by %s: %s", user, data.dict())
    return {"status": "saved"}


# ── Server List ───────────────────────────────────────────────────────────────

@app.get("/api/serverlist")
def get_serverlist(user: str = Depends(get_current_user)):
    return load_serverlist()

@app.post("/api/serverlist")
def set_serverlist(data: ServerListRequest, user: str = Depends(get_current_user)):
    save_serverlist([s.dict() for s in data.servers])
    logger.info("Serverlist updated by %s (%d entries)", user, len(data.servers))
    return {"status": "saved"}

@app.get("/api/serverlist/status")
def get_serverlist_status(user: str = Depends(get_current_user)):
    return svc_helper._load_serverlist() or []


# ── Xray (xray2 / XUI Panel) ───────────────────────────────────────────────────────

@app.get("/api/xray/inbounds")
def list_xray_inbounds(user: str = Depends(get_current_user)):
    return xray.list_inbounds()

@app.post("/api/xray/inbounds")
def add_xray_inbound(inbound: dict = Body(...), user: str = Depends(get_current_user)):
    ok, msg = xray.add_inbound(inbound)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "added", "tag": inbound.get("tag")}

@app.delete("/api/xray/inbounds/{tag}")
def remove_xray_inbound(tag: str, user: str = Depends(get_current_user)):
    ok, msg = xray.remove_inbound(tag)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "removed", "tag": tag}

@app.get("/api/xray/inbounds/{tag}/users")
def list_xray_inbound_users(tag: str, user: str = Depends(get_current_user)):
    return xray.list_users(tag)

@app.post("/api/xray/inbounds/{tag}/users")
def add_xray_inbound_user(tag: str, data: XrayUserRequest, user: str = Depends(get_current_user)):
    ok, identifier, err = xray.add_user(
        tag,
        data.username,
        uid=data.uid,
        password=data.password,
        flow=data.flow or '',
        alter_id=data.alter_id or 0,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=err or "Failed to add Xray user")
    return {"tag": tag, "username": data.username, "id": identifier}

@app.delete("/api/xray/inbounds/{tag}/users/{client_uuid}")
def remove_xray_inbound_user(tag: str, client_uuid: str, user: str = Depends(get_current_user)):
    # client_uuid here is the email (username@tag format)
    logger.info("remove_xray_inbound_user: tag=%s, email=%s", tag, client_uuid)
    ok, err = xray.remove_user(tag, client_uuid)
    if not ok:
        raise HTTPException(status_code=400, detail=err or "Failed to remove Xray user")
    return {"tag": tag, "client_uuid": client_uuid}

@app.get("/api/xray/users/{username}/stats")
def get_xray_user_stats(username: str, user: str = Depends(get_current_user)):
    raise HTTPException(status_code=410, detail="Xray stats functionality has been removed")


# ── Users ─────────────────────────────────────────────────────────────────────

@app.get("/api/users")
def list_users(user: str = Depends(get_current_user)):
    logger.info("list_users called by %s", user)
    users = core.get_users()
    logged_in = monitor.logged_in_users()
    traffic = {t['username']: t for t in monitor.all_user_traffic()}
    for u in users:
        u["connections"] = logged_in.get(u["username"], 0)
        t = traffic.get(u["username"], {})
        u["download"] = t.get("download", 0)
        u["upload"] = t.get("upload", 0)
        u["total"] = t.get("total", 0)
    return users

@app.post("/api/users")
def create_user(data: CreateUserRequest, user: str = Depends(get_current_user)):
    scope = load_scope()

    if not scope.get("services", {}).get("ssh_dropbear", True):
        raise HTTPException(status_code=403, detail="SSH Dropbear is not enabled")

    max_users = scope.get("max_users")
    if max_users and len(core.get_users()) >= max_users:
        raise HTTPException(status_code=403, detail="Max user limit reached")

    days = data.days
    max_expiry     = scope.get("max_expiry")
    default_expiry = scope.get("default_expiry")
    if not days and default_expiry:
        days = default_expiry
    if days and max_expiry and days > max_expiry:
        days = max_expiry

    max_logins = data.max_logins
    scope_max  = scope.get("max_connections")
    if scope_max and (not max_logins or max_logins > scope_max):
        max_logins = scope_max

    ok, password, expires, linux_ok, err = core.add_user(
        data.username, data.password, days, data.temporary, max_logins, data.services
    )
    if not ok:
        error_map = {
            "password_exists": "Password already in use",
            "username_exists": "Username already exists in database",
            "ssh_user_exists": "SSH user already exists on system",
            "root_forbidden": "Cannot create root user",
            "ssh_create_failed": "Failed to create SSH user",
        }
        detail = error_map.get(err, "Failed to create user")
        logger.warning("create_user failed for %r: %s (err=%s)", data.username, detail, err)
        raise HTTPException(status_code=400, detail=detail)

    user_obj = core.get_user(data.username)
    logger.info("User created: %s by %s (days=%s, max_logins=%s, linux_ok=%s, services=%s)",
                data.username, user, days, max_logins, linux_ok, user_obj.get("services") if user_obj else [])

    # Sync for SSH/ZIVPN (not Xray - handled separately)
    if data.services:
        has_ssh = "ssh" in data.services
        has_zivpn = "zivpn" in data.services
        if has_ssh or has_zivpn:
            core.sync()

    # Add Xray users to selected inbounds
    xray_results = []
    if data.xray_inbounds and 'xray' in (user_obj.get("services") or []):
        user_uuid = user_obj.get("uuid")  # Use DB UUID
        logger.info("=== XRAY: using UUID=%s from DB", user_uuid)
        
        for i, tag in enumerate(data.xray_inbounds):
            # Use unique email: username@tag
            xray_email = f"{data.username}@{tag}"
            
            # Check if user already exists
            existing_users = xray.list_users(tag)
            user_exists = any(u.get('email') == xray_email for u in existing_users)
            
            if user_exists:
                ok, uid, err = True, user_uuid, ""
            else:
                ok, uid, err = xray.add_user(tag, xray_email, uid=user_uuid)
            
            xray_results.append({"tag": tag, "ok": ok, "id": uid, "error": err})
            if ok:
                logger.info("Xray user added: %s (uuid=%s) to %s", xray_email, uid, tag)
            else:
                logger.warning("Xray user add failed: %s to %s — %s", xray_email, tag, err)

    return {
        "username":   data.username,
        "password":   password,
        "expires":    expires[:10] if expires else None,
        "temporary":  data.temporary,
        "max_logins": max_logins,
        "services":   user_obj.get("services", []) if user_obj else [],
        "linux_ok":   linux_ok,
        "xray":      xray_results,
    }

@app.get("/api/users/{username}")
def get_user(username: str, user: str = Depends(get_current_user)):
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["connections"] = monitor.user_connections(username)
    return u

@app.delete("/api/users/{username}")
def delete_user(username: str, user: str = Depends(get_current_user)):
    # Get user FIRST before deleting
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Remove from XUI panel inbounds BEFORE deleting from DB
    xray_results = []
    if u and "xray" in (u.get("services") or []):
        user_uuid = u.get("uuid")
        inbounds = xray.list_inbounds()
        for ib in inbounds:
            tag = ib.get("tag")
            email = f"{username}@{tag}"
            ok, err = xray.remove_user(tag, email)
            logger.info("delete_user: %s (uuid=%s) -> %s", email, user_uuid, ok)
            xray_results.append({"tag": tag, "ok": ok, "error": err})
    
    # Then delete from DB
    core.delete_user(username)
    
    logger.info("User deleted: %s by %s", username, user)
    return {"status": "deleted", "xray": xray_results}
    
    logger.info("User deleted: %s by %s", username, user)
    return {"status": "deleted", "xray": xray_results}

@app.post("/api/users/{username}/password")
def change_password(username: str, data: PasswordRequest, user: str = Depends(get_current_user)):
    ok, old, new_or_err = core.change_password(username, data.password)
    if not ok:
        detail = "Password already in use" if new_or_err == "password_exists" else "User not found"
        logger.warning("change_password failed for %r: %s", username, detail)
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Password changed for %s by %s", username, user)
    return {"username": username, "old_password": old, "new_password": new_or_err}

@app.post("/api/users/{username}/expiry")
def modify_expiry(username: str, data: ExpiryRequest, user: str = Depends(get_current_user)):
    ok, new_exp = core.modify_expiry(username, data.days, extend=data.extend)
    if not ok:
        logger.warning("modify_expiry failed for %r: days=%s extend=%s", username, data.days, data.extend)
        raise HTTPException(status_code=400, detail="Failed to update expiry")
    logger.info("Expiry updated: %s → %s by %s", username, new_exp, user)
    return {"username": username, "expires": new_exp[:10] if new_exp else None}

@app.delete("/api/users/{username}/expiry")
def remove_expiry(username: str, user: str = Depends(get_current_user)):
    if not core.set_expiry(username, None):
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("Expiry removed: %s by %s", username, user)
    return {"username": username, "expires": None}

@app.post("/api/users/{username}/maxlogins")
def set_maxlogins(username: str, data: MaxLoginsRequest, user: str = Depends(get_current_user)):
    limit = None if (data.max_logins is None or data.max_logins == 0) else data.max_logins
    if not core.set_maxlogins(username, limit):
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("max_logins set: %s → %s by %s", username, limit, user)
    return {"username": username, "max_logins": limit}

@app.post("/api/users/{username}/activate")
def activate_user(username: str, user: str = Depends(get_current_user)):
    core.set_active(username, True)
    logger.info("User activated: %s by %s", username, user)
    return {"username": username, "status": "Active"}

@app.post("/api/users/{username}/deactivate")
def deactivate_user(username: str, user: str = Depends(get_current_user)):
    core.set_active(username, False)
    logger.info("User deactivated: %s by %s", username, user)
    return {"username": username, "status": "Inactive"}

@app.post("/api/users/{username}/toggle-temporary")
def toggle_temporary(username: str, user: str = Depends(get_current_user)):
    core.toggle_temporary(username)
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("Toggled temporary: %s → %s by %s", username, u["temporary"], user)
    return {"username": username, "temporary": u["temporary"]}

class SetServicesRequest(BaseModel):
    services: list[str]

@app.post("/api/users/{username}/services")
def set_user_services(username: str, data: SetServicesRequest, user: str = Depends(get_current_user)):
    if not core.set_services(username, data.services):
        raise HTTPException(status_code=404, detail="User not found")
    u = core.get_user(username)
    logger.info("Services set: %s → %s by %s", username, data.services, user)
    return {"username": username, "services": u.get("services", []) if u else []}


# ── File Manager ───────────────────────────────────────────────────────────

class FileOpRequest(BaseModel):
    path: str
    content: Optional[str] = None

def _resolve_file_path(p: str) -> str:
    """Resolve a file path, treating '.' as '/'. Never allows escaping root."""
    if not p or p == ".":
        return "/"
    full = os.path.normpath("/" + p.lstrip("/"))
    return full

@app.get("/api/files/list")
@app.get("/api/files/list/")
def list_files_root(user: str = Depends(get_current_user)):
    return files.list_directory("/")

@app.get("/api/files/list/{directory:path}")
def list_files(directory: str, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(directory)
    result = files.list_directory(full_path)
    return result

@app.post("/api/files/create/{filepath:path}")
def create_file(filepath: str, data: FileOpRequest, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(filepath)
    ok = files.create_file(full_path, data.content or "")
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to create file")
    return {"status": "created", "path": filepath}

@app.post("/api/files/create-dir/{directory:path}")
def create_dir(directory: str, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(directory)
    ok = files.create_directory(full_path)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to create directory")
    return {"status": "created", "path": directory}

@app.get("/api/files/read/{filepath:path}")
def read_file(filepath: str, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(filepath)
    try:
        content = files.read_file(full_path)
        return {"path": filepath, "content": content}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

@app.post("/api/files/write/{filepath:path}")
def write_file_endpoint(filepath: str, data: FileOpRequest, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(filepath)
    try:
        files.write_file(full_path, data.content or "")
        return {"status": "written", "path": filepath}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/files/{filepath:path}")
def delete_file(filepath: str, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(filepath)
    is_dir = filepath.endswith("/")
    ok = files.delete_path(full_path, is_dir)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to delete")
    return {"status": "deleted", "path": filepath}

@app.get("/api/files/download-info/{filepath:path}")
def download_info(filepath: str, user: str = Depends(get_current_user)):
    full_path = _resolve_file_path(filepath)
    info = files.get_download_url(full_path)
    if not info.get("exists"):
        raise HTTPException(status_code=404, detail="File not found")
    info["wget"] = files.get_wget_command(full_path)
    info["curl"] = files.get_curl_command(full_path)
    return info


# ── File Management (legacy config file shortcuts) ─────────────────────────────
# NOTE: these MUST be registered AFTER the file manager routes above,
# otherwise /api/files/list etc. get caught by the catch-all.

ALLOWED_CONFIG_FILES = {
    "xray.json",
    "hysteria1.json",
    "hysteria2.yaml",
    "zivpn.json",
    "stunnel.conf",
    "config.yaml",
    "udp-custom.json",
    "websocket",
    "bannerssh",
}

@app.put("/api/files/{filename}")
def write_config_file(filename: str, content: str = Body(...), user: str = Depends(get_current_user)):
    # Optional: Prevent path traversal by ensuring only the filename is used
    safe_filename = os.path.basename(filename)
    
    try:
        files.write_file(safe_filename, content)
        logger.info("File updated: %s by %s", safe_filename, user)
        return {"filename": safe_filename, "status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing file: {str(e)}")

@app.get("/api/files/{filename}/exists")
def check_file_exists(filename: str, user: str = Depends(get_current_user)):
    # Optional: Prevent path traversal
    safe_filename = os.path.basename(filename)
    
    exists = files.file_exists(safe_filename)
    return {"filename": safe_filename, "exists": exists}
# ── Sync & System ─────────────────────────────────────────────────────────────

@app.post("/api/sync")
def sync(user: str = Depends(get_current_user)):
    logger.info("Manual sync: disabled for XUI panel")
    return {"status": "skipped", "reason": "sync disabled - use XUI panel directly"}

@app.get("/api/system")
def system_info(user: str = Depends(get_current_user)):
    logger.info("system_info called by %s", user)
    iface = cfg["IFACE"]
    try:
        info = monitor.system_info() or {}
    except Exception as e:
        logger.error("monitor.system_info() failed: %s", e)
        info = {}
    try:
        bw = monitor.bandwidth_usage(iface) or {}
    except Exception as e:
        logger.error("monitor.bandwidth_usage(%r) failed: %s", iface, e)
        bw = {}
    return {
        "ip":           monitor.public_ip(),
        "cpu":          info.get("cpu"),
        "ram_used":     info.get("ram_used"),
        "ram_total":    info.get("ram_total"),
        "ram_percent":  info.get("ram_percent"),
        "disk_used":    info.get("disk_used"),
        "disk_total":   info.get("disk_total"),
        "disk_percent": info.get("disk_percent"),
        "bandwidth":    bw,
        "connections":  monitor.total_connections(),
    }


@app.get("/api/ssh-users")
def get_ssh_users(user: str = Depends(get_current_user)):
    """Returns all logged-in SSH users with their connection counts and traffic."""
    ssh_users = monitor.logged_in_users()
    traffic = {t['username']: t for t in monitor.all_user_traffic()}
    result = []
    for username, count in ssh_users.items():
        t = traffic.get(username, {})
        result.append({
            'username': username,
            'connections': count,
            'download': t.get("download", 0),
            'upload': t.get("upload", 0),
            'total': t.get("total", 0),
        })
    return result


@app.get("/api/speedtest")
def speedtest(user: str = Depends(get_current_user)):
    logger.info("Speedtest started by %s", user)
    try:
        proc, progress_file = st.start()
        logger.info("Speedtest process started, pid=%s progress_file=%s", getattr(proc, 'pid', '?'), progress_file)
        proc.wait()
        returncode = proc.returncode
        stderr_out = proc.stderr.read() if proc.stderr else b""
        stdout_out = proc.stdout.read() if proc.stdout else b""
        logger.info("Speedtest process exited: returncode=%s", returncode)
        if stderr_out:
            logger.warning("Speedtest stderr: %s", stderr_out.decode(errors="replace").strip())
        if stdout_out:
            logger.info("Speedtest stdout: %s", stdout_out.decode(errors="replace").strip())
        result = st.parse_result(progress_file)
        st.cleanup(progress_file)
        if not result:
            logger.error(
                "Speedtest parse_result returned None — returncode=%s stdout=%r stderr=%r progress_file=%s",
                returncode, stdout_out, stderr_out, progress_file,
            )
            raise HTTPException(status_code=500, detail="Speed test failed — no result parsed")
        logger.info("Speedtest complete: download=%s upload=%s",
                    result.get("download"), result.get("upload"))
        return result
    except HTTPException:
        raise
    except FileNotFoundError as e:
        logger.error("Speedtest binary not found: %s", e)
        raise HTTPException(status_code=500, detail=f"Speedtest binary not found: {e}")
    except Exception as e:
        logger.error("Speedtest unexpected error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Speedtest error: {type(e).__name__}: {e}")


# ── Services (tmux) ───────────────────────────────────────────────────────────

class ServiceStatusRequest(BaseModel):
    status: str   # "enable" | "keep" | "disable"

@app.get("/api/services")
def list_services(lines: int = 10, user: str = Depends(get_current_user)):
    services = svc_helper.watcher.list_services(lines=lines) or []
    try:
        raw = yaml.safe_load(Path("/root/srtunnel/config.yaml").read_text()) or {}
        block      = raw.get("manager", {})
        keep_set   = set(block.get("keep",   []) or [])
        enable_set = set(block.get("enable", []) or [])
        for svc in services:
            name = svc.get("name")
            if name in keep_set:
                svc["status"] = "keep"
            elif name in enable_set:
                svc["status"] = "enable"
            else:
                svc["status"] = "disable"
    except Exception as e:
        logger.warning("Failed to overlay service statuses from config.yaml: %s", e)
    return {
        "watcher":  svc_helper.watcher.active,
        "services": services,
    }

@app.post("/api/services/watcher/start")
def watcher_start(user: str = Depends(get_current_user)):
    started = svc_helper.watcher.start()
    logger.info("Watcher start requested by %s — changed=%s", user, started)
    return {"watcher": svc_helper.watcher.active, "changed": started}

@app.post("/api/services/watcher/stop")
def watcher_stop(user: str = Depends(get_current_user)):
    stopped = svc_helper.watcher.stop()
    logger.info("Watcher stop requested by %s — changed=%s", user, stopped)
    return {"watcher": svc_helper.watcher.active, "changed": stopped}

@app.post("/api/services/{name}/start")
def start_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        logger.warning("start_service failed: %s — %s", name, detail)
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service started: %s by %s", name, user)
    return {"service": name, "status": detail}

@app.post("/api/services/{name}/stop")
def stop_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.stop_service(name)
    if not ok:
        logger.warning("stop_service failed: %s — %s", name, detail)
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service stopped: %s by %s", name, user)
    return {"service": name, "status": detail}

@app.post("/api/services/{name}/reload")
def reload_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.reload_service(name)
    if not ok:
        logger.warning("reload_service failed: %s — %s", name, detail)
        raise HTTPException(status_code=404, detail=detail)
    
    # Determine if it was a reload or restart
    action = "reloaded" if "reloaded" in detail else "restarted"
    logger.info("Service %s: %s by %s — %s", action, name, user, detail)
    return {"service": name, "action": action, "status": detail}

@app.post("/api/services/{name}/restart")
def restart_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        logger.warning("restart_service failed: %s — %s", name, detail)
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service restarted: %s by %s", name, user)
    return {"service": name, "status": "restarted"}

@app.post("/api/services/{name}/status")
def set_service_status(name: str, data: ServiceStatusRequest, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.set_status(name, data.status)
    if not ok:
        logger.warning("set_service_status failed: %s → %s — %s", name, data.status, detail)
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Service status set: %s → %s by %s", name, data.status, user)
    return {"service": name, "status": detail}


@app.get("/api/backup")
def backup_db(user: str = Depends(get_current_user)):
    db = Path("/root/srtunnel/users.db")
    if not db.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    logger.info("DB backup downloaded by %s", user)
    return FileResponse(str(db), filename="users.db", media_type="application/octet-stream")

@app.post("/api/restore-db")
async def restore_db(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    shutil.copy(tmp, "/root/srtunnel/users.db")
    os.remove(tmp)
    core.init_db()
    logger.info("DB restored by %s (sync disabled for XUI panel)", user)
    return {"status": "restored"}

@app.post("/api/merge-db")
async def merge_db(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    ok = core.sync_db(tmp)
    os.remove(tmp)
    if not ok:
        logger.warning("merge-db rejected invalid file uploaded by %s", user)
        raise HTTPException(status_code=400, detail="Invalid database file")
    logger.info("DB merged by %s", user)
    return {"status": "merged"}


# ── DNS ───────────────────────────────────────────────────────────────────────

@app.get("/api/dns")
def dns_list(user: str = Depends(get_current_user)):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    return dns.list_records()

@app.post("/api/dns")
def dns_create(data: DnsRecordRequest, user: str = Depends(get_current_user)):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    result = dns.create_record(data.type, data.name, data.value, data.proxied)
    if not result.get("success"):
        errors = result.get("errors", [])
        msg    = errors[0].get("message") if errors else "Unknown error"
        logger.warning("DNS create failed: %s %s → %s: %s", data.type, data.name, data.value, msg)
        raise HTTPException(status_code=400, detail=msg)
    logger.info("DNS record created: %s %s → %s by %s", data.type, data.name, data.value, user)
    return result["result"]

@app.delete("/api/dns/{record_id}")
def dns_delete(record_id: str, user: str = Depends(get_current_user)):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    result = dns.delete_record(record_id)
    if not result.get("success"):
        logger.warning("DNS delete failed: record_id=%s", record_id)
        raise HTTPException(status_code=400, detail="Could not delete record")
    logger.info("DNS record deleted: %s by %s", record_id, user)
    return {"status": "deleted"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("srapi:app", host="127.0.0.1", port=51700, reload=False, access_log=False)