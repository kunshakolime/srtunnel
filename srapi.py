#!/root/srtunnel/venv/bin/python

import sys, json, os, shutil, subprocess
sys.path.insert(0, "/root/srtunnel")

from pathlib import Path
from typing import Annotated, Optional, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, Body
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from helpers.auth import verify_linux_login, create_token, get_current_user, store_token, revoke_token, list_tokens
from helpers import core, dns, xray2 as xray, files
from helpers import monitor
from helpers import speedtest as st
from helpers import services as svc_helper
import requests as http_requests
import yaml, secrets, logging, traceback, time

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("srapi")


# ── Config ────────────────────────────────────────────────────────────────────

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


# ── Startup ───────────────────────────────────────────────────────────────────

def run_launch_commands():
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


# ── Middleware ────────────────────────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        logger.error("UNHANDLED  %s %s — %.1fms — %s: %s\n%s",
                     request.method, request.url.path, elapsed,
                     type(exc).__name__, exc, traceback.format_exc())
        raise
    elapsed = (time.perf_counter() - start) * 1000
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    logger.log(level, "%s  %s %s — %.1fms",
               response.status_code, request.method, request.url.path, elapsed)
    return response


# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    logger.warning("422 VALIDATION  %s %s — %s", request.method, request.url.path, exc.errors())
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    level = logging.WARNING if exc.status_code < 500 else logging.ERROR
    logger.log(level, "%s HTTP  %s %s — %s", exc.status_code, request.method, request.url.path, exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("500 UNHANDLED  %s %s — %s: %s\n%s",
                 request.method, request.url.path,
                 type(exc).__name__, exc, traceback.format_exc())
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(exc).__name__}: {exc}"})


# ── Scope / Serverlist ────────────────────────────────────────────────────────

SCOPE_FILE      = Path("/root/srtunnel/helpers/scope.json")
SERVERLIST_FILE = Path("/root/srtunnel/helpers/serverlist.json")

def load_scope():
    return json.loads(SCOPE_FILE.read_text()) if SCOPE_FILE.exists() else {}

def save_scope(data):
    SCOPE_FILE.write_text(json.dumps(data, indent=2))

def load_serverlist():
    return json.loads(SERVERLIST_FILE.read_text()) if SERVERLIST_FILE.exists() else []

def save_serverlist(data):
    SERVERLIST_FILE.write_text(json.dumps(data, indent=2))


# ── Shared dependency ─────────────────────────────────────────────────────────
# Using Annotated means FastAPI caches the dependency object — small but free win.

CurrentUser = Annotated[str, Depends(get_current_user)]


# ── Models ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str
    label:    Optional[str] = None

class RevokeRequest(BaseModel):
    token: str

class ScopeRequest(BaseModel):
    max_users:       Optional[int]            = None
    default_expiry:  Optional[int]            = None
    max_expiry:      Optional[int]            = None
    max_connections: Optional[int]            = None
    services:        Optional[Dict[str, bool]] = None

class CreateUserRequest(BaseModel):
    username:      str
    password:      Optional[str]       = None
    days:          Optional[int]       = None
    temporary:     Optional[bool]      = False
    max_logins:    Optional[int]       = None
    services:      Optional[list[str]] = None
    xray_inbounds: Optional[list[str]] = None

class PasswordRequest(BaseModel):
    password: Optional[str] = None

class ExpiryRequest(BaseModel):
    days:   int
    extend: Optional[bool] = False

class MaxLoginsRequest(BaseModel):
    max_logins: Optional[int] = None

class SetServicesRequest(BaseModel):
    services: list[str]

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
    uid:      Optional[str] = None

class FileOpRequest(BaseModel):
    path:    str
    content: Optional[str] = None

class ServiceStatusRequest(BaseModel):
    status: str  # "enable" | "keep" | "disable"


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/login")
def login(data: LoginRequest):
    if not verify_linux_login(data.username, data.password):
        logger.warning("Failed login attempt for user: %s", data.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if data.username != "root":
    raise HTTPException(status_code=403, detail="Only root is allowed")
    label = data.label or f"dashboard-{secrets.token_hex(4)}"
    token = create_token(data.username)
    store_token(token, data.username, label)
    logger.info("Login success: user=%s label=%s", data.username, label)
    return {"token": token}

@app.get("/api/me")
def me(user: CurrentUser):
    return {"user": user}


# ── Token management ──────────────────────────────────────────────────────────

@app.get("/api/tokens")
def get_tokens(user: CurrentUser):
    return list_tokens()

@app.delete("/api/tokens")
def delete_token(data: RevokeRequest, user: CurrentUser):
    if not revoke_token(data.token):
        raise HTTPException(status_code=404, detail="Token not found")
    logger.info("Token revoked by %s", user)
    return {"status": "revoked"}


# ── Scope ─────────────────────────────────────────────────────────────────────

@app.get("/api/scope")
def get_scope(user: CurrentUser):
    return load_scope()

@app.post("/api/scope")
def set_scope(data: ScopeRequest, user: CurrentUser):
    save_scope(data.dict())
    logger.info("Scope updated by %s: %s", user, data.dict())
    return {"status": "saved"}


# ── Server list ───────────────────────────────────────────────────────────────

@app.get("/api/serverlist")
def get_serverlist(user: CurrentUser):
    return load_serverlist()

@app.post("/api/serverlist")
def set_serverlist(data: ServerListRequest, user: CurrentUser):
    save_serverlist([s.dict() for s in data.servers])
    logger.info("Serverlist updated by %s (%d entries)", user, len(data.servers))
    return {"status": "saved"}

@app.get("/api/serverlist/status")
def get_serverlist_status(user: CurrentUser):
    return svc_helper._load_serverlist() or []


# ── Xray (XUI panel) ──────────────────────────────────────────────────────────

@app.get("/api/xray/inbounds")
def list_xray_inbounds(user: CurrentUser):
    return xray.list_inbounds()

@app.post("/api/xray/inbounds")
def add_xray_inbound(inbound: dict = Body(...), user: CurrentUser = None):
    try:
        xray.add_inbound(inbound)
    except (KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "added", "tag": inbound.get("tag")}

@app.delete("/api/xray/inbounds/{tag}")
def remove_xray_inbound(tag: str, user: CurrentUser):
    try:
        xray.remove_inbound(tag)
    except (KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "removed", "tag": tag}

@app.get("/api/xray/inbounds/{tag}/users")
def list_xray_inbound_users(tag: str, user: CurrentUser):
    try:
        return xray.list_users(tag)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/xray/inbounds/{tag}/users")
def add_xray_inbound_user(tag: str, data: XrayUserRequest, user: CurrentUser):
    try:
        xray.add_user(tag, data.username, user_uuid=data.uid)
    except (KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"tag": tag, "username": data.username}

@app.delete("/api/xray/inbounds/{tag}/users/{email}")
def remove_xray_inbound_user(tag: str, email: str, user: CurrentUser):
    try:
        xray.remove_user(tag, email)
    except (KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"tag": tag, "email": email}

@app.get("/api/xray/users/{username}/stats")
def get_xray_user_stats(username: str, user: CurrentUser):
    raise HTTPException(status_code=410, detail="Xray stats functionality has been removed")


# ── Users ─────────────────────────────────────────────────────────────────────

@app.get("/api/users")
def list_users(user: CurrentUser):
    users     = core.get_users()
    logged_in = monitor.logged_in_users()
    traffic   = {t["username"]: t for t in monitor.all_user_traffic()}
    for u in users:
        u["connections"] = logged_in.get(u["username"], 0)
        t = traffic.get(u["username"], {})
        u["download"] = t.get("download", 0)
        u["upload"]   = t.get("upload", 0)
        u["total"]    = t.get("total", 0)
    return users

@app.post("/api/users")
def create_user(data: CreateUserRequest, user: CurrentUser):
    scope = load_scope()

    if not scope.get("services", {}).get("ssh_dropbear", True):
        raise HTTPException(status_code=403, detail="SSH Dropbear is not enabled")

    if (max_users := scope.get("max_users")) and len(core.get_users()) >= max_users:
        raise HTTPException(status_code=403, detail="Max user limit reached")

    days = data.days or scope.get("default_expiry")
    if days and (max_expiry := scope.get("max_expiry")):
        days = min(days, max_expiry)

    max_logins = data.max_logins
    if (scope_max := scope.get("max_connections")) and (not max_logins or max_logins > scope_max):
        max_logins = scope_max

    ok, password, expires, linux_ok, err = core.add_user(
        data.username, data.password, days, data.temporary, max_logins, data.services
    )
    if not ok:
        detail = {
            "password_exists":   "Password already in use",
            "username_exists":   "Username already exists in database",
            "ssh_user_exists":   "SSH user already exists on system",
            "root_forbidden":    "Cannot create root user",
            "ssh_create_failed": "Failed to create SSH user",
        }.get(err, "Failed to create user")
        logger.warning("create_user failed for %r: %s (err=%s)", data.username, detail, err)
        raise HTTPException(status_code=400, detail=detail)

    user_obj = core.get_user(data.username)
    logger.info("User created: %s by %s (days=%s, max_logins=%s, linux_ok=%s)",
                data.username, user, days, max_logins, linux_ok)

    if data.services and any(s in data.services for s in ("ssh", "zivpn")):
        core.sync()

    xray_results = []
    if data.xray_inbounds and "xray" in (user_obj.get("services") or []):
        user_uuid = user_obj.get("uuid")
        logger.info("Xray: using UUID=%s from DB", user_uuid)
        for tag in data.xray_inbounds:
            email = f"{data.username}@{tag}"
            if any(u.get("email") == email for u in xray.list_users(tag)):
                xray_results.append({"tag": tag, "ok": True, "id": user_uuid})
                continue
            try:
                xray.add_user(tag, email, user_uuid=user_uuid)
                xray_results.append({"tag": tag, "ok": True, "id": user_uuid})
                logger.info("Xray user added: %s to %s", email, tag)
            except (KeyError, http_requests.HTTPError) as e:
                xray_results.append({"tag": tag, "ok": False, "error": str(e)})
                logger.warning("Xray user add failed: %s to %s — %s", email, tag, e)

    return {
        "username":   data.username,
        "password":   password,
        "expires":    expires[:10] if expires else None,
        "temporary":  data.temporary,
        "max_logins": max_logins,
        "services":   user_obj.get("services", []) if user_obj else [],
        "linux_ok":   linux_ok,
        "xray":       xray_results,
    }

@app.get("/api/users/{username}")
def get_user(username: str, user: CurrentUser):
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["connections"] = monitor.user_connections(username)
    return u

@app.delete("/api/users/{username}")
def delete_user(username: str, user: CurrentUser):
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    xray_results = []
    if "xray" in (u.get("services") or []):
        for ib in xray.list_inbounds():
            tag   = ib.get("tag")
            email = f"{username}@{tag}"
            try:
                xray.remove_user(tag, email)
                xray_results.append({"tag": tag, "ok": True})
            except (KeyError, http_requests.HTTPError) as e:
                xray_results.append({"tag": tag, "ok": False, "error": str(e)})
            logger.info("delete_user xray: %s -> %s", email, xray_results[-1])

    core.delete_user(username)
    logger.info("User deleted: %s by %s", username, user)
    return {"status": "deleted", "xray": xray_results}

@app.post("/api/users/{username}/password")
def change_password(username: str, data: PasswordRequest, user: CurrentUser):
    ok, old, new_or_err = core.change_password(username, data.password)
    if not ok:
        detail = "Password already in use" if new_or_err == "password_exists" else "User not found"
        logger.warning("change_password failed for %r: %s", username, detail)
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Password changed for %s by %s", username, user)
    return {"username": username, "old_password": old, "new_password": new_or_err}

@app.post("/api/users/{username}/expiry")
def modify_expiry(username: str, data: ExpiryRequest, user: CurrentUser):
    ok, new_exp = core.modify_expiry(username, data.days, extend=data.extend)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update expiry")
    logger.info("Expiry updated: %s → %s by %s", username, new_exp, user)
    return {"username": username, "expires": new_exp[:10] if new_exp else None}

@app.delete("/api/users/{username}/expiry")
def remove_expiry(username: str, user: CurrentUser):
    if not core.set_expiry(username, None):
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("Expiry removed: %s by %s", username, user)
    return {"username": username, "expires": None}

@app.post("/api/users/{username}/maxlogins")
def set_maxlogins(username: str, data: MaxLoginsRequest, user: CurrentUser):
    limit = None if (data.max_logins is None or data.max_logins == 0) else data.max_logins
    if not core.set_maxlogins(username, limit):
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("max_logins set: %s → %s by %s", username, limit, user)
    return {"username": username, "max_logins": limit}

@app.post("/api/users/{username}/activate")
def activate_user(username: str, user: CurrentUser):
    core.set_active(username, True)
    logger.info("User activated: %s by %s", username, user)
    return {"username": username, "status": "Active"}

@app.post("/api/users/{username}/deactivate")
def deactivate_user(username: str, user: CurrentUser):
    core.set_active(username, False)
    logger.info("User deactivated: %s by %s", username, user)
    return {"username": username, "status": "Inactive"}

@app.post("/api/users/{username}/toggle-temporary")
def toggle_temporary(username: str, user: CurrentUser):
    core.toggle_temporary(username)
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("Toggled temporary: %s → %s by %s", username, u["temporary"], user)
    return {"username": username, "temporary": u["temporary"]}

@app.post("/api/users/{username}/services")
def set_user_services(username: str, data: SetServicesRequest, user: CurrentUser):
    if not core.set_services(username, data.services):
        raise HTTPException(status_code=404, detail="User not found")
    u = core.get_user(username)
    logger.info("Services set: %s → %s by %s", username, data.services, user)
    return {"username": username, "services": u.get("services", []) if u else []}


# ── File manager ──────────────────────────────────────────────────────────────

def _resolve_file_path(p: str) -> str:
    if not p or p == ".":
        return "/"
    return os.path.normpath("/" + p.lstrip("/"))

@app.get("/api/files/list")
def list_files(directory: str = "/", user: CurrentUser = None):
    return files.list_directory(_resolve_file_path(directory))

@app.post("/api/files/create/{filepath:path}")
def create_file_endpoint(filepath: str, data: FileOpRequest, user: CurrentUser):
    if not files.create_file(_resolve_file_path(filepath), data.content or ""):
        raise HTTPException(status_code=400, detail="Failed to create file")
    return {"status": "created", "path": filepath}

@app.post("/api/files/create-dir/{directory:path}")
def create_dir(directory: str, user: CurrentUser):
    if not files.create_directory(_resolve_file_path(directory)):
        raise HTTPException(status_code=400, detail="Failed to create directory")
    return {"status": "created", "path": directory}

@app.get("/api/files/read/{filepath:path}")
def read_file(filepath: str, user: CurrentUser):
    try:
        return {"path": filepath, "content": files.read_file(_resolve_file_path(filepath))}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

@app.post("/api/files/write/{filepath:path}")
def write_file_endpoint(filepath: str, data: FileOpRequest, user: CurrentUser):
    try:
        files.write_file(_resolve_file_path(filepath), data.content or "")
        return {"status": "written", "path": filepath}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/files/{filepath:path}")
def delete_file(filepath: str, user: CurrentUser):
    if not files.delete_path(_resolve_file_path(filepath), filepath.endswith("/")):
        raise HTTPException(status_code=400, detail="Failed to delete")
    return {"status": "deleted", "path": filepath}

@app.post("/api/files/upload/{directory:path}")
async def upload_file(directory: str, file: UploadFile = File(...), user: CurrentUser = None):
    full_path = _resolve_file_path(directory)
    if not os.path.isdir(full_path):
        raise HTTPException(status_code=400, detail="Not a directory")
    target = os.path.join(full_path, file.filename)
    files.write_binary_file(target, await file.read())
    return {"status": "uploaded", "path": target}

@app.get("/api/files/download/{filepath:path}")
def download_file(filepath: str, user: CurrentUser):
    full_path = _resolve_file_path(filepath)
    if not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(full_path, filename=os.path.basename(full_path), media_type="application/octet-stream")

@app.get("/api/files/download-info/{filepath:path}")
def download_info(filepath: str, user: CurrentUser):
    full_path = _resolve_file_path(filepath)
    info = files.get_download_url(full_path)
    if not info.get("exists"):
        raise HTTPException(status_code=404, detail="File not found")
    info["wget"] = files.get_wget_command(full_path)
    info["curl"] = files.get_curl_command(full_path)
    return info


# ── Legacy config file shortcuts ──────────────────────────────────────────────
# NOTE: must be registered AFTER the file manager routes above.

@app.put("/api/files/{filename}")
def write_config_file(filename: str, content: str = Body(...), user: CurrentUser = None):
    safe = os.path.basename(filename)
    try:
        files.write_file(safe, content)
        logger.info("File updated: %s by %s", safe, user)
        return {"filename": safe, "status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing file: {e}")

@app.get("/api/files/{filename}/exists")
def check_file_exists(filename: str, user: CurrentUser):
    safe = os.path.basename(filename)
    return {"filename": safe, "exists": files.file_exists(safe)}
# ── Backup / Restore ──────────────────────────────────────────────────────────

@app.get("/api/backup")
def backup_db(user: CurrentUser):
    db = Path("/root/srtunnel/users.db")
    if not db.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    logger.info("DB backup downloaded by %s", user)
    return FileResponse(str(db), filename="users.db", media_type="application/octet-stream")

@app.post("/api/restore-db")
async def restore_db(file: UploadFile = File(...), user: CurrentUser = None):
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    shutil.copy(tmp, "/root/srtunnel/users.db")
    os.remove(tmp)
    core.init_db()
    logger.info("DB restored by %s", user)
    return {"status": "restored"}

@app.post("/api/merge-db")
async def merge_db(file: UploadFile = File(...), user: CurrentUser = None):
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    ok = core.sync_db(tmp)
    os.remove(tmp)
    if not ok:
        logger.warning("merge-db rejected invalid file by %s", user)
        raise HTTPException(status_code=400, detail="Invalid database file")
    logger.info("DB merged by %s", user)
    return {"status": "merged"}


# ── Sync & System ─────────────────────────────────────────────────────────────

@app.post("/api/sync")
def sync(user: CurrentUser):
    return {"status": "skipped", "reason": "sync disabled - use XUI panel directly"}

@app.get("/api/system")
def system_info(user: CurrentUser):
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
def get_ssh_users(user: CurrentUser):
    logged_in = monitor.logged_in_users()
    traffic   = {t["username"]: t for t in monitor.all_user_traffic()}
    return [
        {
            "username":    username,
            "connections": count,
            "download":    traffic.get(username, {}).get("download", 0),
            "upload":      traffic.get(username, {}).get("upload", 0),
            "total":       traffic.get(username, {}).get("total", 0),
        }
        for username, count in logged_in.items()
    ]


# ── Speedtest ─────────────────────────────────────────────────────────────────

@app.get("/api/speedtest")
def speedtest(user: CurrentUser):
    logger.info("Speedtest started by %s", user)
    try:
        proc, progress_file = st.start()
        logger.info("Speedtest pid=%s progress_file=%s", getattr(proc, "pid", "?"), progress_file)
        proc.wait()
        stderr_out = proc.stderr.read() if proc.stderr else b""
        stdout_out = proc.stdout.read() if proc.stdout else b""
        logger.info("Speedtest exited: returncode=%s", proc.returncode)
        if stderr_out:
            logger.warning("Speedtest stderr: %s", stderr_out.decode(errors="replace").strip())
        result = st.parse_result(progress_file)
        st.cleanup(progress_file)
        if not result:
            logger.error("Speedtest parse_result=None returncode=%s stdout=%r stderr=%r",
                         proc.returncode, stdout_out, stderr_out)
            raise HTTPException(status_code=500, detail="Speed test failed — no result parsed")
        logger.info("Speedtest complete: download=%s upload=%s", result.get("download"), result.get("upload"))
        return result
    except HTTPException:
        raise
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"Speedtest binary not found: {e}")
    except Exception as e:
        logger.error("Speedtest error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Speedtest error: {type(e).__name__}: {e}")


# ── Services ──────────────────────────────────────────────────────────────────

@app.get("/api/services")
def list_services(lines: int = 10, user: CurrentUser = None):
    services = svc_helper.watcher.list_services(lines=lines) or []
    try:
        raw      = yaml.safe_load(Path("/root/srtunnel/config.yaml").read_text()) or {}
        block    = raw.get("manager", {})
        keep_set   = set(block.get("keep",   []) or [])
        enable_set = set(block.get("enable", []) or [])
        for svc in services:
            name = svc.get("name")
            svc["status"] = "keep" if name in keep_set else "enable" if name in enable_set else "disable"
    except Exception as e:
        logger.warning("Failed to overlay service statuses: %s", e)
    return {"watcher": svc_helper.watcher.active, "services": services}

@app.post("/api/services/watcher/start")
def watcher_start(user: CurrentUser):
    changed = svc_helper.watcher.start()
    logger.info("Watcher start by %s — changed=%s", user, changed)
    return {"watcher": svc_helper.watcher.active, "changed": changed}

@app.post("/api/services/watcher/stop")
def watcher_stop(user: CurrentUser):
    changed = svc_helper.watcher.stop()
    logger.info("Watcher stop by %s — changed=%s", user, changed)
    return {"watcher": svc_helper.watcher.active, "changed": changed}

@app.post("/api/services/{name}/start")
def start_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service started: %s by %s", name, user)
    return {"service": name, "status": detail}

@app.post("/api/services/{name}/stop")
def stop_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.stop_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service stopped: %s by %s", name, user)
    return {"service": name, "status": detail}

@app.post("/api/services/{name}/reload")
def reload_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.reload_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    action = "reloaded" if "reloaded" in detail else "restarted"
    logger.info("Service %s: %s by %s", action, name, user)
    return {"service": name, "action": action, "status": detail}

@app.post("/api/services/{name}/restart")
def restart_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service restarted: %s by %s", name, user)
    return {"service": name, "status": "restarted"}

@app.post("/api/services/{name}/status")
def set_service_status(name: str, data: ServiceStatusRequest, user: CurrentUser):
    ok, detail = svc_helper.watcher.set_status(name, data.status)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Service status set: %s → %s by %s", name, data.status, user)
    return {"service": name, "status": detail}

# ── DNS ───────────────────────────────────────────────────────────────────────

@app.get("/api/dns")
def dns_list(user: CurrentUser):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    return dns.list_records()

@app.post("/api/dns")
def dns_create(data: DnsRecordRequest, user: CurrentUser):
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
def dns_delete(record_id: str, user: CurrentUser):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    result = dns.delete_record(record_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail="Could not delete record")
    logger.info("DNS record deleted: %s by %s", record_id, user)
    return {"status": "deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("srapi:app", host="127.0.0.1", port=51700, reload=False, access_log=False)
