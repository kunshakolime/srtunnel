#!/root/srtunnel/venv/bin/python

import sys, json, os, shutil, subprocess
sys.path.insert(0, "/root/srtunnel")

from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Dict
from helpers.auth import verify_linux_login, create_token, get_current_user, store_token, revoke_token, list_tokens
from helpers import core, system, dns
from helpers import speedtest as st
from helpers import services as svc_helper
import yaml, secrets, logging

logger = logging.getLogger("srapi")

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

@app.on_event("startup")
def on_startup():
    run_launch_commands()

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
    }

cfg = load_config()
 

app = FastAPI()

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
    label:    Optional[str] = None   # e.g. "my laptop", "dashboard"

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

class PasswordRequest(BaseModel):
    password: Optional[str] = None   # omit for random

class ExpiryRequest(BaseModel):
    days:   int
    extend: Optional[bool] = False   # True = add days, False = set from now

class MaxLoginsRequest(BaseModel):
    max_logins: Optional[int] = None  # None / 0 = unlimited

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


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/login")
def login(data: LoginRequest):
    if not verify_linux_login(data.username, data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    label = data.label or f"dashboard-{secrets.token_hex(4)}"
    token = create_token(data.username)
    store_token(token, data.username, label)
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
    return {"status": "revoked"}


# ── Scope ─────────────────────────────────────────────────────────────────────

@app.get("/api/scope")
def get_scope(user: str = Depends(get_current_user)):
    return load_scope()

@app.post("/api/scope")
def set_scope(data: ScopeRequest, user: str = Depends(get_current_user)):
    save_scope(data.dict())
    return {"status": "saved"}


# ── Server List ───────────────────────────────────────────────────────────────

@app.get("/api/serverlist")
def get_serverlist(user: str = Depends(get_current_user)):
    return load_serverlist()

@app.post("/api/serverlist")
def set_serverlist(data: ServerListRequest, user: str = Depends(get_current_user)):
    save_serverlist([s.dict() for s in data.servers])
    return {"status": "saved"}
@app.get("/api/serverlist/status")
def get_serverlist_status(user: str = Depends(get_current_user)):
    return svc_helper._load_serverlist() or []
# ── Users ─────────────────────────────────────────────────────────────────────

@app.get("/api/users")
def list_users(user: str = Depends(get_current_user)):
    users = core.get_users()
    for u in users:
        u["connections"] = system.user_connections(u["username"])
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
    max_expiry    = scope.get("max_expiry")
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
        data.username, data.password, days, data.temporary, max_logins
    )
    if not ok:
        detail = "Password already in use" if err == "password_exists" else "Username already exists"
        raise HTTPException(status_code=400, detail=detail)

    return {
        "username":   data.username,
        "password":   password,
        "expires":    expires[:10] if expires else None,
        "temporary":  data.temporary,
        "max_logins": max_logins,
        "linux_ok":   linux_ok,
    }

@app.get("/api/users/{username}")
def get_user(username: str, user: str = Depends(get_current_user)):
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["connections"] = system.user_connections(username)
    return u

@app.delete("/api/users/{username}")
def delete_user(username: str, user: str = Depends(get_current_user)):
    if not core.delete_user(username):
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "deleted"}

@app.post("/api/users/{username}/password")
def change_password(username: str, data: PasswordRequest, user: str = Depends(get_current_user)):
    ok, old, new_or_err = core.change_password(username, data.password)
    if not ok:
        detail = "Password already in use" if new_or_err == "password_exists" else "User not found"
        raise HTTPException(status_code=400, detail=detail)
    return {"username": username, "old_password": old, "new_password": new_or_err}

@app.post("/api/users/{username}/expiry")
def modify_expiry(username: str, data: ExpiryRequest, user: str = Depends(get_current_user)):
    ok, new_exp = core.modify_expiry(username, data.days, extend=data.extend)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update expiry")
    return {"username": username, "expires": new_exp[:10] if new_exp else None}

@app.delete("/api/users/{username}/expiry")
def remove_expiry(username: str, user: str = Depends(get_current_user)):
    if not core.set_expiry(username, None):
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "expires": None}

@app.post("/api/users/{username}/maxlogins")
def set_maxlogins(username: str, data: MaxLoginsRequest, user: str = Depends(get_current_user)):
    limit = None if (data.max_logins is None or data.max_logins == 0) else data.max_logins
    if not core.set_maxlogins(username, limit):
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "max_logins": limit}

@app.post("/api/users/{username}/activate")
def activate_user(username: str, user: str = Depends(get_current_user)):
    core.set_active(username, True)
    return {"username": username, "status": "Active"}

@app.post("/api/users/{username}/deactivate")
def deactivate_user(username: str, user: str = Depends(get_current_user)):
    core.set_active(username, False)
    return {"username": username, "status": "Inactive"}

@app.post("/api/users/{username}/toggle-temporary")
def toggle_temporary(username: str, user: str = Depends(get_current_user)):
    core.toggle_temporary(username)
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "temporary": u["temporary"]}


# ── Sync & System ─────────────────────────────────────────────────────────────

@app.post("/api/sync")
def sync(user: str = Depends(get_current_user)):
    return core.sync()

@app.get("/api/system")
def system_info(user: str = Depends(get_current_user)):
    iface = cfg["IFACE"]
    info  = system.system_info() or {}
    bw    = system.bandwidth_usage(iface) or {}
    return {
        "ip":          system.public_ip(),
        "cpu":         info.get("cpu"),
        "ram_used":    info.get("ram_used"),
        "ram_total":   info.get("ram_total"),
        "ram_percent": info.get("ram_percent"),
        "disk_used":   info.get("disk_used"),
        "disk_total":  info.get("disk_total"),
        "disk_percent":info.get("disk_percent"),
        "bandwidth":   bw,
        "connections": system.total_connections(),
    }

@app.get("/api/speedtest")
def speedtest(user: str = Depends(get_current_user)):
    proc, progress_file = st.start()
    proc.wait()
    result = st.parse_result(progress_file)
    st.cleanup(progress_file)
    if not result:
        raise HTTPException(status_code=500, detail="Speed test failed")
    return result


# ── Services (tmux) ───────────────────────────────────────────────────────────

class ServiceStatusRequest(BaseModel):
    status: str   # "enable" | "keep" | "disable"

@app.get("/api/services")
def list_services(lines: int = 10, user: str = Depends(get_current_user)):
    svc_helper.watcher.reload_config()
    return {
        "watcher": svc_helper.watcher.active,
        "services": svc_helper.watcher.list_services(lines=lines),
    }

@app.post("/api/services/watcher/start")
def watcher_start(user: str = Depends(get_current_user)):
    started = svc_helper.watcher.start()
    return {"watcher": svc_helper.watcher.active, "changed": started}

@app.post("/api/services/watcher/stop")
def watcher_stop(user: str = Depends(get_current_user)):
    stopped = svc_helper.watcher.stop()
    return {"watcher": svc_helper.watcher.active, "changed": stopped}

@app.post("/api/services/{name}/start")
def start_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    return {"service": name, "status": detail}

@app.post("/api/services/{name}/stop")
def stop_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.stop_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    return {"service": name, "status": detail}

@app.post("/api/services/{name}/restart")
def restart_service(name: str, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    return {"service": name, "status": "restarted"}

@app.post("/api/services/{name}/status")
def set_service_status(name: str, data: ServiceStatusRequest, user: str = Depends(get_current_user)):
    ok, detail = svc_helper.watcher.set_status(name, data.status)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    return {"service": name, "status": detail}

# ── Backup ────────────────────────────────────────────────────────────────────

@app.get("/api/backup")
def backup_db(user: str = Depends(get_current_user)):
    db = Path("/root/srtunnel/users.db")
    if not db.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    return FileResponse(str(db), filename="users.db", media_type="application/octet-stream")

@app.post("/api/restore-db")
async def restore_db(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    shutil.copy(tmp, "/root/srtunnel/users.db")
    os.remove(tmp)
    core.init_db()
    core.sync()
    return {"status": "restored"}

@app.post("/api/merge-db")
async def merge_db(file: UploadFile = File(...), user: str = Depends(get_current_user)):
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    ok = core.sync_db(tmp)
    os.remove(tmp)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid database file")
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
        raise HTTPException(status_code=400, detail=msg)
    return result["result"]

@app.delete("/api/dns/{record_id}")
def dns_delete(record_id: str, user: str = Depends(get_current_user)):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    result = dns.delete_record(record_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail="Could not delete record")
    return {"status": "deleted"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("srapi:app", host="127.0.0.1", port=51700, reload=False)
