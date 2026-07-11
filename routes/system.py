from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Dict
from pathlib import Path
import logging, traceback

from helpers import monitor, dns, speedtest as st, services as svc_helper
from deps import CurrentUser, cfg, load_scope, save_scope, load_serverlist, save_serverlist

_BASE_DIR = Path(__file__).resolve().parent.parent

logger = logging.getLogger("srapi.system")
router = APIRouter(prefix="/api")


# ── Models ────────────────────────────────────────────────────────────────────

class ScopeRequest(BaseModel):
    max_users:       Optional[int]            = None
    default_expiry:  Optional[int]            = None
    max_expiry:      Optional[int]            = None
    max_connections: Optional[int]            = None
    services:        Optional[Dict[str, bool]] = None

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


# ── System ────────────────────────────────────────────────────────────────────

@router.get("/system")
def system_info(user: CurrentUser):
    cache = monitor.get_system_cache()
    if not cache:
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
        cache = {
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
    return cache

@router.get("/ssh-users")
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

@router.get("/speedtest")
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


# ── Sync ──────────────────────────────────────────────────────────────────────

@router.post("/sync")
def sync(user: CurrentUser):
    return {"status": "skipped", "reason": "sync disabled - use XUI panel directly"}


# ── Scope ─────────────────────────────────────────────────────────────────────

@router.get("/scope")
def get_scope(user: CurrentUser):
    return load_scope()

@router.post("/scope")
def set_scope(data: ScopeRequest, user: CurrentUser):
    save_scope(data.dict())
    logger.info("Scope updated by %s: %s", user, data.dict())
    return {"status": "saved"}


# ── Server list ───────────────────────────────────────────────────────────────

@router.get("/serverlist")
def get_serverlist(user: CurrentUser):
    return load_serverlist()

@router.post("/serverlist")
def set_serverlist(data: ServerListRequest, user: CurrentUser):
    save_serverlist([s.dict() for s in data.servers])
    logger.info("Serverlist updated by %s (%d entries)", user, len(data.servers))
    return {"status": "saved"}

@router.get("/serverlist/status")
def get_serverlist_status(user: CurrentUser):
    return svc_helper._load_serverlist() or []


# ── Backup / Restore ──────────────────────────────────────────────────────────

from helpers import core

@router.get("/backup")
def backup_db(user: CurrentUser):
    db = _BASE_DIR / "users.db"
    if not db.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    logger.info("DB backup downloaded by %s", user)
    return FileResponse(str(db), filename="users.db", media_type="application/octet-stream")

@router.post("/restore-db")
async def restore_db(file: UploadFile = File(...), user: CurrentUser = None):
    import shutil, os
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    shutil.copy(tmp, str(_BASE_DIR / "users.db"))
    os.remove(tmp)
    core.init_db()
    logger.info("DB restored by %s", user)
    return {"status": "restored"}

@router.post("/merge-db")
async def merge_db(file: UploadFile = File(...), user: CurrentUser = None):
    import os
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


# ── DNS ───────────────────────────────────────────────────────────────────────

@router.get("/dns")
def dns_list(user: CurrentUser):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    return dns.list_records()

@router.post("/dns")
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

@router.delete("/dns/{record_id}")
def dns_delete(record_id: str, user: CurrentUser):
    if not dns.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare not configured")
    result = dns.delete_record(record_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail="Could not delete record")
    logger.info("DNS record deleted: %s by %s", record_id, user)
    return {"status": "deleted"}
