from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path
import yaml, logging

from helpers import services as svc_helper
from deps import CurrentUser

logger = logging.getLogger("srapi.services")
router = APIRouter(prefix="/api/services")


# ── Models ────────────────────────────────────────────────────────────────────

class ServiceStatusRequest(BaseModel):
    status: str  # "enable" | "keep" | "disable"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
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

@router.post("/watcher/start")
def watcher_start(user: CurrentUser):
    changed = svc_helper.watcher.start()
    logger.info("Watcher start by %s — changed=%s", user, changed)
    return {"watcher": svc_helper.watcher.active, "changed": changed}

@router.post("/watcher/stop")
def watcher_stop(user: CurrentUser):
    changed = svc_helper.watcher.stop()
    logger.info("Watcher stop by %s — changed=%s", user, changed)
    return {"watcher": svc_helper.watcher.active, "changed": changed}

@router.post("/{name}/start")
def start_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service started: %s by %s", name, user)
    return {"service": name, "status": detail}

@router.post("/{name}/stop")
def stop_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.stop_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service stopped: %s by %s", name, user)
    return {"service": name, "status": detail}

@router.post("/{name}/reload")
def reload_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.reload_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    action = "reloaded" if "reloaded" in detail else "restarted"
    logger.info("Service %s: %s by %s", action, name, user)
    return {"service": name, "action": action, "status": detail}

@router.post("/{name}/restart")
def restart_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.watcher.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service restarted: %s by %s", name, user)
    return {"service": name, "status": "restarted"}

@router.post("/{name}/status")
def set_service_status(name: str, data: ServiceStatusRequest, user: CurrentUser):
    ok, detail = svc_helper.watcher.set_status(name, data.status)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Service status set: %s → %s by %s", name, data.status, user)
    return {"service": name, "status": detail}
