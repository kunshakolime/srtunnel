from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging

from helpers import services as svc_helper
from helpers.deps import CurrentUser

logger = logging.getLogger("srapi.services")
router = APIRouter(prefix="/api/services")


# ── Models ────────────────────────────────────────────────────────────────────

class ServiceStatusRequest(BaseModel):
    status: str  # "enable" | "disable"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
def list_services(lines: int = 10, user: CurrentUser = None):
    return {"services": svc_helper.list_services(lines=lines)}


@router.post("/spawn")
def spawn_services(user: CurrentUser = None):
    """Launch every enabled service once."""
    results = svc_helper.spawn_enabled()
    logger.info("Spawn enabled services by %s — %s", user, results)
    return {"results": results}


@router.post("/{name}/start")
def start_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service started: %s by %s", name, user)
    return {"service": name, "status": detail}


@router.post("/{name}/stop")
def stop_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.stop_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service stopped: %s by %s", name, user)
    return {"service": name, "status": detail}


@router.post("/{name}/reload")
def reload_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.reload_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    action = "reloaded" if "reloaded" in detail else "restarted"
    logger.info("Service %s: %s by %s", action, name, user)
    return {"service": name, "action": action, "status": detail}


@router.post("/{name}/restart")
def restart_service(name: str, user: CurrentUser):
    ok, detail = svc_helper.start_service(name)
    if not ok:
        raise HTTPException(status_code=404, detail=detail)
    logger.info("Service restarted: %s by %s", name, user)
    return {"service": name, "status": "restarted"}


@router.post("/{name}/status")
def set_service_status(name: str, data: ServiceStatusRequest, user: CurrentUser):
    ok, detail = svc_helper.set_status(name, data.status)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Service status set: %s → %s by %s", name, data.status, user)
    return {"service": name, "status": detail}