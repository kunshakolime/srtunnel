"""
routes/services.py

HTTP view over the srtunnel systemd units. This used to drive a second,
tmux-based supervisor; it is now a thin adapter for the dashboard's
"managed" tab so systemd stays the single source of truth.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging

from helpers import systemd, units
from helpers.deps import CurrentUser

logger = logging.getLogger("srapi.services")
router = APIRouter(prefix="/api/services")


class ServiceStatusRequest(BaseModel):
    status: str  # "enable" | "disable"


def _require(name: str):
    if name not in units.managed():
        raise HTTPException(status_code=404, detail="service not found")


@router.get("")
def list_services(user: CurrentUser = None):
    """Unit state only — logs live at /api/services/{name}/logs.

    The dashboard polls this every few seconds, so it must not spawn one
    journalctl per unit. Clients that want logs ask for them per expanded row.
    """
    out = []
    for name, st in units.states().items():
        out.append({
            "name": name,
            "status": "enable" if st["enabled"] else "disable",
            "running": st["active"] == "active",
        })
    return {"services": out}


@router.get("/{name}/logs")
def service_logs(name: str, lines: int = 20, user: CurrentUser = None):
    _require(name)
    return {"log": systemd.logs(name, lines)}


@router.post("/spawn")
def spawn_services(user: CurrentUser = None):
    """Start every enabled unit that is not already running."""
    results = {}
    for name, st in units.states().items():
        if not st["enabled"]:
            continue
        if st["active"] == "active":
            results[name] = "already running"
            continue
        results[name] = "started" if systemd.start(name) else "failed"
    logger.info("Spawn enabled units by %s — %s", user, results)
    return {"results": results}


@router.post("/{name}/start")
def start_service(name: str, user: CurrentUser):
    _require(name)
    if not systemd.start(name):
        raise HTTPException(status_code=400, detail=f"Failed to start {name}")
    logger.info("Service started: %s by %s", name, user)
    return {"service": name, "status": "started"}


@router.post("/{name}/stop")
def stop_service(name: str, user: CurrentUser):
    _require(name)
    if not systemd.stop(name):
        raise HTTPException(status_code=400, detail=f"Failed to stop {name}")
    logger.info("Service stopped: %s by %s", name, user)
    return {"service": name, "status": "stopped"}


@router.post("/{name}/restart")
def restart_service(name: str, user: CurrentUser):
    _require(name)
    if not systemd.restart(name):
        raise HTTPException(status_code=400, detail=f"Failed to restart {name}")
    logger.info("Service restarted: %s by %s", name, user)
    return {"service": name, "status": "restarted"}


@router.post("/{name}/reload")
def reload_service(name: str, user: CurrentUser):
    _require(name)
    if systemd.reload(name):
        action = "reloaded"
    elif systemd.restart(name):
        action = "restarted"
    else:
        raise HTTPException(status_code=400, detail=f"Failed to reload {name}")
    logger.info("Service %s: %s by %s", action, name, user)
    return {"service": name, "action": action, "status": action}


@router.post("/{name}/status")
def set_service_status(name: str, data: ServiceStatusRequest, user: CurrentUser):
    _require(name)
    if data.status == "enable":
        ok = systemd.enable(name)
    elif data.status == "disable":
        ok = systemd.disable(name)
    else:
        raise HTTPException(status_code=400, detail="status must be enable or disable")
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to set {name} {data.status}")
    logger.info("Service status set: %s → %s by %s", name, data.status, user)
    return {"service": name, "status": data.status}
