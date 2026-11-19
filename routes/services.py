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


class UnitUpdateRequest(BaseModel):
    content: str
    apply: bool = True


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
        units.sync_manager_enable(name, True)
    elif data.status == "disable":
        ok = systemd.disable(name)
        units.sync_manager_enable(name, False)
    else:
        raise HTTPException(status_code=400, detail="status must be enable or disable")
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to set {name} {data.status}")
    logger.info("Service status set: %s → %s by %s", name, data.status, user)
    return {"service": name, "status": data.status}


@router.get("/{name}/unit")
def get_service_unit(name: str, user: CurrentUser):
    _require(name)
    try:
        content = units.get_unit_content(name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Unit file for {name} not found")
    return {"name": name, "unit": f"{name}.service", "content": content}


@router.put("/{name}/unit")
@router.post("/{name}/unit")
def update_service_unit(name: str, data: UnitUpdateRequest, user: CurrentUser):
    _require(name)
    content = data.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Unit content cannot be empty")

    units.save_unit_content(name, data.content)
    logger.info("Unit %s.service updated by %s", name, user)

    reconciled = False
    if data.apply:
        try:
            from helpers import reconcile
            reconcile.run(only="units", force=True, restart_units=(name != "srapi"))
            reconciled = True
            logger.info("Reconciled units after %s.service update", name)
        except Exception as e:
            logger.error("Failed to reconcile unit %s: %s", name, e)
            raise HTTPException(status_code=500, detail=f"Saved, but reconcile failed: {e}")

    return {
        "service": name,
        "unit": f"{name}.service",
        "reconciled": reconciled,
        "status": "updated",
    }
