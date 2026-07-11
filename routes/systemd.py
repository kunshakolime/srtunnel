from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging

from helpers import systemd
from deps import CurrentUser

logger = logging.getLogger("srapi.systemd")
router = APIRouter(prefix="/api/systemd")


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
def list_units(user: CurrentUser = None):
    units = systemd.list_units()
    return {"units": units}


@router.get("/{name}/logs")
def get_logs(name: str, lines: int = 20, user: CurrentUser = None):
    return {"name": name, "log": systemd.logs(name, lines)}


@router.post("/{name}/start")
def start_unit(name: str, user: CurrentUser):
    ok = systemd.start(name)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to start {name}")
    logger.info("systemd start: %s by %s", name, user)
    return {"name": name, "active": systemd.unit_status(name)}


@router.post("/{name}/stop")
def stop_unit(name: str, user: CurrentUser):
    ok = systemd.stop(name)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to stop {name}")
    logger.info("systemd stop: %s by %s", name, user)
    return {"name": name, "active": systemd.unit_status(name)}


@router.post("/{name}/restart")
def restart_unit(name: str, user: CurrentUser):
    ok = systemd.restart(name)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to restart {name}")
    logger.info("systemd restart: %s by %s", name, user)
    return {"name": name, "active": systemd.unit_status(name)}


@router.post("/{name}/enable")
def enable_unit(name: str, user: CurrentUser):
    ok = systemd.enable(name)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to enable {name}")
    return {"name": name, "enabled": True}


@router.post("/{name}/disable")
def disable_unit(name: str, user: CurrentUser):
    ok = systemd.disable(name)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to disable {name}")
    return {"name": name, "enabled": False}
