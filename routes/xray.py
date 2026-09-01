from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
import logging

from helpers import xray2 as xray
from helpers.deps import CurrentUser
import requests as http_requests

logger = logging.getLogger("srapi.xray")
router = APIRouter(prefix="/api/xray")


# ── Models ────────────────────────────────────────────────────────────────────

class XrayUserRequest(BaseModel):
    username: str
    uid:      Optional[str] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/inbounds")
def list_xray_inbounds(user: CurrentUser):
    try:
        return xray.list_inbounds()
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/inbounds")
def add_xray_inbound(inbound: dict = Body(...), user: CurrentUser = None):
    try:
        xray.add_inbound(inbound)
    except (RuntimeError, KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "added", "tag": inbound.get("tag")}

@router.delete("/inbounds/{tag}")
def remove_xray_inbound(tag: str, user: CurrentUser):
    try:
        xray.remove_inbound(tag)
    except (RuntimeError, KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "removed", "tag": tag}

@router.get("/inbounds/{tag}/users")
def list_xray_inbound_users(tag: str, user: CurrentUser):
    try:
        return xray.list_users(tag)
    except (RuntimeError, KeyError) as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/inbounds/{tag}/users")
def add_xray_inbound_user(tag: str, data: XrayUserRequest, user: CurrentUser):
    try:
        xray.add_user(tag, data.username, user_uuid=data.uid)
    except (RuntimeError, KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"tag": tag, "username": data.username}

@router.delete("/inbounds/{tag}/users/{email}")
def remove_xray_inbound_user(tag: str, email: str, user: CurrentUser):
    try:
        xray.remove_user(tag, email)
    except (RuntimeError, KeyError, http_requests.HTTPError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"tag": tag, "email": email}

@router.get("/users/{username}/stats")
def get_xray_user_stats(username: str, user: CurrentUser):
    raise HTTPException(status_code=410, detail="Xray stats functionality has been removed")
