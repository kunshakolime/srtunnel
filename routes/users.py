from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import logging

from helpers import core, xray2 as xray, monitor
from helpers.deps import CurrentUser, load_scope
import requests as http_requests

logger = logging.getLogger("srapi.users")
router = APIRouter(prefix="/api")


# ── Models ────────────────────────────────────────────────────────────────────

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


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/users")
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

@router.post("/users")
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
            try:
                existing = xray.list_users(tag)
            except RuntimeError:
                existing = []
            if any(u.get("email") == email for u in existing):
                xray_results.append({"tag": tag, "ok": True, "id": user_uuid})
                continue
            try:
                xray.add_user(tag, email, user_uuid=user_uuid)
                xray_results.append({"tag": tag, "ok": True, "id": user_uuid})
                logger.info("Xray user added: %s to %s", email, tag)
            except (RuntimeError, KeyError, http_requests.HTTPError) as e:
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

@router.get("/users/{username}")
def get_user(username: str, user: CurrentUser):
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["connections"] = monitor.user_connections(username)
    return u

@router.delete("/users/{username}")
def delete_user(username: str, user: CurrentUser):
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    xray_results = []
    if "xray" in (u.get("services") or []):
        try:
            inbounds = xray.list_inbounds()
        except RuntimeError:
            inbounds = []
        for ib in inbounds:
            tag   = ib.get("tag")
            email = f"{username}@{tag}"
            try:
                xray.remove_user(tag, email)
                xray_results.append({"tag": tag, "ok": True})
            except (RuntimeError, KeyError, http_requests.HTTPError) as e:
                xray_results.append({"tag": tag, "ok": False, "error": str(e)})
            logger.info("delete_user xray: %s -> %s", email, xray_results[-1])

    core.delete_user(username)
    logger.info("User deleted: %s by %s", username, user)
    return {"status": "deleted", "xray": xray_results}

@router.post("/users/{username}/password")
def change_password(username: str, data: PasswordRequest, user: CurrentUser):
    ok, old, new_or_err = core.change_password(username, data.password)
    if not ok:
        detail = "Password already in use" if new_or_err == "password_exists" else "User not found"
        logger.warning("change_password failed for %r: %s", username, detail)
        raise HTTPException(status_code=400, detail=detail)
    logger.info("Password changed for %s by %s", username, user)
    return {"username": username, "old_password": old, "new_password": new_or_err}

@router.post("/users/{username}/expiry")
def modify_expiry(username: str, data: ExpiryRequest, user: CurrentUser):
    ok, new_exp = core.modify_expiry(username, data.days, extend=data.extend)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update expiry")
    logger.info("Expiry updated: %s → %s by %s", username, new_exp, user)
    return {"username": username, "expires": new_exp[:10] if new_exp else None}

@router.delete("/users/{username}/expiry")
def remove_expiry(username: str, user: CurrentUser):
    if not core.set_expiry(username, None):
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("Expiry removed: %s by %s", username, user)
    return {"username": username, "expires": None}

@router.post("/users/{username}/maxlogins")
def set_maxlogins(username: str, data: MaxLoginsRequest, user: CurrentUser):
    limit = None if (data.max_logins is None or data.max_logins == 0) else data.max_logins
    if not core.set_maxlogins(username, limit):
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("max_logins set: %s → %s by %s", username, limit, user)
    return {"username": username, "max_logins": limit}

@router.post("/users/{username}/activate")
def activate_user(username: str, user: CurrentUser):
    core.set_active(username, True)
    logger.info("User activated: %s by %s", username, user)
    return {"username": username, "status": "Active"}

@router.post("/users/{username}/deactivate")
def deactivate_user(username: str, user: CurrentUser):
    core.set_active(username, False)
    logger.info("User deactivated: %s by %s", username, user)
    return {"username": username, "status": "Inactive"}

@router.post("/users/{username}/toggle-temporary")
def toggle_temporary(username: str, user: CurrentUser):
    core.toggle_temporary(username)
    u = core.get_user(username)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("Toggled temporary: %s → %s by %s", username, u["temporary"], user)
    return {"username": username, "temporary": u["temporary"]}

@router.post("/users/{username}/services")
def set_user_services(username: str, data: SetServicesRequest, user: CurrentUser):
    if not core.set_services(username, data.services):
        raise HTTPException(status_code=404, detail="User not found")
    u = core.get_user(username)
    logger.info("Services set: %s → %s by %s", username, data.services, user)
    return {"username": username, "services": u.get("services", []) if u else []}
