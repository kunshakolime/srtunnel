from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import secrets, logging

from helpers.auth import verify_linux_login, create_token, store_token, revoke_token, list_tokens
from deps import CurrentUser

logger = logging.getLogger("srapi.auth")
router = APIRouter(prefix="/api")


# ── Models ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str
    label:    Optional[str] = None

class RevokeRequest(BaseModel):
    token: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/health")
def health():
    return {"status": "ok"}

@router.post("/login")
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

@router.get("/me")
def me(user: CurrentUser):
    return {"user": user}


# ── Token management ──────────────────────────────────────────────────────────

@router.get("/tokens")
def get_tokens(user: CurrentUser):
    return list_tokens()

@router.delete("/tokens")
def delete_token(data: RevokeRequest, user: CurrentUser):
    if not revoke_token(data.token):
        raise HTTPException(status_code=404, detail="Token not found")
    logger.info("Token revoked by %s", user)
    return {"status": "revoked"}
