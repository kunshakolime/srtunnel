import pam, json
from pathlib import Path
from jose import jwt, JWTError
from typing import Optional
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets

KEY_FILE = Path(__file__).resolve().parent / ".secret_key"
if KEY_FILE.exists():
    SECRET_KEY = KEY_FILE.read_text().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    KEY_FILE.write_text(SECRET_KEY)
ALGORITHM  = "HS256"

TOKENS_FILE = Path(__file__).resolve().parent / "tokens.json"

security = HTTPBearer(auto_error=False)

# ── tokens.json helpers ───────────────────────────────────────────────────────
# Format: [ { "token": "...", "label": "my laptop", "user": "root", "created": "..." } ]

def _load_tokens() -> list:
    if TOKENS_FILE.exists():
        try: return json.loads(TOKENS_FILE.read_text())
        except: return []
    return []

def _save_tokens(tokens: list):
    TOKENS_FILE.write_text(json.dumps(tokens, indent=2))

def _is_revoked(raw_token: str) -> bool:
    return not any(t["token"] == raw_token for t in _load_tokens())

def store_token(raw_token: str, username: str, label: str = ""):
    from datetime import datetime
    tokens = _load_tokens()
    tokens.append({
        "token":   raw_token,
        "label":   label or "unnamed",
        "user":    username,
        "created": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    })
    _save_tokens(tokens)

def revoke_token(raw_token: str) -> bool:
    tokens = _load_tokens()
    new    = [t for t in tokens if t["token"] != raw_token]
    if len(new) == len(tokens): return False
    _save_tokens(new)
    return True

def list_tokens() -> list:
    return _load_tokens()

# ── core auth ─────────────────────────────────────────────────────────────────

def verify_linux_login(username: str, password: str) -> bool:
    p = pam.pam()
    return p.authenticate(username, password)

def create_token(username: str) -> str:
    # No exp claim — tokens never expire; revocation is via tokens.json
    raw = jwt.encode({"sub": username}, SECRET_KEY, algorithm=ALGORITHM)
    return raw

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    raw = None
    if credentials and credentials.credentials:
        raw = credentials.credentials
    elif "token" in request.query_params:
        raw = request.query_params["token"]
    elif "access_token" in request.cookies:
        raw = request.cookies.get("access_token")
    elif "x-token" in request.headers:
        raw = request.headers.get("x-token")

    if not raw:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(raw, SECRET_KEY, algorithms=[ALGORITHM],
                             options={"verify_exp": False})
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not username or _is_revoked(raw):
        raise HTTPException(status_code=401, detail="Token revoked")

    return username
