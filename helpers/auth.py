import base64
import hashlib
import hmac
import json
import secrets
from pathlib import Path
from typing import Optional
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.requests import HTTPConnection

try:
    import pam as _pam
    _PAM_OK = True
except ImportError:
    try:
        import PAM as _pam
        _PAM_OK = False
    except ImportError:
        _pam = None
        _PAM_OK = False

KEY_FILE = Path(__file__).resolve().parent / ".secret_key"
if KEY_FILE.exists():
    SECRET_KEY = KEY_FILE.read_text().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    KEY_FILE.write_text(SECRET_KEY)
ALGORITHM  = "HS256"

TOKENS_FILE = Path(__file__).resolve().parent / "tokens.json"

security = HTTPBearer(auto_error=False)

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

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
    if _pam is None:
        return False
    if _PAM_OK:
        # high-level python3-pam (C module exposing `pam`)
        p = _pam.pam()
        return p.authenticate(username, password)
    # Debian python3-pam: low-level PAM wrapper
    def conv(auth, query_list, userData=None):
        resp = []
        for _, qtype in query_list:
            if qtype == _pam.PAM_PROMPT_ECHO_ON:
                resp.append((username, 0))
            elif qtype == _pam.PAM_PROMPT_ECHO_OFF:
                resp.append((password, 0))
            else:
                resp.append(("", 0))
        return resp
    try:
        auth = _pam.pam()
        auth.start("passwd")
        auth.set_item(_pam.PAM_USER, username)
        auth.set_item(_pam.PAM_CONV, conv)
        auth.authenticate()
        auth.acct_mgmt()
        return True
    except _pam.error:
        return False
    except Exception:
        return False

def user_in_group(username: str, group: str) -> bool:
    import grp
    try:
        g = grp.getgrnam(group)
        return username in g.gr_mem
    except KeyError:
        return False

def create_token(username: str) -> str:
    # No exp claim — tokens never expire; revocation is via tokens.json
    header = _b64url_encode(b'{"typ":"JWT","alg":"HS256"}')
    payload = _b64url_encode(json.dumps({"sub": username}, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = _b64url_encode(hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def _verify_and_decode_token(raw_token: str) -> dict:
    parts = raw_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = _b64url_encode(hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(sig_b64, expected_sig):
        raise ValueError("Invalid signature")
    return json.loads(_b64url_decode(payload_b64).decode("utf-8"))

def get_current_user(request: HTTPConnection):
    raw = None
    auth_hdr = request.headers.get("authorization")
    if auth_hdr and auth_hdr.lower().startswith("bearer "):
        raw = auth_hdr[7:].strip()
    elif "token" in request.query_params:
        raw = request.query_params["token"]
    elif "access_token" in request.cookies:
        raw = request.cookies.get("access_token")
    elif "x-token" in request.headers:
        raw = request.headers.get("x-token")

    if not raw:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = _verify_and_decode_token(raw)
        username = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not username or _is_revoked(raw):
        raise HTTPException(status_code=401, detail="Token revoked")

    return username
