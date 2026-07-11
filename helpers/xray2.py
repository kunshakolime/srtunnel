import sys
from pathlib import Path
_BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BASE_DIR))

import json
import logging
import uuid
import urllib3
import requests
import yaml
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

# ── Config (lazy — only connects when xui_panel is configured) ───────────────

_cfg = None
_SESSION = None
_BASE = None

def _ensure_config():
    global _cfg, _SESSION, _BASE
    if _cfg is not None:
        return
    raw = yaml.safe_load(open(_BASE_DIR / "config.yaml")) or {}
    panel = raw.get("xui_panel") or {}
    if not panel.get("url") or not panel.get("token"):
        raise RuntimeError("xui_panel.url and xui_panel.token are required in config.yaml")
    _cfg = panel
    _BASE = _cfg["url"].rstrip("/") + "/"
    _SESSION = requests.Session()
    _SESSION.verify = False
    _SESSION.headers["Authorization"] = f"Bearer {_cfg['token']}"

# ── Core HTTP ────────────────────────────────────────────────────────────────

def _get(path):
    _ensure_config()
    r = _SESSION.get(urljoin(_BASE, path))
    r.raise_for_status()
    return r.json()

def _post(path, **kwargs):
    _ensure_config()
    r = _SESSION.post(urljoin(_BASE, path), **kwargs)
    r.raise_for_status()
    return r.json()

# ── Inbounds ─────────────────────────────────────────────────────────────────

def list_inbounds():
    data = _get("panel/api/inbounds/list")
    return data.get("obj", [])

def _inbound_by_tag(tag):
    match = next((ib for ib in list_inbounds() if ib.get("tag") == tag), None)
    if not match:
        raise KeyError(f"inbound '{tag}' not found")
    return match

def add_inbound(cfg):
    return _post("panel/api/inbounds/add", json={
        **{k: cfg.get(k, default) for k, default in [
            ("up", 0), ("down", 0), ("total", 0), ("remark", ""),
            ("enable", True), ("expiryTime", 0), ("listen", ""),
            ("port", None), ("protocol", None),
        ]},
        "settings":       json.dumps(cfg.get("settings", {})),
        "streamSettings": json.dumps(cfg.get("streamSettings", {})),
        "sniffing":       json.dumps(cfg.get("sniffing", {})),
    })

def remove_inbound(tag):
    ib = _inbound_by_tag(tag)
    return _post(f"panel/api/inbounds/del/{ib['id']}")

# ── Users ─────────────────────────────────────────────────────────────────────

def _inbound_users(inbound_id):
    for ib in list_inbounds():
        if ib.get("id") == inbound_id:
            settings = ib.get("settings", {})
            if isinstance(settings, str):
                settings = json.loads(settings)
            return settings.get("clients", [])
    return []

def list_users(tag):
    return _inbound_users(_inbound_by_tag(tag)["id"])

def add_user(tag, email, user_uuid=None, limit_ip=0, total_gb=0, expiry_time=0):
    ib = _inbound_by_tag(tag)
    return _post("panel/api/inbounds/addClient", data={
        "id": ib["id"],
        "settings": json.dumps({"clients": [{
            "id": user_uuid or str(uuid.uuid4()),
            "flow": "", "email": email,
            "limitIp": limit_ip, "totalGB": total_gb,
            "expiryTime": expiry_time, "enable": True,
            "tgId": "", "subId": "", "comment": "", "reset": 0,
        }]}),
    })

def remove_user(tag, email):
    ib = _inbound_by_tag(tag)
    users = _inbound_users(ib["id"])
    match = next((u for u in users if u.get("email") in (email, f"{email}@{tag}")), None)
    if not match:
        raise KeyError(f"user '{email}' not found in inbound '{tag}'")
    return _post(f"panel/api/inbounds/{ib['id']}/delClient/{match['id']}")
