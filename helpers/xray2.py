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

def list_inbounds():
    try:
        data = _get("panel/api/inbounds/list")
        return data.get("obj", [])
    except RuntimeError as e:
        raise RuntimeError(f"Not configured: {e}")
    except Exception as e:
        raise RuntimeError(f"Xray backend not responding: {e}")

def _inbound_by_tag(tag):
    match = next((ib for ib in list_inbounds() if ib.get("tag") == tag), None)
    if not match:
        raise KeyError(f"inbound '{tag}' not found")
    return match

def add_inbound(cfg):
    try:
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
    except RuntimeError as e:
        raise RuntimeError(f"Not configured: {e}")
    except Exception as e:
        raise RuntimeError(f"Xray backend not responding: {e}")

def remove_inbound(tag):
    ib = _inbound_by_tag(tag)
    try:
        return _post(f"panel/api/inbounds/del/{ib['id']}")
    except RuntimeError as e:
        raise RuntimeError(f"Not configured: {e}")
    except Exception as e:
        raise RuntimeError(f"Xray backend not responding: {e}")

def list_users(tag):
    try:
        ib = _inbound_by_tag(tag)
        data = _get(f"panel/api/clients/list?inboundId={ib['id']}")
        return data.get("obj", [])
    except RuntimeError as e:
        raise RuntimeError(f"Not configured: {e}")
    except Exception as e:
        raise RuntimeError(f"Xray backend not responding: {e}")

def add_user(tag, email, user_uuid=None, limit_ip=0, total_gb=0, expiry_time=0):
    ib = _inbound_by_tag(tag)
    try:
        return _post("panel/api/clients/add", json={
            "client": {
                "email": email,
                "uuid": user_uuid or str(uuid.uuid4()),
                "flow": "",
                "limitIp": limit_ip,
                "totalGB": total_gb,
                "expiryTime": expiry_time,
                "enable": True,
                "tgId": 0,
                "subId": "",
                "comment": "",
                "reset": 0,
            },
            "inboundIds": [ib["id"]],
        })
    except RuntimeError as e:
        raise RuntimeError(f"Not configured: {e}")
    except Exception as e:
        raise RuntimeError(f"Xray backend not responding: {e}")

def remove_user(tag, email):
    try:
        return _post(f"panel/api/clients/del/{email}")
    except RuntimeError as e:
        raise RuntimeError(f"Not configured: {e}")
    except Exception as e:
        raise RuntimeError(f"Xray backend not responding: {e}")
