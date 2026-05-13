import sys
sys.path.insert(0, "/root/srtunnel")

import requests
import json
import logging
import urllib3
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load XUI config
_xray_cfg = {}
try:
    import yaml
    raw = yaml.safe_load(open("/root/srtunnel/config.yaml")) or {}
    _xray_cfg = raw.get("xui_panel", {})
except Exception as e:
    logger.warning(f"Could not load xui_panel config: {e}")

XUI_URL   = _xray_cfg.get("url", "")
XUI_TOKEN = _xray_cfg.get("token", "")


class XUIClient:
    def __init__(self, base_url: str = None, token: str = None, verify_ssl: bool = False, debug: bool = False):
        self.base_url = (base_url or XUI_URL).rstrip("/") + "/"
        self.session  = requests.Session()
        self.session.verify = verify_ssl
        self.debug = debug

        _token = token or XUI_TOKEN
        if _token:
            self.session.headers.update({"Authorization": f"Bearer {_token}"})
        else:
            logger.warning("No API token provided; requests will be unauthenticated")

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def list_inbounds(self) -> Dict:
        logger.info("Fetching inbounds list")
        resp = self.session.get(self._url("panel/api/inbounds/list"), headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"Retrieved {len(data.get('obj', []))} inbounds")
        return data

    def add_inbound(self, inbound_config: Dict) -> Dict:
        logger.info(f"Adding new inbound on port {inbound_config.get('port')}")
        payload = {
            "up":             inbound_config.get("up", 0),
            "down":           inbound_config.get("down", 0),
            "total":          inbound_config.get("total", 0),
            "remark":         inbound_config.get("remark", ""),
            "enable":         inbound_config.get("enable", True),
            "expiryTime":     inbound_config.get("expiryTime", 0),
            "listen":         inbound_config.get("listen", ""),
            "port":           inbound_config.get("port"),
            "protocol":       inbound_config.get("protocol"),
            "settings":       json.dumps(inbound_config.get("settings", {})),
            "streamSettings": json.dumps(inbound_config.get("streamSettings", {})),
            "sniffing":       json.dumps(inbound_config.get("sniffing", {})),
        }
        resp = self.session.post(
            self._url("panel/api/inbounds/add"),
            json=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    def delete_inbound(self, inbound_id: int) -> Dict:
        logger.info(f"Deleting inbound {inbound_id}")
        resp = self.session.post(
            self._url(f"panel/api/inbounds/del/{inbound_id}"),
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    def add_user(self, inbound_id: int, email: str, uuid: str = None,
                 limit_ip: int = 0, total_gb: int = 0, expiry_time: int = 0) -> Dict:
        import uuid as uuid_lib
        user_config = {
            "id":         uuid or str(uuid_lib.uuid4()),
            "flow":       "",
            "email":      email,
            "limitIp":    limit_ip,
            "totalGB":    total_gb,
            "expiryTime": expiry_time,
            "enable":     True,
            "tgId":       "",
            "subId":      "",
            "comment":    "",
            "reset":      0,
        }
        logger.info(f"Adding user '{email}' to inbound {inbound_id}")
        try:
            resp = self.session.post(
                self._url("panel/api/inbounds/addClient"),
                data={"id": inbound_id, "settings": json.dumps({"clients": [user_config]})},
            )
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Failed to add user to inbound {inbound_id}: {e}")
            return {"success": False, "msg": f"HTTP {resp.status_code}: {e}"}
        try:
            data = resp.json()
        except Exception:
            data = {"success": resp.status_code == 200, "status_code": resp.status_code}
        if data.get("success"):
            logger.info(f"User added successfully to inbound {inbound_id}")
        return data

    def remove_user(self, inbound_id: int, client_uuid: str) -> Dict:
        logger.info(f"Removing client '{client_uuid}' from inbound {inbound_id}")
        try:
            resp = self.session.post(
                self._url(f"panel/api/inbounds/{inbound_id}/delClient/{client_uuid}"),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Failed to remove user {client_uuid}: {e}")
            return {"success": False, "msg": f"HTTP {resp.status_code}: {e}"}
        try:
            data = resp.json()
        except Exception:
            data = {"success": resp.status_code == 200, "status_code": resp.status_code}
        if data.get("success"):
            logger.info(f"User '{client_uuid}' removed successfully")
        return data

    def get_inbound_users(self, inbound_id: int) -> List[Dict]:
        inbounds = self.list_inbounds()
        clients = []
        if inbounds.get("success") and inbounds.get("obj"):
            for obj in inbounds["obj"]:
                if obj.get("id") == inbound_id:
                    settings = obj.get("settings", {})
                    if isinstance(settings, str):
                        settings = json.loads(settings)
                    clients = settings.get("clients", [])
                    break
        logger.info(f"Found {len(clients)} users in inbound {inbound_id}")
        return clients


# ── Singleton client ─────────────────────────────────────────────────────────
_xray_client: Optional[XUIClient] = None

def _get_client() -> XUIClient:
    """Return the singleton XUIClient, creating it on first call."""
    global _xray_client
    if _xray_client is None:
        _xray_client = XUIClient()
    return _xray_client

def get_xray_client() -> XUIClient:
    """Public accessor for the singleton client."""
    return _get_client()

def _api_call(fn, *args, **kwargs):
    """Execute an XUI API call, letting errors propagate to the caller."""
    return fn(*args, **kwargs)


# ── Backward-compat wrappers ─────────────────────────────────────────────────
_tag_cache: Dict[str, int] = {}

def _get_inbound_id(tag: str) -> Optional[int]:
    if tag in _tag_cache:
        return _tag_cache[tag]
    data = _api_call(lambda: get_xray_client().list_inbounds())
    if not data.get("success"):
        return None
    for ib in data.get("obj", []):
        if ib.get("tag") == tag:
            _tag_cache[tag] = ib["id"]
            return ib["id"]
    return None

def list_inbounds() -> list[dict]:
    data = _api_call(lambda: get_xray_client().list_inbounds())
    return data.get("obj", []) if data.get("success") else []

def add_inbound(inbound: dict) -> tuple[bool, str]:
    result = _api_call(lambda: get_xray_client().add_inbound(inbound))
    if not result.get("success"):
        return False, result.get("msg", "Failed to add inbound")
    _tag_cache.clear()
    return True, "ok"

def remove_inbound(tag: str) -> tuple[bool, str]:
    inbound_id = _get_inbound_id(tag)
    if not inbound_id:
        return False, f"inbound '{tag}' not found"
    result = _api_call(lambda: get_xray_client().delete_inbound(inbound_id))
    if not result.get("success"):
        return False, result.get("msg", "Failed to remove inbound")
    _tag_cache.pop(tag, None)
    return True, "ok"

def list_users(tag: str) -> list[dict]:
    inbound_id = _get_inbound_id(tag)
    if not inbound_id:
        return []
    return _api_call(lambda: get_xray_client().get_inbound_users(inbound_id))

def add_user(tag: str, email: str, *, uid: str = None, password: str = None,
             flow: str = "", alter_id: int = 0) -> tuple[bool, str, str]:
    if not uid:
        import uuid as uuid_lib
        uid = str(uuid_lib.uuid4())
    inbound_id = _get_inbound_id(tag)
    if not inbound_id:
        return False, "", f"inbound '{tag}' not found"
    result = _api_call(lambda: get_xray_client().add_user(inbound_id, email, uid))
    if not result.get("success"):
        return False, "", result.get("msg", "Failed to add user")
    return True, uid, ""

def remove_user(tag: str, email: str) -> tuple[bool, str]:
    inbound_id = _get_inbound_id(tag)
    if not inbound_id:
        return False, f"inbound '{tag}' not found"
    users = _api_call(lambda: get_xray_client().get_inbound_users(inbound_id))
    client_uuid = None
    for u in users:
        em = u.get("email", "")
        if em == email or em == f"{email}@{tag}":
            client_uuid = u.get("id")
            break
    if not client_uuid:
        return False, f"user '{email}' not found"
    result = _api_call(lambda: get_xray_client().remove_user(inbound_id, client_uuid))
    if not result.get("success"):
        return False, result.get("msg", "Failed to remove user")
    return True, "ok"

def sync_users_to_inbound(tag: str, active_users: list[dict]) -> bool:
    logger.warning("sync_users_to_inbound disabled for XUI panel")
    return False

def init(config: dict):
    pass
        
