import requests
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

# json is already imported above

# Configure logging for easier debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class XUIClient:
    """
    XUI Panel API Client - handles authentication and API calls
    """

    DEFAULT_BASE_URL = "https://your3xuidash.com:2053/OeggdfgaOuuDkvs"
    DEFAULT_USERNAME = "user"
    DEFAULT_PASSWORD = "pass"

    def __init__(self, base_url: str = None, verify_ssl: bool = False, debug: bool = False):
        """
        Initialize XUI client.
        
        Args:
            base_url: The base URL of your XUI panel
            verify_ssl: Whether to verify SSL certificates (default: False)
            debug: Enable debug logging (default: False)
        """
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/") + "/"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.debug = debug
        
        if debug:
            logger.setLevel(logging.DEBUG)

    def _url(self, path: str) -> str:
        """Construct full URL from path"""
        return urljoin(self.base_url, path.lstrip("/"))

    def _log_response(self, response: requests.Response, label: str = "Response"):
        """Helper to log response details for debugging"""
        if self.debug:
            logger.debug(f"{label} - Status: {response.status_code}")
            logger.debug(f"{label} - Headers: {dict(response.headers)}")
            try:
                logger.debug(f"{label} - Body: {response.json()}")
            except:
                logger.debug(f"{label} - Body: {response.text}")

    # ==================== Authentication ====================

    def login(self, username: str, password: str, two_factor_code: str = "") -> Dict:
        """
        Logs in and stores cookies in the session.
        
        Args:
            username: Login username
            password: Login password
            two_factor_code: Optional 2FA code
            
        Returns:
            Dict with 'success' status and login response data
            
        Raises:
            RuntimeError: If login fails
        """
        payload = {
            "username": username,
            "password": password,
            "twoFactorCode": two_factor_code
        }

        logger.info(f"Attempting login for user: {username}")
        
        resp = self.session.post(
            self._url("login/"),
            data=payload,
            allow_redirects=True
        )

        self._log_response(resp, "Login")
        resp.raise_for_status()
        data = resp.json()

        if not data.get("success"):
            raise RuntimeError(f"Login failed: {data}")

        logger.info("Login successful")
        return {
            "success": True,
            "data": data,
            "cookies": self.session.cookies.get_dict()
        }

    # ==================== Inbounds Management ====================

    def list_inbounds(self) -> Dict:
        """
        Get list of all inbounds.
        
        Returns:
            API response with list of inbounds
        """
        logger.info("Fetching inbounds list")
        
        resp = self.session.get(
            self._url("panel/api/inbounds/list"),
            headers={"Accept": "application/json"}
        )

        self._log_response(resp, "List Inbounds")
        resp.raise_for_status()
        data = resp.json()
        
        logger.info(f"Retrieved {len(data.get('obj', []))} inbounds")
        return data

    def get_inbound(self, inbound_id: int) -> Dict:
        """
        Get details of a specific inbound.
        
        Args:
            inbound_id: The inbound ID
            
        Returns:
            API response with inbound details
        """
        logger.info(f"Fetching inbound {inbound_id}")
        
        resp = self.session.get(
            self._url(f"panel/api/inbounds/{inbound_id}"),
            headers={"Accept": "application/json"}
        )

        self._log_response(resp, f"Get Inbound {inbound_id}")
        resp.raise_for_status()
        return resp.json()

    def add_inbound(self, inbound_config: Dict) -> Dict:
        """
        Add a new inbound.
        
        Args:
            inbound_config: Dictionary with inbound configuration
                Required fields typically include:
                - port: int
                - protocol: str (vless, vmess, ss, trojan, etc.)
                - settings: dict
                - streamSettings: dict
                - sniffing: dict (optional)
                - tag: str
                
        Returns:
            API response with created inbound details
        """
        logger.info(f"Adding new inbound on port {inbound_config.get('port')}")
        
        payload = {
            "up": inbound_config.get("up", 0),
            "down": inbound_config.get("down", 0),
            "total": inbound_config.get("total", 0),
            "remark": inbound_config.get("remark", ""),
            "enable": inbound_config.get("enable", True),
            "expiryTime": inbound_config.get("expiryTime", 0),
            "listen": inbound_config.get("listen", ""),
            "port": inbound_config.get("port"),
            "protocol": inbound_config.get("protocol"),
            "settings": json.dumps(inbound_config.get("settings", {})),
            "streamSettings": json.dumps(inbound_config.get("streamSettings", {})),
            "sniffing": json.dumps(inbound_config.get("sniffing", {}))
        }
        
        resp = self.session.post(
            self._url("panel/api/inbounds/add"),
            json=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )

        self._log_response(resp, "Add Inbound")
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("success"):
            logger.info(f"Inbound created successfully: {data.get('obj')}")
        
        return data

    def update_inbound(self, inbound_id: int, inbound_config: Dict) -> Dict:
        """
        Update an existing inbound.
        
        Args:
            inbound_id: The inbound ID
            inbound_config: Updated inbound configuration
            
        Returns:
            API response with updated inbound details
        """
        logger.info(f"Updating inbound {inbound_id}")
        
        resp = self.session.post(
            self._url(f"panel/api/inbounds/{inbound_id}/update"),
            headers={"Accept": "application/json"},
            files={"data": (None, json.dumps(inbound_config), "application/json")}
        )

        self._log_response(resp, f"Update Inbound {inbound_id}")
        resp.raise_for_status()
        return resp.json()

    def delete_inbound(self, inbound_id: int) -> Dict:
        """
        Delete an inbound.
        
        Args:
            inbound_id: The inbound ID
            
        Returns:
            API response
        """
        logger.info(f"Deleting inbound {inbound_id}")
        
        resp = self.session.post(
            self._url(f"panel/api/inbounds/del/{inbound_id}"),
            headers={"Accept": "application/json"}
        )

        self._log_response(resp, f"Delete Inbound {inbound_id}")
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("success"):
            logger.info(f"Inbound {inbound_id} deleted successfully")
        
        return data

    # ==================== User Management ====================

    def add_user(self, inbound_id: int, email: str, uuid: str = None, limit_ip: int = 0, total_gb: int = 0, expiry_time: int = 0) -> Dict:
        import uuid as uuid_lib

        user_config = {
            "id": uuid or str(uuid_lib.uuid4()),
            "flow": "",
            "email": email,
            "limitIp": limit_ip,
            "totalGB": total_gb,
            "expiryTime": expiry_time,
            "enable": True,
            "tgId": "",
            "subId": "",
            "comment": "",
            "reset": 0
        }
        
        logger.info(f"Adding user '{email}' to inbound {inbound_id}")
        
        resp = self.session.post(
            self._url(f"panel/api/inbounds/{inbound_id}/addClient"),
            data={
                "id": inbound_id,
                "settings": json.dumps({
                    "clients": [user_config]
                })
            }
        )

        self._log_response(resp, "Add User")
        resp.raise_for_status()
        
        try:
            data = resp.json()
        except:
            # Some responses may not be JSON
            data = {"success": resp.status_code == 200, "status_code": resp.status_code}
        
        if data.get("success"):
            logger.info(f"User added successfully to inbound {inbound_id}")
        
        return data

    def remove_user(self, inbound_id: int, client_uuid: str) -> Dict:
        """
        Remove a user from an inbound.
        
        Args:
            inbound_id: The inbound ID
            client_uuid: The client's UUID
            
        Returns:
            API response
        """
        logger.info(f"Removing client '{client_uuid}' from inbound {inbound_id}")
        
        resp = self.session.post(
            self._url(f"panel/api/inbounds/{inbound_id}/delClient/{client_uuid}"),
            headers={"Accept": "application/json"}
        )

        self._log_response(resp, "Remove User")
        resp.raise_for_status()
        
        try:
            data = resp.json()
        except:
            data = {"success": resp.status_code == 200, "status_code": resp.status_code}
        
        if data.get("success"):
            logger.info(f"User '{client_uuid}' removed successfully")
        
        return data

    def update_user(self, inbound_id: int, client_uuid: str, user_updates: Dict) -> Dict:
        """
        Update a user in an inbound.
        
        Args:
            inbound_id: The inbound ID
            client_uuid: The client's UUID
            user_updates: Fields to update (will merge with existing client data)
            
        Returns:
            API response
        """
        logger.info(f"Updating client '{client_uuid}' in inbound {inbound_id}")
        
        inbound = self.get_inbound(inbound_id)
        if not inbound.get("success"):
            raise RuntimeError(f"Failed to fetch inbound {inbound_id}")
        
        inbound_obj = inbound.get("obj", {})
        clients = []
        user_found = False
        
        if "settings" in inbound_obj and "clients" in inbound_obj["settings"]:
            clients = inbound_obj["settings"]["clients"]
            
            for client in clients:
                if client.get("id") == client_uuid:
                    client.update(user_updates)
                    user_found = True
                    break
        
        if not user_found:
            raise RuntimeError(f"Client '{client_uuid}' not found in inbound {inbound_id}")
        
        resp = self.session.post(
            self._url(f"panel/api/inbounds/{inbound_id}/updateClient"),
            data={
                "id": inbound_id,
                "settings": json.dumps({
                    "clients": clients
                })
            }
        )

        self._log_response(resp, "Update User")
        resp.raise_for_status()
        
        try:
            data = resp.json()
        except:
            data = {"success": resp.status_code == 200, "status_code": resp.status_code}
        
        if data.get("success"):
            logger.info(f"Client '{client_uuid}' updated successfully")
        
        return data

    # ==================== Utility Methods ====================

    def get_session_cookies(self) -> Dict:
        """Get current session cookies"""
        return self.session.cookies.get_dict()

    def set_session_cookies(self, cookies: Dict):
        """Restore session from saved cookies"""
        self.session.cookies.update(cookies)
        logger.info("Session cookies restored")

    def get_inbound_users(self, inbound_id: int) -> List[Dict]:
        """
        Get all users in an inbound.
        
        Args:
            inbound_id: The inbound ID
            
        Returns:
            List of users in the inbound
        """
        inbounds = self.list_inbounds()
        
        clients = []
        if inbounds.get("success") and inbounds.get("obj"):
            for obj in inbounds["obj"]:
                if obj.get("id") == inbound_id:
                    settings = obj.get("settings", {})
                    if isinstance(settings, str):
                        settings = json.loads(settings)
                    if "clients" in settings:
                        clients = settings["clients"]
                    break
        
        logger.info(f"Found {len(clients)} users in inbound {inbound_id}")
        return clients


def create_user_config(email: str, user_id: str = None) -> Dict:
    """Create a user configuration dict"""
    import uuid as uuid_lib
    
    return {
        "id": user_id or str(uuid_lib.uuid4()),
        "flow": "",
        "email": email,
        "limitIp": 0,
        "totalGB": 0,
        "expiryTime": 0,
        "enable": True,
        "tgId": "",
        "subId": "",
        "comment": "",
        "reset": 0
    }


def create_vless_inbound(port: int, tag: str = "vless-in") -> Dict:
    """Create a VLESS inbound configuration"""
    return {
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "none"
        },
        "sniffing": {
            "enabled": False,
            "destOverride": ["http", "tls"]
        },
        "tag": tag,
        "listen": ""
    }


def create_vmess_inbound(port: int, tag: str = "vmess-in") -> Dict:
    """Create a VMess inbound configuration"""
    return {
        "port": port,
        "protocol": "vmess",
        "settings": {
            "clients": [],
            "alterId": 0
        },
        "streamSettings": {
            "network": "tcp",
            "security": "none"
        },
        "sniffing": {
            "enabled": False,
            "destOverride": ["http", "tls"]
        },
        "tag": tag,
        "listen": ""
    }


# ── Wrapper for backward compatibility with old xray.py API ──────────────────
# Uses tag-based string identifiers; maps to inbound_id internally

_tag_to_inbound_id_cache = {}

def _get_or_cache_inbound_id(client: XUIClient, tag: str) -> Optional[int]:
    """Convert tag to inbound_id, using cache when possible."""
    if tag in _tag_to_inbound_id_cache:
        return _tag_to_inbound_id_cache[tag]

    inbounds = client.list_inbounds()
    if not inbounds.get("success"):
        return None

    for ib in inbounds.get("obj", []):
        if ib.get("tag") == tag:
            _tag_to_inbound_id_cache[tag] = ib.get("id")
            return ib.get("id")
    return None

def list_inbounds() -> list[dict]:
    """List all inbounds (backward compat)."""
    client = XUIClient()
    client.login("root", "xboxx321")
    data = client.list_inbounds()
    if not data.get("success"):
        return []
    return data.get("obj", [])

def add_inbound(inbound: dict) -> tuple[bool, str]:
    """Add an inbound (backward compat)."""
    client = XUIClient()
    client.login("root", "xboxx321")
    result = client.add_inbound(inbound)
    if not result.get("success"):
        return False, result.get("msg", "Failed to add inbound")
    _tag_to_inbound_id_cache.clear()
    return True, "ok"

def remove_inbound(tag: str) -> tuple[bool, str]:
    """Remove an inbound by tag (backward compat)."""
    client = XUIClient()
    client.login("root", "xboxx321")
    inbound_id = _get_or_cache_inbound_id(client, tag)
    if not inbound_id:
        return False, f"inbound '{tag}' not found"
    result = client.delete_inbound(inbound_id)
    if not result.get("success"):
        return False, result.get("msg", "Failed to remove inbound")
    _tag_to_inbound_id_cache.pop(tag, None)
    return True, "ok"

def list_users(tag: str) -> list[dict]:
    """List users for an inbound by tag (backward compat)."""
    client = XUIClient()
    client.login("root", "xboxx321")
    inbound_id = _get_or_cache_inbound_id(client, tag)
    if not inbound_id:
        return []
    return client.get_inbound_users(inbound_id)

def add_user(
    tag: str,
    email: str,
    *,
    uid: str | None = None,
    password: str | None = None,
    flow: str = "",
    alter_id: int = 0,
) -> tuple[bool, str, str]:
    """Add a user to an inbound by tag (backward compat)."""
    import uuid as uuid_lib
    client = XUIClient()
    client.login("root", "xboxx321")
    inbound_id = _get_or_cache_inbound_id(client, tag)
    if not inbound_id:
        return False, "", f"inbound '{tag}' not found"

    result = client.add_user(inbound_id, email, uid or str(uuid_lib.uuid4()))
    if not result.get("success"):
        return False, "", result.get("msg", "Failed to add user")
    return True, uid or "", ""

def remove_user(tag: str, email: str) -> tuple[bool, str]:
    """Remove a user from an inbound by tag (backward compat)."""
    client = XUIClient()
    client.login("root", "xboxx321")
    inbound_id = _get_or_cache_inbound_id(client, tag)
    if not inbound_id:
        return False, f"inbound '{tag}' not found"

    # Find the user's client_uuid from the inbound
    users = client.get_inbound_users(inbound_id)
    client_uuid = None
    for u in users:
        if u.get("email") == email:
            client_uuid = u.get("id")
            break

    if not client_uuid:
        return False, f"user '{email}' not found"

    result = client.remove_user(inbound_id, client_uuid)
    if not result.get("success"):
        return False, result.get("msg", "Failed to remove user")
    return True, "ok"

def sync_users_to_inbound(tag: str, active_users: list[dict]) -> bool:
    """Sync users to an inbound by tag (backward compat)."""
    client = XUIClient()
    client.login("root", "xboxx321")
    inbound_id = _get_or_cache_inbound_id(client, tag)
    if not inbound_id:
        logger.error("sync_users_to_inbound: inbound '%s' not found", tag)
        return False

    existing = client.get_inbound_users(inbound_id)
    existing_emails = {u.get("email") for u in existing}
    target_emails = {u.get("username") for u in active_users}

    for email in target_emails - existing_emails:
        client.add_user(inbound_id, email)
        logger.info("sync_users_to_inbound: added %s", email)

    for email in existing_emails - target_emails:
        for u in existing:
            if u.get("email") == email:
                client.remove_user(inbound_id, u.get("id"))
                logger.info("sync_users_to_inbound: removed %s", email)
                break

    logger.info("sync_users_to_inbound: complete")
    return True

def init(config: dict):
    """No-op for compatibility with old init()."""
    pass