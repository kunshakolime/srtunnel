"""
helpers/xray.py  —  Xray config helper.

Simplified version that manages config.json and triggers reloads
when configuration changes, instead of using Xray's runtime API.
"""

import json
import logging
import os
import uuid
from copy import deepcopy

logger = logging.getLogger(__name__)

# ── Module-level config (populated by init) ───────────────────────────────────

_cfg: dict = {}


def init(config: dict):
    _cfg.update(config)


def _c(key, default=None):
    return _cfg.get(key, default)


def _config_path() -> str:
    return _c("XRAY_CONFIG")


# ── JSON config helpers ───────────────────────────────────────────────────────

def read_config() -> dict:
    """Load xray config.json. Returns {} on missing/error."""
    try:
        with open(_config_path(), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error("xray read_config '%s': %s", _config_path(), e)
        return {}


def write_config(data: dict) -> bool:
    """Atomically write xray config.json."""
    path = _config_path()
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.error("xray write_config '%s': %s", path, e)
        return False


def _trigger_reload():
    """Trigger Xray service reload after config changes."""
    try:
        from helpers import services
        ok, detail = services.watcher.reload_service("xray")
        if ok:
            logger.info("xray config changed, service reloaded: %s", detail)
        else:
            logger.warning("xray config changed but reload failed: %s", detail)
    except Exception as e:
        logger.error("xray reload trigger failed: %s", e)


def add_inbound(inbound: dict) -> tuple[bool, str]:
    """
    Add an inbound to config.json and trigger reload.
    `inbound` must be a full Xray inbound object with at least a `tag`.
    """
    tag = inbound.get("tag")
    if not tag:
        return False, "inbound must have a tag"

    # Persist to config
    cfg = read_config()
    inbounds = cfg.setdefault("inbounds", [])
    # Replace if tag already exists
    cfg["inbounds"] = [i for i in inbounds if i.get("tag") != tag]
    cfg["inbounds"].append(inbound)
    if not write_config(cfg):
        return False, "failed to write config"

    # Trigger reload
    _trigger_reload()

    logger.info("xray add_inbound: tag=%s port=%s", tag, inbound.get("port"))
    return True, "ok"


def remove_inbound(tag: str) -> tuple[bool, str]:
    """Remove an inbound by tag from config.json and trigger reload."""
    # Persist to config
    cfg = read_config()
    before = len(cfg.get("inbounds", []))
    cfg["inbounds"] = [i for i in cfg.get("inbounds", []) if i.get("tag") != tag]
    if len(cfg["inbounds"]) == before:
        return False, f"inbound '{tag}' not found in config"
    if not write_config(cfg):
        return False, "failed to write config"

    # Trigger reload
    _trigger_reload()

    logger.info("xray remove_inbound: tag=%s", tag)
    return True, "ok"


def list_inbounds() -> list[dict]:
    """Return the inbounds array from config.json (source of truth)."""
    return read_config().get("inbounds", [])


# ── User management ───────────────────────────────────────────────────────────

def _make_vless_client(uid: str, email: str, flow: str = "") -> dict:
    client = {"id": uid, "email": email}
    if flow:
        client["flow"] = flow
    return client


def _make_vmess_client(uid: str, email: str, alter_id: int = 0) -> dict:
    return {"id": uid, "email": email, "alterId": alter_id}


def _make_trojan_client(password: str, email: str) -> dict:
    return {"password": password, "email": email}


def add_user(
    tag: str,
    email: str,
    *,
    uid: str | None = None,
    password: str | None = None,
    flow: str = "",
    alter_id: int = 0,
) -> tuple[bool, str, str]:
    """
    Add a user to an existing inbound in config.json and trigger reload.

    - For VLESS/VMess: pass uid (generated if omitted).
    - For Trojan:      pass password.
    - email is used as the unique identifier in Xray stats/logs.

    Returns (success, uid_or_password, error_msg).
    """
    # Find the inbound by tag
    inbounds = list_inbounds()
    inbound = next((i for i in inbounds if i.get("tag") == tag), None)
    if inbound is None:
        return False, "", f"inbound '{tag}' not found in config"

    protocol = inbound.get("protocol", "").lower()

    if protocol == "trojan":
        if not password:
            return False, "", "trojan users require a password"
        client = _make_trojan_client(password, email)
        identifier = password
    elif protocol == "vmess":
        uid = uid or str(uuid.uuid4())
        client = _make_vmess_client(uid, email, alter_id)
        identifier = uid
    else:
        # Default: treat as VLESS
        uid = uid or str(uuid.uuid4())
        client = _make_vless_client(uid, email, flow)
        identifier = uid

    # Persist to config
    cfg = read_config()
    found = False
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == tag:
            clients = ib.setdefault("settings", {}).setdefault("clients", [])
            # Remove existing entry for same email to avoid duplication
            ib["settings"]["clients"] = [c for c in clients if c.get("email") != email]
            ib["settings"]["clients"].append(client)
            found = True
            break
    
    if not found:
        return False, "", f"inbound '{tag}' not in config.json"
    
    if not write_config(cfg):
        return False, "", "failed to write config.json"

    # Trigger reload
    _trigger_reload()

    logger.info("xray add_user: tag=%s email=%s protocol=%s", tag, email, protocol)
    return True, identifier, ""


def remove_user(tag: str, email: str) -> tuple[bool, str]:
    """Remove a user (by email) from an inbound in config.json and trigger reload."""
    # Persist to config
    cfg = read_config()
    found = False
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == tag:
            clients = ib.get("settings", {}).get("clients", [])
            before = len(clients)
            ib["settings"]["clients"] = [c for c in clients if c.get("email") != email]
            after = len(ib["settings"]["clients"])
            found = True
            break
    
    if not found:
        return False, f"inbound '{tag}' not found in config.json"
    
    if not write_config(cfg):
        return False, "failed to write config.json"

    # Trigger reload
    _trigger_reload()

    logger.info("xray remove_user: tag=%s email=%s", tag, email)
    return True, "ok"


def list_users(tag: str) -> list[dict]:
    """Return clients list for an inbound from config.json."""
    inbounds = list_inbounds()
    inbound = next((i for i in inbounds if i.get("tag") == tag), None)
    if not inbound:
        return []
    return inbound.get("settings", {}).get("clients", [])


def user_exists(tag: str, email: str) -> bool:
    return any(c.get("email") == email for c in list_users(tag))


# ── Convenience builders ──────────────────────────────────────────────────────

def build_vless_inbound(
    tag: str,
    port: int,
    *,
    listen: str = "0.0.0.0",
    network: str = "tcp",
    security: str = "none",    # "none" | "tls" | "reality"
    tls_settings: dict | None = None,
    reality_settings: dict | None = None,
    header_type: str = "none",
) -> dict:
    """Return a ready-to-use VLESS inbound dict."""
    stream: dict = {"network": network}
    if security != "none":
        stream["security"] = security
        if security == "tls" and tls_settings:
            stream["tlsSettings"] = tls_settings
        elif security == "reality" and reality_settings:
            stream["realitySettings"] = reality_settings
    if header_type != "none":
        stream["tcpSettings"] = {"header": {"type": header_type}}

    return {
        "tag": tag,
        "protocol": "vless",
        "listen": listen,
        "port": port,
        "settings": {
            "clients": [],
            "decryption": "none",
        },
        "streamSettings": stream,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def build_vmess_inbound(
    tag: str,
    port: int,
    *,
    listen: str = "0.0.0.0",
    network: str = "tcp",
    alter_id: int = 0,
) -> dict:
    """Return a ready-to-use VMess inbound dict."""
    return {
        "tag": tag,
        "protocol": "vmess",
        "listen": listen,
        "port": port,
        "settings": {
            "clients": [],
            "defaultPolicy": {"alterId": alter_id, "uplinkOnly": 0, "downlinkOnly": 0},
        },
        "streamSettings": {"network": network},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def build_trojan_inbound(
    tag: str,
    port: int,
    *,
    listen: str = "0.0.0.0",
    network: str = "tcp",
    tls_settings: dict | None = None,
) -> dict:
    """Return a ready-to-use Trojan inbound dict."""
    stream: dict = {"network": network}
    if tls_settings:
        stream["security"] = "tls"
        stream["tlsSettings"] = tls_settings
    return {
        "tag": tag,
        "protocol": "trojan",
        "listen": listen,
        "port": port,
        "settings": {"clients": []},
        "streamSettings": stream,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


# ── DB-integrated sync (called by core.sync) ──────────────────────────────────

def sync_users_to_inbound(tag: str, active_users: list[dict]) -> bool:
    """
    Reconcile an inbound's client list against active_users from the DB.

    active_users: list of dicts with keys: username, password, uid (optional)

    - Users in active_users but not in inbound → added
    - Users in inbound but not in active_users → removed

    Uses email = username as the unique key.
    """
    logger.info("xray sync_users_to_inbound: tag=%s, %d active users from DB", tag, len(active_users))
    
    # Find the inbound by tag
    inbounds = list_inbounds()
    inbound = next((i for i in inbounds if i.get("tag") == tag), None)
    if inbound is None:
        logger.error("xray sync_users_to_inbound: inbound '%s' not found in config", tag)
        return False

    protocol = inbound.get("protocol", "vless").lower()
    existing_emails = {c.get("email") for c in list_users(tag)}
    target_emails   = {u["username"] for u in active_users}
    
    logger.debug("xray sync_users_to_inbound: protocol=%s, existing=%s, target=%s", protocol, existing_emails, target_emails)

    # Add missing
    for user in active_users:
        email = user["username"]
        if email not in existing_emails:
            logger.debug("xray sync_users_to_inbound: adding %s", email)
            if protocol == "trojan":
                ok, _, err = add_user(tag, email, password=user["password"])
            else:
                ok, _, err = add_user(tag, email, uid=user.get("uid"))
            if not ok:
                logger.error("xray sync: failed to add %s to %s: %s", email, tag, err)
            else:
                logger.debug("xray sync: successfully added %s to %s", email, tag)
        else:
            logger.debug("xray sync_users_to_inbound: %s already exists", email)

    # Remove stale
    for email in existing_emails - target_emails:
        logger.debug("xray sync_users_to_inbound: removing %s", email)
        ok, err = remove_user(tag, email)
        if not ok:
            logger.warning("xray sync: failed to remove %s from %s: %s", email, tag, err)
        else:
            logger.debug("xray sync: successfully removed %s from %s", email, tag)
    
    logger.info("xray sync_users_to_inbound: complete")
    return True