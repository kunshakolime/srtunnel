"""
helpers/xray.py  —  Xray runtime + config helper.

How it works
────────────
Xray exposes a local gRPC API via a special inbound in its config:

    {
      "tag": "api",
      "protocol": "dokodemo-door",
      "listen": "127.0.0.1",
      "port": 10085,        ← XRAY_API_PORT in your config.yaml
      "settings": { "address": "127.0.0.1" }
    }

    "api": {
      "tag": "api",
      "services": ["HandlerService", "StatsService", "LoggerService"]
    }

    "routing": {
      "rules": [{ "inboundTag": ["api"], "outboundTag": "api" }]
    }

The `xray api` CLI sub-commands talk to that gRPC port to add/remove
inbounds and users at runtime — no restart needed.

This helper also keeps the JSON config file in sync so that changes
survive a restart.  Every mutating call does:
  1. Mutate the running Xray process via `xray api …`  (runtime)
  2. Patch the JSON config file                        (persistence)

Config keys expected in cfg (set by core.init):
  XRAY_CONFIG   path to xray config JSON   default: /usr/local/etc/xray/config.json
  XRAY_API_PORT gRPC API port              default: 10085
  XRAY_BINARY   path to xray binary        default: xray   (must be on PATH)
"""

import json
import logging
import os
import subprocess
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
    return _c("XRAY_CONFIG", "/root/srtunnel/xray.json")


def _api_port() -> int:
    return int(_c("XRAY_API_PORT", 10085))


def _binary() -> str:
    return _c("XRAY_BINARY", "/root/srtunnel/xray-linux-arm64")


# ── JSON config helpers ───────────────────────────────────────────────────────

def read_config() -> dict:
    """Load xray config.json. Returns {} on missing/error."""
    try:
        with open(_config_path()) as f:
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
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.error("xray write_config '%s': %s", path, e)
        return False


# ── gRPC / CLI wrappers ───────────────────────────────────────────────────────

def _xray_api(*args, input_json: dict | None = None) -> tuple[bool, str]:
    """
    Run:  xray api --server=127.0.0.1:<port> <args…>
    If input_json is given it is piped to stdin.
    Returns (success, stdout_or_stderr).
    """
    cmd = [_binary(), "api", f"--server=127.0.0.1:{_api_port()}", *args]
    try:
        result = subprocess.run(
            cmd,
            input=json.dumps(input_json).encode() if input_json else None,
            capture_output=True,
            timeout=10,
        )
        out = result.stdout.decode().strip()
        err = result.stderr.decode().strip()
        if result.returncode != 0:
            logger.warning("xray api %s failed (rc=%d): %s", " ".join(args), result.returncode, err or out)
            return False, err or out
        return True, out
    except FileNotFoundError:
        logger.error("xray binary not found at '%s'", _binary())
        return False, "xray binary not found"
    except subprocess.TimeoutExpired:
        logger.error("xray api call timed out: %s", " ".join(args))
        return False, "timeout"
    except Exception as e:
        logger.error("xray api unexpected error: %s", e)
        return False, str(e)


# ── Inbound management ────────────────────────────────────────────────────────

def list_inbounds() -> list[dict]:
    """Return the inbounds array from config.json (source of truth)."""
    return read_config().get("inbounds", [])


def get_inbound(tag: str) -> dict | None:
    """Find an inbound by tag."""
    return next((i for i in list_inbounds() if i.get("tag") == tag), None)


def add_inbound(inbound: dict) -> tuple[bool, str]:
    """
    Add an inbound at runtime and persist it to config.json.
    `inbound` must be a full Xray inbound object with at least a `tag`.

    Example inbound (VLESS + TCP):
        {
            "tag": "vless-443",
            "protocol": "vless",
            "listen": "0.0.0.0",
            "port": 443,
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": { "network": "tcp" }
        }
    """
    tag = inbound.get("tag")
    if not tag:
        return False, "inbound must have a tag"

    # 1. Runtime
    ok, msg = _xray_api("addinbound", "--json", input_json=inbound)
    if not ok:
        # Don't touch the file if runtime rejected it
        return False, msg

    # 2. Persist
    cfg = read_config()
    inbounds = cfg.setdefault("inbounds", [])
    # Replace if tag already exists in file (e.g. previous partial failure)
    cfg["inbounds"] = [i for i in inbounds if i.get("tag") != tag]
    cfg["inbounds"].append(inbound)
    if not write_config(cfg):
        logger.warning("xray add_inbound: runtime ok but config write failed for tag=%s", tag)
        return True, "added (config write failed — restart unsafe)"

    logger.info("xray add_inbound: tag=%s port=%s", tag, inbound.get("port"))
    return True, "ok"


def remove_inbound(tag: str) -> tuple[bool, str]:
    """Remove an inbound by tag at runtime and from config.json."""
    # 1. Runtime
    ok, msg = _xray_api("rminbound", tag)
    if not ok:
        return False, msg

    # 2. Persist
    cfg = read_config()
    before = len(cfg.get("inbounds", []))
    cfg["inbounds"] = [i for i in cfg.get("inbounds", []) if i.get("tag") != tag]
    if len(cfg["inbounds"]) == before:
        logger.warning("xray remove_inbound: tag=%s not in config file (was only in runtime?)", tag)
    write_config(cfg)

    logger.info("xray remove_inbound: tag=%s", tag)
    return True, "ok"


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
    Add a user to an existing inbound at runtime and persist.

    - For VLESS/VMess: pass uid (generated if omitted).
    - For Trojan:      pass password.
    - email is used as the unique identifier in Xray stats/logs.

    Returns (success, uid_or_password, error_msg).
    """
    inbound = get_inbound(tag)
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

    payload = {
        "tag": tag,
        "user": {
            "email": email,
            "level": 0,
            "uuid" if protocol != "trojan" else "password": identifier,
        }
    }
    if protocol == "vmess":
        payload["user"]["alterId"] = alter_id
    if flow:
        payload["user"]["flow"] = flow

    # 1. Runtime
    ok, msg = _xray_api("adduser", "--json", input_json=payload)
    if not ok:
        return False, "", msg

    # 2. Persist
    cfg = read_config()
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == tag:
            clients = ib.setdefault("settings", {}).setdefault("clients", [])
            # Remove existing entry for same email to avoid duplication
            ib["settings"]["clients"] = [c for c in clients if c.get("email") != email]
            ib["settings"]["clients"].append(client)
            break
    write_config(cfg)

    logger.info("xray add_user: tag=%s email=%s protocol=%s", tag, email, protocol)
    return True, identifier, ""


def remove_user(tag: str, email: str) -> tuple[bool, str]:
    """Remove a user (by email) from an inbound at runtime and from config.json."""
    # 1. Runtime
    ok, msg = _xray_api("rmuser", "--json", input_json={"tag": tag, "email": email})
    if not ok:
        return False, msg

    # 2. Persist
    cfg = read_config()
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == tag:
            clients = ib.get("settings", {}).get("clients", [])
            ib["settings"]["clients"] = [c for c in clients if c.get("email") != email]
            break
    write_config(cfg)

    logger.info("xray remove_user: tag=%s email=%s", tag, email)
    return True, "ok"


def list_users(tag: str) -> list[dict]:
    """Return clients list for an inbound from config.json."""
    inbound = get_inbound(tag)
    if not inbound:
        return []
    return inbound.get("settings", {}).get("clients", [])


def user_exists(tag: str, email: str) -> bool:
    return any(c.get("email") == email for c in list_users(tag))


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_user_stats(email: str, reset: bool = False) -> dict | None:
    """
    Query per-user traffic from Xray's StatsService.
    Returns {"uplink": bytes, "downlink": bytes} or None on failure.
    Requires StatsService enabled in xray config api block.
    """
    args = ["statsquery", f"--pattern=user>>>{email}>>>traffic"]
    if reset:
        args.append("--reset")
    ok, out = _xray_api(*args)
    if not ok or not out:
        return None
    try:
        data = json.loads(out)
        stats = {}
        for entry in data.get("stat", []):
            name: str = entry.get("name", "")
            value: int = entry.get("value", 0)
            if "uplink" in name:
                stats["uplink"] = value
            elif "downlink" in name:
                stats["downlink"] = value
        return stats
    except Exception as e:
        logger.warning("xray get_user_stats parse failed: %s", e)
        return None


def get_inbound_stats(tag: str, reset: bool = False) -> dict | None:
    """Query per-inbound traffic."""
    args = ["statsquery", f"--pattern=inbound>>>{tag}>>>traffic"]
    if reset:
        args.append("--reset")
    ok, out = _xray_api(*args)
    if not ok or not out:
        return None
    try:
        data = json.loads(out)
        stats = {}
        for entry in data.get("stat", []):
            name: str = entry.get("name", "")
            value: int = entry.get("value", 0)
            if "uplink" in name:
                stats["uplink"] = value
            elif "downlink" in name:
                stats["downlink"] = value
        return stats
    except Exception as e:
        logger.warning("xray get_inbound_stats parse failed: %s", e)
        return None


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
    inbound = get_inbound(tag)
    if inbound is None:
        logger.warning("xray sync_users_to_inbound: inbound '%s' not found", tag)
        return False

    protocol = inbound.get("protocol", "vless").lower()
    existing_emails = {c.get("email") for c in list_users(tag)}
    target_emails   = {u["username"] for u in active_users}

    # Add missing
    for user in active_users:
        email = user["username"]
        if email not in existing_emails:
            if protocol == "trojan":
                ok, _, err = add_user(tag, email, password=user["password"])
            else:
                ok, _, err = add_user(tag, email, uid=user.get("uid"))
            if not ok:
                logger.warning("xray sync: failed to add %s to %s: %s", email, tag, err)

    # Remove stale
    for email in existing_emails - target_emails:
        ok, err = remove_user(tag, email)
        if not ok:
            logger.warning("xray sync: failed to remove %s from %s: %s", email, tag, err)

    return True