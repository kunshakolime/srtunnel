import sys, json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from typing import Annotated, Optional, Dict
from fastapi import Depends
from helpers.auth import get_current_user

CurrentUser = Annotated[str, Depends(get_current_user)]

# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    import yaml
    # support both old root and new configs/ location
    path = BASE_DIR / "configs" / "config.yaml"
    if not path.exists():
        path = BASE_DIR / "config.yaml"
    if not path.exists():
        raise RuntimeError(f"Missing config file: {path}")
    app = (yaml.safe_load(path.read_text()) or {}).get("telegram_bot", {})
    return {
        "DB_FILE":          app.get("db_file", "users.db"),
        "CONFIG_FILE":      app.get("config_file", "./configs/zivpn.json"),
        "DEFAULT_PASSWORD": app.get("default_password", "123"),
        "DOMAIN":           app.get("domain", ""),
        "DNSTT":            app.get("dnstt", ""),
        "KEY":              app.get("slowdnskey", ""),
        "IFACE":            app.get("interface", "eth0"),
        "CF_TOKEN":         app.get("cf_token", ""),
        "CF_ZONE":          app.get("cf_zone", ""),
        "CF_ROOT_DOMAIN":   app.get("cf_root_domain", ""),
        "XRAY_INBOUND_TAG": app.get("xray_inbound_tag", "xray-vless"),
        "XRAY_CONFIG":      app.get("xray_config", str(BASE_DIR / "configs" / "xray.json")),
        "XRAY_API_PORT":    app.get("xray_api_port", 10085),
        "XRAY_BINARY":      app.get("xray_binary", str(BASE_DIR / "bin" / "xray")),
    }

cfg = load_config()

# ── Scope / Serverlist ────────────────────────────────────────────────────────

SCOPE_FILE      = BASE_DIR / "helpers" / "scope.json"
SERVERLIST_FILE = BASE_DIR / "helpers" / "serverlist.json"

def load_scope():
    return json.loads(SCOPE_FILE.read_text()) if SCOPE_FILE.exists() else {}

def save_scope(data):
    SCOPE_FILE.write_text(json.dumps(data, indent=2))

def load_serverlist():
    return json.loads(SERVERLIST_FILE.read_text()) if SERVERLIST_FILE.exists() else []

def save_serverlist(data):
    SERVERLIST_FILE.write_text(json.dumps(data, indent=2))
