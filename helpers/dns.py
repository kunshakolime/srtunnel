import subprocess
import logging
import requests

logger = logging.getLogger(__name__)

_cfg = {}

CF_API_BASE = "https://api.cloudflare.com/client/v4/zones"

RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"]

# Types that cannot be proxied through Cloudflare
NO_PROXY_TYPES = {"TXT", "MX", "AAAA"}


def init(cfg: dict):
    global _cfg
    _cfg = cfg


def _headers():
    return {
        "Authorization": f"Bearer {_cfg.get('CF_TOKEN', '')}",
        "Content-Type": "application/json",
    }


def _api(path=""):
    return f"{CF_API_BASE}/{_cfg.get('CF_ZONE', '')}/dns_records{path}"


def _domain():
    # CF_ROOT_DOMAIN is the canonical key; fall back to DOMAIN for compatibility
    return _cfg.get("CF_ROOT_DOMAIN") or _cfg.get("DOMAIN", "")


# ── Record CRUD ───────────────────────────────────────────────────────────────

def create_record(rtype: str, name: str, content: str, proxied: bool) -> dict:
    """Create a DNS record. Returns the full CF API response dict.
    
    Always sends a bare subdomain label to the CF API — the zone domain
    must NOT be included because CF appends it automatically within the zone.
    e.g. pass "sototo", CF creates "sototo.tululutaz.cfd".
    """
    domain = _domain()
    # Strip the root domain (and any trailing dot) so we always send a bare label
    bare_name = name.strip(".")
    if bare_name.endswith(f".{domain}"):
        bare_name = bare_name[: -(len(domain) + 1)]
    elif bare_name == domain:
        bare_name = "@"

    payload = {
        "type":    rtype,
        "name":    bare_name,
        "content": content,
        "ttl":     1 if proxied else 3600,
        "proxied": proxied,
    }
    try:
        r = requests.post(_api(), headers=_headers(), json=payload, timeout=10)
        return r.json()
    except Exception as e:
        logger.error(f"create_record: {e}")
        return {"success": False, "errors": [{"message": str(e)}]}


def delete_record(record_id: str) -> dict:
    """Delete a DNS record by its CF record ID."""
    try:
        r = requests.delete(_api(f"/{record_id}"), headers=_headers(), timeout=10)
        return r.json()
    except Exception as e:
        logger.error(f"delete_record: {e}")
        return {"success": False, "errors": [{"message": str(e)}]}


def list_records(name_filter: str = None, per_page: int = 100) -> list:
    """
    Return a list of record dicts from CF.
    Each dict has at minimum: id, type, name, content, proxied, ttl.
    Raises RuntimeError on API-level errors so the bot can surface them
    instead of silently showing 'No records found'.
    """
    params = {"per_page": per_page}
    if name_filter:
        params["name"] = f"{name_filter}.{_domain()}"
    try:
        r    = requests.get(_api(), headers=_headers(), params=params, timeout=10)
        data = r.json()
    except Exception as e:
        logger.error(f"list_records: {e}")
        raise RuntimeError(str(e))

    if not data.get("success"):
        errors = data.get("errors", [])
        msg    = errors[0].get("message", "Unknown CF error") if errors else "Unknown CF error"
        logger.error(f"list_records CF error: {msg}")
        raise RuntimeError(msg)

    return data.get("result", [])


def get_record(record_id: str) -> dict | None:
    """Fetch a single record by ID. Returns None on failure."""
    try:
        r    = requests.get(_api(f"/{record_id}"), headers=_headers(), timeout=10)
        data = r.json()
        return data.get("result") if data.get("success") else None
    except Exception as e:
        logger.error(f"get_record: {e}")
        return None


# ── Certbot ───────────────────────────────────────────────────────────────────

def certbot_issue(subdomain: str) -> tuple[bool, str]:
    """
    Run certbot certonly for <subdomain>.<domain>.
    Returns (success: bool, output: str).
    Requires certbot installed and root / sudo access.
    Uses --standalone by default; swap to --nginx / --apache if needed.
    """
    domain = _domain()
    fqdn   = f"{subdomain}.{domain}" if not subdomain.endswith(domain) else subdomain
    cmd = [
        "certbot", "certonly",
        "--standalone", "--non-interactive", "--agree-tos",
        "--register-unsafely-without-email",
        "-d", fqdn,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        success = result.returncode == 0
        output  = (result.stdout + result.stderr).strip()
        return success, output
    except FileNotFoundError:
        return False, "certbot not found"
    except subprocess.TimeoutExpired:
        return False, "certbot timed out"
    except Exception as e:
        return False, str(e)


def certbot_renew_all() -> tuple[bool, str]:
    """Run certbot renew for all certificates."""
    try:
        result = subprocess.run(
            ["certbot", "renew"],
            capture_output=True, text=True, timeout=120,
        )
        success = result.returncode == 0
        output  = (result.stdout + result.stderr).strip()
        return success, output
    except Exception as e:
        return False, str(e)


# ── Config validation ─────────────────────────────────────────────────────────

def is_configured() -> bool:
    """Return True if CF_TOKEN and CF_ZONE are set and not placeholder values."""
    token = _cfg.get("CF_TOKEN", "")
    zone  = _cfg.get("CF_ZONE",  "")
    return bool(
        token and zone
        and token != "YOUR_CF_TOKEN"
        and zone  != "YOUR_ZONE_ID"
    )
