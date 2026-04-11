"""
ZiVPN JSON config helper.
Only touches auth.config (the passwords list) — leaves everything else alone.
"""

import json
import os
import logging

logger = logging.getLogger(__name__)


def read(path):
    """Load zivpn.json. Returns {} if missing or unreadable."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"zivpn read '{path}': {e}")
        return {}


def write(path, data):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"zivpn write '{path}': {e}")
        return False


def set_passwords(path, passwords, fallback=None):
    """Overwrite auth.config with the given password list (deduped).
    Uses fallback if the list is empty."""
    config = read(path)
    config.setdefault("auth", {"mode": "passwords"})
    config["auth"]["config"] = list(set(passwords)) if passwords else ([fallback] if fallback else [])
    return write(path, config)
