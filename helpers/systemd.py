"""
helpers/systemd.py

Thin wrapper around systemctl / journalctl for service management.
"""

import subprocess
import logging
from typing import List, Optional

logger = logging.getLogger("srapi.systemd")


def _run(cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)


def list_units(pattern: str = "*.service") -> List[dict]:
    """List all systemd service units."""
    r = _run(["systemctl", "list-units", "--type=service", "--all", "--plain",
              "--no-legend", "--no-pager", "--plain", "-o", "json", f"--pattern={pattern}"])
    if r.returncode != 0:
        # fallback: parse tabular output
        return _parse_list_units()
    try:
        import json
        units = json.loads(r.stdout)
        return [
            {
                "name":     u.get("unit", "").removesuffix(".service"),
                "full":     u.get("unit", ""),
                "load":     u.get("load", ""),
                "active":   u.get("active", ""),
                "sub":      u.get("sub", ""),
                "description": u.get("description", ""),
            }
            for u in units
        ]
    except Exception:
        return _parse_list_units()


def _parse_list_units() -> List[dict]:
    """Fallback parser for tabular systemctl output."""
    r = _run(["systemctl", "list-units", "--type=service", "--all",
              "--no-legend", "--no-pager"])
    if r.returncode != 0:
        return []
    units = []
    for line in r.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name = parts[0].removesuffix(".service")
        units.append({
            "name":        name,
            "full":        parts[0],
            "load":        parts[1],
            "active":      parts[2],
            "sub":         parts[3],
            "description": parts[4] if len(parts) > 4 else "",
        })
    return units


def unit_status(name: str) -> Optional[str]:
    """Return active/inactive/failed etc."""
    r = _run(["systemctl", "is-active", f"{name}.service"])
    return r.stdout.strip() if r.returncode in (0, 3) else "unknown"


def is_enabled(name: str) -> bool:
    r = _run(["systemctl", "is-enabled", f"{name}.service"])
    return r.stdout.strip() == "enabled"


def start(name: str) -> bool:
    r = _run(["systemctl", "start", f"{name}.service"])
    if r.returncode != 0:
        logger.error("systemctl start %s failed: %s", name, r.stderr.strip())
    return r.returncode == 0


def stop(name: str) -> bool:
    r = _run(["systemctl", "stop", f"{name}.service"])
    if r.returncode != 0:
        logger.error("systemctl stop %s failed: %s", name, r.stderr.strip())
    return r.returncode == 0


def restart(name: str) -> bool:
    r = _run(["systemctl", "restart", f"{name}.service"])
    if r.returncode != 0:
        logger.error("systemctl restart %s failed: %s", name, r.stderr.strip())
    return r.returncode == 0


def enable(name: str) -> bool:
    r = _run(["systemctl", "enable", f"{name}.service"])
    return r.returncode == 0


def disable(name: str) -> bool:
    r = _run(["systemctl", "disable", f"{name}.service"])
    return r.returncode == 0


def logs(name: str, lines: int = 20) -> List[str]:
    """Fetch recent journal logs for a unit."""
    r = _run(["journalctl", "-u", f"{name}.service", "-n", str(lines),
              "--no-pager", "-o", "cat", "--no-hostname"], timeout=5)
    if r.returncode != 0:
        return [f"(no logs: {r.stderr.strip()})"]
    return [l for l in r.stdout.splitlines() if l.strip()][-lines:]
