"""
helpers/monitor.py
System monitoring: CPU, RAM, disk, connections, bandwidth, public IP.
"""

import subprocess
import logging
import time
import psutil

logger = logging.getLogger(__name__)

_ip_cache = {"ip": None, "ts": 0}


# ── Connection tracking ─────────────────────────────────────────────────────

def logged_in_users():
    """Get all logged-in SSH users with their connection counts. Returns {username: count}."""
    try:
        out = subprocess.run(['who'], capture_output=True, text=True).stdout
        users = {}
        for line in out.splitlines():
            parts = line.split()
            if parts:
                user = parts[0]
                users[user] = users.get(user, 0) + 1
        return users
    except Exception:
        return {}


def user_connections(username):
    """Active SSH sessions for a specific user (via `who`)."""
    return logged_in_users().get(username, 0)


def total_connections():
    """Total active SSH sessions, excluding root (via `who`)."""
    users = logged_in_users()
    return sum(count for user, count in users.items() if user != 'root')


# ── System stats ──────────────────────────────────────────────────────────────

def system_info():
    """CPU, RAM, disk usage. Returns None on error."""
    try:
        ram  = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return {
            'cpu':          psutil.cpu_percent(interval=1),
            'ram_used':     ram.used  / 1024**3,
            'ram_total':    ram.total / 1024**3,
            'ram_percent':  ram.percent,
            'disk_used':    disk.used  / 1024**3,
            'disk_total':   disk.total / 1024**3,
            'disk_percent': disk.percent,
        }
    except Exception as e:
        logger.error(f"system_info: {e}")
        return None


# ── Public IP ───────────────────────────────────────────────────────────────

def public_ip(ttl=300):
    """Public IPv4 address with TTL-based caching."""
    now = time.time()
    if _ip_cache["ip"] and now - _ip_cache["ts"] < ttl:
        return _ip_cache["ip"]
    try:
        r = subprocess.run(['curl', '-4', '-s', 'ifconfig.me'], capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip()
        if r.returncode == 0 and ip and ':' not in ip:
            _ip_cache.update(ip=ip, ts=now)
            return ip
    except Exception as e:
        logger.error(f"public_ip: {e}")
    return _ip_cache["ip"] or "N/A"


# ── Bandwidth ─────────────────────────────────────────────────────────────────

def _fmt_speed(bps):
    """Format bytes/sec into human readable Mbps or Gbps."""
    mbps = bps * 8 / 1_000_000
    if mbps >= 1000:
        return f"{mbps/1000:.2f} Gbps"
    return f"{mbps:.1f} Mbps"


def _read_iface_bytes(iface):
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if iface in line:
                    fields = line.split()
                    return int(fields[1]), int(fields[9])  # rx, tx bytes
    except Exception:
        pass
    return None, None


def bandwidth_usage(iface, interval=1):
    """Sample interface bytes over `interval` seconds.
    Returns dict with rx/tx in bps and human-readable strings, or None on error."""
    rx1, tx1 = _read_iface_bytes(iface)
    if rx1 is None:
        return None
    time.sleep(interval)
    rx2, tx2 = _read_iface_bytes(iface)
    if rx2 is None:
        return None
    rx_bps = (rx2 - rx1) / interval
    tx_bps = (tx2 - tx1) / interval
    return {
        'rx_bps': rx_bps,
        'tx_bps': tx_bps,
        'rx': _fmt_speed(rx_bps),
        'tx': _fmt_speed(tx_bps),
    }
