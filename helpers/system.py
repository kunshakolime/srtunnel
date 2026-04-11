"""
helpers/system.py
Linux system utilities: SSH user management, connection tracking,
system resource stats, public IP lookup, and bandwidth sampling.

Speedtest logic lives in helpers/speedtest.py — not here.
"""

import subprocess
import logging
import time
import psutil

logger = logging.getLogger(__name__)

LIMITS_CONF = "/etc/security/limits.conf"

_ip_cache = {"ip": None, "ts": 0}


# ── Linux user management ─────────────────────────────────────────────────────

def user_exists(username):
    return subprocess.run(['id', username], capture_output=True).returncode == 0


def create_user(username, password, max_logins=None):
    """Create a no-home, nologin system user for SSH tunneling."""
    try:
        subprocess.run(
            ['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', username],
            check=True
        )
        proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, text=True)
        proc.communicate(f"{username}:{password}\n")
        if proc.returncode != 0:
            logger.error(f"chpasswd failed for '{username}'")
            return False
        if max_logins and max_logins > 0:
            set_maxlogins(username, max_logins)
        logger.info(f"Created user '{username}'")
        return True
    except Exception as e:
        logger.error(f"create_user '{username}': {e}")
        return False


def delete_user(username):
    """Kill all sessions and remove the Linux user."""
    try:
        for pat in [f'sshd: {username}', f'dropbear.*{username}']:
            subprocess.run(['pkill', '-KILL', '-f', pat], check=False)
        subprocess.run(['pkill', '-KILL', '-u', username], check=False)
        subprocess.run(['userdel', username], check=True)
        set_maxlogins(username, None)
        logger.info(f"Deleted user '{username}'")
        return True
    except Exception as e:
        logger.error(f"delete_user '{username}': {e}")
        return False


def update_password(username, password):
    try:
        proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, text=True)
        proc.communicate(f"{username}:{password}\n")
        ok = proc.returncode == 0
        if ok:
            logger.info(f"Password updated for '{username}'")
        return ok
    except Exception as e:
        logger.error(f"update_password '{username}': {e}")
        return False


# ── limits.conf ───────────────────────────────────────────────────────────────

def set_maxlogins(username, limit):
    """Write (or remove) a maxlogins entry in /etc/security/limits.conf."""
    try:
        try:
            lines = open(LIMITS_CONF).readlines()
        except FileNotFoundError:
            lines = []

        lines = [l for l in lines if not (l.strip().startswith(f"{username} ") and "maxlogins" in l)]

        if limit and limit > 0:
            lines.append(f"{username}    -    maxlogins    {limit + 1}\n")

        open(LIMITS_CONF, 'w').writelines(lines)
        return True
    except Exception as e:
        logger.error(f"set_maxlogins '{username}': {e}")
        return False


# ── Connection tracking ───────────────────────────────────────────────────────

def user_connections(username):
    """Active SSH sessions for a specific user (via `who`)."""
    try:
        out = subprocess.run(['who'], capture_output=True, text=True).stdout
        return sum(1 for l in out.splitlines() if l.split() and l.split()[0] == username)
    except Exception:
        return 0


def total_connections():
    """Total active SSH sessions, excluding root (via `who`)."""
    try:
        out = subprocess.run(['who'], capture_output=True, text=True).stdout
        return sum(1 for l in out.splitlines() if l.split() and l.split()[0] != 'root')
    except Exception:
        return 0


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
