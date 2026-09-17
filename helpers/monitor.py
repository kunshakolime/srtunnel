"""
helpers/monitor.py
System monitoring: CPU, RAM, disk, connections, bandwidth, public IP, user traffic.
"""

import subprocess
import logging
import time
import glob
import pwd
import json
import re
import os
from pathlib import Path

import psutil
import socket

logger = logging.getLogger(__name__)

_ip_cache = {"ip": None, "ts": 0}

TRAFFIC_CACHE = Path(__file__).resolve().parent.parent / "data" / "traffic_totals.json"


# ── Connection tracking ───────────────────────────────────────────────────────

def logged_in_users():
    """Returns {username: session_count} for all logged-in SSH users."""
    try:
        out = subprocess.run(["who"], capture_output=True, text=True).stdout
        users = {}
        for line in out.splitlines():
            parts = line.split()
            if parts:
                users[parts[0]] = users.get(parts[0], 0) + 1
        return users
    except Exception:
        return {}

def user_connections(username):
    return logged_in_users().get(username, 0)

def total_connections():
    return sum(c for u, c in logged_in_users().items() if u != "root")


# ── Listening sockets (port map) ───────────────────────────────────────────────

def listening_ports():
    """Every process listening on a port — what port and who owns it."""
    out = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.laddr or not conn.laddr.port:
                continue
            kind = {socket.SOCK_STREAM: "tcp", socket.SOCK_DGRAM: "udp"}.get(conn.type)
            if not kind:
                continue
            if kind == "tcp" and conn.status != psutil.CONN_LISTEN:
                continue
            if kind == "udp" and conn.raddr:
                continue
            if kind == "udp" and conn.laddr.port >= 49152:
                continue  # skip ephemeral per-flow UDP sockets, only show real listeners
            name = ""
            pid  = conn.pid
            if pid is not None:
                try:
                    name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    name = ""
            out.append({
                "proto":   kind,
                "address": conn.laddr.ip,
                "port":    conn.laddr.port,
                "pid":     pid,
                "process": name,
            })
    except (psutil.Error, OSError):
        pass
    # dedupe (udp can report the same socket twice)
    seen, uniq = set(), []
    for e in out:
        key = (e["proto"], e["pid"], e["address"], e["port"])
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    # a process with many distinct UDP ports is a proxy/forwarder (e.g. xray),
    # not a listener — drop its UDP rows so the map stays glanceable
    udp_ports: dict = {}
    for e in uniq:
        if e["proto"] == "udp" and e["pid"]:
            udp_ports.setdefault(e["pid"], set()).add(e["port"])
    noisy = {pid for pid, ports in udp_ports.items() if len(ports) > 5}
    uniq  = [e for e in uniq if not (e["proto"] == "udp" and e["pid"] in noisy)]
    uniq.sort(key=lambda e: (e["port"], e["proto"], e["process"]))
    return uniq


# ── System stats ──────────────────────────────────────────────────────────────

def system_info():
    try:
        ram  = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return {
            "cpu":          psutil.cpu_percent(interval=1),
            "ram_used":     ram.used   / 1024**3,
            "ram_total":    ram.total  / 1024**3,
            "ram_percent":  ram.percent,
            "disk_used":    disk.used  / 1024**3,
            "disk_total":   disk.total / 1024**3,
            "disk_percent": disk.percent,
        }
    except Exception as e:
        logger.error("system_info: %s", e)
        return None


# ── Public IP ─────────────────────────────────────────────────────────────────

def public_ip(ttl=300):
    now = time.time()
    if _ip_cache["ip"] and now - _ip_cache["ts"] < ttl:
        return _ip_cache["ip"]
    try:
        r = subprocess.run(["curl", "-4", "-s", "ifconfig.me"],
                           capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip()
        if r.returncode == 0 and ip and ":" not in ip:
            _ip_cache.update(ip=ip, ts=now)
            return ip
    except Exception as e:
        logger.error("public_ip: %s", e)
    return _ip_cache["ip"] or "N/A"


# ── Bandwidth ─────────────────────────────────────────────────────────────────

def _fmt_speed(bps):
    mbps = bps * 8 / 1_000_000
    return f"{mbps/1000:.2f} Gbps" if mbps >= 1000 else f"{mbps:.1f} Mbps"

def _read_iface_bytes(iface):
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    fields = line.split()
                    return int(fields[1]), int(fields[9])
    except Exception:
        pass
    return None, None

def bandwidth_usage(iface, interval=1):
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
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "rx": _fmt_speed(rx_bps),
        "tx": _fmt_speed(tx_bps),
    }


# ── User traffic ──────────────────────────────────────────────────────────────

def _load_cache():
    try:
        return json.loads(TRAFFIC_CACHE.read_text())
    except Exception:
        return {}

def _sum_traffic(filepath):
    """Sum in/out bytes from a traffic log file using awk."""
    try:
        result = subprocess.run(
            ["awk", "-F,", "/^in/{i+=$2} /^out/{o+=$2} END{print i+0, o+0}", filepath],
            capture_output=True, text=True, timeout=10,
        )
        parts = result.stdout.strip().split()
        if len(parts) == 2:
            return int(parts[0]), int(parts[1])
    except Exception as e:
        logger.error("_sum_traffic %s: %s", filepath, e)
    return 0, 0

def _get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ValueError, OSError):
        return f"uid:{uid}"

def all_user_traffic():
    """Returns list of dicts with per-user traffic totals, including historical data.

    Rotation is handled by bin/traffic_wrapper.py — this only reads.
    """
    cache = _load_cache()
    results = []
    for log_file in glob.glob("/tmp/traffic_user_*.log"):
        match = re.search(r"_(\d+)\.log$", log_file)
        if not match:
            continue
        uid     = match.group(1)
        uid_key = f"uid_{uid}"
        live_in, live_out = _sum_traffic(log_file)
        cached    = cache.get(uid_key, {"in": 0, "out": 0})
        total_in  = cached["in"]  + live_in
        total_out = cached["out"] + live_out
        results.append({
            "uid":      int(uid),
            "username": _get_username(int(uid)),
            "download": total_in,
            "upload":   total_out,
            "total":    total_in + total_out,
        })
    return results

def user_traffic(username=None, uid=None):
    for entry in all_user_traffic():
        if username and entry["username"] == username:
            return entry
        if uid is not None and entry["uid"] == uid:
            return entry
    return None

import threading

_system_cache = {}

def _background_sampler(iface, interval=2):
    while True:
        try:
            info = system_info() or {}
            bw   = bandwidth_usage(iface) or {}
            _system_cache.update({
                "ip":           public_ip(),
                "cpu":          info.get("cpu"),
                "ram_used":     info.get("ram_used"),
                "ram_total":    info.get("ram_total"),
                "ram_percent":  info.get("ram_percent"),
                "disk_used":    info.get("disk_used"),
                "disk_total":   info.get("disk_total"),
                "disk_percent": info.get("disk_percent"),
                "bandwidth":    bw,
                "connections":  total_connections(),
            })
        except Exception as e:
            logger.error("background_sampler: %s", e)
        time.sleep(interval)

def start_sampler(iface):
    t = threading.Thread(target=_background_sampler, args=(iface,), daemon=True)
    t.start()

def get_system_cache():
    return _system_cache.copy()
