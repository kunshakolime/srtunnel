"""
helpers/services.py

Loads services from config.yaml (manager block), watches tmux sessions,
and restarts keep-alive services when they die.
"""

import subprocess
import threading
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from ruamel.yaml import YAML

# ── constants ────────────────────────────────────────────────────────────────

CONFIG_FILE        = Path("/root/srtunnel/config.yaml")
TMUX_BLOCK         = "manager"
KEEPALIVE_INTERVAL = 2   # seconds between keep-alive checks

# ── yaml ─────────────────────────────────────────────────────────────────────

_yaml = YAML()
_yaml.preserve_quotes = True
_yaml.width = 4096

def _load_config():
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE) as f:
        return _yaml.load(f) or {}

def _save_config(full):
    with open(CONFIG_FILE, "w") as f:
        _yaml.dump(full, f)

# ── model ─────────────────────────────────────────────────────────────────────

@dataclass
class Service:
    name:    str
    command: str
    status:  str          # "enable" | "keep" | "disable"
    running: bool = False

# ── parsing ───────────────────────────────────────────────────────────────────

def _parse_services(block) -> List[Service]:
    keep_set   = set(block.get("keep",   []) or [])
    enable_set = set(block.get("enable", []) or [])
    services   = block.get("services", {}) or {}

    result = []
    for name, command in services.items():
        if name in keep_set:
            status = "keep"
        elif name in enable_set:
            status = "enable"
        else:
            status = "disable"
        result.append(Service(name=name, command=str(command or ""), status=status))

    result.sort(key=lambda s: s.name)
    return result

# ── tmux helpers ──────────────────────────────────────────────────────────────

def _tmux(*args) -> bool:
    r = subprocess.run(["tmux", *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0

def _active_sessions():
    p = subprocess.run(
        ["tmux", "list-sessions", "-F", "#{session_name}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    return set(p.stdout.splitlines()) if p.returncode == 0 else set()

def _start_session(s: Service):
    _tmux("kill-session", "-t", s.name)
    subprocess.run(
        ["tmux", "new-session", "-d", "-s", s.name, "bash", "-c", s.command],
        cwd=str(CONFIG_FILE.parent)
    )

def _stop_session(name: str):
    _tmux("kill-session", "-t", name)

def _capture_pane(name: str, lines: int) -> List[str]:
    p = subprocess.run(
        ["tmux", "capture-pane", "-t", f"{name}:0.0", "-p", "-S", f"-{lines}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    if p.returncode != 0:
        return []
    return [l for l in p.stdout.splitlines() if l.strip()][-lines:]

# ── watcher ───────────────────────────────────────────────────────────────────

class _Watcher:
    def __init__(self):
        self._lock     = threading.Lock()
        self._services: List[Service] = []
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._reload()

    def _reload(self):
        block = _load_config().get(TMUX_BLOCK, {})
        with self._lock:
            self._services = _parse_services(block)

    def _sync_running(self):
        active = _active_sessions()
        with self._lock:
            for s in self._services:
                s.running = s.name in active

    def _loop(self):
        # on start: launch enabled services that aren't running yet
        self._sync_running()
        with self._lock:
            to_start = [s for s in self._services if s.status in ("enable", "keep") and not s.running]
        for s in to_start:
            _start_session(s)
            time.sleep(0.3)

        while self._running:
            self._sync_running()
            with self._lock:
                to_restart = [s for s in self._services if s.status == "keep" and not s.running]
            for s in to_restart:
                _start_session(s)
            time.sleep(KEEPALIVE_INTERVAL)

    # ── public interface ──────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return False
        self._reload()
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if not self._running:
            return False
        self._running = False
        return True

    @property
    def active(self):
        return self._running

    def list_services(self, lines: int = 10):
        self._sync_running()
        with self._lock:
            services = list(self._services)
        result = []
        for s in services:
            result.append({
                "name":    s.name,
                "status":  s.status,
                "running": s.running,
                "log":     _capture_pane(s.name, lines) if s.running else [],
            })
        return result

    def start_service(self, name: str):
        with self._lock:
            s = next((x for x in self._services if x.name == name), None)
        if not s:
            return False, "service not found"
        _start_session(s)
        return True, "started"

    def stop_service(self, name: str):
        with self._lock:
            s = next((x for x in self._services if x.name == name), None)
        if not s:
            return False, "service not found"
        _stop_session(name)
        return True, "stopped"

    def set_status(self, name: str, new_status: str):
        if new_status not in ("enable", "keep", "disable"):
            return False, "invalid status"

        full  = _load_config()
        block = full.setdefault(TMUX_BLOCK, {})

        for key in ("keep", "enable"):
            lst = block.get(key) or []
            if name in lst:
                lst.remove(name)
            block[key] = lst

        if new_status == "keep":
            block.setdefault("keep", []).append(name)
        elif new_status == "enable":
            block.setdefault("enable", []).append(name)

        _save_config(full)
        self._reload()
        return True, new_status


# ── singleton ─────────────────────────────────────────────────────────────────

watcher = _Watcher()


# ── Server monitor ─────────────────────────────────────────────────────────────

import json
import urllib.request

SERVERLIST_FILE    = Path("/root/srtunnel/helpers/serverlist.json")
SERVER_CHECK_INTERVAL = 30   # seconds

def _load_serverlist():
    if not SERVERLIST_FILE.exists():
        return []
    try:
        return json.loads(SERVERLIST_FILE.read_text())
    except Exception:
        return []

def _save_serverlist(data):
    SERVERLIST_FILE.write_text(json.dumps(data, indent=2))

def _ping(url: str) -> bool:
    try:
        req = urllib.request.Request(url + "/api/health", method="GET")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False

def _server_monitor_loop():
    while True:
        servers = _load_serverlist()
        changed = False
        for s in servers:
            online = _ping(s.get("url", ""))
            s["online"]    = online
            s["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) if online else s.get("last_seen")
            changed = True
        if changed:
            _save_serverlist(servers)
        time.sleep(SERVER_CHECK_INTERVAL)

def start_server_monitor():
    t = threading.Thread(target=_server_monitor_loop, daemon=True)
    t.start()

start_server_monitor()
