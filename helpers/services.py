"""
helpers/services.py

Loads services from config.yaml (manager block), watches tmux sessions,
and restarts keep-alive services when they die.
"""

import glob
import os
import subprocess
import threading
import time
import logging
import shlex
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from ruamel.yaml import YAML

# ── constants ────────────────────────────────────────────────────────────────

CONFIG_FILE        = Path(__file__).resolve().parent.parent / "configs" / "config.yaml"
# fallback for old installs where config.yaml is still at root
if not CONFIG_FILE.exists():
    _fallback = Path(__file__).resolve().parent.parent / "config.yaml"
    if _fallback.exists():
        CONFIG_FILE = _fallback
TMUX_BLOCK         = "manager"
KEEPALIVE_INTERVAL = 2   # seconds between keep-alive checks

logger = logging.getLogger("srapi.services")

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

def _tmux_sockets() -> set:
    """All tmux server sockets for this user (default server + any -L/-S ones)."""
    base = os.environ.get("TMUX_TMPDIR") or os.environ.get("TMPDIR") or "/tmp"
    return set(glob.glob(os.path.join(base, f"tmux-{os.getuid()}", "*")))

def _active_sessions():
    sessions = set()
    for sock in _tmux_sockets():
        p = subprocess.run(
            ["tmux", "-S", sock, "list-sessions", "-F", "#{session_name}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        if p.returncode == 0:
            sessions.update(p.stdout.splitlines())
    return sessions

def _tmux_kill_session(name: str):
    """Kill session `name` in every tmux server, not just the default one."""
    for sock in _tmux_sockets():
        subprocess.run(["tmux", "-S", sock, "kill-session", "-t", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _is_alive(name: str) -> bool:
    """Check if a tmux session with a live pane exists in ANY tmux server.

    Scans every server socket so a session running in another tmux server is
    still recognised as alive — otherwise the watcher would spawn a duplicate.
    """
    for sock in _tmux_sockets():
        p = subprocess.run(
            ["tmux", "-S", sock, "list-panes", "-t", name, "-F", "#{pane_pid}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        if p.returncode != 0 or not p.stdout.strip():
            continue
        pid = p.stdout.strip().splitlines()[0]
        # check if the pane's child process is still running
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ValueError):
            continue
    return False

LOG_DIR = Path("/tmp/srapi-services")

# Stop auto-restarting a `keep` service after this many consecutive
# startup failures. Prevents an infinite 2s crash-loop (and its memory /
# journal flood) when a service can't start (e.g. port already bound
# elsewhere). The reason is written to the service's own log file.
FAILURE_LIMIT = 3

def _note_give_up(name: str, count: int):
    log_file = LOG_DIR / f"{name}.log"
    try:
        with open(log_file, "a") as f:
            f.write(f"\n[watcher] Service '{name}' stopped because it died too many times "
                    f"({count} consecutive failures).\n")
            f.write("[watcher] Auto-restarts are suspended. Fix the issue, then "
                    "start it manually (or reload the service).\n")
    except Exception:
        pass
    logger.error("Service %s gave up after %d consecutive failures — see %s",
                 name, count, log_file)

def _start_session(s: Service):
    _tmux_kill_session(s.name)
    LOG_DIR.mkdir(exist_ok=True)
    log_file = LOG_DIR / f"{s.name}.log"
    log_file.write_text("")  # clear old log
    cmd = ["tmux", "new-session", "-d", "-s", s.name,
           "bash", "-c", f"script -q --flush -e -c {shlex.quote(s.command)} {shlex.quote(str(log_file))} 2>/dev/null"]
    # run from project root so relative ./bin/* and ./configs/* work
    _cwd = str(CONFIG_FILE.parent.parent if CONFIG_FILE.parent.name == "configs" else CONFIG_FILE.parent)
    r = subprocess.run(
        cmd, cwd=_cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if r.returncode != 0:
        logger.error("tmux new-session failed for %s: %s", s.name, r.stderr.strip())
        return False
    time.sleep(1)
    if log_file.exists() and log_file.read_text().strip():
        logger.info("Service %s output:\n%s", s.name, log_file.read_text().strip())
    if not _is_alive(s.name):
        logger.error("Service %s died — see %s", s.name, log_file)
        return False
    return True

def _stop_session(name: str):
    _tmux_kill_session(name)

def _reload_session(name: str):
    """Send SIGHUP to the process in the tmux session to reload it."""
    try:
        # Get the PID of the process in the tmux session
        p = subprocess.run(
            ["tmux", "list-panes", "-t", name, "-F", "#{pane_pid}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        if p.returncode != 0:
            return False, "could not get pane PID"
        
        pane_pid = p.stdout.strip()
        if not pane_pid:
            return False, "no pane PID found"
        
        # Send SIGHUP to reload the process
        p = subprocess.run(["kill", "-HUP", pane_pid], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if p.returncode == 0:
            return True, f"reload signal sent to PID {pane_pid}"
        else:
            return False, f"reload signal failed for PID {pane_pid}"
    except Exception as e:
        return False, f"reload error: {e}"

def _capture_log(name: str, lines: int) -> List[str]:
    log_file = LOG_DIR / f"{name}.log"
    if log_file.exists():
        text = log_file.read_text()
        return [l for l in text.splitlines() if l.strip()][-lines:]
    return []

# ── watcher ───────────────────────────────────────────────────────────────────

class _Watcher:
    def __init__(self):
        self._lock     = threading.Lock()
        self._services: List[Service] = []
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._failures: dict = {}
        self._gave_up: set = set()
        self._reload()

    def _reload(self):
        block = _load_config().get(TMUX_BLOCK, {})
        with self._lock:
            self._services = _parse_services(block)
            self._config_mtime = CONFIG_FILE.stat().st_mtime if CONFIG_FILE.exists() else 0

    def _sync_running(self):
        with self._lock:
            for s in self._services:
                s.running = _is_alive(s.name)

    def _record_start(self, name: str, ok: bool):
        with self._lock:
            if ok:
                self._failures.pop(name, None)
                self._gave_up.discard(name)
            else:
                self._failures[name] = self._failures.get(name, 0) + 1
                if self._failures[name] >= FAILURE_LIMIT:
                    self._gave_up.add(name)
                    self._failures.pop(name, None)
                    _note_give_up(name, FAILURE_LIMIT)

    def _loop(self):
        # on start: launch enabled services that aren't running yet
        self._sync_running()
        with self._lock:
            to_start = [s for s in self._services if s.status in ("enable", "keep") and not s.running]
        for s in to_start:
            ok = _start_session(s)
            self._record_start(s.name, ok)
            time.sleep(0.3)

        while self._running:
            # reload config if it changed on disk
            try:
                mtime = CONFIG_FILE.stat().st_mtime if CONFIG_FILE.exists() else 0
                if mtime != self._config_mtime:
                    self._reload()
            except OSError:
                pass

            self._sync_running()
            with self._lock:
                to_restart = [s for s in self._services
                              if s.status == "keep" and not s.running
                              and s.name not in self._gave_up]
            for s in to_restart:
                ok = _start_session(s)
                self._record_start(s.name, ok)
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
                "log":     _capture_log(s.name, lines),
            })
        return result

    def start_service(self, name: str):
        with self._lock:
            s = next((x for x in self._services if x.name == name), None)
        if not s:
            return False, "service not found"
        with self._lock:
            self._failures.pop(name, None)
            self._gave_up.discard(name)
        ok = _start_session(s)
        self._record_start(name, ok)
        return True, "started"

    def stop_service(self, name: str):
        with self._lock:
            s = next((x for x in self._services if x.name == name), None)
        if not s:
            return False, "service not found"
        _stop_session(name)
        return True, "stopped"

    def reload_service(self, name: str):
        """Reload a service by sending SIGHUP, or restart if reload fails."""
        with self._lock:
            s = next((x for x in self._services if x.name == name), None)
        if not s:
            return False, "service not found"
        
        # First try to reload by sending SIGHUP
        success, msg = _reload_session(name)
        if success:
            return True, f"reloaded ({msg})"
        
        # If reload fails, fall back to restart
        _stop_session(name)
        time.sleep(0.5)  # Brief pause
        _start_session(s)
        return True, "restarted (reload not supported)"

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

SERVERLIST_FILE    = Path(__file__).resolve().parent / "serverlist.json"
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
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url + "/api/health", method="GET")
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
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