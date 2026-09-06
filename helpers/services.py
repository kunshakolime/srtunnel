"""
helpers/services.py

Parses the services defined in config.yaml (manager block) and exposes
one-shot tmux spawn/stop/reload operations. It does NOT supervise
services: launching is an explicit, stateless command — the web UI button
or `app/spawn_services.py`. Nothing here stays running or revives a dead
service.
"""

import glob
import os
import subprocess
import threading
import time
import logging
import shlex
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
from ruamel.yaml import YAML

# ── constants ────────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).resolve().parent.parent / "configs" / "config.yaml"
# fallback for old installs where config.yaml is still at root
if not CONFIG_FILE.exists():
    _fallback = Path(__file__).resolve().parent.parent / "config.yaml"
    if _fallback.exists():
        CONFIG_FILE = _fallback
TMUX_BLOCK = "manager"

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

def load_services() -> List[Service]:
    """Services defined in config.yaml, with current status derived from keep/enable."""
    return _parse_services(_load_config().get(TMUX_BLOCK, {}))

def find_service(name: str) -> Optional[Service]:
    return next((s for s in load_services() if s.name == name), None)

# ── tmux helpers ──────────────────────────────────────────────────────────────

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
    still recognised as alive — otherwise a new spawn would duplicate it.
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

# ── one-shot public API ───────────────────────────────────────────────────────

def list_services(lines: int = 10) -> List[dict]:
    result = []
    for s in load_services():
        result.append({
            "name":    s.name,
            "status":  s.status,
            "running": _is_alive(s.name),
            "log":     _capture_log(s.name, lines),
        })
    return result

def spawn_enabled() -> dict:
    """Launch every enable/keep service once. Does not run as a supervisor."""
    results = {}
    for s in load_services():
        if s.status not in ("enable", "keep"):
            continue
        if _is_alive(s.name):
            results[s.name] = "already running"
            continue
        results[s.name] = "started" if _start_session(s) else "failed"
        time.sleep(0.3)
    return results

def start_service(name: str):
    s = find_service(name)
    if not s:
        return False, "service not found"
    ok = _start_session(s)
    return True, "started" if ok else f"start failed — see {LOG_DIR / (name + '.log')}"

def stop_service(name: str):
    if not find_service(name):
        return False, "service not found"
    _stop_session(name)
    return True, "stopped"

def reload_service(name: str):
    """Reload a service by sending SIGHUP, or restart if reload fails."""
    s = find_service(name)
    if not s:
        return False, "service not found"

    success, msg = _reload_session(name)
    if success:
        return True, f"reloaded ({msg})"

    _stop_session(name)
    time.sleep(0.5)
    _start_session(s)
    return True, "restarted (reload not supported)"

def set_status(name: str, new_status: str):
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
    return True, new_status

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