#!/usr/bin/env python3
"""
traffic_wrapper.py
Launches traffic_meter_user (eBPF per-user traffic logger) and handles log
rotation independently — no dependency on srapi being up.

traffic_meter_user writes /tmp/traffic_user_{uid}.log (in,<bytes> / out,<bytes>).
This wrapper sums those into data/traffic_totals.json on a schedule, then truncates.
"""

import glob
import json
import logging
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

BOT_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR  = BOT_DIR / "data"
BIN_DIR   = BOT_DIR / "bin"
LOG_DIR   = Path("/tmp")
CACHE     = DATA_DIR / "traffic_totals.json"
METER     = BIN_DIR / "traffic_meter_user"

ROTATE_LINES = 10_000       # rotate when log exceeds this
POLL_SEC     = 30           # check logs this often
METER_RESTART_SEC = 2

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("traffic_wrapper")

_meter_proc = None

# ── meter lifecycle ────────────────────────────────────────────────────────

def start_meter():
    global _meter_proc
    log.info("Starting traffic_meter_user")
    _meter_proc = subprocess.Popen(
        [str(METER)],
        cwd=str(BIN_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

def meter_alive():
    return _meter_proc is not None and _meter_proc.poll() is None

# ── log rotation ───────────────────────────────────────────────────────────

def _line_count(path):
    try:
        r = subprocess.run(["wc", "-l", path], capture_output=True, text=True, timeout=5)
        return int(r.stdout.split()[0])
    except Exception:
        return 0

def _sum_traffic(path):
    """Sum in/out bytes from a log via awk."""
    try:
        r = subprocess.run(
            ["awk", "-F,", "/^in/{i+=$2} /^out/{o+=$2} END{print i+0, o+0}", path],
            capture_output=True, text=True, timeout=10,
        )
        parts = r.stdout.strip().split()
        if len(parts) == 2:
            return int(parts[0]), int(parts[1])
    except Exception:
        pass
    return 0, 0

def _load_cache():
    try:
        return json.loads(CACHE.read_text())
    except Exception:
        return {}

def _save_cache(data):
    CACHE.write_text(json.dumps(data))

def _get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ValueError, OSError):
        return f"uid:{uid}"

def rotate_logs():
    cache = _load_cache()
    changed = False
    for log_file in glob.glob(str(LOG_DIR / "traffic_user_*.log")):
        match = re.search(r"_(\d+)\.log$", log_file)
        if not match:
            continue
        uid = match.group(1)
        uid_key = f"uid_{uid}"
        if _line_count(log_file) < ROTATE_LINES:
            continue
        total_in, total_out = _sum_traffic(log_file)
        if total_in == 0 and total_out == 0:
            continue
        prev = cache.get(uid_key, {"in": 0, "out": 0})
        cache[uid_key] = {"in": prev["in"] + total_in, "out": prev["out"] + total_out}
        open(log_file, "w").close()  # truncate
        log.info("Rotated %s — cumulative in=%d out=%d", log_file,
                 cache[uid_key]["in"], cache[uid_key]["out"])
        changed = True
    if changed:
        _save_cache(cache)

# ── public query (for srapi to call instead of its own rotation) ───────────

def query_all():
    """Returns list of per-user traffic dicts, combining live logs + cache."""
    cache = _load_cache()
    results = []
    for log_file in glob.glob(str(LOG_DIR / "traffic_user_*.log")):
        match = re.search(r"_(\d+)\.log$", log_file)
        if not match:
            continue
        uid = int(match.group(1))
        uid_key = f"uid_{uid}"
        live_in, live_out = _sum_traffic(log_file)
        cached = cache.get(uid_key, {"in": 0, "out": 0})
        total_in  = cached["in"]  + live_in
        total_out = cached["out"] + live_out
        results.append({
            "uid":      uid,
            "username": _get_username(uid),
            "download": total_in,
            "upload":   total_out,
            "total":    total_in + total_out,
        })
    return results

# ── main loop ──────────────────────────────────────────────────────────────

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    start_meter()
    try:
        while True:
            time.sleep(POLL_SEC)
            if not meter_alive():
                log.warning("traffic_meter_user died (exit %s), restarting",
                            _meter_proc.returncode)
                start_meter()
            rotate_logs()
    except KeyboardInterrupt:
        pass
    finally:
        if meter_alive():
            _meter_proc.terminate()
            _meter_proc.wait(timeout=5)

if __name__ == "__main__":
    main()
