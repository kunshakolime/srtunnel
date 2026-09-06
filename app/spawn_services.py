#!/usr/bin/env python3
"""
One-shot service spawner.

Parses config.yaml, runs the manager launch_commands, and launches each
enable/keep service into its own tmux session — then exits. It never stays
running and never brings a stopped service back up on its own; that is
deliberate: restarting is done on demand (manual, cron, or systemd).

Usage:
    python3 app/spawn_services.py            # spawn all enable + keep services
    python3 app/spawn_services.py <name>     # spawn just that one service
"""

import sys
import logging
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from helpers import services as svc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("spawn_services")


def run_launch_commands():
    """Boot-time tweaks from manager.launch_commands (sysctl, iptables, ...)."""
    block = svc._load_config().get(svc.TMUX_BLOCK, {})
    for cmd in block.get("launch_commands") or []:
        try:
            subprocess.run(cmd, shell=True, check=True)
            logger.info("launch_command ok: %s", cmd)
        except subprocess.CalledProcessError as e:
            logger.warning("launch_command failed: %s — %s", cmd, e)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv:
        name = argv[0]
        s = svc.find_service(name)
        if not s:
            logger.error("service %r not found in config", name)
            return 2
        ok = svc._start_session(s)
        if ok:
            logger.info("%s: started", name)
            return 0
        logger.error("%s: FAILED — see %s", name, svc.LOG_DIR / f"{name}.log")
        return 1

    run_launch_commands()
    results = svc.spawn_enabled()
    for name, status in results.items():
        logger.info("%-20s %s", name, status)
    failed = [n for n, s in results.items() if s == "failed"]
    if failed:
        logger.error("failed to spawn: %s", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())