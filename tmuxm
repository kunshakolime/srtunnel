#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import curses
from ruamel.yaml import YAML
from pathlib import Path
from dataclasses import dataclass

CONFIG_FILE = Path(__file__).resolve().parent / "config.yaml"
TMUX_BLOCK = "tmux_manager"
MANAGER_SESSION = "tmux-manager"

KEEPALIVE_INTERVAL = 10
SESSION_REFRESH_INTERVAL = 1.0

# ---------------- tmux helpers ----------------

def tmux(*args):
    return subprocess.run(
        ["tmux", *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def list_sessions():
    p = subprocess.run(
        ["tmux", "list-sessions", "-F", "#{session_name}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    return set(p.stdout.splitlines()) if p.returncode == 0 else set()

# ---------------- config ----------------

yaml_rt = YAML()
yaml_rt.preserve_quotes = True

def load_full_config():
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE) as f:
        return yaml_rt.load(f) or {}

def load_config():
    full = load_full_config()
    return full.setdefault(TMUX_BLOCK, {})

def save_config(full):
    with open(CONFIG_FILE, "w") as f:
        yaml_rt.dump(full, f)

# ---------------- model ----------------

@dataclass
class Service:
    name: str
    command: str
    enabled: bool
    keep_alive: bool
    running: bool = False

# ---------------- manager ----------------

class TmuxManager:
    def __init__(self):
        self.full_config = load_full_config()
        self.block = self.full_config.setdefault(TMUX_BLOCK, {})
        self.services = [
            Service(
                name=n,
                command=s.get("command", ""),
                enabled=s.get("enabled", True),
                keep_alive=s.get("keep_alive", False),
            )
            for n, s in self.block.get("services", {}).items()
        ]
        self.services.sort(key=lambda s: s.name)

        self.sessions = set()
        self.last_refresh = 0
        self.last_keepalive = 0

        self.selected = 0
        self.scroll = 0
        self.message = None
        self.message_time = 0
        self.dirty = True

    # -------- lifecycle --------

    def refresh_sessions(self):
        now = time.time()
        if now - self.last_refresh < SESSION_REFRESH_INTERVAL:
            return

        self.last_refresh = now
        new_sessions = list_sessions()

        changed = False
        for s in self.services:
            new = s.name in new_sessions
            if s.running != new:
                s.running = new
                changed = True

        if changed:
            self.sessions = new_sessions
            self.dirty = True
        else:
            self.sessions = new_sessions

    def keep_alive(self):
        now = time.time()
        if now - self.last_keepalive < KEEPALIVE_INTERVAL:
            return

        for s in self.services:
            if s.enabled and s.keep_alive and not s.running:
                self.start(s)

        self.last_keepalive = now

    # -------- actions --------

    def start(self, s: Service):
        if s.running:
            tmux("kill-session", "-t", s.name)
            time.sleep(0.2)
        tmux("new-session", "-d", "-s", s.name, "bash", "-c", s.command)
        self.flash(f"Started {s.name}")

    def stop(self, s: Service):
        if s.running:
            tmux("kill-session", "-t", s.name)
            self.flash(f"Stopped {s.name}")
        else:
            self.flash(f"{s.name} not running")

    def toggle(self, s: Service, key: str):
        setattr(s, key, not getattr(s, key))

        services = self.block.setdefault("services", {})
        svc = services.setdefault(s.name, {})
        svc[key] = getattr(s, key)

        save_config(self.full_config)
        self.flash(f"{s.name}: {key} = {getattr(s, key)}")

    # -------- ui --------

    def flash(self, msg):
        self.message = msg
        self.message_time = time.time()
        self.dirty = True

    def draw(self, stdscr):
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        stdscr.addstr(0, (w - 12)//2, "TMUX MANAGER", curses.A_BOLD)
        stdscr.hline(1, 0, ord("="), w)

        if self.message and time.time() - self.message_time < 3:
            stdscr.addstr(2, 0, f"► {self.message}", curses.A_REVERSE)

        y0 = 4
        max_rows = h - y0 - 6

        for i, s in enumerate(self.services[self.scroll:self.scroll + max_rows]):
            idx = self.scroll + i
            sel = idx == self.selected

            line = (
                f" [{' *' if s.running else ' '}]"
                f" [{'E' if s.enabled else 'D'}]"
                f" [{'K' if s.keep_alive else ' '} ] "
                f"{s.name:<18} {s.command[:w-45]}"
            )

            stdscr.addstr(
                y0 + i, 2, line,
                curses.A_REVERSE if sel else curses.A_NORMAL
            )

        stdscr.hline(h - 6, 0, ord("-"), w)
        stdscr.addstr(h - 5, 2, "↑↓ select | space start/stop | enter switch session")
        stdscr.addstr(h - 4, 2, "e enable | k keepalive")
        stdscr.addstr(h - 3, 2, "Ctrl+b d = detach tmux")
        stdscr.addstr(h - 2, 2, "Ctrl+b s = session list (dont press ESC)")

        stdscr.refresh()

    # -------- loop --------

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.timeout(1000)

        while True:
            self.refresh_sessions()
            self.keep_alive()

            if self.dirty:
                self.draw(stdscr)
                self.dirty = False

            k = stdscr.getch()
            if k == -1:
                continue

            self.dirty = True

            if k == curses.KEY_UP and self.selected > 0:
                self.selected -= 1
                self.scroll = min(self.scroll, self.selected)

            elif k == curses.KEY_DOWN and self.selected < len(self.services) - 1:
                self.selected += 1
                if self.selected >= self.scroll + (stdscr.getmaxyx()[0] - 10):
                    self.scroll += 1

            elif k == ord(" "):
                s = self.services[self.selected]
                self.stop(s) if s.running else self.start(s)

            elif k == ord("e"):
                self.toggle(self.services[self.selected], "enabled")

            elif k == ord("k"):
                self.toggle(self.services[self.selected], "keep_alive")

            elif k in (10, 13):
                s = self.services[self.selected]
                if s.running:
                    curses.endwin()
                    subprocess.run(["tmux", "switch-client", "-t", s.name])
                    curses.wrapper(self.run)

# ---------------- entry ----------------

def main():
    if subprocess.run(["which", "tmux"], capture_output=True).returncode != 0:
        print("tmux not installed")
        sys.exit(1)

    if "TMUX" not in os.environ:
        if tmux("has-session", "-t", MANAGER_SESSION).returncode == 0:
            subprocess.run(["tmux", "attach", "-t", MANAGER_SESSION])
            return

        subprocess.run([
            "tmux", "new-session", "-s", MANAGER_SESSION,
            sys.executable, __file__, "--in-tmux"
        ])
        return

    if "--in-tmux" in sys.argv:
        curses.wrapper(TmuxManager().run)

if __name__ == "__main__":
    main()
