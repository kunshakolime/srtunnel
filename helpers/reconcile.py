"""
helpers/reconcile.py

Render the repository's templates into their live system paths, once and
idempotently.

    srtunnel reconcile --dry-run
    srtunnel reconcile

Every target is compared before it is written. A live file that no longer
matches what reconcile last wrote is reported as *drift* and left alone
unless --force is given, so hand-edited deployment files are never silently
clobbered.

Validation (`nginx -t`, `sshd -t`) runs before the matching service is
reloaded; if it fails, the previously written files are restored.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
BOT_DIR = str(BASE_DIR)
UNIT_DIR = BASE_DIR / "configs" / "units"
# Third-party binaries live outside the checkout so `git clean` and repo
# updates cannot touch them. Populated by scripts/debinstall.sh.
BIN_DIR = Path("/usr/local/libexec/srtunnel")

STATE_DIR = Path("/var/lib/srtunnel")
STATE_FILE = STATE_DIR / "reconcile.json"
BACKUP_DIR = STATE_DIR / "backups"

SSHD_DROPIN = """# Managed by srtunnel reconcile — local edits will be overwritten.
KexAlgorithms +diffie-hellman-group14-sha1
Banner {bot}/configs/bannerssh
UsePAM yes
# ws-sr/stunnel dial the backend from 127.0.0.1, so every tunnel user shares
# one source address. OpenSSH 9.8+ PerSourcePenalties would let one bad client
# reject everyone else with "Not allowed at this time" — exempt loopback and
# lift the (global) pre-auth connection cap.
PerSourcePenaltyExemptList 127.0.0.1/32,::1/128
MaxStartups 100:30:200
"""

SYSCTL_DROPIN = """# Managed by srtunnel reconcile
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
"""


@dataclass
class Target:
    name: str
    kind: str                      # unit | nginx | stunnel | cockpit | sshd | sysctl
    dst: Path
    source: Optional[Path] = None
    text: Optional[str] = None
    mode: int = 0o644


@dataclass
class Action:
    dst: Path
    kind: str
    name: str
    status: str                    # create | update | same | drift | missing-source
    diff: str = ""
    backup: str = ""

    def as_dict(self) -> dict:
        return {
            "path": str(self.dst),
            "kind": self.kind,
            "name": self.name,
            "status": self.status,
            "diff": self.diff,
        }


# ── targets ───────────────────────────────────────────────────────────────────

def targets() -> list[Target]:
    ts: list[Target] = []

    for src in sorted(UNIT_DIR.glob("*.service")):
        ts.append(Target("units", "unit", Path("/etc/systemd/system") / src.name, source=src))

    ts.append(Target("nginx-srtunnel", "nginx",
                     Path("/etc/nginx/sites-available/srtunnel"),
                     source=BASE_DIR / "configs" / "srtunnel.nginx"))
    ts.append(Target("nginx-ws", "nginx",
                     Path("/etc/nginx/stream-available/ws"),
                     source=BASE_DIR / "configs" / "ws.nginx"))
    ts.append(Target("stunnel", "stunnel",
                     Path("/etc/stunnel/stunnel.conf"),
                     source=BASE_DIR / "configs" / "stunnel.conf"))
    if Path("/etc/cockpit").is_dir():
        ts.append(Target("cockpit", "cockpit",
                         Path("/etc/cockpit/cockpit.conf"),
                         source=BASE_DIR / "configs" / "cockpit.conf"))
    ts.append(Target("sshd", "sshd",
                     Path("/etc/ssh/sshd_config.d/srtunnel.conf"),
                     text=SSHD_DROPIN.format(bot=BOT_DIR), mode=0o600))
    ts.append(Target("sysctl", "sysctl",
                     Path("/etc/sysctl.d/99-srtunnel.conf"),
                     text=SYSCTL_DROPIN))
    return ts


# ── rendering / state ─────────────────────────────────────────────────────────

def _render(t: Target) -> bytes:
    data = t.text if t.text is not None else t.source.read_text()
    data = (data.replace("${BIN_DIR}", str(BIN_DIR))
                .replace("${BOT_DIR}", BOT_DIR)
                .replace("/opt/srtunnel", BOT_DIR))
    return data.encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))


def _diff(live: bytes, new: bytes, dst: Path) -> str:
    return "".join(difflib.unified_diff(
        live.decode("utf-8", "replace").splitlines(keepends=True),
        new.decode("utf-8", "replace").splitlines(keepends=True),
        fromfile=f"live:{dst}", tofile="repo", n=2,
    ))


# ── planning ──────────────────────────────────────────────────────────────────

def _split(value: Optional[str]) -> set[str]:
    return {v.strip() for v in (value or "").split(",") if v.strip()}


def adopt(names: set[str]) -> list[str]:
    """Mark targets as intentionally local: record them and never overwrite them."""
    state = _load_state()
    adopted = []
    for t in targets():
        if t.name in names and t.dst.exists():
            state[str(t.dst)] = "local"
            adopted.append(t.name)
    _save_state(state)
    return adopted


def unadopt(names: set[str]) -> list[str]:
    state = _load_state()
    removed = []
    for t in targets():
        if t.name in names and state.get(str(t.dst)) == "local":
            state.pop(str(t.dst), None)
            removed.append(t.name)
    _save_state(state)
    return removed


def plan(force: bool = False, only: Optional[str] = None, skip: Optional[str] = None) -> list[tuple[Target, Action]]:
    keep, drop = _split(only), _split(skip)
    state = _load_state()
    items: list[tuple[Target, Action]] = []

    for t in targets():
        if keep and t.name not in keep:
            continue
        if t.name in drop:
            continue
        if t.source is not None and not t.source.exists():
            items.append((t, Action(t.dst, t.kind, t.name, "missing-source")))
            continue

        new = _render(t)
        live = t.dst.read_bytes() if t.dst.exists() else None
        prev = state.get(str(t.dst))

        if live is None:
            status = "create"
        elif prev == "local":
            status = "same"              # explicitly pinned by --adopt
        elif live == new:
            status = "same"
        elif prev is not None and _sha(live) == prev:
            status = "update"            # we wrote it last time; repo changed
        elif force:
            status = "update"            # drift, explicitly overwritten
        else:
            status = "drift"             # unknown / hand-edited live file

        diff = _diff(live, new, t.dst) if live is not None and status in ("update", "drift") else ""
        items.append((t, Action(t.dst, t.kind, t.name, status, diff)))

    return items


# ── applying ──────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 60) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout)
        return p.returncode == 0, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def _active(name: str) -> bool:
    ok, out = _run(["systemctl", "is-active", f"{name}.service"], timeout=10)
    return ok and out.strip() == "active"


def _ensure_symlinks() -> None:
    pairs = [
        (Path("/etc/nginx/sites-enabled/srtunnel"),
         Path("/etc/nginx/sites-available/srtunnel")),
        (Path("/etc/nginx/stream-enabled/ws"),
         Path("/etc/nginx/stream-available/ws")),
    ]
    for link, target in pairs:
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() and os.readlink(link) == str(target):
            continue
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)
    Path("/etc/nginx/stream-enabled").mkdir(parents=True, exist_ok=True)
    Path("/etc/nginx/stream-available").mkdir(parents=True, exist_ok=True)


def _ensure_stream_include() -> Optional[Path]:
    """Add the stream include to nginx.conf once; return the backup if changed."""
    conf = Path("/etc/nginx/nginx.conf")
    if not conf.exists():
        return None
    text = conf.read_text()
    if "stream-enabled" in text or "http {" not in text:
        return None
    backup = BACKUP_DIR / f"nginx.conf.{int(time.time())}"
    shutil.copy2(conf, backup)
    conf.write_text(text.replace(
        "http {",
        "stream {\n    include /etc/nginx/stream-enabled/*;\n}\n\nhttp {",
        1,
    ))
    return backup


def _restore(written: list[tuple[Target, Action]], state: dict) -> None:
    for t, a in written:
        try:
            if a.backup:
                shutil.copy2(a.backup, t.dst)
            elif t.dst.exists():
                t.dst.unlink()
        except OSError:
            pass
        state.pop(str(t.dst), None)
    _save_state(state)


def _enable_units() -> dict[str, str]:
    """Enable the units listed in configs/config.yaml → manager.enable."""
    try:
        import yaml
        raw = yaml.safe_load((BASE_DIR / "configs" / "config.yaml").read_text()) or {}
    except Exception:
        return {}
    names = (raw.get("manager") or {}).get("enable") or []
    result = {}
    for name in names:
        unit = Path("/etc/systemd/system") / f"{name}.service"
        if not unit.exists():
            continue
        ok, out = _run(["systemctl", "is-enabled", f"{name}.service"], timeout=10)
        if ok and out.strip() == "enabled":
            result[name] = "already enabled"
            continue
        ok, out = _run(["systemctl", "enable", "--now", f"{name}.service"], timeout=30)
        result[name] = "enabled+started" if ok else f"failed: {out}"
    return result


def run(dry_run: bool = False, force: bool = False,
        only: Optional[str] = None, skip: Optional[str] = None) -> dict:
    items = plan(force=force, only=only, skip=skip)
    changes = [a for _, a in items if a.status != "same"]
    result = {
        "dry_run": dry_run,
        "changes": [a.as_dict() for a in changes],
        "validated": {},
        "enabled": {},
        "error": None,
    }
    if dry_run:
        return result

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    state = _load_state()
    written: list[tuple[Target, Action]] = []
    stamp = str(int(time.time()))

    for t, a in items:
        if a.status == "same":
            if state.get(str(t.dst)) != "local":
                state[str(t.dst)] = _sha(_render(t))
            continue
        if a.status not in ("create", "update"):
            continue

        data = _render(t)
        if t.dst.exists():
            backup = BACKUP_DIR / f"{t.dst.name}.{stamp}"
            shutil.copy2(t.dst, backup)
            a.backup = str(backup)

        t.dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = t.dst.with_name(t.dst.name + ".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, t.mode)
        os.replace(tmp, t.dst)
        state[str(t.dst)] = _sha(data)
        written.append((t, a))

    _save_state(state)
    written_names = {t.name for t, _ in written}

    # ── nginx ────────────────────────────────────────────────────────────────
    if any(t.kind == "nginx" for t, _ in written):
        _ensure_symlinks()
        nginx_conf_backup = _ensure_stream_include()
        ok, out = _run(["nginx", "-t"])
        result["validated"]["nginx"] = "ok" if ok else out
        if not ok:
            _restore(written, state)
            if nginx_conf_backup is not None:
                shutil.copy2(nginx_conf_backup, "/etc/nginx/nginx.conf")
            result["error"] = "nginx -t failed; changes rolled back"
            return result
        ok, out = _run(["systemctl", "reload", "nginx"])
        result["validated"]["reload:nginx"] = "ok" if ok else out

    # ── sshd ─────────────────────────────────────────────────────────────────
    if "sshd" in written_names:
        ok, out = _run(["sshd", "-t"])
        result["validated"]["sshd"] = "ok" if ok else out
        if not ok:
            _restore(written, state)
            result["error"] = "sshd -t failed; changes rolled back"
            return result
        if not _run(["systemctl", "reload", "sshd"])[0]:
            _run(["systemctl", "reload", "ssh"])

    # ── sysctl ───────────────────────────────────────────────────────────────
    if "sysctl" in written_names:
        ok, out = _run(["sysctl", "-q", "-p", "/etc/sysctl.d/99-srtunnel.conf"])
        result["validated"]["sysctl"] = "ok" if ok else out

    # ── units ────────────────────────────────────────────────────────────────
    unit_changes = [(t, a) for t, a in written if t.kind == "unit"]
    if unit_changes:
        _run(["systemctl", "daemon-reload"])
        for t, _ in unit_changes:
            name = t.dst.stem
            if _active(name):
                ok, out = _run(["systemctl", "restart", f"{name}.service"], timeout=60)
                result["validated"][f"restart:{name}"] = "ok" if ok else out

    # ── simple restarts ──────────────────────────────────────────────────────
    for kind in ("stunnel", "cockpit"):
        if any(t.kind == kind for t, _ in written) and _active(kind):
            ok, out = _run(["systemctl", "restart", kind], timeout=60)
            result["validated"][f"restart:{kind}"] = "ok" if ok else out

    result["enabled"] = _enable_units()
    return result
