"""
helpers/units.py

The set of systemd units srtunnel owns (everything in configs/units/) and
their current state. One source of truth for the CLI and the HTTP adapter.
"""

import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
UNIT_DIR = BASE_DIR / "configs" / "units"

_PROPS = ("Id", "ActiveState", "UnitFileState", "MainPID")


def managed() -> list[str]:
    return [p.stem for p in sorted(UNIT_DIR.glob("*.service"))]


def states(names: list[str] | None = None) -> dict[str, dict]:
    """State for many units in one `systemctl show` call.

    The dashboard polls this every few seconds; one subprocess instead of
    three per unit matters on a Pi.
    """
    names = list(names if names is not None else managed())
    out = {
        n: {"name": n, "unit": f"{n}.service", "active": "unknown",
            "enabled": False, "pid": 0}
        for n in names
    }
    if not names:
        return out

    cmd = ["systemctl", "show", *(f"--property={p}" for p in _PROPS),
           *(f"{n}.service" for n in names)]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return out

    current = None
    for line in r.stdout.splitlines():
        key, _, value = line.partition("=")
        if key == "Id":
            current = value.removesuffix(".service")
            continue
        rec = out.get(current or "")
        if rec is None:
            continue
        if key == "ActiveState":
            rec["active"] = value
        elif key == "UnitFileState":
            rec["enabled"] = value in ("enabled", "enabled-runtime")
        elif key == "MainPID":
            try:
                rec["pid"] = int(value)
            except ValueError:
                rec["pid"] = 0
    return out


def state(name: str) -> dict:
    return states([name])[name]


def sync_manager_enable(name: str, enable: bool) -> None:
    """Keep configs/config.yaml manager.enable in sync when a managed unit is enabled/disabled."""
    if name not in managed():
        return
    import yaml
    for p in (BASE_DIR / "configs" / "config.yaml", BASE_DIR / "config.yaml"):
        if p.is_file():
            try:
                raw = yaml.safe_load(p.read_text()) or {}
                mgr = raw.get("manager") or {}
                en = list(mgr.get("enable") or [])
                if enable and name not in en:
                    en.append(name)
                elif not enable and name in en:
                    en.remove(name)
                mgr["enable"] = en
                raw["manager"] = mgr
                p.write_text(yaml.dump(raw, sort_keys=False))
            except Exception:
                pass
            break
