"""
helpers/units.py

The set of systemd units srtunnel owns (everything in configs/units/) and
their current state. One source of truth for the CLI and the HTTP adapter.
"""

import re
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

    for block in re.split(r"\n\s*\n", r.stdout.strip()):
        props = {}
        for line in block.splitlines():
            k, _, v = line.partition("=")
            if k and v:
                props[k] = v
        name = props.get("Id", "").removesuffix(".service")
        if not name or name not in out:
            continue
        rec = out[name]
        rec["active"] = props.get("ActiveState", "unknown")
        rec["enabled"] = props.get("UnitFileState") in ("enabled", "enabled-runtime")
        try:
            rec["pid"] = int(props.get("MainPID", 0))
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
