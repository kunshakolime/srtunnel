"""
Manager for third-party release binaries in /usr/local/libexec/srtunnel.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

BIN_DIR = Path(os.environ.get("SRTUNNEL_BIN_DIR", "/usr/local/libexec/srtunnel"))
RELEASE_BASE_URL = "https://github.com/kunshakolime/srtunnel/releases/latest/download"

BINS_BY_ARCH: dict[str, list[str]] = {
    "amd64": [
        "badvpn-udpgw",
        "dnstt-server",
        "hysteria2",
        "udp-custom",
        "udp-zivpn",
        "ipmask_tool",
        "traffic_meter_user",
    ],
    "arm64": [
        "badvpn-udpgw",
        "udp-zivpn",
        "ipmask_tool",
        "traffic_meter_user",
    ],
}

COMMON_FILES = [
    ("traffic_meter.bpf.o", 0o644),
]

AFFECTED_SERVICES = [
    "badvpn",
    "hysteria2",
    "slowdns",
    "udpcustom",
    "zivpn",
    "trafficmeter",
]


def detect_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise RuntimeError(f"Unsupported architecture: {machine}")


def list_bins() -> list[str]:
    if not BIN_DIR.is_dir():
        return []
    return [p.name for p in sorted(BIN_DIR.iterdir()) if p.is_file() and not p.name.startswith(".")]


def update_bins(restart: bool = True) -> int:
    try:
        arch = detect_arch()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    bins = BINS_BY_ARCH.get(arch, [])
    print(f"Updating {arch} binaries in {BIN_DIR}...")

    failed: list[str] = []

    for name in bins:
        asset_name = f"{name}-{arch}"
        url = f"{RELEASE_BASE_URL}/{asset_name}"
        tmp_dst = BIN_DIR / f".tmp.{name}"
        final_dst = BIN_DIR / name

        print(f"  Fetching {name}...")
        res = subprocess.run(["curl", "-fsSL", url, "-o", str(tmp_dst)])
        if res.returncode == 0:
            tmp_dst.chmod(0o755)
            tmp_dst.replace(final_dst)
        else:
            if tmp_dst.exists():
                tmp_dst.unlink(missing_ok=True)
            print(f"  Failed to download {name}")
            failed.append(name)

    for name, mode in COMMON_FILES:
        url = f"{RELEASE_BASE_URL}/{name}"
        tmp_dst = BIN_DIR / f".tmp.{name}"
        final_dst = BIN_DIR / name

        print(f"  Fetching {name}...")
        res = subprocess.run(["curl", "-fsSL", url, "-o", str(tmp_dst)])
        if res.returncode == 0:
            tmp_dst.chmod(mode)
            tmp_dst.replace(final_dst)
        else:
            if tmp_dst.exists():
                tmp_dst.unlink(missing_ok=True)
            print(f"  Failed to download {name}")
            failed.append(name)

    if failed:
        print(f"WARNING: Failed to update: {', '.join(failed)}", file=sys.stderr)

    if restart:
        print("Restarting active services...")
        for svc in AFFECTED_SERVICES:
            check = subprocess.run(["systemctl", "is-active", "--quiet", f"{svc}.service"])
            if check.returncode == 0:
                subprocess.run(["systemctl", "try-restart", f"{svc}.service"])
                print(f"  Restarted {svc}.service")

    print("Binaries update complete.")
    return 1 if failed else 0
