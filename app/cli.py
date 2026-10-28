#!/opt/srtunnel/venv/bin/python
"""
app/cli.py

Scriptable entrypoint for srtunnel.

    srtunnel                     # same as `srtunnel status`
    srtunnel status [--json]
    srtunnel reconcile [--dry-run|--check] [--force] [--only NAMES] [--skip NAMES] [--json]
    srtunnel bin                 # show where the release binaries are installed
    srtunnel exec NAME [args]    # run one of them (not on PATH)
    srtunnel cert                # show the TLS certificate
    srtunnel cert -d DOMAIN      # obtain/renew a Let's Encrypt certificate
    srtunnel cert --selfsigned   # generate a self-signed pair if missing
    srtunnel run                 # foreground srapi (replaces startsrapi.sh)
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Release binaries — kept off PATH, see binaries.lock.
BIN_DIR = Path(os.environ.get("SRTUNNEL_BIN_DIR", "/usr/local/libexec/srtunnel"))


# ── helpers ───────────────────────────────────────────────────────────────────

def _version() -> str:
    try:
        p = subprocess.run(["git", "-C", str(BASE_DIR), "rev-parse", "--short", "HEAD"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5)
        return p.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _user_count() -> int | None:
    db = BASE_DIR / "users.db"
    if not db.exists():
        return None
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return con.execute("SELECT count(*) FROM users").fetchone()[0]
        finally:
            con.close()
    except sqlite3.Error:
        return None


def collect_status() -> dict:
    from helpers import monitor, reconcile, units

    ports: dict[int, set[int]] = {}
    for p in monitor.listening_ports():
        if p.get("pid"):
            ports.setdefault(p["pid"], set()).add(p["port"])

    unit_rows = []
    for name, st in units.states().items():
        st["ports"] = sorted(ports.get(st["pid"], set()))
        unit_rows.append(st)

    drift = [
        {"path": a.dst, "kind": a.kind, "name": a.name, "status": a.status}
        for _, a in reconcile.plan()
        if a.status in ("create", "update", "drift")
    ]

    db = BASE_DIR / "users.db"
    return {
        "schema": 1,
        "version": _version(),
        "base_dir": str(BASE_DIR),
        "units": unit_rows,
        "drift": drift,
        "users": _user_count(),
        "db_bytes": db.stat().st_size if db.exists() else 0,
    }


def _print_status(s: dict) -> None:
    print(f"srtunnel {s['version']}  {s['base_dir']}")
    print(f"{'UNIT':<14}{'ACTIVE':<10}{'ENABLED':<10}{'PID':<8}PORTS")
    for u in s["units"]:
        ports = ",".join(str(p) for p in u["ports"]) or "-"
        print(f"{u['name']:<14}{u['active']:<10}{'yes' if u['enabled'] else 'no':<10}"
              f"{u['pid'] or '-':<8}{ports}")
    print()
    print(f"users: {s['users'] if s['users'] is not None else 'n/a'}   "
          f"db: {s['db_bytes']} bytes   drift: {len(s['drift'])}")
    for d in s["drift"]:
        print(f"  {d['status']:<8}{d['path']}")


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_status(args) -> int:
    s = collect_status()
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        _print_status(s)
    return 0


def cmd_reconcile(args) -> int:
    from helpers import reconcile

    dry = args.dry_run or args.check
    adopted = reconcile.adopt({x.strip() for x in (args.adopt or "").split(",") if x.strip()}) if args.adopt else []
    unadopted = reconcile.unadopt({x.strip() for x in (args.unadopt or "").split(",") if x.strip()}) if args.unadopt else []
    result = reconcile.run(dry_run=dry, force=args.force,
                           only=args.only, skip=args.skip)

    result["adopted"] = adopted
    result["unadopted"] = unadopted

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if dry:
            print("reconcile (dry-run)")
        for c in result["changes"]:
            sym = {"create": "+", "update": "~", "drift": "!",
                   "missing-source": "?"}.get(c["status"], " ")
            print(f" {sym} {c['path']}  ({c['kind']})")
            if c["status"] == "drift":
                print("     live file was hand-edited — use --force to overwrite")
            if dry and c.get("diff"):
                print(c["diff"].rstrip())
        if not result["changes"]:
            print("in sync — nothing to do")
        for k, v in result["validated"].items():
            print(f" {k}: {v}")
        for k, v in result["enabled"].items():
            print(f" enable {k}: {v}")
        for n in result.get("adopted", []):
            print(f" adopted (local): {n}")
        for n in result.get("unadopted", []):
            print(f" unadopted: {n}")

    if result["error"]:
        print(result["error"], file=sys.stderr)
        return 1
    if args.check and result["changes"]:
        return 1
    return 0


def cmd_run(args) -> int:
    target = BASE_DIR / "app" / "srapi.py"
    os.execv(sys.executable, [sys.executable, str(target)])


def cmd_version(args) -> int:
    print(_version())
    return 0


def cmd_bin(args) -> int:
    print(BIN_DIR)
    if not BIN_DIR.is_dir():
        print("  (not installed — run scripts/debinstall.sh)", file=sys.stderr)
        return 1
    for p in sorted(BIN_DIR.iterdir()):
        if p.is_file() and not p.name.startswith("."):
            print(f"  {p.name}")
    return 0


def cmd_exec(args) -> int:
    exe = BIN_DIR / args.name
    if not exe.is_file():
        print(f"{exe} not installed — run scripts/debinstall.sh", file=sys.stderr)
        return 127
    try:
        os.execv(str(exe), [args.name, *args.args])
    except OSError as e:
        print(f"cannot exec {exe}: {e}", file=sys.stderr)
        return 127


def cmd_cert(args) -> int:
    from helpers import certs

    if args.selfsigned:
        ok, msg = certs.self_signed(args.domain, force=args.force)
        print(msg, file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1

    if args.domain:
        ok, msg = certs.issue(args.domain, force=args.force)
        print(msg)
        return 0 if ok else 1

    info = certs.describe()
    if args.json:
        print(json.dumps(info, indent=2))
        return 0 if info["present"] else 1
    if not info["present"]:
        print(f"no certificate at {info['cert']} — run "
              f"`srtunnel cert --selfsigned` or `srtunnel cert -d DOMAIN`",
              file=sys.stderr)
        return 1

    print(info["cert"] + (f" -> {info['link']}" if info.get("link") else ""))
    print(f"  subject  {info.get('subject', '?')}")
    print(f"  issuer   {info.get('issuer', '?')}")
    days = info.get("days_left")
    print(f"  expires  {info.get('notAfter', '?')}"
          + (f"  ({days} days)" if days is not None else ""))
    print(f"  key      {info['key']}")
    return 0


# ── entrypoint ────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="srtunnel",
        description="srtunnel — scriptable status and system reconciliation",
    )
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("status", help="show units, ports, users and config drift")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("reconcile", help="render templates into system paths")
    p.add_argument("--dry-run", action="store_true", help="show changes without writing")
    p.add_argument("--check", action="store_true", help="dry-run; exit 1 if anything would change")
    p.add_argument("--force", action="store_true", help="overwrite hand-edited live files")
    p.add_argument("--only", default=None, help="comma list: units,nginx-srtunnel,nginx-ws,stunnel,cockpit,sshd,sysctl")
    p.add_argument("--skip", default=None, help="comma list of the same names to skip")
    p.add_argument("--adopt", default=None, help="pin targets as local (never overwrite)")
    p.add_argument("--unadopt", default=None, help="remove a local pin")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_reconcile)

    p = sub.add_parser("run", help="run srapi in the foreground")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("bin", help="list the installed release binaries")
    p.set_defaults(func=cmd_bin)

    p = sub.add_parser("exec", help="run an installed binary: srtunnel exec NAME [args]")
    p.add_argument("name")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_exec)

    p = sub.add_parser("cert", help="show or obtain the TLS certificate")
    p.add_argument("-d", "--domain", help="Let's Encrypt domain (or CN for --selfsigned)")
    p.add_argument("--selfsigned", action="store_true",
                   help="generate a self-signed pair if missing")
    p.add_argument("--force", action="store_true",
                   help="ignore the renewal window / replace the existing pair")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_cert)

    p = sub.add_parser("version", help="print the deployed commit")
    p.set_defaults(func=cmd_version)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args = parser.parse_args(["status"])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
