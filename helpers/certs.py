"""
helpers/certs.py

The one TLS certificate pair every consumer reads:

    <repo>/fullchain.pem    certificate (+ chain)
    <repo>/privkey.pem      private key

The pair is either self-signed or a symlink into /etc/letsencrypt/live/<domain>/.
stunnel, nginx, hysteria2 and zivpn all reference these stable paths, so
swapping the source never means editing service configs.

certbot runs with the standalone authenticator because nginx owns :80. The
stop/start hooks are passed at issuance and stored in the renewal config, so
`certbot.timer` can renew unattended, and the deploy hook restarts stunnel
(which only reads the certificate at startup).
"""

from __future__ import annotations

import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CERT = BASE_DIR / "fullchain.pem"
KEY = BASE_DIR / "privkey.pem"
LE_LIVE = Path("/etc/letsencrypt/live")

NGINX_STOP = "systemctl stop nginx 2>/dev/null || true"
NGINX_START = "systemctl start nginx 2>/dev/null || true"
STUNNEL_RESTART = "systemctl try-restart stunnel 2>/dev/null || true"

RENEW_DAYS = 30


def _run(cmd: list[str], timeout: int = 180) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout)
        return p.returncode == 0, p.stdout.strip()
    except FileNotFoundError:
        return False, f"{cmd[0]} not found"
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def _active(unit: str) -> bool:
    ok, out = _run(["systemctl", "is-active", unit], timeout=10)
    return ok and out.strip() == "active"


def describe() -> dict:
    """Current certificate: paths, subject, issuer, expiry."""
    info = {
        "cert": str(CERT),
        "key": str(KEY),
        "present": CERT.is_file() and KEY.is_file(),
        "link": os.readlink(CERT) if CERT.is_symlink() else None,
    }
    if not info["present"]:
        return info

    ok, out = _run(["openssl", "x509", "-in", str(CERT), "-noout",
                    "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"], timeout=10)
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()

    try:
        end = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        info["days_left"] = (end - datetime.now(timezone.utc)).days
    except (KeyError, ValueError):
        info["days_left"] = None
    return info


def _issued_for(domain: str) -> bool:
    """True when fullchain.pem already points at this domain's lineage."""
    target = str(LE_LIVE / domain / "fullchain.pem")
    return CERT.is_symlink() and os.readlink(CERT) == target


def self_signed(cn: str | None = None, force: bool = False) -> tuple[bool, str]:
    """Generate a long-lived self-signed pair (idempotent unless force=True)."""
    if CERT.is_file() and KEY.is_file() and not force:
        return True, f"certificate already present at {CERT}"
    cn = cn or socket.getfqdn() or socket.gethostname()
    CERT.unlink(missing_ok=True)
    KEY.unlink(missing_ok=True)
    ok, out = _run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:prime256v1", "-days", "3650",
                    "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}",
                    "-keyout", str(KEY), "-out", str(CERT)], timeout=60)
    if ok:
        os.chmod(CERT, 0o644)
        os.chmod(KEY, 0o600)
        return True, f"self-signed certificate for {cn} at {CERT}"
    return False, out or "openssl failed"


def _activate() -> None:
    """Make the running daemons pick up the current files."""
    if _active("nginx"):
        _run(["systemctl", "reload", "nginx"], timeout=30)
    else:
        _run(["systemctl", "start", "nginx"], timeout=30)
    _run(["systemctl", "try-restart", "stunnel"], timeout=60)


def issue(domain: str, force: bool = False) -> tuple[bool, str]:
    """Obtain (or renew) a Let's Encrypt certificate for domain via certbot."""
    if not force:
        info = describe()
        if _issued_for(domain) and (info.get("days_left") or 0) > RENEW_DAYS:
            return True, (f"certificate for {domain} is valid for "
                          f"{info['days_left']} more days — nothing to do")

    # :80 must be free for the HTTP-01 challenge; nginx owns it here.
    _run(["systemctl", "stop", "nginx"], timeout=30)
    ok, out = _run(["certbot", "certonly", "--standalone", "--non-interactive",
                    "--agree-tos", "--register-unsafely-without-email",
                    "--cert-name", domain, "-d", domain,
                    "--pre-hook", NGINX_STOP,
                    "--post-hook", NGINX_START,
                    "--deploy-hook", STUNNEL_RESTART], timeout=300)
    if not ok:
        _run(["systemctl", "start", "nginx"], timeout=30)
        return False, out

    live = LE_LIVE / domain
    CERT.unlink(missing_ok=True)
    KEY.unlink(missing_ok=True)
    CERT.symlink_to(live / "fullchain.pem")
    KEY.symlink_to(live / "privkey.pem")
    _activate()
    return True, out or f"installed {live} for {domain}"
