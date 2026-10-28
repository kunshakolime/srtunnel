#!/usr/bin/env bash
# ── srtunnel Uninstall Script ─────────────────────────────────────────────────
set -euo pipefail

BOT_DIR="/opt/srtunnel"

confirm() {
    read -rp "$1 [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

echo "========================================"
echo "  srtunnel Uninstall Script"
echo "========================================"
echo ""
# ── Stop & Disable Services ───────────────────────────────────────────────────
echo ""
echo "[1/8] Stopping and disabling services..."

# srtunnel-owned units (read from the repo before it is removed)
if [[ -d "$BOT_DIR/configs/units" ]]; then
    for u in "$BOT_DIR"/configs/units/*.service; do
        svc=$(basename "$u" .service)
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done
fi

for svc in srapi stunnel4 nginx; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  Stopping $svc..."
        systemctl stop "$svc" || true
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        echo "  Disabling $svc..."
        systemctl disable "$svc" || true
    fi
done

# ── Remove systemd Unit ───────────────────────────────────────────────────────
echo ""
echo "[2/8] Removing systemd unit files..."

if [[ -d "$BOT_DIR/configs/units" ]]; then
    for u in "$BOT_DIR"/configs/units/*.service; do
        rm -f "/etc/systemd/system/$(basename "$u")"
    done
else
    rm -f /etc/systemd/system/{srapi,ws-sr,badvpn,dropbear,hysteria2,pystunnel,slowdns,stunnel,telegrambot,trafficmeter,udpcustom,zivpn}.service
fi
systemctl daemon-reload

# ── Remove Symlinks ───────────────────────────────────────────────────────────
echo ""
echo "[3/8] Removing symlinks..."

rm -f /usr/sbin/srtunnel
rm -rf /usr/local/libexec/srtunnel
rm -f /etc/stunnel/stunnel.conf
rm -f /etc/sysctl.d/99-srtunnel.conf
rm -rf /var/lib/srtunnel

# ── Revert SSH Config ─────────────────────────────────────────────────────────
echo ""
echo "[4/8] Reverting SSH configuration..."

rm -f /etc/ssh/sshd_config.d/srtunnel.conf

if [[ -f /etc/ssh/sshd_config.bak ]]; then
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    echo "  Restored sshd_config from backup."
    systemctl reload sshd || true
else
    echo "  WARNING: No sshd_config backup found. Removing srtunnel-added lines manually..."
    sed -i '/KexAlgorithms +diffie-hellman-group14-sha1/d' /etc/ssh/sshd_config
    sed -i "\|Banner $BOT_DIR/configs/bannerssh|d" /etc/ssh/sshd_config
    sed -i "\|Banner $BOT_DIR/bannerssh|d" /etc/ssh/sshd_config
    sed -i '/UsePAM yes/d' /etc/ssh/sshd_config
    systemctl reload sshd || true
fi

# Remove /sbin/nologin from /etc/shells if we added it
# (it may legitimately exist; only remove the duplicate if it was appended)
# We leave /etc/shells alone to be safe since nologin may have existed before.

# ── Revert Nginx Config ───────────────────────────────────────────────────────
echo ""
echo "[5/8] Reverting Nginx configuration..."

rm -f /etc/nginx/sites-enabled/srtunnel
rm -f /etc/nginx/sites-available/srtunnel
rm -f /etc/nginx/sites-enabled/srtdash
rm -f /etc/nginx/sites-available/srtdash
rm -f /etc/nginx/stream-enabled/srtdash
rm -f /etc/nginx/stream-enabled/ws /etc/nginx/stream-available/ws
rmdir --ignore-fail-on-non-empty /etc/nginx/stream-available 2>/dev/null || true
rmdir --ignore-fail-on-non-empty /etc/nginx/stream-enabled 2>/dev/null || true

# Remove the stream {} block we injected into nginx.conf
if grep -q 'include /etc/nginx/stream-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
    sed -i '/^stream {/,/^}/d' /etc/nginx/nginx.conf
    echo "  Removed stream block from nginx.conf."
fi

# Remove srtdash web root
rm -rf /var/www/srtdash

# Restart nginx only if config is valid and nginx exists
if command -v nginx &>/dev/null && nginx -t 2>/dev/null; then
    systemctl restart nginx || true
fi

# ── Remove Installed Packages ─────────────────────────────────────────────────
echo ""
echo "[6/8] Removing installed packages..."

if confirm "  Remove packages installed by the setup script? (stunnel4, nginx, nftables, etc.)"; then
    apt remove -y --purge \
        stunnel4 nginx libnginx-mod-stream speedtest \
        2>/dev/null || true
    apt autoremove -y 2>/dev/null || true
    echo "  Done. Note: git, openssh-server, python3, curl, etc. were NOT removed"
    echo "  as they are commonly pre-installed or used by other services."
else
    echo "  Skipping package removal."
fi

# ── Remove Let's Encrypt Certificates ──────────────────────────────────────────
echo ""
echo "[7/8] Removing Let's Encrypt certificates..."

if [[ -d /etc/letsencrypt/live ]]; then
    echo "  Existing certificates found:"
    for c in /etc/letsencrypt/live/*/; do
        echo "    - $(basename "$c")"
    done
    if confirm "  Remove all Let's Encrypt certificates and cleanup?"; then
        rm -rf /etc/letsencrypt
        echo "  Certificates removed."
    else
        echo "  Skipping certificate removal."
    fi
else
    echo "  No Let's Encrypt certificates found."
fi

# ── Remove Bot Directory ──────────────────────────────────────────────────────
echo ""
echo "[8/8] Removing srtunnel directory..."

if [[ -d "$BOT_DIR" ]]; then
    if confirm "  Delete $BOT_DIR and all its contents?"; then
        rm -rf "$BOT_DIR"
        echo "  $BOT_DIR removed."
    else
        echo "  Skipping directory removal."
    fi
else
    echo "  $BOT_DIR not found, nothing to remove."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  srtunnel uninstall complete."
echo "========================================"
echo ""
echo "You may want to manually review:"
echo "  - /etc/shells          (may still contain /sbin/nologin)"
echo "  - /etc/stunnel/        (any remaining stunnel configs)"
echo "  - Firewall/nftables rules if any were added separately"