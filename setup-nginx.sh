#!/usr/bin/env bash
set -e

# setup-nginx.sh — nginx reverse-proxy for srtdash / srtunnel
# Extracted from debinstall.sh so debinstall stays minimal.
# Run manually after install:  sudo ./setup-nginx.sh
# Hardwired to example.com — edit /etc/nginx/stream-enabled/srtdash and
# /etc/nginx/sites-available/srtdash if you use a real domain.

BOT_DIR="/opt/srtunnel"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/config.template.yaml" && -f "$SCRIPT_DIR/srtdash.nginx" ]]; then
    BOT_DIR="$SCRIPT_DIR"
fi
cd "$BOT_DIR"

echo "Setting up nginx (BOT_DIR=$BOT_DIR)..."

# ── Dashboard static files ──────────────────────────────────────────────────
cp -r ./srtdash /var/www/srtdash 2>/dev/null || true

# ── Stream (SNI) ────────────────────────────────────────────────────────────
mkdir -p /etc/nginx/stream-enabled

cat > /etc/nginx/stream-enabled/srtdash << 'EOF'
map_hash_bucket_size 128;

map $ssl_preread_server_name $backend {
    default        127.0.0.1:8443;
    example.com        127.0.0.1:8444;
    srtnl.example.com  127.0.0.1:8444;
    rt1.example.com    127.0.0.1:8445;
    rt2.example.com    127.0.0.1:8446;
}

server {
    listen 443;
    proxy_pass $backend;
    ssl_preread on;
}
EOF

# ── HTTP vhost (srtdash) ────────────────────────────────────────────────────
# srtdash.nginx contains ${DOMAIN} and ${BOT_DIR} — replace with hardwired values
if [[ -f srtdash.nginx ]]; then
    sed -e "s|\${DOMAIN}|example.com|g" -e "s|\${BOT_DIR}|$BOT_DIR|g" srtdash.nginx > /etc/nginx/sites-available/srtdash
    ln -sf /etc/nginx/sites-available/srtdash /etc/nginx/sites-enabled/srtdash
else
    echo "WARNING: srtdash.nginx not found in $BOT_DIR — skipping vhost" >&2
fi

# ── Ensure stream include in nginx.conf ────────────────────────────────────
if ! grep -q "stream-enabled" /etc/nginx/nginx.conf; then
    sed -i '/^http {/i stream {\n    include /etc/nginx/stream-enabled/*;\n}\n' /etc/nginx/nginx.conf
    echo "Added stream include to /etc/nginx/nginx.conf"
fi

# Remove default site (binds :80, conflicts with stream)
rm -f /etc/nginx/sites-enabled/default

# ── Verify & enable ─────────────────────────────────────────────────────────
nginx -t
systemctl enable nginx 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true

echo "nginx setup done. Edit /etc/nginx/stream-enabled/srtdash for real domains and run: nginx -t && systemctl reload nginx"
