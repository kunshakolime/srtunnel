#!/usr/bin/env bash
set -e

BOT_DIR="/opt/srtunnel"
REPO="https://raw.githubusercontent.com/kunshakolime/srtunnel/main/"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/config.template.yaml" && -f "$SCRIPT_DIR/srapi.py" ]]; then
    BOT_DIR="$SCRIPT_DIR"
    echo "Detected existing repo at $BOT_DIR — skipping clone."
fi

die() { echo "ERROR: $*" >&2; exit 1; }
fetch() { local src="$1" dst="$2"; [[ "$src" == http* ]] || src="${REPO}$src"; curl -fsSL "$src" -o "$dst" || echo "WARNING: failed to fetch $src"; }

# ── Distro Check ──────────────────────────────────────────────────────────────
[ -f /etc/os-release ] || die "Cannot detect Linux distro."
source /etc/os-release
case "$ID" in debian|ubuntu) ;; *) die "Distro $ID not supported." ;; esac

# ── APT Dependencies ──────────────────────────────────────────────────────────
echo "Installing base dependencies..."
apt update -qq
apt install -y -qq git openssh-server stunnel4 python3 python3-certbot tmux curl openssl nano nftables libpam0g-dev nginx libnginx-mod-stream

# ── Python deps (Debian python3- equivalents of requirements.txt) ───────────
# requirements.txt: fastapi, uvicorn, requests, httpx, ruamel.yaml, psutil, PyYAML,
#                   python-pam, python-jose[cryptography], python-multipart, websockets
apt install -y -qq \
    python3-fastapi python3-uvicorn python3-requests python3-httpx \
    python3-ruamel.yaml python3-psutil python3-yaml python3-pam \
    python3-cryptography python3-jwcrypto \
    python3-python-multipart python3-websockets python3-pip

# python3-jose has no Debian package (only python3-josepy/joserfc); install via pip system-wide
pip install --break-system-packages "python-jose[cryptography]" 2>/dev/null \
 || pip3 install --break-system-packages "python-jose[cryptography]" 2>/dev/null \
 || echo "WARNING: python-jose not installed — JWT auth may fail" >&2

if [[ "$BOT_DIR" != "$SCRIPT_DIR" ]]; then
    git clone https://github.com/kunshakolime/srtunnel.git "$BOT_DIR"
fi
cd "$BOT_DIR"
mv ./bin/deb13amd64/* ./ 2>/dev/null || true
rm -rf ./bin/ 2>/dev/null || true
chmod +x ./* 2>/dev/null || true

mv ./badvpn-udpgw64 ./badvpn-udpgw 2>/dev/null || true
mv ./udp-zivpn-linux-amd64 ./udp-zivpn 2>/dev/null || true
mv ./udp-custom-linux-amd64 ./udp-custom 2>/dev/null || true
mv ./hysteria-linux-amd64-v1.3.5 ./hysteria1 2>/dev/null || true
mv ./hysteria-linux-amd64-v2.7.0 ./hysteria2 2>/dev/null || true

fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"   geoip.dat
fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat" geosite.dat

ln -sf "$BOT_DIR/srtunnel" /usr/sbin/srtunnel

# ── SSH tweak ─────────────────────────────────────────────────────────────
sshd_ensure(){ grep -qF "$1" /etc/ssh/sshd_config || echo "$1" >> /etc/ssh/sshd_config; }
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sshd_ensure "KexAlgorithms +diffie-hellman-group14-sha1"
sshd_ensure "Banner $BOT_DIR/bannerssh"
sshd_ensure "UsePAM yes"
echo "/sbin/nologin" >> /etc/shells
systemctl reload sshd || true

# ── Render Config (hardwired) ───────────────────────────────────────────────
cp config.template.yaml config.yaml
cp xray.template.json xray.json
echo "Hardwired config copied to config.yaml / xray.json — edit manually if needed."

# nginx setup moved to ./setup-nginx.sh — run it separately if needed
# (keeps debinstall minimal; dependencies still installed via apt)

# ── SlowDNS key ───────────────────────────────────────────────────────────────
./dnstt-server -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub 2>/dev/null || true

cat > /etc/systemd/system/srapi.service << 'EOF'
[Unit]
Description=srtunnel API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/srtunnel/srapi.py
WorkingDirectory=/opt/srtunnel
Restart=always
KillMode=process
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
EOF

#ln -sf /opt/srtunnel/stunnel.conf /etc/stunnel/stunnel.conf

# ── Dashboard admin group ─────────────────────────────────────────────────────
groupadd -f srtadmin 2>/dev/null || true
usermod -aG srtadmin root 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now srapi 2>/dev/null || true

echo "tunnel up and running (nginx not configured — run ./setup-nginx.sh if needed)"
