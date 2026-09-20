#!/usr/bin/env bash
set -e

BOT_DIR="/opt/srtunnel"
REPO="https://raw.githubusercontent.com/kunshakolime/srtunnel/main/"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# repo root is parent of scripts/ when installed from clone
REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "$SCRIPT_DIR")"

if [[ -f "$REPO_ROOT/configs/config.template.yaml" && -f "$REPO_ROOT/app/srapi.py" ]]; then
    BOT_DIR="$REPO_ROOT"
    echo "Detected existing repo at $BOT_DIR — skipping clone."
elif [[ -f "$SCRIPT_DIR/configs/config.template.yaml" && -f "$SCRIPT_DIR/app/srapi.py" ]]; then
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
apt install -y -qq git openssh-server stunnel4 python3 certbot tmux curl openssl nano nftables libpam0g-dev nginx libnginx-mod-stream

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

if [[ "$BOT_DIR" != "$REPO_ROOT" && "$BOT_DIR" != "$SCRIPT_DIR" ]]; then
    git clone https://github.com/kunshakolime/srtunnel.git "$BOT_DIR"
fi
cd "$BOT_DIR"
mkdir -p bin configs
# binaries ship per-arch (bin/deb13amd64, bin/arm64) — flatten into bin/
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
    amd64|x86_64)  ARCH_BIN="deb13amd64" ;;
    arm64|aarch64) ARCH_BIN="arm64" ;;
    *) die "Architecture $ARCH not supported." ;;
esac
if [ -d "./bin/$ARCH_BIN" ]; then
    mv "./bin/$ARCH_BIN"/* ./bin/ 2>/dev/null || true
    rmdir "./bin/$ARCH_BIN" 2>/dev/null || true
fi
chmod +x ./bin/* 2>/dev/null || true
chmod +x ./* 2>/dev/null || true

mv ./bin/badvpn-udpgw64 ./bin/badvpn-udpgw 2>/dev/null || true
mv ./bin/udp-zivpn-linux-amd64 ./bin/udp-zivpn 2>/dev/null || true
mv ./bin/udp-custom-linux-amd64 ./bin/udp-custom 2>/dev/null || true
mv ./bin/hysteria-linux-amd64-v1.3.5 ./bin/hysteria1 2>/dev/null || true
mv ./bin/hysteria-linux-amd64-v2.7.0 ./bin/hysteria2 2>/dev/null || true

# flag binaries this checkout has no build for (the arm64 set is incomplete)
for b in badvpn-udpgw dbclient dnstt-client dnstt-server dropbear dropbear-pam \
         dropbearconvert dropbearkey hysteria1 hysteria2 ipmask_tool \
         traffic_meter_user ttyd udp-custom udp-zivpn xray; do
    [ -x "./bin/$b" ] || echo "WARNING: no $ARCH build for $b — its service(s) will fail" >&2
done

fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"   geoip.dat
fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat" geosite.dat

ln -sf "$BOT_DIR/bin/srtunnel" /usr/sbin/srtunnel

# ── SSH tweak ─────────────────────────────────────────────────────────────
sshd_ensure(){ grep -qF "$1" /etc/ssh/sshd_config || echo "$1" >> /etc/ssh/sshd_config; }
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sshd_ensure "KexAlgorithms +diffie-hellman-group14-sha1"
sshd_ensure "Banner $BOT_DIR/configs/bannerssh"
sshd_ensure "UsePAM yes"
echo "/sbin/nologin" >> /etc/shells
systemctl reload sshd || true

# ── Render Config (hardwired) ───────────────────────────────────────────────
cp configs/config.template.yaml configs/config.yaml
cp configs/xray.template.json configs/xray.json
echo "Hardwired config copied to configs/config.yaml / configs/xray.json — edit manually if needed."

# ── nginx stream front for ws-sr + http front (tunnel + cockpit) ─────────
mkdir -p /etc/nginx/stream-available /etc/nginx/stream-enabled
sed "s|\${BOT_DIR}|$BOT_DIR|g" configs/ws.nginx > /etc/nginx/stream-available/ws
ln -sf /etc/nginx/stream-available/ws /etc/nginx/stream-enabled/ws
sed "s|\${BOT_DIR}|$BOT_DIR|g" configs/srtunnel.nginx > /etc/nginx/sites-available/srtunnel
ln -sf /etc/nginx/sites-available/srtunnel /etc/nginx/sites-enabled/srtunnel
if ! grep -q "stream-enabled" /etc/nginx/nginx.conf; then
    sed -i '/^http {/i stream {\n    include /etc/nginx/stream-enabled/*;\n}\n' /etc/nginx/nginx.conf
fi
rm -f /etc/nginx/sites-enabled/default   # binds :80, conflicts with stream
nginx -t && systemctl reload nginx 2>/dev/null || true

# ── cockpit behind the http front (UrlRoot + ProtocolHeader) ─────────────
if [ -d /etc/cockpit ]; then
    cp -f "$BOT_DIR/configs/cockpit.conf" /etc/cockpit/cockpit.conf
    systemctl restart cockpit 2>/dev/null || true
fi

# ── silence the default Debian warranty banner (/etc/motd) ───────────────
: > /etc/motd

# ── SlowDNS key ───────────────────────────────────────────────────────────────
./bin/dnstt-server -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub 2>/dev/null || true

ln -sf /opt/srtunnel/configs/stunnel.conf /etc/stunnel/stunnel.conf 2>/dev/null || true

# ── Install tunnel unit files ──────────────────────────────────────────────
echo "Installing tunnel systemd units..."
for unit in configs/units/*.service; do
    [ -e "$unit" ] || continue
    sed "s|/opt/srtunnel|$BOT_DIR|g" "$unit" > "/etc/systemd/system/$(basename "$unit")"
done

# ── Dashboard admin group ─────────────────────────────────────────────────────
groupadd -f srtadmin 2>/dev/null || true
usermod -aG srtadmin root 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now srapi 2>/dev/null || true
for svc in ${SRTUNNEL_ENABLE:-badvpn ws-sr}; do
    systemctl enable --now "$svc" 2>/dev/null || true
done

echo "tunnel up and running (nginx stream front for ws-sr installed; dashboard vhost still needs ./scripts/setup-nginx.sh)"
