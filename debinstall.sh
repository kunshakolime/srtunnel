#!/usr/bin/env bash

BOT_DIR="/opt/srtunnel"
REPO="https://raw.githubusercontent.com/kunshakolime/srtunnel/main/"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If run from inside a cloned repo, use that instead of cloning again
if [[ -f "$SCRIPT_DIR/config.template.yaml" && -f "$SCRIPT_DIR/srapi.py" ]]; then
    BOT_DIR="$SCRIPT_DIR"
    echo "Detected existing repo at $BOT_DIR — skipping clone."
fi
SSH_DEF="22"
H1_DEF="1000:2999"
H2_DEF="3000:5999"
ZU_DEF="6000:19999"
UC_DEF="20000:30000"
DEFAULT_IFACE="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
SSL_DEF="8443"
HTTP_DEF="80, 8080, 8000, 8880"
HTTPS_DEF="8446"
MY_SPEED="? Mbps"

fetch()      { local src="$1" dst="$2"; [[ "$src" == http* ]] || src="${REPO}$src"; curl -fsSL "$src" -o "$dst" || echo "WARNING: failed to fetch $src"; }
speedtest() {
    local bytes; bytes=$(curl -o /dev/null --max-time "${2:-60}" --silent --write-out "%{speed_download}" "${1:-http://test-debit.free.fr/65536.rnd}")
    awk "BEGIN{ b=$bytes*8; if(b>=1073741824) printf \"%.2f Gbps\",b/1073741824; else if(b>=1048576) printf \"%.2f Mbps\",b/1048576; else if(b>=1024) printf \"%.2f Kbps\",b/1024; else printf \"%.2f bps\",b }"
}


# ── Distro Check ──────────────────────────────────────────────────────────────
[ -f /etc/os-release ] || die "Cannot detect Linux distro."
source /etc/os-release
case "$ID" in debian|ubuntu) ;; *) die "Distro $ID not supported." ;; esac



# ── APT Dependencies ──────────────────────────────────────────────────────────
echo "Installing base dependencies..."
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
apt update -qq
apt install -y -qq speedtest
apt install -y -qq git openssh-server stunnel4 python3 python3-venv tmux gettext-base python3-psutil curl openssl nano nftables iptables libpam0g-dev nginx libnginx-mod-stream

if [[ "$BOT_DIR" != "$SCRIPT_DIR" ]]; then
    git clone https://github.com/kunshakolime/srtunnel.git "$BOT_DIR"
fi
cd "$BOT_DIR"
mv ./bin/deb13amd64/* ./
rm -rf ./bin/
chmod +x ./*

mv ./badvpn-udpgw64 ./badvpn-udpgw
mv ./udp-zivpn-linux-amd64 ./udp-zivpn
mv ./udp-custom-linux-amd64 ./udp-custom
mv ./hysteria-linux-amd64-v1.3.5 ./hysteria1
mv ./hysteria-linux-amd64-v2.7.0 ./hysteria2


fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"   geoip.dat
fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat" geosite.dat




# ── Python Venv ───────────────────────────────────────────────────────────────
echo "Setting up Python venv..."
[ -d venv ] || python3 -m venv venv
$BOT_DIR/venv/bin/pip install --upgrade pip -r requirements.txt


ln -sf "$BOT_DIR/srtunnel" /usr/sbin/srtunnel

# ── SSH tweak ─────────────────────────────────────────────────────────────
sshd_ensure(){ grep -qF "$1" /etc/ssh/sshd_config || echo "$1" >> /etc/ssh/sshd_config; }
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sshd_ensure "KexAlgorithms +diffie-hellman-group14-sha1"
sshd_ensure "Banner $BOT_DIR/bannerssh"
sshd_ensure "UsePAM yes"
echo "/sbin/nologin" >> /etc/shells
systemctl reload sshd




# ── User Input ────────────────────────────────────────────────────────────────

IFACE="${IFACE:-$DEFAULT_IFACE}"
SSH="${SSH:-$SSH_DEF}"
H1_PR="${H1_PR:-$H1_DEF}"
H2_PR="${H2_PR:-$H2_DEF}"
ZU_PR="${ZU_PR:-$ZU_DEF}"
UC_PR="${UC_PR:-$UC_DEF}"
RUN_TEST="${RUN_SPEEDTEST:-N}"
SSL="${SSL:-$SSL_DEF}"
HTTP="${HTTP:-$HTTP_DEF}"
HTTPS="${HTTPS:-$HTTPS_DEF}"
CF_ROOT_DOMAIN="${ROOT_DOMAIN:-}"
CF_TOKEN="${CF_TOKEN:-}"
CF_ZONE="${CF_ZONE:-}"

# These usually require user-specific values, so they remain empty if not set
TOKEN="${TOKEN:-}"
DOMAIN="${DOMAIN:-}"
SLOWDNSDOMAIN="${SLOWDNSDOMAIN:-sd.$DOMAIN}"


export IFACE SSH TOKEN DOMAIN SLOWDNSDOMAIN H1_PR H2_PR ZU_PR UC_PR MY_SPEED SSL HTTP HTTPS CF_ROOT_DOMAIN CF_TOKEN CF_ZONE XRAY_PASS
# ── Render Config ─────────────────────────────────────────────────────────────
envsubst < config.template.yaml > config.yaml
envsubst '$DOMAIN' < xray.template.json > xray.json

cp -r ./srtdash /var/www/srtdash

# Create stream-enabled directory
mkdir -p /etc/nginx/stream-enabled

cat > /etc/nginx/stream-enabled/srtdash << EOF
map_hash_bucket_size 128;

map \$ssl_preread_server_name \$backend {
    default        127.0.0.1:8443;
    $DOMAIN        127.0.0.1:8444;
    srtnl.$DOMAIN  127.0.0.1:8444;
    rt1.$DOMAIN    127.0.0.1:8445;
    rt2.$DOMAIN    127.0.0.1:8446;
}

server {
    listen 443;
    proxy_pass \$backend;
    ssl_preread on;
}
EOF

envsubst '${DOMAIN}${BOT_DIR}' < srtdash.nginx > /etc/nginx/sites-available/srtdash
ln -sf /etc/nginx/sites-available/srtdash /etc/nginx/sites-enabled/srtdash

# Add stream block to nginx.conf
if ! grep -q "stream-enabled" /etc/nginx/nginx.conf; then
    sed -i '/^http {/i stream {\n    include /etc/nginx/stream-enabled/*;\n}\n' /etc/nginx/nginx.conf
fi

# Remove default site (binds port 80, conflicts with stream)
rm -f /etc/nginx/sites-enabled/default

# ── TLS Certificate ───────────────────────────────────────────────────────────
./dnstt-server -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365 -subj "/CN=localhost"
echo "Test certificates generated."
if [[ -n "$DOMAIN" ]]; then
    CERT_DOMAINS=("$DOMAIN" "srtnl.$DOMAIN" "rt1.$DOMAIN" "rt2.$DOMAIN")
    DOMAIN_ARGS=(); for d in "${CERT_DOMAINS[@]}"; do DOMAIN_ARGS+=(-d "$d"); done

    systemctl stop nginx 2>/dev/null || true

    if $BOT_DIR/venv/bin/certbot certonly \
        --standalone \
        --non-interactive --agree-tos --register-unsafely-without-email \
        --expand \
        "${DOMAIN_ARGS[@]}"; then

        LIVE="/etc/letsencrypt/live/$DOMAIN"
        if [[ -f "$LIVE/fullchain.pem" && -f "$LIVE/privkey.pem" ]]; then
            ln -sf "$LIVE/fullchain.pem" $BOT_DIR/server.crt
            ln -sf "$LIVE/privkey.pem"  $BOT_DIR/server.key
            echo "Real certs linked for $DOMAIN"
        else
            echo "WARNING: certbot succeeded but cert files not found, keeping self-signed."
        fi
    else
        echo "WARNING: certbot failed, keeping self-signed certs."
    fi

    systemctl start nginx 2>/dev/null || true
fi

cat > /etc/systemd/system/srapi.service << 'EOF'
[Unit]
Description=srtunnel API
After=network.target

[Service]
ExecStart=/opt/srtunnel/venv/bin/python /opt/srtunnel/srapi.py
WorkingDirectory=/opt/srtunnel
Restart=always
Environment=PATH=/opt/srtunnel/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
EOF

ln -sf /opt/srtunnel/stunnel.conf /etc/stunnel/stunnel.conf

# ── Done ──────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now srapi
nginx -t
systemctl enable nginx
systemctl restart nginx

. <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/3x-ui-install-noninteractive.sh | sed 's/\r$//')

echo "tunnel up and running"
