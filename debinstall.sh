BOT_DIR="/root/srtunnel"
REPO="https://raw.githubusercontent.com/kunshakolime/srtunnel/main/"

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
apt update -qq && apt install -y -qq git openssh-server python3 python3-venv tmux gettext-base python3-psutil curl openssl nano nftables iptables speedtest libpam0g-dev nginx

cd
git clone https://github.com/kunshakolime/srtunnel.git
cd $BOT_DIR
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
$BOT_DIR/venv/bin/pip install -q --upgrade pip && $BOT_DIR/venv/bin/pip install -q python-telegram-bot ruamel.yaml psutil PyYAML certbot
#for api
$BOT_DIR/venv/bin/pip install -q fastapi uvicorn python-pam python-jose[cryptography] python-multipart




ln -sf "$BOT_DIR/srtunnel" /usr/sbin/srtunnel
cp -r ./srtdash /var/www/srtdash

# ── Certificates ──────────────────────────────────────────────────────────────
./dnstt-server -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365 -subj "/CN=localhost"
echo "Certificates generated."
# ── SSH tweak ─────────────────────────────────────────────────────────────
sshd_ensure(){ grep -qF "$1" /etc/ssh/sshd_config || echo "$1" >> /etc/ssh/sshd_config; }
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sshd_ensure "KexAlgorithms +diffie-hellman-group14-sha1"
sshd_ensure "Banner $BOT_DIR/bannerssh"
sshd_ensure "UsePAM yes"
echo "/sbin/nologin" >> /etc/shells
systemctl reload sshd


SSH_DEF="22"    H1_DEF="1000:2999"  H2_DEF="3000:5999"
ZU_DEF="6000:19999"                 UC_DEF="20000:30000"


# ── User Input ────────────────────────────────────────────────────────────────
DEFAULT_IFACE="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
read -rp "Interface             [$DEFAULT_IFACE]: " IFACE; IFACE="${IFACE:-$DEFAULT_IFACE}"
read -rp "SSH backend port      [$SSH_DEF]: "       SSH;   SSH="${SSH:-$SSH_DEF}"
read -rp "Hysteria 1 port range [$H1_DEF]: "        H1_PR; H1_PR="${H1_PR:-$H1_DEF}"
read -rp "Hysteria 2 port range [$H2_DEF]: "        H2_PR; H2_PR="${H2_PR:-$H2_DEF}"
read -rp "ZiVPN UDP port range  [$ZU_DEF]: "        ZU_PR; ZU_PR="${ZU_PR:-$ZU_DEF}"
read -rp "UDP Custom port range [$UC_DEF]: "        UC_PR; UC_PR="${UC_PR:-$UC_DEF}"
read -rp "Telegram ID: "    ID
read -rp "Telegram token: " TOKEN
read -rp "Domain: "         DOMAIN;        DOMAIN="${DOMAIN:-}"
read -rp "SlowDNS domain: " SLOWDNSDOMAIN; SLOWDNSDOMAIN="${SLOWDNSDOMAIN:-}"

read -rp "Run speedtest? [Y/n]: " RUN_TEST
if [[ "${RUN_TEST:-Y}" =~ ^[Yy]$ ]]; then
    echo "Running speedtest..."; MY_SPEED=$(speedtest); echo "Speed: $MY_SPEED"
else
    MY_SPEED="? Mbps"; echo "Skipping speedtest."
fi

export IFACE SSH ID TOKEN DOMAIN SLOWDNSDOMAIN H1_PR H2_PR ZU_PR UC_PR MY_SPEED
# ── Render Config ─────────────────────────────────────────────────────────────
envsubst < config.template.yaml > config.yaml
# ── Setup Nginx ─────────────────────────────────────────────────────────────
envsubst '$DOMAIN' < srtdash.template > /etc/nginx/sites-available/srtdash

ln -sf /etc/nginx/sites-available/srtdash /etc/nginx/sites-enabled/srtdash
rm -f /etc/nginx/sites-enabled/default

chown -R www-data:www-data /var/www/srtdash
chmod -R 755 /var/www/srtdash

nginx -t
systemctl enable nginx
systemctl restart nginx



cat > /etc/systemd/system/srapi.service << 'EOF'
[Unit]
Description=srtunnel API
After=network.target

[Service]
ExecStart=/root/srtunnel/venv/bin/python /root/srtunnel/srapi.py
WorkingDirectory=/root/srtunnel
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now srapi


# ── Done ──────────────────────────────────────────────────────────────────────
nano config.yaml

