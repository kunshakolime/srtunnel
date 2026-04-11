BOT_DIR="/root/srtunnel"

fetch()      { local src="$1" dst="$2"; [[ "$src" == http* ]] || src="${REPO}$src"; curl -fsSL "$src" -o "$dst" || echo "WARNING: failed to fetch $src"; }


# ── Distro Check ──────────────────────────────────────────────────────────────
[ -f /etc/os-release ] || die "Cannot detect Linux distro."
source /etc/os-release
case "$ID" in debian|ubuntu) ;; *) die "Distro $ID not supported." ;; esac




cd
git clone https://github.com/kunshakolime/srtunnel.git
cd $BOT_DIR
mv ./bin/deb13amd64/* ./
rm -rf ./bin/
chmod +x ./*
fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"   geoip.dat
fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat" geosite.dat



# ── APT Dependencies ──────────────────────────────────────────────────────────
echo "Installing base dependencies..."
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
apt update -qq && apt install -y -qq openssh-server python3 python3-venv tmux gettext-base python3-psutil curl openssl nano nftables iptables speedtest libpam0g-dev nginx
# ── Python Venv ───────────────────────────────────────────────────────────────
echo "Setting up Python venv..."
[ -d venv ] || python3 -m venv venv
$BOT_DIR/venv/bin/pip install -q --upgrade pip && $BOT_DIR/venv/bin/pip install -q python-telegram-bot ruamel.yaml psutil PyYAML certbot
#for api
$BOT_DIR/venv/bin/pip install -q fastapi uvicorn python-pam python-jose[cryptography] python-multipart




ln -sf "$BOT_DIR/srtunnel" /usr/sbin/srtunnel
cp -r ./srtdash /var/www/srtdash
# ── SSH tweak ─────────────────────────────────────────────────────────────
sshd_ensure(){ grep -qF "$1" /etc/ssh/sshd_config || echo "$1" >> /etc/ssh/sshd_config; }
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sshd_ensure "KexAlgorithms +diffie-hellman-group14-sha1"
sshd_ensure "Banner $BOT_DIR/bannerssh"
sshd_ensure "UsePAM yes"
echo "/sbin/nologin" >> /etc/shells
systemctl reload sshd




