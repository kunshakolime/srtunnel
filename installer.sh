#!/usr/bin/env bash

# ── Constants ─────────────────────────────────────────────────────────────────
BOT_DIR="/root/srtunnel"
REPO="https://raw.githubusercontent.com/kunshakolime/srtunnel/main/"

SSH_DEF="22"    H1_DEF="1000:2999"  H2_DEF="3000:5999"
ZU_DEF="6000:19999"                 UC_DEF="20000:30000"

. <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/installer2.sh)

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

# ── Certificates ──────────────────────────────────────────────────────────────
./dnstt-server -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365 -subj "/CN=localhost"
echo "Certificates generated."
# ── Render Config ─────────────────────────────────────────────────────────────
curl -fsSL "${REPO}config.yaml" | envsubst > config.yaml


# ── Done ──────────────────────────────────────────────────────────────────────
nano config.yaml
