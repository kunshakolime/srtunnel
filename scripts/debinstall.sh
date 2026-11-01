#!/usr/bin/env bash
set -e

# usage: debinstall.sh [-d DOMAIN] [-u]
#   -d DOMAIN   request a Let's Encrypt certificate for DOMAIN (certbot
#               standalone, :80 released by stopping nginx). Without -d a
#               self-signed certificate is generated so TLS can start.
#   -u          update release binaries only (skips apt, clone, venv, configs)
DOMAIN=""
UPDATE_ONLY=""
usage() { echo "usage: $0 [-d DOMAIN] [-u]" >&2; }
while getopts ":d:ubh" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        u|b) UPDATE_ONLY=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

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

# ── Release binaries definition ──────────────────────────────────────────────
BIN_DIR="/usr/local/libexec/srtunnel"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) die "Architecture $ARCH not supported." ;;
esac

install_bins() {
    local base_url="https://github.com/kunshakolime/srtunnel/releases/latest/download"
    local bins=()
    case "$ARCH" in
        amd64) bins=(badvpn-udpgw dnstt-server hysteria2 udp-custom udp-zivpn ipmask_tool traffic_meter_user) ;;
        arm64) bins=(badvpn-udpgw udp-zivpn ipmask_tool traffic_meter_user) ;;
    esac

    mkdir -p "$BIN_DIR"
    echo "Downloading $ARCH binaries..."
    for b in "${bins[@]}"; do
        curl -fsSL "$base_url/${b}-${ARCH}" -o "$BIN_DIR/.tmp.$b" && \
            chmod 0755 "$BIN_DIR/.tmp.$b" && \
            mv -f "$BIN_DIR/.tmp.$b" "$BIN_DIR/$b" || \
            echo "WARNING: failed to download ${b}-${ARCH}" >&2
    done

    curl -fsSL "$base_url/traffic_meter.bpf.o" -o "$BIN_DIR/.tmp.traffic_meter.bpf.o" && \
        chmod 0644 "$BIN_DIR/.tmp.traffic_meter.bpf.o" && \
        mv -f "$BIN_DIR/.tmp.traffic_meter.bpf.o" "$BIN_DIR/traffic_meter.bpf.o" || \
        echo "WARNING: failed to download traffic_meter.bpf.o" >&2
}

if [[ "$UPDATE_ONLY" == "1" ]]; then
    echo "Updating binaries in $BIN_DIR..."
    install_bins
    echo "Restarting active services..."
    for s in badvpn hysteria2 slowdns udpcustom zivpn trafficmeter; do
        systemctl try-restart "$s.service" 2>/dev/null || true
    done
    echo "Binaries update complete."
    exit 0
fi

# ── APT Dependencies ──────────────────────────────────────────────────────────
echo "Installing base dependencies..."
apt update -qq
apt install -y -qq git openssh-server stunnel4 python3 python3-venv certbot curl openssl nano nftables libpam0g-dev nginx libnginx-mod-stream

# ── Python deps are installed into a venv (see "Python venv" below) ─────────

if [[ "$BOT_DIR" != "$REPO_ROOT" && "$BOT_DIR" != "$SCRIPT_DIR" ]]; then
    git clone https://github.com/kunshakolime/srtunnel.git "$BOT_DIR"
fi
cd "$BOT_DIR"
srt() { "$BOT_DIR/venv/bin/python" "$BOT_DIR/app/cli.py" "$@"; }

# ── Release binaries ──────────────────────────────────────────────────────────
# Third-party binaries are GitHub release assets, not tracked in git.
# They live outside the checkout so `git clean` and repo updates cannot touch them.
install_bins

# The arm64 bundle is a subset of amd64; warn instead of failing at service start.
for b in badvpn-udpgw dnstt-server hysteria2 udp-custom udp-zivpn; do
    [ -x "$BIN_DIR/$b" ] || echo "WARNING: no $ARCH build for $b — its service(s) will fail" >&2
done

fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"   geoip.dat
fetch "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat" geosite.dat

# ── Python venv ───────────────────────────────────────────────────────────────
echo "Setting up Python venv..."
[ -d "$BOT_DIR/venv" ] || python3 -m venv "$BOT_DIR/venv"
"$BOT_DIR/venv/bin/pip" install --quiet --upgrade pip
"$BOT_DIR/venv/bin/pip" install --quiet -r "$BOT_DIR/requirements.txt"

ln -sf "$BOT_DIR/bin/srtunnel" /usr/sbin/srtunnel

# ── SSH tweak ─────────────────────────────────────────────────────────────
grep -qxF "/sbin/nologin" /etc/shells || echo "/sbin/nologin" >> /etc/shells

# ── Render Config (hardwired; never clobber an existing deployment) ────────
[ -f configs/config.yaml ]      || cp configs/config.template.yaml configs/config.yaml
[ -f configs/xray.json ]        || cp configs/xray.template.json configs/xray.json
[ -f configs/zivpn.json ]       || cp configs/zivpn.template.json configs/zivpn.json
[ -f configs/udp-custom.json ]  || cp configs/udp-custom.template.json configs/udp-custom.json
[ -f configs/hysteria2.yaml ]   || cp configs/hysteria2.template.yaml configs/hysteria2.yaml
[ -f configs/hysteria1.json ]   || cp configs/hysteria1.template.json configs/hysteria1.json
echo "Configs initialized from templates if missing — edit manually if needed."

# ── TLS certificate ───────────────────────────────────────────────────────────
# fullchain.pem / privkey.pem are the stable paths every consumer reads.
# `srtunnel cert` owns both the self-signed fallback and the certbot flow, so
# the same code is available after installation.
srt cert --selfsigned
if [[ -n "$DOMAIN" ]]; then
    srt cert -d "$DOMAIN" \
        || echo "WARNING: certbot failed for $DOMAIN — keeping the existing certificate." >&2
fi

# ── nginx: the default site binds :80 and conflicts with the stream front ────
rm -f /etc/nginx/sites-enabled/default

# ── silence the default Debian warranty banner (/etc/motd) ───────────────
: > /etc/motd

# ── SlowDNS key ───────────────────────────────────────────────────────────────
"$BIN_DIR/dnstt-server" -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub 2>/dev/null || true

# ── Dashboard admin group ─────────────────────────────────────────────────────
groupadd -f srtadmin 2>/dev/null || true
usermod -aG srtadmin root 2>/dev/null || true

# ── Render units, nginx, sshd drop-in, sysctl, stunnel, cockpit ───────────────
echo "Reconciling system configuration..."
srt reconcile

echo "tunnel installed — 'srtunnel status' to inspect, 'srtunnel reconcile --dry-run' to check drift"
