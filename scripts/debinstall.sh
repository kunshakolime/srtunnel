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
apt install -y -qq git openssh-server stunnel4 python3 python3-venv certbot curl openssl nano nftables libpam0g-dev nginx libnginx-mod-stream

# ── Python deps are installed into a venv (see "Python venv" below) ─────────

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

# ── Python venv ───────────────────────────────────────────────────────────────
echo "Setting up Python venv..."
[ -d "$BOT_DIR/venv" ] || python3 -m venv "$BOT_DIR/venv"
"$BOT_DIR/venv/bin/pip" install --quiet --upgrade pip
"$BOT_DIR/venv/bin/pip" install --quiet -r "$BOT_DIR/requirements.txt"

ln -sf "$BOT_DIR/bin/srtunnel" /usr/sbin/srtunnel

# ── SSH tweak ─────────────────────────────────────────────────────────────
grep -qxF "/sbin/nologin" /etc/shells || echo "/sbin/nologin" >> /etc/shells

# ── Render Config (hardwired; never clobber an existing deployment) ────────
[ -f configs/config.yaml ] || cp configs/config.template.yaml configs/config.yaml
[ -f configs/xray.json ]   || cp configs/xray.template.json configs/xray.json
echo "Config at configs/config.yaml / configs/xray.json — edit manually if needed."

# ── nginx: the default site binds :80 and conflicts with the stream front ────
rm -f /etc/nginx/sites-enabled/default

# ── silence the default Debian warranty banner (/etc/motd) ───────────────
: > /etc/motd

# ── SlowDNS key ───────────────────────────────────────────────────────────────
./bin/dnstt-server -gen-key -privkey-file slowdns.key -pubkey-file slowdns.pub 2>/dev/null || true

# ── Dashboard admin group ─────────────────────────────────────────────────────
groupadd -f srtadmin 2>/dev/null || true
usermod -aG srtadmin root 2>/dev/null || true

# ── Render units, nginx, sshd drop-in, sysctl, stunnel, cockpit ───────────────
echo "Reconciling system configuration..."
"$BOT_DIR/venv/bin/python" "$BOT_DIR/app/cli.py" reconcile

echo "tunnel installed — 'srtunnel status' to inspect, 'srtunnel reconcile --dry-run' to check drift"
