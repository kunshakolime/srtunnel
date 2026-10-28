#!/usr/bin/env bash
set -e

# usage: debinstall.sh [-d DOMAIN]
#   -d DOMAIN   request a Let's Encrypt certificate for DOMAIN (certbot
#               standalone, :80 released by stopping nginx). Without -d a
#               self-signed certificate is generated so TLS can start.
DOMAIN=""
usage() { echo "usage: $0 [-d DOMAIN]" >&2; }
while getopts ":d:h" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
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
# Third-party binaries are GitHub release assets (pinned in binaries.lock), not
# tracked in git. They live outside the checkout so `git clean` and repo updates
# cannot touch them. `srtunnel bin` / `srtunnel exec NAME` reach them.
BIN_DIR="/usr/local/libexec/srtunnel"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) die "Architecture $ARCH not supported." ;;
esac

install_bins() {
    local tmp tag want url
    tmp="$(mktemp -d)"
    curl -fsSL "${REPO}binaries.lock" -o "$tmp/binaries.lock" || die "cannot fetch binaries.lock"
    tag="$(sed -n 's/^TAG=//p' "$tmp/binaries.lock")"
    want="$(sed -n "s/^$ARCH=//p" "$tmp/binaries.lock")"
    [[ -n "$tag" && -n "$want" ]] || die "binaries.lock has no $ARCH entry"
    mkdir -p "$BIN_DIR"

    if [[ "$(cat "$BIN_DIR/.release" 2>/dev/null)" == "$tag-$ARCH" ]]; then
        echo "Binaries $tag ($ARCH) already installed in $BIN_DIR."
    else
        url="https://github.com/kunshakolime/srtunnel/releases/download/$tag/srtunnel-bins-$ARCH.tar.gz"
        echo "Downloading $tag ($ARCH) binaries..."
        curl -fsSL "$url" -o "$tmp/bins.tar.gz" || die "cannot download $url"
        echo "$want  $tmp/bins.tar.gz" | sha256sum -c - >/dev/null 2>&1 \
            || die "checksum mismatch for $url — refusing to install"
        tar -xzf "$tmp/bins.tar.gz" -C "$BIN_DIR"
        chmod 0755 "$BIN_DIR"/*
        echo "$tag-$ARCH" > "$BIN_DIR/.release"
    fi

    # small per-arch artifacts built from this repo, kept version-coupled
    for f in traffic_meter_user ipmask_tool; do
        install -m0755 "bin/$ARCH/$f" "$BIN_DIR/$f"
    done
    install -m0644 "bin/$ARCH/traffic_meter.bpf.o" "$BIN_DIR/traffic_meter.bpf.o"
    rm -rf "$tmp"
}

install_bins

# The arm64 bundle is a subset of amd64; warn instead of failing at service start.
for b in badvpn-udpgw dropbear dnstt-server hysteria2 udp-custom udp-zivpn; do
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
[ -f configs/config.yaml ] || cp configs/config.template.yaml configs/config.yaml
[ -f configs/xray.json ]   || cp configs/xray.template.json configs/xray.json
echo "Config at configs/config.yaml / configs/xray.json — edit manually if needed."

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
