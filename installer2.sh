#!/usr/bin/env bash

# ── Constants ─────────────────────────────────────────────────────────────────

REPO="https://raw.githubusercontent.com/kunshakolime/srtunnel/main/"


# ── Helpers ───────────────────────────────────────────────────────────────────
die()        { echo "Error: $*" >&2; exit 1; }
fetchx()     { fetch "$1" "$2" && chmod +x "$2"; }


speedtest() {
    local bytes; bytes=$(curl -o /dev/null --max-time "${2:-60}" --silent --write-out "%{speed_download}" "${1:-http://test-debit.free.fr/65536.rnd}")
    awk "BEGIN{ b=$bytes*8; if(b>=1073741824) printf \"%.2f Gbps\",b/1073741824; else if(b>=1048576) printf \"%.2f Mbps\",b/1048576; else if(b>=1024) printf \"%.2f Kbps\",b/1024; else printf \"%.2f bps\",b }"
}


mkdir -p "$BOT_DIR" && cd "$BOT_DIR"



#speedtest --accept-license --accept-gdpr

mkdir -p /etc/dropbear
for f in dropbear dropbearkey dropbearconvert dbclient; do fetchx "dropbear/2025.89/debian13/amd64/$f" "/usr/sbin/$f"; done

+
# ── Configs & Data Files ─────────────────────────────────────────────────────




# ── Done ──────────────────────────────────────────────────────────────────────
