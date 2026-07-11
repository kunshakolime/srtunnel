#!/usr/bin/env bash
# Quick-start srapi without installing as a systemd service.
# Usage: ./startsrapi.sh
set -e
cd "$(dirname "$0")"

# Generate config.yaml from template if missing
if [[ ! -f config.yaml ]]; then
    echo "Generating config.yaml with test defaults..."
    IFACE="${IFACE:-eth0}"
    SSH="${SSH:-22}"
    H1_PR="${H1_PR:-1000:2999}"
    H2_PR="${H2_PR:-3000:5999}"
    ZU_PR="${ZU_PR:-6000:19999}"
    UC_PR="${UC_PR:-20000:30000}"
    HTTP="${HTTP:-80, 8080}"
    HTTPS="${HTTPS:-8446}"
    MY_SPEED="${MY_SPEED:-100 Mbps}"
    export IFACE SSH H1_PR H2_PR ZU_PR UC_PR HTTP HTTPS MY_SPEED \
        TOKEN="" DOMAIN="" SLOWDNSDOMAIN="sd.test.local" \
        CF_ROOT_DOMAIN="" CF_TOKEN="" CF_ZONE="" XRAY_PASS=""
    envsubst < config.template.yaml > config.yaml
    echo "Done. Edit config.yaml to taste."
fi

# Activate venv if present
if [[ -d venv ]]; then
    source venv/bin/activate
fi

exec python3 srapi.py
