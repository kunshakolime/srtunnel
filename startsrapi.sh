#!/usr/bin/env bash
# Quick-start srapi without installing as a systemd service.
# Usage: ./startsrapi.sh
set -e
cd "$(dirname "$0")"

# Generate configs/config.yaml from hardwired template if missing
if [[ ! -f configs/config.yaml ]]; then
    echo "Copying hardwired configs/config.template.yaml to configs/config.yaml..."
    cp configs/config.template.yaml configs/config.yaml
    [[ -f configs/xray.template.json && ! -f configs/xray.json ]] && cp configs/xray.template.json configs/xray.json
    echo "Done. Edit configs/config.yaml to taste."
fi
# compat: if old config.yaml exists at root, keep using it
if [[ -f config.yaml && ! -f configs/config.yaml ]]; then
    echo "Found legacy config.yaml at root — using it"
fi

exec python3 srapi.py
