#!/usr/bin/env bash
# Quick-start srapi without installing as a systemd service.
# Usage: ./startsrapi.sh
set -e
cd "$(dirname "$0")"

# Generate config.yaml from hardwired template if missing
if [[ ! -f config.yaml ]]; then
    echo "Copying hardwired config.template.yaml to config.yaml..."
    cp config.template.yaml config.yaml
    [[ -f xray.template.json && ! -f xray.json ]] && cp xray.template.json xray.json
    echo "Done. Edit config.yaml to taste."
fi

exec python3 srapi.py
