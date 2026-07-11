#!/usr/bin/env bash
# Quick-start srapi without installing as a systemd service.
# Usage: ./startsrapi.sh
set -e
cd "$(dirname "$0")"

# Activate venv if present
if [[ -d venv ]]; then
    source venv/bin/activate
fi

exec python3 srapi.py
