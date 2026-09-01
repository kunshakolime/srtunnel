#!/usr/bin/env bash
# Quick-start srapi without installing as a systemd service.
# Usage: ./startsrapi.sh
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "$SCRIPT_DIR")"
# if run from repo root (old location), REPO_ROOT is already correct
if [[ -f "$REPO_ROOT/app/srapi.py" ]]; then
  cd "$REPO_ROOT"
else
  cd "$SCRIPT_DIR"
  REPO_ROOT="$SCRIPT_DIR"
fi

# Generate configs/config.yaml from hardwired template if missing
if [[ ! -f configs/config.yaml && ! -f "$REPO_ROOT/configs/config.yaml" ]]; then
    echo "Copying hardwired configs/config.template.yaml to configs/config.yaml..."
    cp configs/config.template.yaml configs/config.yaml 2>/dev/null || cp "$REPO_ROOT/configs/config.template.yaml" configs/config.yaml
    [[ -f configs/xray.template.json && ! -f configs/xray.json ]] && cp configs/xray.template.json configs/xray.json 2>/dev/null || true
    [[ -f "$REPO_ROOT/configs/xray.template.json" && ! -f "$REPO_ROOT/configs/xray.json" ]] && cp "$REPO_ROOT/configs/xray.template.json" "$REPO_ROOT/configs/xray.json" 2>/dev/null || true
    echo "Done. Edit configs/config.yaml to taste."
fi
# compat: if old config.yaml exists at root, keep using it
if [[ -f config.yaml && ! -f configs/config.yaml ]]; then
    echo "Found legacy config.yaml at root — using it"
fi

exec python3 app/srapi.py
