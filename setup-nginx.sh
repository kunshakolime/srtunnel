#!/usr/bin/env bash
# compat shim — moved to scripts/setup-nginx.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/scripts/setup-nginx.sh" ]]; then
  exec bash "$SCRIPT_DIR/scripts/setup-nginx.sh" "$@"
else
  echo "ERROR: scripts/setup-nginx.sh not found" >&2
  exit 1
fi
