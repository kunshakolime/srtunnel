#!/usr/bin/env bash
# compat shim — moved to scripts/uninstall.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/scripts/uninstall.sh" ]]; then
  exec bash "$SCRIPT_DIR/scripts/uninstall.sh" "$@"
else
  echo "ERROR: scripts/uninstall.sh not found" >&2
  exit 1
fi
