#!/usr/bin/env bash
# Tellina uninstall. Removes user service and binary. Quarantine dir kept by default.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin/tellina"
UNIT_DIR="$HOME/.config/systemd/user"
QUARANTINE="$HOME/.local/share/tellina/quarantine"

REMOVE_QUARANTINE=0
for arg in "$@"; do
  case "$arg" in
    --purge-quarantine) REMOVE_QUARANTINE=1 ;;
    -h|--help)
      echo "Usage: ./uninstall.sh [--purge-quarantine]"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

if systemctl --user is-active --quiet download-security.service 2>/dev/null; then
  systemctl --user disable --now download-security.service
else
  systemctl --user disable download-security.service 2>/dev/null || true
fi

rm -f "$UNIT_DIR/download-security.service" \
      "$UNIT_DIR/download-security-notify-failure.service" \
      "$BIN"
systemctl --user daemon-reload

if [[ "$REMOVE_QUARANTINE" -eq 1 && -d "$QUARANTINE" ]]; then
  rm -rf "$QUARANTINE"
  echo "Removed quarantine: $QUARANTINE"
fi

echo "Tellina uninstalled (quarantine kept unless --purge-quarantine)."
echo "ClamAV packages were not removed."
