#!/usr/bin/env bash
# Install Tellina binary and user systemd units (called by install.sh). Idempotent.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HOME/.local/bin/tellina"
UNIT_DIR="$HOME/.config/systemd/user"

mkdir -p "$HOME/.local/bin" "$UNIT_DIR" "$HOME/.local/share/tellina/quarantine"
chmod 700 "$HOME/.local/share/tellina/quarantine" 2>/dev/null || true
install -m 755 "$ROOT/bin/tellina" "$BIN"
install -m 644 "$ROOT/systemd/download-security.service" "$UNIT_DIR/download-security.service"
install -m 644 "$ROOT/systemd/download-security-notify-failure.service" \
  "$UNIT_DIR/download-security-notify-failure.service"

systemctl --user daemon-reload
echo "Installed binary: $BIN"
echo "Installed unit:  $UNIT_DIR/download-security.service"
