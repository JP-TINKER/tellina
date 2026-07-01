#!/usr/bin/env bash
# Tellina install for Linux (user systemd, zero config).
# Usage: ./install.sh [--no-deps] [--no-start]
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")" && pwd)"
NO_DEPS=0
NO_START=0

for arg in "$@"; do
  case "$arg" in
    --no-deps) NO_DEPS=1 ;;
    --no-start) NO_START=1 ;;
    -h|--help)
      cat <<'EOF'
Tellina install

  ./install.sh              Install deps (Debian/Ubuntu), binary, systemd user unit, start
  ./install.sh --no-deps      Skip apt; you already have clamav + inotify-tools + file
  ./install.sh --no-start     Install files only; do not enable/start the service

Requires: Linux, bash 4+, GNU coreutils, systemd user session, ClamAV (not ClamTK).

After install:
  journalctl --user -u download-security.service -f

Optional faster scans (needs sudo once):
  ./scripts/enable-clamd.sh
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (try --help)" >&2
      exit 1
      ;;
  esac
done

log() { echo "[tellina install] $*"; }

clamav_db_dir() {
  local dir
  if command -v clamconf >/dev/null 2>&1; then
    dir=$(clamconf -n 2>/dev/null | awk -F'= ' '/DatabaseDirectory/{print $2; exit}')
    [[ -n "$dir" ]] && { echo "$dir"; return 0; }
  fi
  echo "/var/lib/clamav"
}

clamav_db_ready() {
  local d="$1"
  [[ -f "$d/main.cvd" || -f "$d/main.cld" ]]
}

ensure_clamav_database() {
  local db_dir wait_i=0
  db_dir=$(clamav_db_dir)
  if clamav_db_ready "$db_dir"; then
    return 0
  fi

  log "ClamAV virus definitions not found under $db_dir."

  if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
    log "clamav-freshclam is downloading definitions; first install can take several minutes..."
    while (( wait_i < 120 )); do
      sleep 5
      if clamav_db_ready "$db_dir"; then
        log "Virus definitions ready."
        return 0
      fi
      wait_i=$(( wait_i + 1 ))
    done
    echo "Timed out waiting for clamav-freshclam. Check: sudo systemctl status clamav-freshclam" >&2
    exit 1
  fi

  log "Downloading virus definitions now (first install; may take several minutes)..."
  if sudo freshclam; then
    log "Virus definitions ready."
    return 0
  fi

  echo "freshclam failed. If clamav-freshclam holds the DB lock, try:" >&2
  echo "  sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need_cmd systemctl
if ! systemctl --user status >/dev/null 2>&1; then
  echo "FATAL: systemd user session not available. Log in to a desktop session and retry." >&2
  exit 1
fi

install_apt_deps() {
  if [[ "$NO_DEPS" -eq 1 ]]; then
    log "Skipping package install (--no-deps)"
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    log "Non-Debian system: install ClamAV, inotify-tools, and file from your distro, then re-run with --no-deps"
    return 0
  fi
  log "Installing packages (sudo may prompt)..."
  sudo apt-get update -qq
  sudo apt-get install -y \
    clamav \
    inotify-tools \
    file \
    unzip \
    poppler-utils
  sudo systemctl enable --now clamav-freshclam 2>/dev/null || true
}

check_runtime_deps() {
  local missing=0
  for cmd in inotifywait clamscan file; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Missing: $cmd" >&2
      missing=1
    fi
  done
  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
  ensure_clamav_database
}

install_apt_deps
check_runtime_deps

log "Installing Tellina binary and user units..."
bash "$ROOT/scripts/install-local.sh"

if [[ "$NO_START" -eq 0 ]]; then
  log "Enabling and starting download-security.service..."
  systemctl --user enable --now download-security.service
  sleep 1
  if systemctl --user is-active --quiet download-security.service; then
    log "Service is active."
  else
    log "Service not active yet (normal over SSH or before graphical session)."
    log "It starts with your desktop login. Verify: systemctl --user status download-security.service"
  fi
fi

cat <<EOF

Tellina installed.

  Binary:     ~/.local/bin/tellina
  Quarantine: ~/.local/share/tellina/quarantine
  Logs:       journalctl --user -u download-security.service -f

Tellina depends on ClamAV (scanner + signatures), not ClamTK (GUI).
It scans ~/Downloads after each download completes (post-download gate, not on-access).

Optional: faster scans with clamd:
  $ROOT/scripts/enable-clamd.sh
  (then log out and back in)

Remove:
  $ROOT/uninstall.sh

EOF
