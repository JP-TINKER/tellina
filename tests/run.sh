#!/usr/bin/env bash
# Validation harness for download-security.service
# Exit 0 = all assertions passed. Exit 1 = real failure.
#
# Log line format:  OK <size>B | <mime> | <path>
#                   QUARANTINE <reason> | sha256=... | <path>
#                   SKIP ... : <path>
#
# Manual (after reboot/login, before running tests):
#   systemctl --user is-active download-security.service
#   journalctl --user -u download-security.service -n3 --no-pager

set -euo pipefail

UNIT="${DOWNLOAD_SECURITY_UNIT:-download-security.service}"
WATCH="${DOWNLOAD_WATCH_DIR:-$HOME/Downloads}"
QUARANTINE="${DOWNLOAD_QUARANTINE_DIR:-$HOME/.local/share/tellina/quarantine}"
WAIT_SCAN="${TEST_SCAN_WAIT:-15}"
WAIT_SLOW="${TEST_SLOW_WAIT:-25}"

PASS=0
FAIL=0
TEST_START=$(date '+%Y-%m-%d %H:%M:%S')

log_lines() {
  journalctl --user -u "$UNIT" --since "$TEST_START" --no-pager 2>/dev/null || true
}

lines_for() {
  local needle="$1"
  log_lines | grep -F "$needle" || true
}

count_ok() {
  local needle="$1"
  lines_for "$needle" | grep -c ' OK ' || true
}

count_quarantine() {
  local needle="$1"
  lines_for "$needle" | grep -c ' QUARANTINE ' || true
}

pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "FAIL: $1"
  FAIL=$((FAIL + 1))
}

require_service() {
  if ! systemctl --user is-active --quiet "$UNIT" 2>/dev/null; then
    echo "FATAL: $UNIT is not active. Start it first:"
    echo "  systemctl --user start $UNIT"
    exit 2
  fi
}

check_boot_service() {
  echo "=== service auto-start check (manual) ==="
  if systemctl --user is-active --quiet "$UNIT" 2>/dev/null; then
    echo "Service is active now."
    journalctl --user -u "$UNIT" -n 3 --no-pager
    echo ""
    echo "After reboot/login (without manual start), re-run:"
    echo "  $0 --boot-check"
  else
    echo "Service is inactive."
    exit 2
  fi
  exit 0
}

if [[ "${1:-}" == "--boot-check" ]]; then
  check_boot_service
fi

require_service
TELLINA="$(cd "$(dirname "$0")/.." && pwd)/bin/tellina"
echo "=== download-security test harness ==="
echo "started: $TEST_START"
echo "watch:   $WATCH"
echo ""

# --- 1. clean file: one OK, file stays ---
F_CLEAN="$WATCH/rt-clean.txt"
rm -f "$F_CLEAN"
echo 'clean' >"$F_CLEAN"
sleep "$WAIT_SCAN"
n_ok=$(count_ok "rt-clean.txt")
if [[ "$n_ok" -eq 1 && -f "$F_CLEAN" ]]; then
  pass "clean file (1 OK, file in Downloads)"
else
  fail "clean file (expected 1 OK + file present; got OK=$n_ok, exists=$([[ -f $F_CLEAN ]] && echo yes || echo no))"
fi
rm -f "$F_CLEAN"

# --- 2. slow direct-write: at least one OK after append loop completes ---
F_SLOW="$WATCH/bigfile.bin"
rm -f "$F_SLOW"
(
  for _ in $(seq 1 8); do
    dd if=/dev/urandom bs=1M count=1 >>"$F_SLOW" 2>/dev/null
    sleep 1
  done
)
sleep "$WAIT_SLOW"
n_ok=$(count_ok "bigfile.bin")
if [[ "$n_ok" -ge 1 && -f "$F_SLOW" ]]; then
  pass "slow direct-write (>=1 OK after completion, file present)"
else
  fail "slow direct-write (expected >=1 OK + file present; got OK=$n_ok, exists=$([[ -f $F_SLOW ]] && echo yes || echo no))"
fi
rm -f "$F_SLOW"
sleep 2

# --- 3. browser-style rename: one OK, file stays ---
F_BROWSER="$WATCH/rt-browser.txt"
F_PART="$WATCH/rt-browser.part"
rm -f "$F_BROWSER" "$F_PART"
echo 'browser' >"$F_PART"
sleep 1
mv "$F_PART" "$F_BROWSER"
sleep "$WAIT_SCAN"
n_ok=$(count_ok "rt-browser.txt")
if [[ "$n_ok" -eq 1 && -f "$F_BROWSER" ]]; then
  pass "browser rename (1 OK, file in Downloads)"
else
  fail "browser rename (expected 1 OK + file present; got OK=$n_ok, exists=$([[ -f $F_BROWSER ]] && echo yes || echo no))"
fi
rm -f "$F_BROWSER"

# --- 4. symlink outside watch root: under_watch guard emits SKIP ---
F_LINK="$WATCH/rt-symlink-outside"
rm -f "$F_LINK"
ln -sf /etc/hosts "$F_LINK"
out=$(STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 "$TELLINA" --scan-once "$F_LINK" 2>&1) || true
if grep -q 'SKIP path outside watch root' <<<"$out"; then
  pass "symlink outside tree (SKIP logged; under_watch guard fired)"
else
  fail "symlink outside tree (expected SKIP path outside watch root)"
fi
rm -f "$F_LINK"

# --- 5. EICAR: quarantined, removed from Downloads ---
F_EICAR="$WATCH/eicar.com"
rm -f "$F_EICAR"
printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$F_EICAR"
sleep "$WAIT_SCAN"
n_q=$(count_quarantine "eicar.com")
if [[ "$n_q" -ge 1 && ! -f "$F_EICAR" ]]; then
  pass "EICAR (quarantined, removed from Downloads)"
else
  fail "EICAR (expected QUARANTINE + file gone; quarantine=$n_q, in_downloads=$([[ -f $F_EICAR ]] && echo yes || echo no))"
fi

# --- 6. fake executable pdf: quarantined ---
F_FAKE="$WATCH/rt-fake.pdf"
rm -f "$F_FAKE"
printf '#!/bin/sh\necho x\n' >"$F_FAKE"
chmod +x "$F_FAKE"
sleep "$WAIT_SCAN"
n_q=$(count_quarantine "rt-fake.pdf")
if [[ "$n_q" -ge 1 && ! -f "$F_FAKE" ]]; then
  pass "fake pdf (quarantined, removed from Downloads)"
else
  fail "fake pdf (expected QUARANTINE + file gone; quarantine=$n_q, in_downloads=$([[ -f $F_FAKE ]] && echo yes || echo no))"
fi

# --- 7. fail-open: AV error leaves file, logs SKIP (harness uses --scan-once + test rc) ---
F_FAILOPEN="$WATCH/rt-failopen.txt"
rm -f "$F_FAILOPEN"
echo 'fail-open probe' >"$F_FAILOPEN"
out=$(TELLINA_TEST_AV_RC=2 STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 "$TELLINA" --scan-once "$F_FAILOPEN" 2>&1) || true
if [[ -f "$F_FAILOPEN" ]] && grep -q 'SKIP scan error (rc=2)' <<<"$out"; then
  pass "fail-open (file stays, SKIP logged on AV rc=2)"
else
  fail "fail-open (expected file present + SKIP rc=2; exists=$([[ -f $F_FAILOPEN ]] && echo yes || echo no))"
fi
rm -f "$F_FAILOPEN"

# --- 8. size cap: oversize skipped without scan ---
F_BIG="$WATCH/rt-oversize.bin"
rm -f "$F_BIG"
dd if=/dev/zero bs=1 count=200 of="$F_BIG" 2>/dev/null
out=$(DOWNLOAD_MAX_SCAN_BYTES=100 STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 "$TELLINA" --scan-once "$F_BIG" 2>&1) || true
if [[ -f "$F_BIG" ]] && grep -q 'SKIP too large' <<<"$out"; then
  pass "size cap (oversize skipped, file stays)"
else
  fail "size cap (expected SKIP too large + file present)"
fi
rm -f "$F_BIG"

echo ""
echo "=== $PASS passed, $FAIL failed ==="
if [[ "$FAIL" -gt 0 ]]; then
  echo ""
  echo "Recent journal (since test start):"
  log_lines | tail -20
  exit 1
fi
exit 0
