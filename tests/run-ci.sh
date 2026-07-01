#!/usr/bin/env bash
# CI harness: --scan-once only. No systemd user service, no inotify, no D-Bus.
# Covers: clean scan, EICAR quarantine, fake PDF, fail-open, size cap.
# Does NOT cover: inotify (slow write, browser rename), notifications, auto-start.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TELLINA="$ROOT/bin/tellina"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

export DOWNLOAD_WATCH_DIR="$TMP/watch"
export DOWNLOAD_QUARANTINE_DIR="$TMP/quarantine"
mkdir -p "$DOWNLOAD_WATCH_DIR"

PASS=0
FAIL=0

pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "FAIL: $1"
  FAIL=$((FAIL + 1))
}

scan_once() {
  STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 "$TELLINA" --scan-once "$1" 2>&1
}

echo "=== tellina CI harness (--scan-once) ==="
echo "watch:      $DOWNLOAD_WATCH_DIR"
echo "quarantine: $DOWNLOAD_QUARANTINE_DIR"
echo ""

# --- 1. clean file ---
F_CLEAN="$DOWNLOAD_WATCH_DIR/clean.txt"
echo 'clean' >"$F_CLEAN"
out=$(scan_once "$F_CLEAN") || true
if [[ -f "$F_CLEAN" ]] && grep -q ' OK ' <<<"$out"; then
  pass "clean file (OK logged, file present)"
else
  fail "clean file (expected OK + file present)"
fi

# --- 2. EICAR: quarantined, defanged ---
F_EICAR="$DOWNLOAD_WATCH_DIR/eicar.com"
printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$F_EICAR"
out=$(scan_once "$F_EICAR") || true
qdir_mode=$(stat -c '%a' "$DOWNLOAD_QUARANTINE_DIR" 2>/dev/null || echo 0)
qfile=$(find "$DOWNLOAD_QUARANTINE_DIR" -name '*eicar.com' -print -quit 2>/dev/null || true)
qfile_mode=$([[ -n "$qfile" ]] && stat -c '%a' "$qfile" 2>/dev/null || echo 0)
if [[ ! -f "$F_EICAR" ]] && grep -q ' QUARANTINE ' <<<"$out" && [[ "$qdir_mode" == 700 ]] && [[ "$qfile_mode" == 400 ]]; then
  pass "EICAR (quarantined, dir 0700, file 0400)"
else
  fail "EICAR (expected quarantine + modes; qdir=$qdir_mode qfile=$qfile_mode exists=$([[ -f $F_EICAR ]] && echo yes || echo no))"
fi

# --- 3. fake executable pdf ---
F_FAKE="$DOWNLOAD_WATCH_DIR/rt-fake.pdf"
printf '#!/bin/sh\necho x\n' >"$F_FAKE"
chmod +x "$F_FAKE"
out=$(scan_once "$F_FAKE") || true
if [[ ! -f "$F_FAKE" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
  pass "fake pdf (quarantined)"
else
  fail "fake pdf (expected QUARANTINE + file gone)"
fi

# --- 4. fail-open ---
F_FAILOPEN="$DOWNLOAD_WATCH_DIR/rt-failopen.txt"
echo 'fail-open probe' >"$F_FAILOPEN"
out=$(TELLINA_TEST_AV_RC=2 scan_once "$F_FAILOPEN") || true
if [[ -f "$F_FAILOPEN" ]] && grep -q 'SKIP scan error (rc=2)' <<<"$out"; then
  pass "fail-open (file stays, SKIP logged on AV rc=2)"
else
  fail "fail-open (expected file present + SKIP rc=2)"
fi

# --- 5. size cap ---
F_BIG="$DOWNLOAD_WATCH_DIR/rt-oversize.bin"
dd if=/dev/zero bs=1 count=200 of="$F_BIG" 2>/dev/null
out=$(DOWNLOAD_MAX_SCAN_BYTES=100 scan_once "$F_BIG") || true
if [[ -f "$F_BIG" ]] && grep -q 'SKIP too large' <<<"$out"; then
  pass "size cap (oversize skipped, file stays)"
else
  fail "size cap (expected SKIP too large + file present)"
fi

echo ""
echo "=== $PASS passed, $FAIL failed ==="
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
