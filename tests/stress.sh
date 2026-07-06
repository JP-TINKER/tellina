#!/usr/bin/env bash
# Tellina v2 stress test: exercises the REAL inotify watch loop at volume.
#
# Unlike run-ci.sh (one-shot --scan-once) and run.sh (live service, needs D-Bus),
# this drives the actual `inotifywait | while read` loop with bursts and checks
# verdicts, throughput, release-echo suppression under load, crash-sweep, and
# edge-case names. The desktop notify call fails gracefully (no D-Bus needed),
# so this runs headless in CI or a sandbox.
#
# Needs: setsid, inotifywait, clamscan, file, sha256sum, stat, cp, awk.
#
#   A: real-ClamAV correctness burst (mixed verdicts).
#   B: throughput burst via a fast clamscan PATH shim (isolates mechanism speed
#      + suppression under load; 25 files).
#   C: crash-sweep at volume (10 stranded hold files).
#   D: edge-case names (over-long, spaces, unicode, empty, .part).
set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TELLINA="$ROOT/bin/tellina"
command -v inotifywait >/dev/null || { echo "FATAL: inotifywait not found"; exit 2; }
command -v clamscan    >/dev/null || { echo "FATAL: clamscan not found";    exit 2; }

TMP=$(mktemp -d); RT="$TMP/runtime"; mkdir -p "$RT"
WATCH="$TMP/watch"; Q="$TMP/quarantine"; mkdir -p "$WATCH" "$Q"
SHIM="$TMP/shim"; mkdir -p "$SHIM"
PID=""
cleanup(){ [[ -n "$PID" ]] && kill -TERM -- -"$PID" 2>/dev/null; wait "$PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

# Fast clamscan shim: clean by default, "infected" (rc=1) if the basename
# contains eicar. Isolates loop/hold/release overhead from ClamAV's ~6 s DB load.
cat > "$SHIM/clamscan" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in --version) echo "ClamAV-shim 1.0"; exit 0;; esac; done
f="${@: -1}"
case "$(basename "$f")" in *eicar*|*EICAR*) exit 1;; esac
exit 0
EOF
chmod +x "$SHIM/clamscan"
cat > "$SHIM/clamdscan" <<'EOF'
#!/usr/bin/env bash
exit 2  # force probe to fail -> backend=clamscan
EOF
chmod +x "$SHIM/clamdscan"

PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

start_service(){
  local label="$1" useshim="$2"; LOG="$TMP/log_$label"; : >"$LOG"
  local p="$PATH"; [[ "$useshim" == 1 ]] && p="$SHIM:$PATH"
  # setsid -> own process group so stop_service kills tellina + inotifywait child
  setsid env XDG_RUNTIME_DIR="$RT" DOWNLOAD_WATCH_DIR="$WATCH" DOWNLOAD_QUARANTINE_DIR="$Q" \
      STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 PATH="$p" "$TELLINA" >"$LOG" 2>&1 &
  PID=$!
  for i in $(seq 1 200); do grep -q 'Watches established' "$LOG" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}
stop_service(){ [[ -n "$PID" ]] && kill -TERM -- -"$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; sleep 0.3; }
hold_empty(){ [[ -z "$(ls -A "$RT/tellina/hold" 2>/dev/null)" ]]; }
drain(){ # $1=label  $2=iters  -- wait until hold empty + log quiet for ~2s
  local label="$1" max="$2" last=0 quiet=0 n he
  for i in $(seq 1 "$max"); do
    n=$(grep -cE ' OK |SKIP release echo| HOLD ' "$TMP/log_$label" || true)
    he=$(hold_empty && echo 1 || echo 0)
    if [[ "$he" == 1 && "$n" == "$last" ]]; then quiet=$((quiet+1)); else quiet=0; fi
    last=$n; (( quiet >= 4 )) && break; sleep 0.5
  done
}

echo "=== Part A: real-ClamAV correctness burst (no shim; mixed verdicts) ==="
start_service A 0 || { echo "  service did not start"; exit 1; }
echo 'clean1' > "$WATCH/a-clean1.txt"
echo 'clean2' > "$WATCH/a-clean2.txt"
printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WATCH/a-eicar1.com"
printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WATCH/a-eicar2.com"
cp "$(command -v cat)" "$WATCH/a-elf.pdf"
drain A 120 || true
stop_service
n_ok=$(grep -c ' OK ' "$TMP/log_A" || true)
n_q=$(grep -c ' QUARANTINE ' "$TMP/log_A" || true)
c1=$([[ -f $WATCH/a-clean1.txt ]] && echo y || echo n)
c2=$([[ -f $WATCH/a-clean2.txt ]] && echo y || echo n)
e1=$([[ -f $WATCH/a-eicar1.com ]] && echo y || echo n)
e2=$([[ -f $WATCH/a-eicar2.com ]] && echo y || echo n)
elf=$([[ -f $WATCH/a-elf.pdf ]] && echo y || echo n)
[[ "$c1$c2" == yy && "$e1$e2" == nn && "$elf" == n && "$n_ok" -eq 2 && "$n_q" -eq 3 ]] && \
  ok "real-ClamAV burst: 2 clean released, 3 quarantined (2 EICAR + ELF.pdf)" || \
  bad "real burst (clean=$c1$c2 eicar=$e1$e2 elf=$elf ok=$n_ok q=$n_q)"
hold_empty && ok "hold empty after Part A" || bad "hold leaked after Part A"

echo
echo "=== Part B: throughput burst (shim; 25 clean files) ==="
rm -f "$WATCH"/* 2>/dev/null; rm -rf "$Q"/* 2>/dev/null; rm -rf "$RT/tellina/hold"/* 2>/dev/null
start_service B 1 || { echo "  service did not start"; exit 1; }
t0=$(date +%s.%N)
for i in $(seq -w 1 25); do echo "clean payload $i" > "$WATCH/b-file$i.txt"; done
drain B 180 || true
t1=$(date +%s.%N)
stop_service
n_ok=$(grep -c ' OK ' "$TMP/log_B" || true)
n_echo=$(grep -c 'SKIP release echo' "$TMP/log_B" || true)
n_err=$(grep -cE ' ERROR |FATAL' "$TMP/log_B" || true)
present=$(ls -1 "$WATCH"/b-file*.txt 2>/dev/null | wc -l)
dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
rate=$(awk -v n="$n_ok" -v d="$dur" 'BEGIN{ if(d+0>0) printf "%.1f", n/d; else print "0" }')
[[ "$n_ok" -eq 25 && "$present" -eq 25 && "$n_echo" -eq 25 && "$n_err" -eq 0 ]] && \
  ok "throughput: 25 files in ${dur}s (${rate} files/s); 25 OK + 25 release-echo suppressed, 0 errors" || \
  bad "throughput (ok=$n_ok present=$present echo=$n_echo err=$n_err dur=${dur}s)"
dups=$(grep ' OK ' "$TMP/log_B" | sed -E 's/.* \| //; s/ .*//' | sort | uniq -d | wc -l)
[[ "$dups" -eq 0 ]] && ok "no duplicate OK (release-echo suppression held under burst)" || bad "duplicate OK lines: $dups"
hold_empty && ok "hold empty after Part B" || bad "hold leaked after Part B"

echo
echo "=== Part C: crash-sweep at volume (shim; 10 stranded files) ==="
rm -f "$WATCH"/* 2>/dev/null; rm -rf "$RT/tellina/hold"/* 2>/dev/null
HD="$RT/tellina/hold"; mkdir -p "$HD"
for i in $(seq -w 1 10); do
  h="$HD/20260702-00000${i}__c-file$i.txt"; echo "stranded $i" >"$h"
  printf '%s\n%s\n%s\n' "$WATCH/c-file$i.txt" "$(stat -c%s "$h")" "$(sha256sum "$h"|awk '{print $1}')" >"$h.ingress"
done
sweep_out=$(env XDG_RUNTIME_DIR="$RT" DOWNLOAD_WATCH_DIR="$WATCH" DOWNLOAD_QUARANTINE_DIR="$Q" \
    STABLE_WAIT=0 DOWNLOAD_STABLE_SEC=0 PATH="$SHIM:$PATH" "$TELLINA" --sweep-once 2>&1) || true
n_sweep=$(grep -c ' SWEEP ' <<<"$sweep_out" || true)
n_ok=$(grep -c ' OK ' <<<"$sweep_out" || true)
released=$(ls -1 "$WATCH"/c-file*.txt 2>/dev/null | wc -l)
[[ "$n_sweep" -eq 10 && "$n_ok" -eq 10 && "$released" -eq 10 ]] && ok "crash sweep: 10 stranded files all reprocessed + released" || bad "sweep (sweep=$n_sweep ok=$n_ok released=$released)"
hold_empty && ok "hold empty after Part C" || bad "hold leaked after Part C"

echo
echo "=== Part D: edge-case names (shim) ==="
rm -f "$WATCH"/* 2>/dev/null
start_service D 1 || { echo "  service did not start"; exit 1; }
# 240-char name -> too long for hold (stamp__name > 255) -> honest in-place fallback
LONG=$(printf 'z%.0s' $(seq 1 240)); echo 'long name' > "$WATCH/$LONG.txt"
echo 'spaced name' > "$WATCH/d spaced name.txt"
echo 'unicode name' > "$WATCH/d-名前.txt"
: > "$WATCH/d-empty.txt"                      # empty -> skip unstable
echo 'partial' > "$WATCH/d-skip.part"         # .part -> skipped, not scanned
drain D 40 || true
stop_service
long_inplace=$(grep -c 'WARN move to hold failed' "$TMP/log_D" || true)
spaced=$( [[ -f "$WATCH/d spaced name.txt" ]] && echo y || echo n)
uni=$( [[ -f "$WATCH/d-名前.txt" ]] && echo y || echo n)
empt=$(grep -c 'SKIP unstable or empty' "$TMP/log_D" || true)
partskip=$(grep -c 'd-skip.part' "$TMP/log_D" || true)
[[ "$long_inplace" -ge 1 ]] && ok "240-char name: hold move failed honestly -> scanned in place" || bad "240-char name handling"
[[ "$spaced" == y ]] && ok "spaces in name: held + released" || bad "spaces name"
[[ "$uni" == y ]] && ok "unicode in name: held + released" || bad "unicode name"
[[ "$empt" -ge 1 ]] && ok "empty file: skipped as unstable" || bad "empty file"
[[ "$partskip" -eq 0 && -f "$WATCH/d-skip.part" ]] && ok ".part file: skipped (not scanned), left in place" || bad ".part handling"
hold_empty && ok "hold empty after Part D" || bad "hold leaked after Part D"

echo
echo "=== Stress result: $PASS passed, $FAIL failed ==="
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
