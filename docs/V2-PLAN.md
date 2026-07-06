# Tellina v2 design

This is the design behind the shipped v2 (`bin/tellina`): move a completed
download off the disk into a private, memory-backed hold, scan it there, then
release it or quarantine it. Strictly user-space: no root, no new packages, no
network calls, silent on a clean result.

v1 scanned files where they landed. v2 moves small files into the hold first,
so an unscanned file spends less time sitting in `~/Downloads` under its real
name.

## Mission

Unobtrusive, automatic, minimal dependencies, silent on pass, runs as a normal
user. Do no harm: never break a download, never lock up `~/Downloads`, never
confiscate a file the scanner simply failed to check.

## Hard rules

1. No new packages beyond v1's set (`clamav`, `inotify-tools`, `file`, `unzip`;
   `poppler-utils` optional).
2. No root, ever. A feature that needs root is out of scope, full stop.
3. No outbound network calls. ClamAV's own signature updates (via `freshclam`)
   are the only outside intelligence.
4. Fail open. A scanner malfunction releases (small file) or leaves alone
   (large file); it never confiscates. Alert after 5 scanner errors in a row.
5. Silent on a clean result: one log line, no popup.
6. No settings screen, no runtime toggles. Defaults are the product.

## Allowed tools

`inotifywait`, `clamscan`/`clamdscan --fdpass`, `file`, `unzip`, `pdfinfo`
(optional), `sha256sum`, `stat`, `mv`, `cp`, `chmod`, `df`, `realpath`, `date`,
`mktemp`. Bash 4+. Nothing else.

## The RAM hold

- Lives at `$XDG_RUNTIME_DIR/tellina/hold`, a private, memory-backed folder
  that already exists on any systemd desktop; Tellina mounts nothing new.
  Its contents evaporate on reboot or logout.
- If that folder isn't available, Tellina scans every file where it is
  instead (the v1 behavior) and logs a clear warning. Never a silent fallback.
- Scans by open file descriptor when the ClamAV daemon is available
  (`clamdscan --fdpass`), so no extra temp file is created on that path either.

## Small vs. large

- The hold's size cap defaults to 6.25% of your RAM, clamped between 128 MiB
  and 1 GiB (`DOWNLOAD_RAM_HOLD_MAX` pins a fixed size instead). A file at or
  above the cap, or one that doesn't have enough free space in the hold's
  filesystem, is scanned in place instead.
- Files above 2 GiB (`MAX_SCAN_BYTES`) are never scanned at all. They're left
  alone and logged, never quarantined for size alone.

## Checks, cheapest first

1. **Desktop launcher**: a `.desktop` file with an `Exec=` line runs a command
   when opened and would otherwise get a free pass, since it's plain text.
   Always malicious.
2. **Disguised executable**: a real program's file type, wearing a document or
   image name. Always malicious, regardless of size.
3. **Structure**: does the EPUB/zip actually open, does the PDF have pages.
   Encrypted PDFs pass through, since they can't be inspected. A file that
   fails this is `unknown`, not `malicious`.
4. **ClamAV scan**, with its size limits raised to match Tellina's 2 GiB cap
   so nothing in that range is skipped and reported clean unscanned. A match
   is `malicious`; a clean result is `clean`; anything else is a scanner error
   (see fail-open, below).

## Verdicts

| Verdict | Small (held) | Large (in place) |
|---------|--------------|-------------------|
| clean | released, original permissions restored, logged | logged, untouched |
| malicious | deleted from the hold, a record kept, one alert | quarantined, one alert |
| unknown | quarantined, one alert | left in place, logged |
| too large | n/a | left in place, logged |

`unknown` is the key change from v1, which released anything that didn't
explicitly fail. v2 quarantines a small file it can't positively clear, and
leaves a large one alone rather than confiscating it on a hunch.

A confirmed-malicious small file only ever exists in the hold (memory), so it's
deleted there rather than copied into on-disk quarantine: no second copy of the
malware is ever written to disk, only a short record of what happened. That
applies to the two high-confidence verdicts (a signature match, or a real
program disguised as a document). Verdicts that could be wrong stay in
quarantine so a mistake is recoverable. A large malicious file was already on
disk, so it's simply moved to quarantine as before.

## Fail-open

A scanner result that's neither "clean" nor "match" (a crash, a timeout) logs
the error, counts toward a consecutive-error total, and releases the small
held file back to `~/Downloads` unscanned rather than trapping it. A large
file just stays where it is. After 5 errors in a row, one alert fires. A
broken scanner should never be the reason a download gets stuck or deleted.

## Fingerprint check

At the moment a file enters the hold, Tellina records its size and checksum.
Right before releasing a clean file, it checks both again. A mismatch means
the file changed while held, verdict `unknown`, quarantined instead of
released.

## Not re-scanning its own releases

Copying a clean file back to `~/Downloads` raises a new file-system event,
which would otherwise make Tellina scan its own output forever. On release,
Tellina remembers that file's inode and size; the next matching event is
recognized as its own echo and skipped, no matter how long it takes to arrive.
A genuinely different file (different inode or size, like a fresh re-download)
still gets scanned normally.

## Crash recovery

If the service dies mid-scan, a file can be stranded in the hold. On the next
start, before anything else, Tellina reprocesses every stranded file using the
record it kept of where it came from (`--sweep-once` runs the same pass on
demand). Nothing sits in the hold forgotten.

## Quarantine

Lives at `~/.local/share/tellina/quarantine`, locked to your account, files
made non-executable. Each quarantined file keeps a short record alongside it:
where it came from, why it was flagged, and its checksum.

## Tests

- `tests/run-ci.sh`: headless, no live service needed. Exercises the full
  decision tree (hold and release, malware handling, disguised executables,
  fail-open, size limits, fingerprint mismatch, crash recovery, and more).
  19 cases, all green.
- `tests/run.sh`: the same coverage plus the live file-watching service and
  the release-echo guard under real conditions. Needs the service running.
- `tests/redteam.sh`: tries to actively defeat Tellina and reports what got
  through, honestly, as either stopped, a known limit, or a real problem.

## Risks, acknowledged and not hidden

- A file briefly exists in `~/Downloads` before the move to the hold. Shorter
  than v1 (which left it there for the whole scan), but not zero.
- Moving a file mid-download can break an actively-writing downloader (some
  torrents, chunked writes). Partially mitigated, not fully solved.
- The hold's cap adapts to available RAM; an oversize file falls back to being
  scanned in place, so a full hold pressures memory, never disk.
- The hold is memory, so a hard power cut loses anything in it. A service
  restart recovers anything a normal crash stranded. This is the deliberate
  trade for never leaving an unscanned file sitting on disk.
- The hold does not reduce disk writes. A clean file is still written to disk
  twice (the original download, then the release copy). Its value is
  isolating the file during the scan and gating release on a clean result,
  not saving writes. Full detail in [THREAT-MODEL.md](THREAT-MODEL.md).

## Rejected

Anything needing root or a network call, on principle: a loopback-mounted
hold, an immutable-flag lock, a hash blocklist. Each was considered and cut
for breaking one of the hard rules above.
