# Changelog

All notable changes to Tellina are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-07-01

### Added

- RAM-backed staging area: small downloads move to a memory-only hold, get
  scanned there, and only return to `~/Downloads` if they're clean
- Hold size adjusts to your RAM automatically (6.25%, between 128 MiB and
  1 GiB); `DOWNLOAD_RAM_HOLD_MAX` can pin a fixed size instead
- New `unknown` verdict for files that can't be clearly assessed (corrupt
  documents, tampered files). These are quarantined instead of released
- Fingerprint check (size + SHA-256) confirms a held file wasn't altered
  before it's released
- Crash recovery: files stranded in the hold by a crash are picked back up
  and processed on the next start (`--sweep-once` runs this on demand)
- Faster scans via `clamdscan --fdpass` when the ClamAV daemon is running
- Quarantined files get a `.meta` note recording what happened and why
- Detects a real program disguised as a document (e.g., a Linux executable
  renamed `invoice.pdf`)
- Detects a downloaded `.desktop` launcher, a common trick for running a
  command when the file is opened
- ClamAV's built-in size limits are raised to match Tellina's own limit, so
  large files get fully scanned instead of silently skipped and marked clean
- Malware caught in the RAM hold is deleted on the spot instead of being
  copied into quarantine, so Tellina never writes a second copy of it to disk
- New adversarial test suite (`tests/redteam.sh`) that tries to break Tellina
  and reports what got through

### Changed

- Large files are scanned where they sit instead of moved; files over 2 GiB
  are skipped and logged, never scanned
- A scanner error never blocks a download: the file is released (if small)
  or left alone (if large), with an alert after 5 errors in a row
- If the RAM hold isn't available, every file is scanned in place instead,
  with a warning logged
- A released file keeps its original permissions instead of always becoming
  non-executable, so things like AppImages don't lose their "run" bit

### Fixed

- A text file that merely starts with `#!` was wrongly flagged as a
  disguised program; the check now looks at the real file type, not the text
- Test-only switches for simulating scanner failures could be triggered by an
  environment variable in the live service; they're now confined to the
  one-shot test command
- A crafted recovery file could point the crash-recovery step at a location
  outside `~/Downloads`; recovery now only ever writes back inside it
- A filename containing a newline could slip past the live watcher unseen;
  a periodic safety sweep now catches these
- A PDF that `pdfinfo` merely failed to parse was wrongly treated as corrupt
- Filenames are stripped of stray line breaks before they reach the log, so
  a crafted filename can't forge a fake log entry
- A single failed quarantine during crash recovery could stop the rest of
  the recovery from running; one failure no longer blocks the others
- Under a burst of many downloads at once, the loop that stops Tellina from
  re-scanning its own released files could time out and cause every file to
  be scanned two or three times over; the fix makes that check exact instead
  of time-limited
- A file padded past the 2 GiB scan limit but disguised as a document is now
  still caught by the (very fast) disguise check, instead of slipping through
  as "too large to scan"

### Security

- The `unknown` verdict closes a gap from the first version, which released
  any file that didn't explicitly fail a check
- The fingerprint check catches tampering while a file sits in the hold
- Malware found in the RAM hold is deleted, never written to disk, so a
  confirmed threat leaves no new copy behind
- Still no new dependencies, no root access, and no network calls

[0.2.0]: https://github.com/JP-TINKER/tellina/releases/tag/v0.2.0

## [0.1.0] - 2026-07-01

### Added

- Post-download guard for `~/Downloads`: ClamAV scan plus basic file-type and
  structure checks
- Runs as a systemd user service, with a crash notification if it dies
- `install.sh` / `uninstall.sh` for Debian and Ubuntu; `--no-deps` for other
  distros
- Quarantine folder locked down (`0700` dir, `0400` files, non-executable)
- Test harnesses: `tests/run.sh` (local, full) and `tests/run-ci.sh`
  (headless, for CI)
- GitHub Actions runs `run-ci.sh` on every push

### Security

- A scanner error never blocks a download; an alert fires after 5 errors in
  a row
- Files over 2 GiB are not scanned, to avoid overloading `clamscan`
- Warns once at startup if the virus definitions are more than 7 days old

### Known limits

- Scans after the download finishes, not while it's happening
- CI does not cover the live watcher, desktop notifications, or auto-start
  after login; those are checked by hand

[0.1.0]: https://github.com/JP-TINKER/tellina/releases/tag/v0.1.0
