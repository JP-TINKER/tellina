# Tellina operator guide (v2)

Silent download guard for `~/Downloads`. Small completed downloads move into a
RAM-backed hold, get scanned, and only return to `~/Downloads` on a clean
verdict. Large files are scanned where they are instead.

This is not on-access protection: a completed file briefly sits in
`~/Downloads` before Tellina moves it to the hold, and a large or
actively-written file is scanned in place rather than held. See
[THREAT-MODEL.md](THREAT-MODEL.md) for the full honest account.

| Verdict | What happens |
|---------|--------------|
| clean | Small: released to `~/Downloads` (original mode preserved, default `0644`), one journal line. Large: left in place, one journal line. No popup. |
| malicious (small) | Unlinked from the RAM hold + one desktop alert; a `.meta` record is kept (`retained=no`), but no on-disk copy of the malware is written |
| malicious (large) | Moved to quarantine (`0400`) + one desktop alert (already on disk) |
| desktop launcher | Downloaded `.desktop` with `Exec=`: quarantined (`0400`, preserved) + one alert |
| unknown (small) | Quarantined (`0400`) + one alert (corrupt document or fingerprint mismatch) |
| unknown (large) | Left in place + `SKIP` log (never confiscate a big file on a hunch) |
| too-large | Left in place + `SKIP too large` log (above 2 GiB) |
| scanner error | Small released back (`RELEASE unscanned`); large left in place. Alert after 5 in a row |

## How it works (automatic)

1. A file finishes downloading; `inotify` sees the event (skips `.part`,
   `.crdownload`, `.tmp`, and dotfiles).
2. Tellina waits until the file is stable (not still being written).
3. Over 2 GiB → logged `SKIP too large`, left alone, done.
4. Small enough for the RAM hold (adaptive cap: 6.25% of RAM, clamped to
   [128 MiB, 1 GiB], or `DOWNLOAD_RAM_HOLD_MAX` if set) → moved into the hold.
   Otherwise scanned in place.
5. Checked in order: is it a `.desktop` launcher with an `Exec=` line, is it a
   real executable disguised as a document, does its structure check out
   (an EPUB or PDF that fails to open), then a full ClamAV scan.
6. Clean and small → fingerprint check, then copied back to `~/Downloads` with
   its original permissions. Clean and large → logged, left alone. Malicious
   and small → deleted from the hold, never written to disk. Malicious and
   large → moved to quarantine, since it was already on disk.

If `$XDG_RUNTIME_DIR` isn't available, Tellina scans everything in place and
logs `WARN no RAM hold`, so the fallback is visible, not silent.

## Log

Journal only (rotated by journald):

```bash
journalctl --user -u download-security.service -f
```

v2 line shapes:

```
HOLD <size>B | <src> -> <held>
OK <size>B | <mime> | <path>
RELEASE unscanned | <path>
QUARANTINE <reason> | sha256=... | <path>
QUARANTINE <reason> | sha256=... | not retained (unlinked from RAM hold) | <name>
SWEEP reprocessing stranded hold file: <held> -> <orig>
SKIP release echo: <path>
SKIP too large (<size>B > <cap>B): <path>
SKIP scan error (rc=N): <path>
SKIP corrupt document (large, left in place): <path>
```

One desktop alert on quarantine or after 5 consecutive scanner errors. Stale
virus definitions (over 7 days) warn once at service start. A crash triggers
one critical notify via systemd `OnFailure`.

## Manual sweep

If a file is stranded in the hold (e.g. after a service crash it was already
reprocessed at startup, but you can re-run on demand):

```bash
~/.local/bin/tellina --sweep-once
```

Reprocesses every file in the hold and exits.

## Install / update

```bash
./install.sh
```

Installs packages on Debian and Ubuntu, `~/.local/bin/tellina`, user units, and
enables the service. Re-run after any update to refresh the installed binary.

## Faster scans (optional)

Tellina probes for a running ClamAV daemon (`clamdscan`) at startup and uses it
if it answers; otherwise it falls back to the slower `clamscan`. On Debian and
Ubuntu, you need group membership for the daemon path to work:

```bash
./scripts/enable-clamd.sh
# log out and back in for clamdscan group membership
```

## Service

```bash
systemctl --user status download-security.service
systemctl --user restart download-security.service
systemctl --user disable download-security.service   # turn off
```

## Quarantine

Default: `~/.local/share/tellina/quarantine/` (dir `0700`; files `0400`,
non-executable). Each file gets a timestamp prefix (nothing overwritten) and a
`<file>.meta` sidecar with original path, reason, verdict, SHA-256, timestamp.

## Environment overrides

| Variable | Default | Effect |
|----------|---------|--------|
| `DOWNLOAD_WATCH_DIR` | `~/Downloads` | Watch root |
| `DOWNLOAD_QUARANTINE_DIR` | `~/.local/share/tellina/quarantine` | Quarantine dir |
| `DOWNLOAD_RAM_HOLD_MAX` | (unset → adaptive) | If set, fixed byte cap for the RAM hold. Unset: 6.25% of RAM clamped to [128 MiB, 1 GiB]. Files at/above are scanned in place |
| `DOWNLOAD_MAX_SCAN_BYTES` | 2147483648 (2 GiB) | Files above this are not scanned |
| `DOWNLOAD_STABLE_SEC` | 2 | Seconds before stability re-check |
| `DOWNLOAD_DB_MAX_AGE_SEC` | 604800 (7 days) | Stale-DB warning threshold |
| `DOWNLOAD_ERROR_NOTIFY_THRESHOLD` | 5 | Consecutive scanner errors before alert |
| `DOWNLOAD_SUPPRESS_TTL` | 3600 | Release-echo suppression cleanup-reap window (seconds); suppression itself matches on `inode:size` regardless of age |

## Boot after login

Auto-start after login is not verified until you see it yourself. After logout
and login (without manual start), the journal should show a `START` line from
Tellina alone.

```bash
journalctl --user -u download-security.service -b --no-pager | grep START
```

## Expectations

- Idle: no CPU use
- Per small file: move to hold + scan + release; usually a few seconds (faster
  with `clamd`)
- Large files: scanned in place; above 2 GiB not scanned
- Not a guarantee against unknown malware; signatures and obvious fakes only

## Known edge cases

- **Normal downloaders** (browsers, wget, curl, scp): work cleanly, one
  finish event, straight through the hold.
- **Writers that append in a loop** (some torrent clients, `yt-dlp` chunked
  writes): moving the file mid-write can break the download. `wait_stable`
  and skipping `.part`-style names help, but this is a real limitation, not
  fully solved.
- **Symlinks**: creating one doesn't trigger a scan. If one is scanned and
  points outside `~/Downloads`, Tellina logs and refuses to touch it.

## Tests

Full (local): `./tests/run.sh`. Service must be active; includes inotify, hold,
release-echo, fingerprint, corrupt, and crash-sweep cases.

CI subset: `./tests/run-ci.sh`. Headless; `--scan-once`/`--sweep-once` only;
19 cases including the v2 hold path.

Red team: `./tests/redteam.sh`. Adversarial suite that tries to defeat the
tool and scores each attack as defended, a documented limit, or a real
vulnerability. Results save under `tests/results/`.

Stress: `./tests/stress.sh`. Headless; drives the real inotify loop with
25-file bursts (verdicts, throughput, release-echo suppression under load),
crash-sweep at volume, and edge-case names.

Boot-check (manual; does not prove auto-start):

```bash
./tests/run.sh --boot-check
```
