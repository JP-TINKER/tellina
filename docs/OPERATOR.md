# Tellina operator guide

Silent post-download guard for `~/Downloads`.

Every completed download is scanned in the background. This is not on-access protection. A file can be opened before the scan finishes.

| Result | What happens |
|--------|----------------|
| Pass | File stays in Downloads; one journal line (no popup) |
| Fail | File moved to quarantine and desktop alert |

## Checks (automatic)

1. Download finished (skips `.part`, `.crdownload`, and similar; watches `close_write` and `moved_to` only)
2. Non-empty, stable file size
3. Under 2 GiB (larger files skipped with log; avoids clamscan fail-open)
4. ClamAV signature scan
5. `file`: extension vs actual type (for example, fake `.pdf` executable)
6. Structure: EPUB zip test; PDF page count if `pdfinfo` is available

## Log

Journal only (rotated by journald):

```bash
journalctl --user -u download-security.service -f
```

If ClamAV fails repeatedly, you get one desktop alert (not per file). Stale virus definitions (over 7 days) warn once at service start. A crash triggers one critical notify via systemd `OnFailure`.

## Install / update

```bash
./install.sh
```

Installs packages on Debian and Ubuntu, `~/.local/bin/tellina`, user units, and enables the service.

## Faster scans (optional)

Tellina probes `clamdscan` at startup. If the daemon answers, scans use it. Otherwise `clamscan`. On Debian and Ubuntu, group membership still matters for `--fdpass`:

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

Default: `~/.local/share/tellina/quarantine/` (directory mode `0700`; quarantined files `0400`, non-executable).

Files get a timestamp prefix so nothing is overwritten.

## Boot after login

Auto-start after login is not verified until you see it yourself. After logout and login (without manual start), the journal should show a `START` line from Tellina alone. Until then, treat auto-start as unconfirmed.

```bash
journalctl --user -u download-security.service -b --no-pager | grep START
```

## Expectations

- Idle: no CPU use
- Per file: usually a few seconds
- Not a guarantee against unknown malware; signatures and obvious fakes only

## Known edge cases

Safe (single-fd downloaders): browsers, wget, curl, scp. One `close_write` at completion.

Partial-file edge (append-in-loop): documented; rare for real downloaders. Fix deferred (debounce by size).

Symlinks: no `-e create`, so symlink creation does not trigger inotify scan. If scanned, targets outside `~/Downloads` log `SKIP path outside watch root`.

## Tests

Full (local): `./tests/run.sh`. Service must be active; includes inotify cases.

CI subset: `./tests/run-ci.sh`. Headless; `--scan-once` only.

Boot-check (manual; does not prove auto-start):

```bash
./tests/run.sh --boot-check
```
