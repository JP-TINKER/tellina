# Tellina threat model (v2)

A personal Linux download guard. Small completed downloads move into a private,
RAM-backed hold, get scanned there, and only return to `~/Downloads` on a clean
verdict. Large files are scanned where they are instead. This is a post-download
gate, not real-time, always-on protection, and not enterprise-grade endpoint
security.

## In scope

- Watches `~/Downloads` (including subfolders) for completed files
- Small files: held in a private, memory-only folder while scanned, then
  released on a clean verdict
- ClamAV signature scan of the held file, with ClamAV's own size limits raised
  so a large file is fully scanned instead of silently skipped and marked clean
  (see "Scanning large files fully" below)
- Four possible verdicts: clean, malicious, unknown, too large to scan
- Catches a real program disguised as a document (a Linux/Windows/Mac
  executable wearing a `.pdf`, `.png`, etc. name); a plain text file that just
  starts with `#!` is not mistaken for one
- Catches a downloaded `.desktop` launcher, a common way to smuggle in a
  command that runs when the file is opened
- A light structural check (does the EPUB or PDF actually open); encrypted
  PDFs are let through, since they can't be inspected
- A fingerprint check (size and checksum) confirms nothing changed while a
  file was held
- Guards against re-scanning its own released files in a loop
- Picks back up any file stranded in the hold after a crash
- Quarantines bad files and sends one desktop alert; warns once if virus
  definitions are more than 7 days old or the scanner starts failing

## Out of scope

- Malware ClamAV has no signature for (zero-days, custom malware)
- Real-time, on-access scanning (needs root access Tellina doesn't have)
- Files over 2 GiB (skipped and logged, not scanned)
- Anything outside `~/Downloads`, and dotfiles within it
- Any kind of network lookup (Tellina makes no outbound calls at all)

## The honest limits of the RAM hold

A completed download briefly sits in `~/Downloads` under its real name before
Tellina moves it into the hold. That window used to last for the whole scan;
now it's just the few seconds it takes to notice and move the file. Tellina
does **not** claim the file never touches `~/Downloads` at all, only that the
window is short. (Anyone able to race that folder is already running as you,
on your own single-user machine.)

The hold does not save disk writes, either, and it can't. Your browser writes
the finished download to disk before Tellina ever sees it; nothing short of
root access or built-in browser support could prevent that first write, so
Tellina doesn't try. What it does control is what happens after:

- A **clean** small file is copied from the hold back to `~/Downloads`. That's
  a second disk write, the cost of scanning it in isolation first.
- A **malicious** small file is never written back. Tellina records what it
  was and why it was blocked (name, checksum, reason) and then deletes it from
  the hold, so no second copy of the malware ever reaches your disk. Verdicts
  that could be wrong (a corrupt document, a fingerprint mismatch, a `.desktop`
  launcher) are kept in quarantine instead of deleted, so a mistake can be
  undone.

Deleting a file only removes its directory entry; it doesn't scrub the bytes,
and that isn't reliably possible on an SSD anyway. So Tellina cannot promise
to erase your browser's original copy. What it does promise is narrower and
true: it never adds a second on-disk copy of confirmed malware.

## Scanning large files fully

Left at its defaults, ClamAV gives up on a file past 100 MiB (or 400 MiB for
an archive's contents) and reports it clean without actually finishing the
scan. Since Tellina accepts files up to 2 GiB, that gap would let a large
infected download through unscanned. Tellina raises ClamAV's limits to match
its own 2 GiB cap so nothing in that range is skipped. (The daemon mode,
`clamdscan`, ignores this setting on the command line, so `enable-clamd.sh`
sets it directly in ClamAV's own config instead.)

## Verdict policy

| Verdict | Small (held) | Large (in place) |
|---------|--------------|-------------------|
| clean | released to `~/Downloads`, original permissions restored | left in place |
| malicious | deleted from the hold, a record kept, one alert (no disk copy) | moved to quarantine, one alert |
| unknown | quarantined, one alert | left in place, logged |
| desktop launcher | quarantined, one alert | quarantined, one alert |
| too large to scan | n/a | left in place, logged |

`unknown` covers a corrupt document or a file that changed while it was held.
Tellina's first version released anything that didn't explicitly fail; this
version quarantines what it can't clearly judge instead of guessing.

A file over the 2 GiB scan limit skips the full virus scan, but it still gets
the disguised-executable check, since that only reads the file's header and
costs almost nothing even on a multi-gigabyte file. So a real program padded
past the limit and wearing a document's name is still caught. A file that's
padded past the limit but not disguised, and would otherwise have matched a
known signature, does slip through unscanned. That's a real, acknowledged gap.

## Known risks

| Risk | What limits it |
|------|-----------------|
| A file briefly sits in `~/Downloads` before the move to the hold | Window is a few seconds; far shorter than the first version, which left it there for the whole scan |
| Moving a file mid-download can break an active writer (some torrents, chunked downloads) | Tellina waits for the file to stop changing first and skips known temp extensions; not a full fix |
| The hold can run out of room under memory pressure | Its size auto-adjusts to available RAM (128 MiB-1 GiB); files that don't fit are scanned in place instead |
| A hard power loss wipes the hold (it's memory, not disk) | A service restart recovers anything stranded by a crash; a real power cut still loses it, a deliberate trade for never leaving an unscanned file sitting on disk |
| A broken scanner could block every download | Scanner errors release the file rather than block it; you get an alert after 5 in a row |
| Releasing a clean file could trigger Tellina to re-scan its own release forever | Tellina recognizes its own release and skips it, no matter how long a busy period takes |
| A newline inside a filename can slip past the live file watcher | A periodic safety sweep catches anything the watcher couldn't name |
| Creating a symlink doesn't trigger a scan | Low impact; a scanned symlink pointing outside `~/Downloads` is refused and logged |
| Tellina can't stop you from opening a file before the scan finishes | Accepted; this is a post-download gate, not real-time protection |

One narrower risk is worth spelling out: Tellina recognizes its own release by
a file's identity (inode and size), not a time limit, so a burst of releases
can't outrun it. The trade-off is a rare edge case: if a file at the exact same
path is deleted and a new file of the exact same size happens to land on the
same freed inode within an hour, Tellina could mistake it for its own echo and
skip it. An attacker can't engineer this remotely, and a real re-download gets
a new inode, so it still gets scanned. This sits outside what Tellina is built
to guard: files as they arrive, not tampering with `~/Downloads` after the
fact.

## Things stated here that still need your own eyes to confirm

- That the service actually starts by itself after you log in (check the
  journal after a real login, not a manual start)
- That the release-echo guard above holds up under a real burst of downloads
  (see `tests/stress.sh` for a repeatable check)

## Trust boundaries

Runs as your normal user. No root, ever. No network calls, ever. The hold
lives in `$XDG_RUNTIME_DIR`, a memory-backed folder your own account already
owns. Quarantine lives under `~/.local/share/tellina/quarantine`, locked to
your account only, with files made non-executable. A confirmed-malicious held
file is deleted rather than moved there, leaving only its record behind.
Released files keep their original permissions, so a legitimately-executable
download doesn't quietly lose its "run" bit.
