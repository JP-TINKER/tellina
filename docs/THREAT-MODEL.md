# Tellina threat model (v1)

Personal Linux download guard. Post-download gate, not on-access and not enterprise EDR.

Files may be opened before the background scan finishes. That comes with async watching. On a single-user desktop, anyone who can race your Downloads folder already runs as you.

## In scope

- Watch `~/Downloads` (recursive) for completed files
- ClamAV signature scan (`clamscan` or `clamdscan --fdpass`)
- Skip files over 2 GiB (avoids clamscan choke and fail-open)
- Extension vs MIME mismatch on document-like names
- Light structure check (EPUB zip, PDF pages, encrypted PDF pass-through)
- Quarantine and desktop notify on fail; journal log on pass
- Stale signature DB warning at start (once per run if over 7 days)
- Service crash notification via systemd `OnFailure`

## Out of scope

- Zero-day and unknown malware
- Real-time on-access (`clamonacc` / fanotify; needs root)
- Scanning dotfiles and non-Downloads paths
- Network inspection

## Known risks

| Risk | Mitigation |
|------|------------|
| Fail-open on AV rc≠0, rc≠1 | Alert after 5 consecutive errors; size cap reduces rc=2 frequency |
| Append-in-loop partial scan and debounce | Rare; browsers, wget, and curl are safe; documented only |
| Symlinks without `-e create` | No scan event; low impact |
| Async scan vs open-by-user | Accepted; post-download gate (see README) |

## Unverified claims

| Claim | Evidence needed |
|-------|-----------------|
| Service auto-starts after login | Fresh login or reboot journal shows `START` without manual `systemctl start` |

## Trust boundaries

Runs as user. No root. Quarantine is `mv` under `~/.local/share/tellina/quarantine` by default (directory `0700`; files `0400` after quarantine).
