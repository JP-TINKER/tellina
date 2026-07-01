# Changelog

All notable changes to Tellina are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-07-01

### Added

- Post-download guard for `~/Downloads` (ClamAV scan, MIME/extension checks, light structure validation)
- User systemd unit `download-security.service` with crash notification via `OnFailure`
- `install.sh` and `uninstall.sh` for Debian/Ubuntu; `--no-deps` path for other distros
- Quarantine hardening: directory `0700`, quarantined files `0400` (non-executable)
- Local test harness `tests/run.sh` (inotify and journal integration)
- CI harness `tests/run-ci.sh` (`--scan-once` subset for headless runners)
- GitHub Actions workflow running `run-ci.sh` only

### Security

- Fail-open on AV errors with alert after 5 consecutive failures
- 2 GiB scan size cap to avoid clamscan choke
- Stale virus-definition warning at service start (over 7 days)

### Known limits

- Post-download gate, not on-access protection
- CI does not cover inotify behavior, desktop notifications, or post-login auto-start (local verification only)

[0.1.0]: https://github.com/JP-TINKER/tellina/releases/tag/v0.1.0
