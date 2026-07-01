# Tellina

Silent Linux download guard. Tellina watches `~/Downloads`, scans finished files with ClamAV, and quarantines detected malware and suspicious files. Quiet on pass. Alerts only on fail or scanner trouble.

This is not on-access or real-time protection. A file can be opened before the background scan finishes. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

Limitations: ClamAV catches known signatures, not zero-day malware. Files over 2 GiB are not scanned; they stay in Downloads and are logged only. If the scanner errors on a file, the file stays in place. You get a desktop alert after repeated failures.

## Who this is for

Linux desktop users on systemd, comfortable with a terminal. Debian and Ubuntu get a one-command install below. On Fedora, Arch, and other distros, install packages from your distro, then run `./install.sh --no-deps`.

No config file is required. Defaults are enough.

## Requirements

- Linux with a systemd user session (typical desktop login)
- bash 4+ and GNU coreutils (`date`, `stat`, and so on). Not macOS or BSD.
- [ClamAV](https://www.clamav.net/) (scanner and virus definitions via `freshclam`). Not ClamTK; the GUI is optional and unused.
- inotify-tools, file, unzip; poppler-utils optional (PDF structure check)
- Desktop session with D-Bus (standard on GNOME, KDE, and similar; used for quarantine alerts)

`install.sh` on Debian and Ubuntu installs the packages above and waits for virus definitions before starting Tellina.

## Install

```bash
git clone https://github.com/JP-TINKER/tellina.git
cd tellina
./install.sh
```

The first install may spend several minutes downloading ClamAV signatures. That is normal.

Already have dependencies?

```bash
./install.sh --no-deps
```

Fedora and Arch (install packages, then run the line above):

```bash
# Fedora: sudo dnf install clamav clamav-freshclam inotify-tools file unzip
# Arch:   sudo pacman -S clamav inotify-tools file unzip
./install.sh --no-deps
```

## Check it is running

```bash
systemctl --user status download-security.service
journalctl --user -u download-security.service -f
```

Drop a clean file in `~/Downloads`. You should see one `OK` line in the journal. No popup on pass is normal.

## Optional: faster scans

Tellina uses `clamdscan` when a working ClamAV daemon answers at startup (probed directly, not guessed from systemd unit names). Otherwise it uses `clamscan`.

For Debian and Ubuntu daemon and group setup:

```bash
./scripts/enable-clamd.sh
# log out and back in for clamav group membership
```

## Uninstall

```bash
./uninstall.sh
./uninstall.sh --purge-quarantine   # also remove ~/.local/share/tellina/quarantine
```

## Defaults

| Setting | Default |
|---------|---------|
| Watch directory | `~/Downloads` |
| Quarantine | `~/.local/share/tellina/quarantine` |
| Max scan size | 2 GiB (larger files not scanned; skipped with log) |
| Service name | `download-security.service` |

Advanced overrides use environment variables. See [docs/OPERATOR.md](docs/OPERATOR.md).

## Documentation

- [Operator guide](docs/OPERATOR.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Changelog](CHANGELOG.md)
- [Security](SECURITY.md)

## Tests (developers)

Local (full): `./tests/run.sh` requires `download-security.service` to be active. Covers inotify paths (slow write, browser rename) and journal integration.

CI / headless: `./tests/run-ci.sh` runs without a service or D-Bus. Uses `--scan-once` only (clean file, EICAR, fake PDF, fail-open, size cap).

GitHub Actions runs `run-ci.sh` only. Inotify behavior, desktop notifications, and post-login auto-start are verified locally, not in CI.

## License

MIT. See [LICENSE](LICENSE).
