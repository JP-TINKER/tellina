# Tellina

Tellina is a quiet virus scanner for your `~/Downloads` folder on Linux. When a
download finishes, Tellina checks it before you'd normally get to open it. Clean
files show up like normal. Malware gets quarantined and you get a popup. If
nothing is wrong, you see nothing, just one line in a log.

**How it checks a file without leaving it exposed on disk:** small downloads are
moved into a short-lived holding area in your computer's memory (RAM), scanned
there with the ClamAV antivirus engine, and only copied back to `~/Downloads` if
they come back clean. Large files are scanned where they are instead of moved.
If a held file turns out to be malware, it's deleted right out of memory, so no
copy of it ever gets written to your disk. Full details, including the honest
limits, are in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## What it doesn't do

- It's not real-time, always-on protection. It checks a file after the download
  finishes, not while your browser is writing it.
- It only catches malware that ClamAV already has a signature for. Brand-new
  ("zero-day") malware can get through.
- It doesn't scan files bigger than 2 GiB. Those are left alone and logged.
- Your browser still writes the download to disk before Tellina ever sees it.
  Stopping that would need root access or a browser plugin, so Tellina doesn't
  try. What it controls is what happens next: a clean file gets written back to
  disk once more, and a file confirmed as malware is never written to disk again.

## Who this is for

Linux desktop users on systemd who are comfortable with a terminal. Debian and
Ubuntu get a one-command install below. On Fedora, Arch, and other distros,
install the packages yourself, then run `./install.sh --no-deps`.

No configuration file, no settings screen. The defaults are the product.

## Requirements

- Linux with a systemd user session (a normal desktop login)
- bash 4+ and GNU coreutils. Not macOS or BSD.
- [ClamAV](https://www.clamav.net/), the scanner (not the ClamTK GUI, which
  Tellina doesn't need)
- inotify-tools, file, unzip; poppler-utils is optional, for a PDF check
- A desktop session with D-Bus (GNOME, KDE, and similar; used for alerts)

`install.sh` installs all of this on Debian and Ubuntu, and waits for virus
definitions to download before starting Tellina.

## Install

```bash
git clone https://github.com/JP-TINKER/tellina.git
cd tellina
./install.sh
```

The first install can take a few minutes while it downloads ClamAV's virus
definitions. That's normal.

Already have the dependencies installed?

```bash
./install.sh --no-deps
```

Fedora and Arch (install the packages yourself first):

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

Drop a clean file into `~/Downloads`. You should see one `OK` line in the log
(small files show a `HOLD` line first, then `OK`). Seeing no popup is the
normal, expected result for a clean file.

## How the staging area works

A small download is moved into a private folder that lives in memory, not on
disk (technically, your system's `tmpfs`). It's scanned there and copied back
to `~/Downloads` only if it comes back clean. A file that can't be clearly
judged, a corrupt document, one that changed while it was being scanned, is
quarantined rather than let through, which closes a gap from Tellina's first
version (which let through anything that didn't explicitly fail). If the memory
folder isn't available for some reason, Tellina just scans files where they are
and says so in the log. More detail is in [docs/V2-PLAN.md](docs/V2-PLAN.md).

Two more things it checks for specifically, because a plain virus scan misses
them: a downloaded `.desktop` file (a launcher that runs a command when you
double-click it, a common trick for smuggling in malware), and a large file
that ClamAV would otherwise give up on partway through and call clean without
finishing the scan.

## Optional: faster scans

Tellina uses `clamdscan`, which talks to a background ClamAV daemon, whenever
that daemon is running. Otherwise it falls back to the slower `clamscan`.

To set up the daemon on Debian and Ubuntu:

```bash
./scripts/enable-clamd.sh
# then log out and back in, so your account picks up clamav group membership
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
| RAM hold | `$XDG_RUNTIME_DIR/tellina/hold` |
| RAM hold max size | 6.25% of your RAM, between 128 MiB and 1 GiB (adjustable) |
| Quarantine folder | `~/.local/share/tellina/quarantine` |
| Max scan size | 2 GiB (bigger files are skipped, not scanned) |
| Service name | `download-security.service` |

These can be changed with environment variables; see
[docs/OPERATOR.md](docs/OPERATOR.md).

## Documentation

- [Operator guide](docs/OPERATOR.md), for running and tuning Tellina
- [Threat model](docs/THREAT-MODEL.md), the full honest account of what it
  protects against and what it doesn't
- [v2 design](docs/V2-PLAN.md), how it's built
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## Tests (developers)

- `./tests/run.sh`: the full local suite. Needs the service running.
- `./tests/run-ci.sh`: a headless subset that doesn't need a running service.
  This is what CI runs.
- `./tests/redteam.sh`: an adversarial suite that tries to break Tellina and
  reports, honestly, what got through.
- `./tests/stress.sh`: sends it a burst of files at once and checks it keeps
  up correctly.

GitHub Actions runs `run-ci.sh` and `stress.sh` on every push. Desktop alerts
and auto-start after login can only be checked by hand, via `run.sh`.

## License

MIT. See [LICENSE](LICENSE).
