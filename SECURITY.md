# Security

Tellina is a personal post-download scanner. It is not enterprise endpoint protection.

## Reporting

Open a [GitHub issue](https://github.com/JP-TINKER/tellina/issues) with steps to reproduce. For sensitive reports, use [GitHub private vulnerability reporting](https://github.com/JP-TINKER/tellina/security/advisories/new) if enabled on the repository.

## Scope

In scope: quarantine bypass, fail-open when signatures should match, path escape from `~/Downloads`, privilege escalation beyond the installing user.

Out of scope: malware ClamAV does not detect, race between download and user opening a file (documented post-download behavior), missing scans on files over 2 GiB (documented limit).
