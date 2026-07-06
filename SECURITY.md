# Security

Tellina is a personal download scanner for one user's machine, not enterprise
endpoint protection.

## Reporting a problem

Open a [GitHub issue](https://github.com/JP-TINKER/tellina/issues) with steps
to reproduce it. For anything sensitive, use [private vulnerability
reporting](https://github.com/JP-TINKER/tellina/security/advisories/new) if
it's enabled on the repository.

## What's in scope

A way to bypass quarantine, a scanner error that fails closed instead of open,
a way to escape `~/Downloads`, or anything that escalates privileges beyond
the user who installed Tellina.

## What's not

Malware ClamAV itself can't detect, the brief window between a download
finishing and Tellina scanning it, and files over 2 GiB not being scanned.
These are documented limits, not bugs.
