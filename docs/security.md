# Security review notes

This page is for security reviewers, ISSOs and ISSMs approving Blackbox for
use.

## What Blackbox does

- It reads the Windows event logs, or on Linux the auditd log, the system
  log (or journal) and the auth log.
- It writes translated events and reports to its own data folder.
- It runs `auditpol`, `reg query`, `wevtutil gl`, `auditctl -l` and
  `auditctl -s`. These commands read settings for `check`; none of them
  change anything.

## What it does not do

- **It makes no network connections.** It has no listening ports and never
  connects out. On Linux, the systemd service runs with
  `PrivateNetwork=yes`, so it has no network access at all.
- **It never modifies logs.** It never clears, rotates, deletes or forwards
  them.
- **It never changes audit settings.** `check` only reports; the fixes it
  suggests are for administrators to apply.
- **It needs no other software:** no runtime, service, database or
  third-party code.

## Privileges

Blackbox runs as SYSTEM on Windows and as root on Linux, only because
reading the Security log or the audit log requires it. Its data folder is
restricted to Administrators and SYSTEM on Windows, and to root on Linux.

The Linux service is also sandboxed with `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/blackbox`, `NoNewPrivileges=yes` and
`PrivateTmp=yes`.

## Integrity

- Every report folder has a `manifest.sha256`. `blackbox verify` or
  `sha256sum -c manifest.sha256` detects any change.
- Collected events are only marked as read after they are safely written
  to disk, so a crash cannot lose them.

## Supply chain

- **No dependencies.** The Go module uses only the Go standard library; it
  has no third-party dependencies.
- **Offline, reproducible builds.** Builds use `-trimpath`, cgo is off, and
  build IDs are stripped, so the same source gives the same binary.
- **Checksums.** Each release publishes a `SHA256SUMS` file.
- **Tested on every change.** CI runs the unit tests on Linux and Windows.
  It also runs Blackbox against real event logs on a Windows machine, and
  against real auditd on an Ubuntu machine.

## Retention

Reports and collected events are kept forever by default. Set
`retention_days` to prune them ([configuration](configuration.md)).
