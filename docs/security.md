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

- **It opens no network connections of its own and listens on no port.**
  On a standalone computer it never touches the network. On Linux, the
  systemd service runs with `PrivateNetwork=yes`, so it has no network
  access at all.
- **On a LAN it only reads and writes files.** A computer set to send to a
  collector copies files into the collector's shared folder. It uses the
  operating system's own file sharing:
  - Windows: the SMB client, signed in with the stored account, or the
    computer's domain account
  - Linux: a CIFS mount that systemd sets up before each run; the
    sandboxed service itself still has no network access
  - a VirtualBox shared folder, which needs no network at all

  See [LAN security](#lan-security).
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

## LAN security

- **Least privilege on the inbox.** On a Windows collector, the inbox
  folder is restricted by SID to:
  - Administrators and SYSTEM
  - a local group, **Blackbox Senders**, that may add, change and remove files
    there (Modify), and nothing else

  If shared, the share grants Change to that group only. The installer
  creates the group and, when asked, adds named accounts to it. It never
  creates accounts itself.
- **Stored credentials.**
  - Windows: a sender's share password is encrypted with DPAPI, bound to
    the machine. It is kept in the data folder, which only Administrators
    and SYSTEM can read.
  - Linux: the password is in `/etc/blackbox/share.cred`, mode 0600, owned
    by root.
  - Neither is ever written to the settings file or shown on screen.
  - In a domain, Windows senders need no stored password.
- **Passwords typed on command lines are hidden.** Command-line auditing
  records commands as typed, including any password in them. Before an
  event is stored or reported, Blackbox replaces these with `********`:
  - `NAME=value` where the name contains PASSWORD, PASSWD or SECRET
  - PowerShell `-Password …` and `ConvertTo-SecureString '…'`
  - `net user NAME PASSWORD` and `net use \\server\share PASSWORD`
  - `sshpass -p …`, and `echo … | sudo -S`

  PowerShell `-EncodedCommand` is decoded first, so a password inside it
  is hidden too. The original logs are not changed.
- **Original logs are kept unaltered.** The daily log archives are exact
  copies, so they are not redacted: a password typed on a command line is
  in them as it is in the log itself. They are in the reports folder,
  which only Administrators and SYSTEM (Windows) or root (Linux) can
  read. Each file's SHA-256 is recorded in the zip and checked by the
  collector, and each report records the SHA-256 of every zip it covers.
- **Share mount (Linux).** The share is mounted inside Blackbox's data
  folder only, with root-only file permissions and `nosuid,nodev,noexec`.
- **Tamper evidence in transit.** Each batch has:
  - a SHA-256 checksum, and a closing record that detects a cut-short file
  - a per-sender sequence number

  The collector reports missing batch numbers, and sets damaged or
  altered batches aside and reports them. These checks detect loss and
  accidental or careless change, not a determined attacker with write
  access to the inbox. The batches are not cryptographically signed.
- **No loops, no spoofed collectors.**
  - A computer refuses its own batches.
  - It only delivers to a folder that has the collector's marker file, so
    an unmounted share (an empty local folder) is never written to by
    mistake.
- **What a sender can claim.** A sender supplies the host names in its
  data. The Systems page lists every computer seen, so an unexpected one
  stands out. If one computer delivers collection records for another,
  the report marks that system "via" the computer that delivered them.

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
