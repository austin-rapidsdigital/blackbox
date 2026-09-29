# Blackbox — Design

Open source audit log review tool for air-gapped Windows and Linux systems and
small air-gapped LANs (10–30 hosts, designed to scale further).

Blackbox reads Windows event logs and Linux audit logs, **translates events into
plain English**, groups them into the categories auditors actually review, and
produces a self-contained HTML report on a recurring schedule.

Status: **draft for discussion.** Nothing here is final.

---

## 1. Goals

1. **Readable output.** Every event is shown as a sentence a reviewer can
   understand without looking up event IDs or decoding hex codes.
   - Bad: `4625 | 0xC000006A | LogonType 10 | S-1-5-21-...-1104`
   - Good: `jsmith failed to log on to WS-07 via Remote Desktop from 10.1.1.20 — wrong password`
2. **Focus on what auditors review**, in priority order:
   1. Privileged events and privileged commands
   2. USB and removable media activity
   3. Failed logons and lockouts
   4. Other security-relevant events (account changes, audit policy changes,
      logs cleared, audit service stopped, time changes, new services, and so on)
3. **Simple installation and setup.** One file to copy across the air gap, one
   command to install, and a default configuration that works without editing.
4. **Meets DCSA / DISA STIG / RMF (NIST SP 800-53) audit review expectations**,
   including continuous coverage, integrity and retention.
5. **Easy to get approved.** Small codebase, few dependencies, no network
   listeners, read-only access to logs, reproducible builds and an SBOM.
6. **Ready for Splunk.** Normalized events are also written as JSON, so moving
   to Splunk later loses nothing.

### Non-goals (for now)

- Real-time alerting or SIEM features. That is Splunk's job later.
- An always-on web application with its own user accounts. We may add an
  optional viewer later, but static reports come first (see §6).

---

## 2. Target platforms

| Platform | Log sources |
|---|---|
| Windows 11 Enterprise | Security, System, Application, PowerShell/Operational, Partition/Diagnostic, DriverFrameworks-UserMode, Defender, Sysmon (if installed) |
| Windows Server 2025 | Same as above; also the log collector role once the LAN is on a domain (§7) |
| Ubuntu 22.04 / 24.04 | auditd (`/var/log/audit/audit.log*`), journald, `/var/log/auth.log`, AppArmor |
| AlmaLinux 8.10 | auditd, journald, `/var/log/secure`, SELinux AVC |

Everything ships as a single static binary for each OS (Go, cross-compiled),
with no runtime to install: no Python, .NET, Java or Node.

---

## 3. Architecture

```
 ┌──────────┐   ┌───────────┐   ┌──────────────┐   ┌──────────┐   ┌──────────────┐
 │ Collect  │ → │ Normalize │ → │ Classify +   │ → │ Report   │ → │ Seal +       │
 │ evtx /   │   │ common    │   │ Translate    │   │ HTML +   │   │ retain       │
 │ auditd / │   │ event     │   │ (YAML rules) │   │ JSON/CSV │   │ (SHA-256     │
 │ journald │   │ schema    │   │              │   │          │   │  manifest)   │
 └──────────┘   └───────────┘   └──────────────┘   └──────────┘   └──────────────┘
       ▲                                                                 │
       └──────────── bookmark (last record read) ◄──────────────────────┘
```

- **Collect**
  - Parse `.evtx` files directly. On a live system, use the Windows Event Log
    API so that archived and rolled-over logs are also read.
  - Parse raw auditd logs, grouping records into complete events by their
    serial number.
- **Normalize**
  - Put every event into one schema: time, host, OS, category, severity,
    actor (user and SID/UID), target, action, outcome, source IP, process,
    command line, raw event.
- **Classify and translate**
  - YAML rule files map raw events to a category and a plain-English
    template. Rules are data, not code, so we can add or adjust them without
    rebuilding the binary.
- **Report**
  - One self-contained HTML file per run, plus `events.jsonl` and CSV files.
- **Seal**
  - A SHA-256 manifest covers every output file, and the retention policy
    decides how long outputs are kept.

### Decoding that makes events readable

- **Windows**
  - Logon types: 2 = at the console, 3 = over the network, 10 = Remote
    Desktop, and so on.
  - `Status`/`SubStatus` codes: `0xC000006A` = wrong password,
    `0xC0000064` = no such user, `0xC0000234` = account locked, and so on.
  - `%%` message tokens, for example `%%1937` = elevated token.
  - SIDs resolved to names; group names; UAC flag changes.
- **Linux**
  - Hex-encoded `proctitle` decoded to the actual command line.
  - EXECVE arguments rejoined into one command.
  - `auid`/`uid`/`euid` resolved to usernames, so "who really ran this" is
    clear through sudo and su.
  - Syscall numbers resolved to names.
  - STIG audit rule keys, such as `-k privileged`, `-k usb` or `-k identity`,
    used as classification hints.

---

## 4. Event coverage (initial rule set)

Each category is tagged with the NIST 800-53 controls it supports.

### 4.1 Privileged activity — AC-6(9), AU-2, AU-12

| Windows | Linux |
|---|---|
| 4672 special privileges assigned at logon | `USER_CMD` (sudo), with the full decoded command |
| 4688 process created with an elevated token (includes the command line when that auditing is enabled) | `su` / `USER_START` sessions as root |
| 4648 logon with explicit credentials (runas) | EXECVE where `euid=0` and `auid≠0` (a normal user acting as root) |
| 4673 / 4674 privileged service or object operations | STIG `privileged-*` keys (passwd, chage, usermod, mount, and so on) |
| 4104 PowerShell script block logging | Changes to sudoers, sudo config |

### 4.2 USB and removable media — MP-7, AC-19, AU-2

| Windows | Linux |
|---|---|
| Partition/Diagnostic 1006: device connected, with vendor, model, **serial number** and capacity (enabled by default on Windows 11) | Kernel "new USB device" messages with vendor, product and serial |
| 6416 new external device recognized (needs the "Audit PnP Activity" policy) | `usb-storage` / `uas` attach and detach |
| 4663 access to removable storage (needs the "Audit Removable Storage" policy) | `mount` / `umount` syscalls on removable devices |
| DriverFrameworks-UserMode 2003 / 2100 connect and disconnect | udev add/remove events (from journald) |

The report pairs each connect with its disconnect, links the device to the
logged-on user, and flags devices not seen before.

### 4.3 Failed logons and lockouts — AC-7, AU-2, IA-2

| Windows | Linux |
|---|---|
| 4625 failed logon, with the reason decoded | `USER_LOGIN` / `USER_AUTH` with `res=failed` |
| 4740 account locked out | faillock / pam_faillock lockouts |
| 4771 / 4776 Kerberos / NTLM failures (after the domain move) | sshd `Failed password` / `Invalid user` |
| 4767 account unlocked | sudo authentication failures |

The report also detects patterns: repeated failures for one account, one
source trying many accounts, and failures followed by a success.

### 4.4 Other security events

| Area | Windows | Linux | Controls |
|---|---|---|---|
| **Audit log cleared / audit stopped** | 1102, 104, 4719 (audit policy changed), 1100 (event log service shut down) | `DAEMON_END`, `CONFIG_CHANGE`, auditd rules changed, gaps in the log | AU-5, AU-9 |
| Account management | 4720 / 4722 / 4725 / 4726 / 4738 / 4781, group membership changes 4728 / 4732 / 4756 | `ADD_USER`, `DEL_USER`, `USER_MGMT`, `ADD_GROUP`, identity file changes | AC-2 |
| Successful logon / logoff | 4624 / 4634 / 4647 (summarized, not listed one by one) | `USER_LOGIN`, `USER_END` | AC-2, AU-2 |
| System time changed | 4616 | `adjtimex` / `settimeofday` / `clock_settime` | AU-8 |
| New services / scheduled tasks | 7045, 4697, 4698 | systemd unit changes, cron changes | CM-7, SI-4 |
| Malware / security software | Defender 1116 / 1117 / 5001 (real-time protection off) | — | SI-3 |
| Mandatory access control | — | SELinux AVC denials (Alma), AppArmor DENIED (Ubuntu) | AC-3 |
| System start / shutdown | 4608, 1074, 6005 / 6006 / 6008 | boot / shutdown records | AU-2 |

---

## 5. Audit health check: coverage is part of the report

A report is only as good as the auditing turned on underneath it. Every report
begins with an **audit health** panel:

- **Coverage window.** The time period this report covers, and any **gaps**
  since the previous report, detected from the bookmark (AU-6, AU-5).
- **Log cleared or audit stopped** during the period. Always shown at the top
  and never hidden.
- **Log rollover.** A warning when the Security log wrapped before it was read,
  which means events were lost. The panel suggests a larger log size.
- **Audit configuration check.** Compares the live configuration against what
  the STIGs require, and lists anything missing:
  - Windows: `auditpol` subcategories (Logon, Special Logon, Process Creation,
    PnP Activity, Removable Storage, Audit Policy Change, Security Group
    Management, and so on), plus command-line logging in 4688 events.
  - Linux: loaded auditd rules (`auditctl -l`) compared with the STIG rules
    for Ubuntu and RHEL/Alma.
  - For example: "USB auditing is **not** enabled on WS-04, so the USB section
    for this host is incomplete."

`blackbox check` runs the configuration check on its own. We also ship a
recommended baseline so hosts can be brought into compliance:

- an `auditpol` backup file for Windows
- an auditd rules file for Linux

The tool **never changes audit settings unless you explicitly ask it to**.

---

## 6. Report format

**Decision: one self-contained static HTML file per run.** All CSS and JS are
embedded in the file. It needs no server, runs no network calls, and works in
any browser on an air-gapped machine.

Why:

- No listening port, logins or TLS, so there is nothing new to add to the
  system's authorization package.
- Each report is a single, fixed piece of evidence: hashable, easy to archive
  and possible to burn to media.
- Sorting, filtering and expanding tables still work offline through the
  built-in JS.

### Layout

1. **Header**
   - Classification banner (configurable text and color)
   - Hosts covered, time window, Blackbox version and rule-set version
2. **Summary**
   - Counts by category
   - Anything unusual, highlighted
   - Audit health (§5)
3. **Sections, in priority order**
   - Privileged activity
   - USB and removable media
   - Failed logons
   - Account changes
   - Audit and system integrity
   - Other
4. **Per-user and per-host views.** For example, "everything jsmith did this
   week."
5. **Raw event detail.** Collapsed under each translated row, so the original
   is always available.
6. **Review record** (see below).

### Review and sign-off (optional, configurable)

This follows the current workflow: the ISSO or auditor reviews first, then the
ISSM.

- **Printable signature block.** The report ends with review lines for the
  ISSO/Auditor and the ISSM (name, date, signature, comments). This works when
  printed or signed on paper.
- **Recorded review (optional).** `blackbox review <report> --role isso` asks
  for the reviewer's name and notes. It stores them in a review log alongside
  the report and adds them to the manifest, so the report itself is never
  modified. The report index then shows each report as *Awaiting ISSO* →
  *Awaiting ISSM* → *Reviewed*. This gives an AU-6 review trail without a web
  server.

### Other outputs, written on every run

- `events.jsonl`: all normalized events, in a format Splunk can ingest
- CSV exports for each category
- `manifest.sha256`
- `index.html`: links to every report, with its coverage window and review
  status

An optional read-only viewer (`blackbox serve`) could come later if a live
dashboard is needed. Splunk may make that unnecessary.

---

## 7. Deployment models

### Phase 1: now (standalone hosts and workgroup LAN)

**Model A: standalone.** Each host runs Blackbox on a schedule and writes its
own reports locally. This covers standalone air-gapped systems.

**Model A+: gather.** Each host writes its `events.jsonl` to a shared folder,
or an admin copies them to one place. `blackbox merge` then combines them
into a single LAN report with a section for each host. No forwarding setup is
needed, so this works before the domain exists.

### Phase 2: after the domain move (recommended target)

**Model B: central collector** on Windows Server 2025.

- **Windows hosts.** Windows Event Forwarding (WEF), where the hosts push
  their events to the collector (source-initiated subscriptions), configured
  by **Group Policy**. With a domain, WEF needs no certificates and no
  software on each host. This is why the domain move helps so much.
- **Linux hosts.**
  - Standard options: auditd's `audisp-remote` or rsyslog forwarding.
  - Or simply Model A+ for the Linux machines.
- **Blackbox** runs once on the collector and produces one LAN-wide report.

Later, Splunk can read from the same collector: add a Splunk forwarder or
point it at the `events.jsonl` output.

We will provide step-by-step guides and GPO / rsyslog templates for Phase 2.

---

## 8. Install and setup (simplicity is a priority)

**Target: from copying the file to the first report in under 5 minutes, with
no config editing.**

### Windows

```powershell
# Copy blackbox.exe onto the system, then in an elevated prompt:
.\blackbox.exe install
```

`install` does the following:

- Copies the binary into `C:\Program Files\Blackbox\`.
- Creates `C:\ProgramData\Blackbox\` for the config, reports and state. The
  folder is restricted to Administrators and SYSTEM.
- Writes a commented default `config.yaml`.
- Registers a scheduled task that runs as SYSTEM, weekly by default.
- Runs `blackbox check` and prints what auditing is missing.
- Produces the first report immediately so you can see it working.

An MSI package can come later for deployment through Group Policy.

### Linux

```bash
sudo ./blackbox install
```

`install` does the following:

- Installs the binary to `/usr/local/bin`.
- Creates `/etc/blackbox/config.yaml`, and `/var/lib/blackbox/` for reports
  and state, readable by root only.
- Creates a systemd service and timer, weekly by default.
- Runs the configuration check and produces the first report.

We will also build `.deb` (Ubuntu) and `.rpm` (Alma) packages for sites that
prefer package installs. Neither package has any dependencies.

### Everyday commands

```
blackbox run                  # generate a report now (the scheduler runs this)
blackbox check                # check the audit configuration against the STIG baseline
blackbox review <report>      # record ISSO/ISSM review
blackbox merge <dirs...>      # combine several hosts into one LAN report
blackbox verify <report-dir>  # check the SHA-256 manifest
blackbox uninstall            # remove the task/timer; reports are kept
```

---

## 9. Security and approval considerations

- **Read-only.** Blackbox reads logs and never modifies or deletes them. The
  only exception is `blackbox install`, and applying the audit baseline, which
  only happens when explicitly requested.
- **No network access at all.** No listening ports and no outbound calls.
- **Least privilege.** Runs as SYSTEM or root only because reading the Security
  log and `audit.log` requires it. Outputs are restricted to Administrators or
  root.
- **Integrity.** A SHA-256 manifest for every run (AU-9). Signing reports with
  a site key is an optional later addition.
- **Retention.** A configurable retention period that defaults to **keep
  everything**. It never deletes anything automatically unless configured to
  (AU-11).
- **Supply chain.**
  - Dependencies kept to a minimum and vendored into the repository, so the
    code builds fully offline.
  - Reproducible builds.
  - An SBOM (CycloneDX) and SHA-256 checksums published with every release.
- **FIPS.** Build with Go's FIPS 140-3 module (`GOFIPS140`) so hashing uses
  validated cryptography.
- **Classification banner.** Configurable, and shown on every report.

---

## 10. Configuration (default shown)

```yaml
site_name: "Example Site"
banner:
  text: "UNCLASSIFIED"
  color: "green"
schedule: weekly            # daily | weekly | monthly (used by install)
output_dir: default         # platform default path
retention_days: 0           # 0 = keep forever
categories:                 # everything on by default
  privileged: true
  usb: true
  failed_logons: true
  account_changes: true
  audit_integrity: true
  logon_summary: true
  other: true
exclude:                    # noise filters, e.g. service accounts
  users: []
review:
  signature_block: true
  roles: [ "ISSO/Auditor", "ISSM" ]
```

---

## 11. Roadmap

| Milestone | Scope |
|---|---|
| **M1: single Windows host** | evtx collection, normalization, translation for §4.1–4.3, HTML report, bookmark, manifest, `install` / `run` |
| **M2: Linux** | auditd and journald collection for Ubuntu 22.04/24.04 and Alma 8.10, the same report |
| **M3: audit health** | `check` against the STIG baselines, gap and rollover detection, audit-integrity section |
| **M4: LAN (Model A+)** | `merge`, per-host views, index page, review records |
| **M5: packaging** | MSI, .deb, .rpm, SBOM, reproducible release builds |
| **M6: domain / collector (Model B)** | WEF and forwarding guides, GPO templates, collector mode |
| Later | Optional `serve` viewer, report signing, Splunk ingestion notes |

---

## 12. Open questions

1. Report schedule: weekly for everyone, or does it vary by system?
2. Does anyone other than the ISSO and ISSM review reports, for example
   custodians?
3. Should `install` offer to apply the STIG audit baseline, or only report
   what is missing? Some sites need configuration changes to go through
   change control.
4. What classification banner text and colors should the defaults use?
5. Are there existing site templates or formats that the reports should match
   for ISSM or DCSA review?
