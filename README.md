# Blackbox

Audit log review for air-gapped Windows systems and small air-gapped LANs.
Linux support (Ubuntu 22.04/24.04, AlmaLinux 8.10) is the next milestone.

Blackbox reads the Windows event logs, **translates each event into plain
English**, groups the events the way auditors review them, and produces a
single HTML report on a schedule. The report opens in any browser and needs
no server. It flags what needs attention and tells you whether the audit
trail is complete.

| Raw event (what other tools show) | Blackbox |
|---|---|
| `4625 · 0xC000006D · 0xC000006A · LogonType 3 · 10.1.1.99` | Failed logon for administrator over the network from 10.1.1.99 — wrong password. |
| `4732 · S-1-5-21-…-1005 · S-1-5-32-544` | admin_jd added tempuser to the privileged group Administrators. |
| `1006 · BusType 7 · Capacity 15634268160 · USB\VID_0781&PID_5567\4C53…` | USB storage connected: SanDisk Cruzer Blade (serial 4C530001231109115405), 15.6 GB. |
| `4719 · %%8274 · {0cce9245-…} · %%8448, %%8450` | Audit policy for "Removable Storage" was changed by admin_jd: success auditing removed, failure auditing removed. |

## Screenshots

These come from the synthetic sample in `testdata/sample-events.xml`, a
made-up workstation day. Regenerate them with `scripts/screenshots.sh`.

**Overview:** the reporting period, whether collection was complete, and
what needs attention.
![Overview](docs/screenshots/overview.png)

**Failed Logons & Lockouts,** with one event expanded to show its decoded
details.
![Failed logons](docs/screenshots/failed-logons.png)

**USB & Removable Media**
![USB and removable media](docs/screenshots/usb.png)

**Privileged Activity**
![Privileged activity](docs/screenshots/privileged.png)

**Audit health:** the logs read, events lost, and the busiest event types.
![Audit health](docs/screenshots/health.png)

## What a report contains

Each report is one self-contained file, `report.html`, laid out for a
desktop monitor. A sidebar switches between the views below, all inside the
same file.

- **Overview.** It starts with the reporting period (from, to and length),
  then shows whether collection was complete, event counts by category, and
  "Needs attention." High-severity events are listed one by one. Patterns across events are also flagged: possible password guessing,
  one source trying several accounts, and a successful logon after repeated
  failures. Medium-severity items are counted by type.
- **Audit health.**
  - Were any events lost to log rollover?
  - Was a log cleared?
  - How much history does each log hold?
  - Which event types are flooding the log?
  - Is auditing configured as the DISA STIG requires? Where it isn't, the
    report says which report section is incomplete as a result and gives
    the exact command that fixes it.
- **Sections, in auditor priority order**, each tagged with the NIST SP
  800-53 controls it supports:
  - **Privileged Activity:** administrator logons, programs run as
    administrator (with full command lines), RunAs, and commands that can
    clear logs or weaken auditing.
  - **USB & Removable Media:**
    - devices connected and disconnected, with make, model, serial number
      and size, and flagged the first time a device is seen
    - files written to, read from or deleted on removable media
    - blocked access attempts
    - mounted ISO/VHD files
  - **Failed Logons & Lockouts,** with the reason decoded.
  - **Account & Group Changes,** with additions to privileged groups
    flagged high.
  - **Audit & System Integrity:** logs cleared, audit policy changes,
    system time changes, startups and shutdowns.
  - **Other Security Events:** new services and scheduled tasks, and
    Microsoft Defender detections or protection being turned off.
  - **Logon Activity:** who logged on, how and from where. Service and
    computer accounts are left out.
- **People.** Everything in the report counted per account. Click an
  account to filter the whole report to that person.

Every report folder also contains:


- `events.csv`: opens in Excel
- `events.jsonl`: ready for Splunk
- `summary.json`
- `manifest.sha256`: SHA-256 hashes of all the files above

## Why hourly collection matters

Busy Windows systems can overwrite their Security log in less than a day.
Blackbox therefore **collects every hour** but **reports daily, weekly or
monthly**. Each collection copies only the security-relevant events and
remembers where it stopped (a bookmark), so events are captured before they
roll over. The copy stays small even when a noisy tool generates millions
of events.

If events are ever lost anyway, because the system was off longer than the
log could hold or because a log was cleared, the report says so, with how
many events were lost and between which times. You can report weekly
without losing anything.

## Install (Windows 11 / Server 2025)

Copy `blackbox.exe` onto the system. Then, in an **elevated** Command
Prompt or PowerShell:

```
blackbox.exe install --site "Lab 3" --report-every weekly
```

That's all. `install`:

1. Copies itself to `C:\Program Files\Blackbox\`.
2. Creates `C:\ProgramData\Blackbox\` for the config, reports and collected
   data. Only Administrators and SYSTEM can open it.
3. Writes a commented `blackbox.conf`.
4. Registers the scheduled task **Blackbox Audit Collection**. The task runs
   as SYSTEM every hour and at startup, and catches up after the system has
   been off.
5. Checks the audit settings against the STIG and prints what is missing.
   It changes nothing.
6. Collects and produces the first report straight away.

Reports are in `C:\ProgramData\Blackbox\reports\`. Open `index.html` there
for a list of all reports.

Install options:

| Option | Default | |
|---|---|---|
| `--site` | *(blank)* | Name shown at the top of reports |
| `--report-every` | `weekly` | `daily`, `weekly` (periods end Monday 00:00) or `monthly` |
| `--collect-every` | `1h` | Use `30m` or `15m` on very busy systems |

Running `install` again upgrades the program and keeps your settings.
`blackbox uninstall` removes the scheduled task and keeps all reports.

## Commands

```
blackbox install [options]     Set up scheduled collection and reporting
blackbox run                   What the schedule runs: collect, and report if one is due
blackbox report                Collect and produce a report now (--preview leaves the schedule alone)
blackbox report --xml FILE     Report on exported event logs (works on any OS)
blackbox check [--all]         Compare audit settings with the DISA STIG (report only)
blackbox verify FOLDER         Confirm a report has not been altered (exit code 1 if it has)
blackbox uninstall             Remove the scheduled task, keep reports
```

### Try it without installing

Export some events on any Windows machine, then produce a report from the
file. This works on any OS, including an unclassified test laptop:

```
wevtutil qe Security /f:xml /c:20000 > security.xml
wevtutil qe System /f:xml /c:5000 > system.xml
blackbox report --xml security.xml --xml system.xml
```

The repository includes a synthetic sample:

```
blackbox report --xml testdata/sample-events.xml
```

## Security properties (for your security review)

- **Standard library only.** No third-party code: the Go module has zero
  dependencies. It builds offline with `scripts/build.sh` into a single
  static binary per platform, with SHA-256 checksums.
- **Read-only.** Blackbox reads logs and never modifies, clears or
  forwards them. `check` reports settings and never changes them.
- **No network activity.** Blackbox listens on no ports and makes no
  outbound connections.
- **Runs as SYSTEM** only because reading the Security log requires it. Its
  data folder is restricted to Administrators and SYSTEM.
- **Tamper evidence.** Every report has a SHA-256 manifest, which
  `blackbox verify` (or `sha256sum -c manifest.sha256`) checks.
- **Retention.** Reports and collected data are kept forever by default.
  Set `retention_days` to prune them.

## Building

```
go test ./...
VERSION=0.1.0 scripts/build.sh   # → dist/blackbox.exe, dist/blackbox-linux-*, dist/SHA256SUMS
```

Requires Go 1.24 or later. Design notes and the roadmap are in
[docs/DESIGN.md](docs/DESIGN.md).
