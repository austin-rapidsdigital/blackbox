# Reports

## Collection and report periods

Blackbox **collects** every hour and **reports** on the schedule you
choose:

- **Collecting:** each run copies only the security-relevant events out of
  the logs and remembers where it stopped. Events are captured before a
  busy log overwrites them, and the copy stays small.
- **Reporting:**
  - The first report is produced at install time. Installing again (to
    upgrade or change settings) does not produce one, so the schedule is
    kept.
  - After that, each report ends at the time set by `report_at` (default
    `Wednesday 00:00`: a weekly report covers the week up to Tuesday night,
    ready for Wednesday morning). Daily reports end at that time each day,
    monthly ones on the 1st.
  - Each report starts where the previous one ended, so every event
    appears in exactly one report.
  - Events that happened earlier but were collected late, for example
    because the system was off, go into the next report marked **Late**.

To produce a report now, run `blackbox report`. This is an **interim**
report: it covers the time since the last scheduled report, is marked
*Interim* in the report and on the list of reports, and does not change the
schedule. The next scheduled report still covers its whole period. Interim
reports do not include the original logs; those go with the scheduled
report.

**A report for any period.** `blackbox report` run by hand asks which
period to cover: press Enter for the time since the last report, type a
number of days (`30`), a start date (`2026-09-01`), or a start and end date
(`2026-09-01 2026-09-15`). The same as options:

```
blackbox report --days 30
blackbox report --from 2026-09-01
blackbox report --from 2026-09-01 --to 2026-09-15
```

The events come from Blackbox's own copy, which reaches back to the oldest
events in each log when it was installed and is kept for
`retention_days` (for good by default). For any time before that copy
starts, Blackbox reads this computer's event logs (or Linux logs) as far
back as they still go. The report says what it covers and where the
earliest available event is. It is saved with `_range` in its folder name,
listed as Interim, and does not change the schedule. On a collector it
covers every system's collected events; only the collector's own logs can
be read further back.

If you change `report_at`, the next report ends at the new time and
covers the time since the last report (so it may be shorter or longer
than usual once).

## Severities

| Severity | Meaning | Examples |
|---|---|---|
| **High** | Review now | Log cleared, auditing stopped, user added to an admin group, audit tampering command, malware detected, USB device never seen before, USB network adapter |
| **Medium** | Review | Account created or deleted, password reset, USB storage connected, file written to USB, service installed, time changed, refused sudo command |
| **Low** | Routine but relevant | Single failed logon, sudo command, admin logon |
| **Info** | Context | Logons, logoffs, startup and shutdown |

Only High and Medium are flagged in the report: the event tables show
the severity for those and a dash for the rest. Every event is still
listed, whatever its severity.

## Detections

Detections are patterns across several events: steps that are ordinary on
their own but worth a look together, and things done for the first time.
They are worked out from events Blackbox already collects, so they add
nothing to what computers collect, store or send. They are also listed in
each report's `summary.json`.

| Detection | Severity | When |
|---|---|---|
| Possible password guessing | High | 5 or more failed logons for one account on one computer within 15 minutes |
| One source tried several accounts | High | Failures for 3 or more accounts from one address within 15 minutes |
| Same account failing on several computers | High | Failed logons for one account on 3 or more computers within 30 minutes (a collector sees every computer) |
| Possible covering of tracks | High | An account created, someone added to a privileged group, or sudo rules changed, then within 24 hours on the same computer a log cleared or altered, auditing stopped, an audit rule added or removed, or anti-malware turned off, by a person |
| Account created and deleted within a day | High | The same account created and deleted on one computer within 24 hours |
| Auditing was switched off | High | The audit service stopped by a person, with how long it stayed off |
| Successful logon after failures | Medium | 3 or more failures, then a success, within 30 minutes |
| New USB device, then administrator activity | Medium | Administrator rights used within 30 minutes of a USB device never seen before |
| Administrator activity outside working hours | Medium | Needs `working_hours` in the [settings](configuration.md); one detection per person, computer and day |
| First logon to this computer | Medium | A person logs on (at the computer, by Remote Desktop or SSH) to a computer they have not logged on to before |
| First use of administrator rights | Medium | A person uses administrator rights on a computer for the first time |
| First logon from this address | Medium | A logon to a computer from a network address not seen before |

**Across reports.** Each report also looks at the day before its period,
so a pattern that starts at the end of one report and finishes in the
next is still detected. It is reported once, in the report where it
finishes.

**First times.** Blackbox remembers who has logged on to each computer,
who has used administrator rights on it, and the addresses logons came
from. A computer's first report only learns this, and says so, so that
installing Blackbox does not flag everyone. Something not seen for a year
counts as new again. Service and computer accounts, and SYSTEM, are left
out.

## Original logs

Reports show what Blackbox found in the logs. The original logs are kept
too, for an assessor or an investigation, because the report's own event
lists and `events.zip` hold only the security-relevant events, translated.

Each report's folder holds the original logs it was made from, unaltered:
one zip per computer, `logs-COMPUTER.zip`, covering the report's period.

| Computer | What is in the zip | Open it with |
|---|---|---|
| Windows | `Security.evtx`, `System.evtx`, and the USB, Defender, device and PowerShell (`Microsoft-Windows-PowerShell-Operational.evtx`, every script block, not only the ones reported) logs, as `.evtx` files | Event Viewer (Open Saved Log), or `Get-WinEvent -Path` |
| Linux | `audit.log`: the audit records, in their original format | `ausearch -if audit.log`, or `aureport -if audit.log` |
| Linux | `syslog`/`messages` and `auth.log`/`secure`: the lines for the period (or `journal.log` from the systemd journal when there are no log files) | Any text editor |

Inside, there is a folder for each day, named for the time it covers (in
UTC), with that day's logs and an `archive.json` listing each file's
SHA-256. The zip's own SHA-256 is in the report's `manifest.sha256`, so
`blackbox verify` checks it with the rest of the report.

**How it works.** Once a day each computer saves its logs since the last
save, so nothing rolls over before the report is made. The first save
reaches back a week. When a report is made, the computer saves its logs up
to the end of the period, then the saved days go into the report's folder.
It works the same on a standalone computer and on a collector.

A computer that sends to a collector delivers its daily saves with its
events. The collector checks every file against its hash when it arrives;
a damaged or altered zip is set aside in the inbox's `rejected` folder. A
day's logs go into the report whose period its save ends in, so a
computer that was off catches up in the next report.

The **Original logs** page lists each computer's zip with its size and
SHA-256, checked against the hash recorded when the zip was made, and
shows what is inside each one. A computer with no logs for the period is
listed first, as Missing.
They are also listed in `summary.json`. The zips are removed with their
reports after `retention_days`.

Expect a few MB a day per Windows computer (much less for Linux),
compressed. It depends on how busy the Security log is.

## Is the audit trail complete?

The Overview flags a report as incomplete when:

- events were overwritten before collection, for example because the
  system was off longer than the log could hold
- a log was cleared
- auditing was switched off
- a Linux log was rotated away before it was read, or the kernel dropped
  audit records

The **Audit health** page shows every system against every STIG audit
check (logon, account management, policy change, privilege use, process
creation, removable storage, PowerShell logging, log size, reporting, logs
intact), the gaps with how to fix them, and each system's own settings
table. Blackbox only reports audit settings; it never changes them.
"How to fix" gives the Group Policy location and setting for each gap
(for example Computer Configuration > Policies > Windows Settings >
Security Settings > Advanced Audit Policy Configuration > Audit Policies >
Object Access > Audit Removable Storage).

The **Antivirus** column shows Microsoft Defender on each Windows system:
the security intelligence (definitions) version, the date that version was
created, and whether real-time protection is on. Definitions created more
than 7 days ago, or protection turned off, show as a gap. The Systems page
lists the version and its date for each system. It is read once a day with
`Get-MpComputerStatus`.

## Output files

Every report is a folder containing:

| File | |
|---|---|
| `report.html` | The report. Open it in any browser; it works offline |
| `data/` | The events the report's pages list, compressed, one file per page and day. `report.html` reads them only when a page needs them; keep them next to it |
| `logs-COMPUTER.zip` | The original logs, one per computer (see above) |
| `events.zip` | Every event as `events.csv`, for Excel. Double-click to open |
| `summary.json` | Counts and period, used by the report list |
| `manifest.sha256` | SHA-256 hash of each file |

To confirm a report has not been altered, run
`blackbox verify <report folder>`, or `sha256sum -c manifest.sha256`.
The report also checks each data file as it loads it: if one was changed,
**Verified** at the top of every page turns red.

**Large networks.** A report lists up to 2,000,000 events. Above that,
routine Info events (mostly logons) are counted and charted but not
listed, and the event pages say so; every High, Medium and Low event, and
every event a detection points to, is always listed. All of them are in
the original logs. Tables draw only the rows on screen, so a page with
hundreds of thousands of events still scrolls smoothly.

The folder of reports has an `index.html`: detections per week over the
last twelve reports, and each report with its week, systems, events,
detections and whether its audit trail is complete.
