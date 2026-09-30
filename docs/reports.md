# Reports

## Collection and report periods

Blackbox **collects** every hour and **reports** on the schedule you
choose:

- **Collecting:** each run copies only the security-relevant events out of
  the logs and remembers where it stopped. Events are captured before a
  busy log overwrites them, and the copy stays small.
- **Reporting:**
  - The first report is produced at install time.
  - After that, a daily report ends at midnight, a weekly one on Monday at
    00:00, and a monthly one on the 1st.
  - Each report starts where the previous one ended, so every event
    appears in exactly one report.
  - Events that happened earlier but were collected late, for example
    because the system was off, go into the next report marked **Late**.

To produce a report now, run `blackbox report`. Add `--preview` to leave
the schedule alone.

## Severities

| Severity | Meaning | Examples |
|---|---|---|
| **High** | Review now | Log cleared, auditing stopped, user added to an admin group, audit tampering command, malware detected, USB device never seen before, USB network adapter |
| **Medium** | Review | Account created or deleted, password reset, USB storage connected, file written to USB, service installed, time changed, refused sudo command |
| **Low** | Routine but relevant | Single failed logon, sudo command, admin logon |
| **Info** | Context | Logons, logoffs, startup and shutdown |

The Overview starts with **Detections**, then lists every high-severity
event under **Needs attention**, then counts the medium ones by type under
**Also review**.

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
too, for an assessor or an investigation, because the report's own
`events.csv` and `events.jsonl` hold only the security-relevant events,
translated.

Each report's folder holds the original logs it was made from, unaltered:
one zip per computer, `logs-COMPUTER.zip`, covering the report's period.

| Computer | What is in the zip | Open it with |
|---|---|---|
| Windows | `Security.evtx`, `System.evtx`, and the USB, Defender and device logs, as `.evtx` files | Event Viewer (Open Saved Log), or `Get-WinEvent -Path` |
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

The **Audit health** view lists each computer's zip with its period, size
and SHA-256, and warns about any computer with no logs for the period.
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

The **Audit health** view shows:

- every log read, and how much history each one holds
- the busiest event types, which point at noisy tools
- the STIG audit-setting check

## Output files

Every report is a folder containing:

| File | |
|---|---|
| `report.html` | The report: one self-contained file that opens offline in any browser |
| `events.csv` | Every event, for Excel |
| `events.jsonl` | Every event as JSON lines, for Splunk or other tools |
| `summary.json` | Counts and period, used by the report list |
| `manifest.sha256` | SHA-256 hash of each file |

To confirm a report has not been altered, run
`blackbox verify <report folder>`, or `sha256sum -c manifest.sha256`.
