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

The Overview lists every high-severity event and finding, then counts the
medium ones by type under **Also review**.

## Findings

Findings are patterns that span several events:

- **Possible password guessing:** 5 or more failed logons for one account
  within 15 minutes.
- **One source tried several accounts:** failures for 3 or more accounts
  from one address within 15 minutes.
- **Successful logon after failures:** 3 or more failures, then a success,
  within 30 minutes.
- **Auditing was switched off:** the audit service was stopped by a
  person, with how long it stayed off.

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
