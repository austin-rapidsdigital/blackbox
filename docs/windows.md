# Windows guide

Supports Windows 11 and Windows Server 2025.

No other software is needed. Blackbox is a single self-contained program:
there is no .NET, Go or other runtime to install.

## Install

1. Download `blackbox-<version>-windows-amd64.zip` from
   [Releases](https://github.com/casea1/blackbox/releases/latest) and copy
   it to the system.
2. Extract it and double-click **`Install.cmd`**, then approve the
   administrator prompt.
3. Answer the questions. Press Enter to accept a default. For a single
   computer:

```
1. How will this computer's audit events be reviewed?
     1) On this computer            (it produces its own reports)
     2) Send to a collector         (for a virtual machine, or a workstation on a LAN)
     3) This is the collector       (its reports cover it and every computer that sends to it)
   Choose 1-3 [1]:

2. Site or system name, shown at the top of each report
   [none]: Lab 3

3. How often should a report be produced?
     1) Daily
     2) Weekly
     3) Monthly (each period ends on the 1st)
   Choose 1-3 [2]:

4. Which day and time should each weekly report be ready?
   The week ends then. "Wednesday 00:00" covers the week up to Tuesday night,
   so auditors have a fresh report on Wednesday morning.
   [Wednesday 00:00]:

5. Where should reports be saved?
   Use a folder you have locked down if you like; Blackbox only needs to write to it.
   [C:\ProgramData\Blackbox\reports]: D:\AuditReports

6. How often should events be collected from the logs?
     1) Every hour        (recommended)
     2) Every 30 minutes
     3) Every 15 minutes  (for busy systems whose logs fill up within a few hours)
   Choose 1-3 [1]:

Summary
   This computer:    standalone: reports on itself
   Site name:        Lab 3
   Reports:          weekly, ready Wednesday 00:00 (each covers the week to Tuesday night)
   Saved in:         D:\AuditReports
   Collect events:   every hour

Install these settings? (Y/n):
```

For a PC with Linux VMs, or a LAN, see [Several computers](lan.md): the
other choices ask where the inbox is, or where to send.

Each answer is checked as you give it. A report folder must be a full path
that Blackbox can write to:

- **If the folder already exists,** its permissions are left exactly as
  they are.
- **If it doesn't exist,** Blackbox offers to create it, restricted to
  Administrators and SYSTEM.

Setup then:

- copies `blackbox.exe` to `C:\Program Files\Blackbox\`
- creates `C:\ProgramData\Blackbox\`, readable only by Administrators and
  SYSTEM, which holds the settings, reports and collected events
- registers the scheduled task **Blackbox Audit Collection**, which runs as
  SYSTEM every hour and at startup, and catches up after the system has
  been off
- adds **Blackbox** to Settings → Apps (and Programs and Features), with
  its version, so it can be inventoried and uninstalled like any other
  program
- checks the audit settings against the DISA STIG (Windows 11 or Windows
  Server 2025, whichever the computer is) and lists what is missing (it
  changes nothing)
- collects events and produces the first report. The first run reads the
  whole Security log, so it can take a few minutes.

## Changing settings later

**Double-click `Install.cmd` again.** It shows the current settings as the
defaults, so press Enter through everything except what you want to
change. Running a newer version's `Install.cmd` the same way upgrades
Blackbox and keeps your settings.

To change a single setting from a script, use `blackbox config`:

```
blackbox config                                   (show the current settings)
blackbox config set report_dir D:\AuditReports    (checks the folder first)
blackbox config set report_every daily
```

New reports go to the new folder. Existing reports are not moved.

### Unattended installs (SCCM, Intune, GPO scripts)

Options skip the questions. Any setting not given keeps its current value,
or the default on a first install:

```
blackbox.exe install --yes --site "Lab 3" --report-dir D:\AuditReports
```

| Option | Meaning |
|---|---|
| `--yes` | Don't ask questions |
| `--site` | Name shown at the top of reports (`-` clears it) |
| `--report-every` | `daily`, `weekly` or `monthly` |
| `--report-dir` | Folder for reports (`default` for the standard location) |
| `--collect-every` | `1h`, `30m` or `15m` |
| `--no-first-report` | Skip the first report; it comes at the next scheduled run |

**Report folder on a network share:** the scheduled task runs as SYSTEM,
which reaches network shares as the computer account (`DOMAIN\COMPUTER$`).
Grant that account write access to the share and folder. On a workgroup
system with no domain, use a local folder.

## Where things are

| | |
|---|---|
| Program | `C:\Program Files\Blackbox\blackbox.exe` |
| Settings | `C:\ProgramData\Blackbox\blackbox.conf` ([reference](configuration.md)) |
| Reports | `C:\ProgramData\Blackbox\reports\` by default, or the folder you chose (open `index.html`) |
| Log of each run | `C:\ProgramData\Blackbox\blackbox.log` |

## What Blackbox reads

| Event log | Used for |
|---|---|
| Security | Logons, failed logons, lockouts, admin logons, elevated programs, account and group changes, audit policy changes, log cleared, removable storage file access |
| System | Services installed, startup and shutdown, other logs cleared |
| Microsoft-Windows-Partition/Diagnostic | USB storage make, model, serial and size (on by default) |
| Microsoft-Windows-Kernel-PnP/Configuration | First-time USB device setup |
| Microsoft-Windows-DriverFrameworks-UserMode/Operational | Extra USB detail (optional, off by default) |
| Microsoft-Windows-Windows Defender/Operational | Malware detections, protection turned off |
| Microsoft-Windows-PowerShell/Operational | Suspicious PowerShell scripts: clearing logs or weakening auditing, turning off Defender, downloading and running code, password-stealing tools, malware-scanning (AMSI) bypasses |

PowerShell records every script it runs (event 4104, Script Block
Logging), which on a managed computer is thousands a day. Blackbox reports
only the suspicious ones: those matching the list above (High), and those
PowerShell itself flags as suspicious (Medium), with the script's name or
path and the word that got it flagged. Commands Windows generates for its
own modules (for example Defender's `MSFT_MpScan`, which PowerShell flags
because of words like "Scan") are not reported. The rest are counted but
not listed, and stay in the original log saved with each report. A large
script is recorded in several parts; matching parts of one script are
shown as one row. Windows PowerShell 5.1 is read; PowerShell 7 writes to a
separate log that Blackbox does not read yet.

Script Block Logging must be turned on by Group Policy: Administrative
Templates > Windows Components > Windows PowerShell > Turn on PowerShell
Script Block Logging (STIG WN11-CC-000326 on Windows 11, WN25-CC-000460 on
Server 2025; `blackbox.exe check` shows whether it is on). Without it,
only the scripts PowerShell flags itself are recorded.

## Audit settings

A report can only show what Windows records. To compare the system with
the STIG, run:

```
blackbox.exe check
```

Blackbox picks the STIG from the kind of Windows:

| Computer | Compared with |
|---|---|
| Windows 11 (workstations) | Windows 11 STIG V2R8 (audit rules unchanged through V2R10, September 2026) |
| Windows Server (any version) | Windows Server 2025 STIG V1R1 |

Each setting shows its STIG rule ID (for example `WN11-AU-000505`). Each
item that falls short is listed with the report section it affects and the
exact command or Group Policy setting that fixes it. Blackbox never changes
settings itself. The report's **Audit health** view shows the same check,
and which STIG it used.

What is checked:

- **Advanced audit policy**: every subcategory the STIG requires, with
  success and/or failure exactly as the STIG says. This includes the 2026
  additions: File System, Handle Manipulation and Registry (success and
  failure), and Process Creation failures (Windows 11).
- **Security log size**:
  - Windows 11 (WN11-AU-000505): it must hold **at least a week** of
    events. Blackbox measures this: from the oldest event when the log is
    full, or from how fast it is filling when it is not (once it has a day
    of events). If it falls short, the fix shows a size that would hold a
    week. DISA's example size is 5,120,000 KB (about 5 GB).
  - Windows Server 2025 (WN25-CC-000280): at least 196,608 KB.
- **System and Application log sizes**: at least 32,768 KB.
- **Command line in process creation events.** Without it, elevated
  programs are listed by name only.
- **Audit: Force audit policy subcategory settings.** Without it, the
  advanced audit policy can be ignored.
- **PowerShell script block logging**, and on Windows 11 **PowerShell
  transcription**.
- **USB logs** (Partition/Diagnostic and Kernel-PnP/Configuration),
  which the report needs for device details, and the **PowerShell log**
  (on by default; shown for information, never as a failure). These are
  not STIG rules.

On a server, Other Logon/Logoff Events auditing is not a STIG rule, but
the report needs it for Remote Desktop sessions. It is listed as
recommended, not as a failure.

The File System, Handle Manipulation and Registry rules record far more
events where files and keys have auditing (SACLs) set. That is why the STIG
asks for a much larger Security log. Blackbox reads these events but
reports only what matters, so the report itself does not grow much.

## Reporting on exported logs

Export events on any Windows machine, then produce a report on any OS:

```
wevtutil qe Security /f:xml /c:20000 > security.xml
wevtutil qe System /f:xml /c:5000 > system.xml
blackbox report --xml security.xml --xml system.xml
```

On Windows, saved `.evtx` files work too: `blackbox report --evtx Security.evtx`.

## Uninstall

Use **Settings → Apps → Blackbox → Uninstall**, or double-click
`Uninstall.cmd`. This removes the scheduled task, the program and the Apps
entry. Reports, settings and collected events are kept.
