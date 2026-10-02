# Windows guide

Supports Windows 11 and Windows Server 2025.

No other software is needed. Blackbox is a single self-contained program:
there is no .NET, Go or other runtime to install.

## Install

1. Download `Blackbox-Setup-<version>.exe` from
   [Releases](https://github.com/casea1/blackbox/releases/latest) and copy
   that one file to the system.
2. Double-click it and approve the administrator prompt.
3. Answer the questions in the setup window. Each page shows a default you
   can keep by clicking **Next**. For a single computer the pages are:

| Page | Asks |
|---|---|
| This computer | How will this computer's audit events be reviewed? On this computer, send to a collector, or this is the collector |
| Reports | Site name; daily, weekly or monthly; when each report is ready (default Wednesday 00:00); where reports are saved, with **Browse…** |
| Collection | How often events are collected (every hour is recommended), and whether to show the status icon to administrators |
| Ready to install | A summary of your answers, and **Install** |

The last page shows each step as it happens: the install, the audit
settings check, then the first report. When it is done, **Open report**
opens it.

The window asks exactly the same questions as `blackbox install` at a
command prompt, which still works and is what scripts use:

```
Blackbox-Setup-<version>.exe install --yes --site "Lab 3" --report-dir D:\AuditReports
```

(From cmd.exe, put `start /wait` in front so the prompt waits for it.)

For a PC with Linux VMs, or a LAN, see [Several computers](lan.md): the
other choices ask where the inbox is, or where to send.

Each answer is checked as you give it. A report folder must be a full path
that Blackbox can write to:

- **If the folder already exists,** its permissions are left exactly as
  they are.
- **If it doesn't exist,** Blackbox offers to create it, restricted to
  Administrators and SYSTEM.

Setup then:

- copies `blackbox.exe` (the command-line program) and `blackboxw.exe`
  (the same program for the setup window and the status icon, which opens
  no console) to `C:\Program Files\Blackbox\`
- creates `C:\ProgramData\Blackbox\`, readable only by Administrators and
  SYSTEM, which holds the settings, reports and collected events
- registers the scheduled task **Blackbox Audit Collection**, which runs as
  SYSTEM every hour and at startup, and catches up after the system has
  been off
- adds **Blackbox** to Settings → Apps (and Programs and Features), with
  its version, so it can be inventoried and uninstalled like any other
  program
- on a collector or standalone computer, registers **Blackbox Status**,
  which shows the [status icon](#status-icon) to administrators
- checks the audit settings against the DISA STIG (Windows 11 or Windows
  Server 2025, whichever the computer is) and lists what is missing (it
  changes nothing)
- collects events and produces the first report. The first run reads the
  whole Security log, so it can take a few minutes.

## Changing settings later

Open **Settings → Apps**, find **Blackbox** and choose **Modify**, or pick
**Change settings…** on the status icon. The setup window opens with your
current settings filled in, so change only what you need.

**To upgrade,** double-click the newer `Blackbox-Setup-<version>.exe`. It
says which version is installed, keeps your settings, and doesn't move
the report schedule. A collection running at that moment, or an open
status icon, doesn't block it. Setup then checks the new program starts,
and puts the previous one back if it doesn't.

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

## Status icon

On a collector or standalone computer, members of **Administrators** see a
Blackbox icon by the clock when they log on. It is started by the
scheduled task **Blackbox Status**, with full rights, so there is no UAC
prompt. Untick the box on the Collection page of setup to turn it off.

| Dot | Means |
|---|---|
| Green | Collecting on schedule; nothing needs attention |
| Amber | Something to look at: audit settings to fix, Defender intelligence out of date, a computer that has stopped sending, or files set aside in the inbox |
| Red | Collection has stopped (no run for twice the interval plus 15 minutes), or the last run failed |
| Grey (no dot) | The status can't be read |

Click it for the menu:
- the status, and anything to look at;
- **Open latest report** and **Open all reports**;
- **Make an interim report…**, for a chosen period (the schedule doesn't change);
- **Collect now**;
- **Status details…**, the same as `blackbox status`;
- **Change settings…**;
- **Close this icon**.

It shows a notification when a scheduled report is ready, when collection
stops, when a computer stops sending, when audit settings stop matching
the STIG, and after an upgrade. Each is shown once.

Reports open in your normal browser without administrator rights. The
default reports folder is readable only by administrators with full
rights. If your account can't open it, the icon asks before giving your
account read access to that folder. This is the same as Explorer's
**Continue** button.

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

Use **Settings → Apps → Blackbox → Uninstall**, or run
`"C:\Program Files\Blackbox\blackbox.exe" uninstall` as an administrator.
This removes the scheduled tasks, the status icon, the program and the
Apps entry. Reports, settings and collected events are kept.
