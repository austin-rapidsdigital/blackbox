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
3. Answer four questions. Press Enter to accept a default:

```
1. Site or system name, shown at the top of each report
   [none]: Lab 3

2. How often should a report be produced?
     1) Daily   (each report covers one day, ending at midnight)
     2) Weekly  (Monday 00:00 to Monday 00:00)
     3) Monthly (1st to 1st)
   Choose 1-3 [2]:

3. Where should reports be saved?
   Use a folder you have locked down if you like; Blackbox only needs to write to it.
   [C:\ProgramData\Blackbox\reports]: D:\AuditReports

4. How often should events be collected from the logs?
     1) Every hour        (recommended)
     2) Every 30 minutes
     3) Every 15 minutes  (for busy systems whose logs fill up within a few hours)
   Choose 1-3 [1]:

Summary
   Site name:        Lab 3
   Reports:          weekly, saved in D:\AuditReports
   Collect events:   every hour

Install these settings? (Y/n):
```

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
- checks the audit settings against the Windows 11 STIG and lists what is
  missing (it changes nothing)
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

## Audit settings

A report can only show what Windows records. To compare the system with
the STIG requirements that matter for the report, run:

```
blackbox.exe check
```

Each item that falls short is listed with the report section it affects
and the exact command or Group Policy setting that fixes it. Blackbox never
changes settings itself. The report's **Audit health** view shows the same
check.

The most important settings are:

- **Security log size:** at least 1 GB, as the STIG requires. The default
  is 20 MB, which a busy system fills in hours.
- **Command-line auditing for new processes.** Without it, elevated
  programs are listed by name only.
- **Removable Storage** and **Plug and Play** auditing, for USB file
  access and device details.

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
