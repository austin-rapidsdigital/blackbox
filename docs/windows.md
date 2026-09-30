# Windows guide

Supports Windows 11 and Windows Server 2025.

## Install

1. Download `blackbox-<version>-windows-amd64.zip` from
   [Releases](https://github.com/casea1/blackbox/releases/latest) and copy
   it to the system.
2. Unzip it and double-click **`Install.cmd`**, then approve the
   administrator prompt.
3. Enter a site name (optional) and how often you want reports: daily,
   weekly or monthly.

The installer then:

- copies `blackbox.exe` to `C:\Program Files\Blackbox\`
- creates `C:\ProgramData\Blackbox\`, readable only by Administrators and
  SYSTEM, which holds the settings, reports and collected events
- registers the scheduled task **Blackbox Audit Collection**, which runs as
  SYSTEM every hour and at startup, and catches up after the system has
  been off
- checks the audit settings against the Windows 11 STIG and lists what is
  missing (it changes nothing)
- collects events and produces the first report. The first run reads the
  whole Security log, so it can take a few minutes.

Running the installer again upgrades Blackbox and keeps your settings.

### Installing from the command line

From an administrator Command Prompt:

```
blackbox.exe install --site "Lab 3" --report-every daily --collect-every 30m
```

| Option | Default | Meaning |
|---|---|---|
| `--site` | *(blank)* | Name shown at the top of reports |
| `--report-every` | `weekly` | `daily`, `weekly` (periods end Monday 00:00) or `monthly` |
| `--collect-every` | `1h` | Use `30m` or `15m` on systems whose Security log fills in hours |
| `--no-first-report` | off | Skip the first report (it comes at the next scheduled run) |

## Where things are

| | |
|---|---|
| Program | `C:\Program Files\Blackbox\blackbox.exe` |
| Settings | `C:\ProgramData\Blackbox\blackbox.conf` ([reference](configuration.md)) |
| Reports | `C:\ProgramData\Blackbox\reports\` (open `index.html`) |
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

Double-click `Uninstall.cmd`, or run `blackbox.exe uninstall` as an
administrator. This removes the scheduled task. Reports and collected
events stay in `C:\ProgramData\Blackbox\`.
