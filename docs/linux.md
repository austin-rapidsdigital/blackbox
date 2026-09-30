# Linux guide

Supports Ubuntu 22.04 and 24.04, and AlmaLinux 8.10.

No other software is needed. Blackbox is a single self-contained program:
there is no Go or other runtime to install.

## Install

```sh
tar xzf blackbox-<version>-linux-amd64.tar.gz     # or linux-arm64
cd blackbox-<version>-linux-amd64
sudo ./install.sh
```

Setup asks how this computer's events will be reviewed, then only what
that needs. Each question has a default you can accept by pressing Enter:

- **On this computer:**
  - a site name
  - the report schedule (daily, weekly or monthly)
  - the report folder (any full path; an existing folder's permissions
    are left as they are)
  - how often to collect events
- **Send to a collector** (a VM, or a workstation on a LAN):
  - the collector's inbox. A VirtualBox shared folder is found
    automatically; for a Windows share, setup asks for an account.
  - how often to collect events

  See [Several computers](lan.md).

Each answer is checked as you give it. See the
[Windows guide](windows.md#install) for what the questions look like.

Setup then:

- copies `blackbox` to `/usr/local/bin/`
- creates `/var/lib/blackbox/` (root only) for reports and collected
  events, and `/etc/blackbox/blackbox.conf`
- installs and starts `blackbox.timer`, which runs every hour and catches
  up after the system has been off. The service it runs is sandboxed:
  - no network access
  - a read-only view of the system
  - it can write only to `/var/lib/blackbox`, the report folder and, on a
    LAN, the folders it sends to and receives in
- checks the audit configuration and produces the first report

## Changing settings later

**Run `sudo ./install.sh` again.** It shows the current settings as the
defaults. Or change one setting:

```sh
sudo blackbox config                                  # show the current settings
sudo blackbox config set report_dir /srv/audit-reports
```

Moving the report folder also updates the service sandbox, so the
scheduled job is allowed to write there. New reports go to the new folder;
existing reports are not moved.

A report folder on NFS or CIFS works if the system mounts it (through
`/etc/fstab` or autofs). Blackbox itself has no network access.

**Unattended installs** (Ansible, scripts) use the same options as on
Windows:

```sh
sudo ./install.sh --yes --site "Lab 3" --report-dir /srv/audit-reports
```

The options are `--yes`, `--site`, `--report-every`, `--report-dir`,
`--collect-every` (which must divide an hour or a day evenly, e.g. `15m`,
`30m`, `1h`) and `--no-first-report`.

## Set up auditd

auditd records logons, sudo, account changes and audit integrity. The STIG
requires it, but **Ubuntu does not install it by default**. Without it,
Blackbox falls back to `auth.log`/`secure`, which records less.

Blackbox includes a rules file that covers everything the report needs:

```sh
sudo apt install auditd                 # Ubuntu (AlmaLinux: sudo dnf install audit)
sudo blackbox check --audit-rules | sudo tee /etc/audit/rules.d/99-blackbox.rules
sudo augenrules --load
sudo blackbox check                     # lists anything still missing
```

Review the rules against your site's STIG checklist before using them. The
last rule (`-e 2`) locks the rules until the next reboot, as the STIG
requires.

`blackbox check` also looks for:

- `audit=1` on the kernel command line
- the ENRICHED log format, which records names instead of user ID numbers
- a large enough audit backlog
- a system log that survives reboots

## Where things are

| | |
|---|---|
| Program | `/usr/local/bin/blackbox` |
| Settings | `/etc/blackbox/blackbox.conf` ([reference](configuration.md)) |
| Reports | `/var/lib/blackbox/reports/` by default, or the folder you chose (open `index.html`) |
| Schedule | `systemctl list-timers blackbox.timer` |
| Log of each run | `journalctl -u blackbox.service` |

## What Blackbox reads

| Log | Used for |
|---|---|
| `/var/log/audit/audit.log` | Logons, failed logons and lockouts, sudo and su, root shells, account and group changes, sudoers and `/etc/passwd` edits, auditd stopped, audit rules changed, time changes, kernel modules, AppArmor/SELinux |
| `/var/log/syslog` (Ubuntu), `/var/log/messages` (Alma), or the systemd journal | USB devices from kernel messages (make, model, serial, size, USB network adapters), and who mounted them (udisks) |
| `/var/log/auth.log` (Ubuntu), `/var/log/secure` (Alma) | Only when auditd is not installed: logons, sudo, su and account changes |

Each file is read from where the last run stopped. Blackbox follows log
rotation, and the report says if anything was rotated away, or dropped by
the kernel, before it could be read.

## Reporting on copied logs

Copy the logs off the system, then produce a report on any OS. Rotated
copies and `.gz` files work too:

```sh
blackbox report --audit audit.log --audit audit.log.1 --syslog syslog --passwd passwd
```

`--passwd` is optional. It turns user ID numbers into names when the audit
log is not in ENRICHED format. Use `--host NAME` if the logs don't include
the host name.

## Uninstall

```sh
sudo ./uninstall.sh          # or: sudo blackbox uninstall
```

This removes the timer. Reports and collected events stay in
`/var/lib/blackbox/`.
