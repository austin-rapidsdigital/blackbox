# Linux guide

Supports Ubuntu 22.04 and 24.04, and AlmaLinux 8.10.

## Install

```sh
tar xzf blackbox-<version>-linux-amd64.tar.gz     # or linux-arm64
cd blackbox-<version>-linux-amd64
sudo ./install.sh --site "Lab 3" --report-every weekly
```

The installer:

- copies `blackbox` to `/usr/local/bin/`
- creates `/var/lib/blackbox/` (root only) for reports and collected
  events, and `/etc/blackbox/blackbox.conf`
- installs and starts `blackbox.timer`, which runs every hour and catches
  up after the system has been off. The service it runs is sandboxed:
  - no network access
  - a read-only view of the system
  - it can write only to `/var/lib/blackbox`
- checks the audit configuration and produces the first report

The options are the same as on Windows: `--site`, `--report-every`
(`daily`, `weekly` or `monthly`), and `--collect-every`, which must divide
an hour or a day evenly, e.g. `15m`, `30m`, `1h` or `2h`.

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
| Reports | `/var/lib/blackbox/reports/` (open `index.html`) |
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
