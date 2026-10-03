# Linux guide

Supports Ubuntu 22.04 and 24.04, and AlmaLinux 8.10.

**Ubuntu 26.04 is not supported yet.** Blackbox already handles what
changes there: OpenSSH 10's `sshd-session` and `sshd-auth`, the GNU
tools renamed `gnurm`, `gnucp` and so on (shown by their usual names),
and sudo-rs, which writes no audit record of the commands it runs
(`blackbox check` flags it, and Blackbox reads sudo's journal lines
instead). It is not yet tested on 26.04 in CI, so use it there at your
own risk until it is listed here.

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

What the rules record, beyond logons and sudo (each is a report row):

| Rules (key) | In the report |
|---|---|
| `perm_access` (EACCES and EPERM) | A person refused access to a file (Medium) |
| `perm_mod` (chmod, chown, setxattr) | Permission and owner changes: setuid or setgid set High, files under `/etc`, `/usr`, `/var/log` and other system folders Medium, the rest Low; `setcap` High |
| `delete` | Files deleted or renamed by a person (Low; system folders Medium), one row per folder |
| `logon_config` | Changes to PAM and `/etc/security` (High), `sshd_config` and the login message scripts (Medium) |
| `scheduled_jobs`, `systemd_units` | Cron jobs and systemd services or timers created or changed (Medium) |
| `blackbox` | Changes to Blackbox's settings, data, program or timer by anything other than Blackbox (High) |
| `privileged-*`, `modules`, `perm_chng` | The STIG's privileged programs, `kmod`, `setfacl`, `chacl` |
| `session`, `logins` | utmp, wtmp, btmp, lastlog and faillock |

Files written by the package manager (`dpkg`, `rpm`, `dnf`, `apt`) are
not listed: the `sudo apt …` command that ran it is. Any other keyed rule,
including your site's own, is still a row: "jsmith: the audit rule
"my_rule" recorded openat on /srv/plan.txt".

Files and folders are watched with `-a always,exit -F path=` (or `dir=`)
rules, not `-w`, as the current STIGs write them. `--missing` treats the
two as the same rule, so a baseline loaded with `-w` is not duplicated.

**Watching Blackbox itself (AU-9).** Besides the `blackbox` rules above,
commands that change Blackbox are reported High whoever runs them:
`blackbox config set` for `exclude_users`, `exclude_processes`,
`retention_days`, `report_dir`, `send_to` or `inbox` (other settings
Medium), `systemctl stop`, `disable` or `mask` of `blackbox.timer`,
`blackbox uninstall`, and deleting Blackbox's files.

**On a STIG-hardened system** (for example, one built with Ubuntu's USG
or an Ansible STIG role), most of these rules are already loaded under
other key names. Install only the ones that are missing, so nothing is
recorded twice:

```sh
sudo blackbox check --audit-rules --missing | sudo install -m 0600 /dev/stdin /etc/audit/rules.d/99-blackbox.rules
sudo augenrules --load
```

`--missing` compares against the rules actually loaded (`auditctl -l`),
ignores key names, and leaves out watches on files that do not exist. If
the loaded rules are locked (`-e 2`), the new ones take effect at the next
reboot, and `blackbox check` says so.

> **Ubuntu USG (`usg fix`) writes `/etc/audit/audit.rules` directly.**
> `augenrules` rebuilds that file from `rules.d`, so adding any file to
> `rules.d` would drop the STIG rules at the next `augenrules --load` or
> reboot. `--missing` warns when this applies. Keep the existing rules
> first:
>
> ```sh
> sudo install -m 0600 /etc/audit/audit.rules /etc/audit/rules.d/50-existing.rules
> ```

`blackbox check` also looks for:

- `audit=1` and `audit_backlog_limit=8192` on the kernel command line.
  If they are in GRUB's settings but the running kernel doesn't have
  them yet, it says "takes effect at the next boot".
- the ENRICHED log format, which records names instead of user ID numbers
- a large enough audit backlog
- what auditd does as its disk fills (`auditd.conf`): `space_left_action`
  must tell someone (email, exec or syslog), `admin_space_left_action`
  single or halt, and `disk_full_action` and `disk_error_action` anything
  but SUSPEND or IGNORE, which stop recording without anyone knowing;
  `action_mail_acct` set
- the audit log readable only by root (log 0600 or 0640, folder 0750)
- time synchronisation: chrony or systemd-timesyncd running (AU-8)
- sudo-rs, which records no audit events of sudo commands
- ClamAV, when installed: definitions built within the last 30 days, and
  its scanner service running (as Defender is checked on Windows)
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
