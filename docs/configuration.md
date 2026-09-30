# Configuration

The settings file is `C:\ProgramData\Blackbox\blackbox.conf` on Windows
and `/etc/blackbox/blackbox.conf` on Linux. It is a plain `key = value`
file:

- lines starting with `#` are comments
- lists are comma-separated
- changes take effect at the next scheduled run

| Setting | Default | Meaning |
|---|---|---|
| `site_name` | *(blank)* | Name shown at the top of reports |
| `report_every` | `weekly` | `daily`, `weekly` or `monthly` |
| `retention_days` | `0` | Days to keep reports and collected events; `0` keeps them forever |
| `exclude_users` | *(none)* | Accounts to leave out of reports, e.g. `svc_backup, svc_scanner` |
| `exclude_processes` | *(none)* | Programs to leave out, by name or full path, e.g. `scan.exe` |
| `data_dir` | platform default | Where reports and collected events are stored |

How often events are collected is set when you install (`--collect-every`),
because it is part of the schedule.
