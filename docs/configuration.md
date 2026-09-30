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
| `report_dir` | *(blank = default)* | Folder for reports. Any full path Blackbox can write to, including one you have locked down |
| `collect_every` | `1h` | How often events are collected. To change it, run the installer again, which updates the schedule |
| `retention_days` | `0` | Days to keep reports and collected events; `0` keeps them forever |
| `exclude_users` | *(none)* | Accounts to leave out of reports, e.g. `svc_backup, svc_scanner` |
| `exclude_processes` | *(none)* | Programs to leave out, by name or full path, e.g. `scan.exe` |
| `data_dir` | platform default | Where reports and collected events are stored |

The easiest way to change settings is to run the installer again: it shows
the current values as defaults. To change one setting from a script:

```
blackbox config set report_dir D:\AuditReports
blackbox config set report_every daily
```

`blackbox config set` checks the value before saving it. For `report_dir`,
it also checks the folder is writable, and on Linux lets the service write
there. Run `blackbox config` to see the current settings.
