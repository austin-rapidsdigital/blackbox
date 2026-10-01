import os
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'lan3.py')).read().replace('\nl1c()', ''))

C4 = '''
.ck{display:grid;grid-template-columns:28px 190px 1fr auto;gap:12px;align-items:center;padding:12px 4px;border-bottom:1px solid rgba(0,30,98,.07)}
.ck:last-child{border-bottom:0}
.ck .i{width:24px;height:24px;display:grid;place-items:center}
.ck.ok .i{color:#1A9A50;background:#E6F5EC}.ck.bad .i{color:#D12C2C;background:#FDECEC}.ck.warn .i{color:#A35A00;background:#FDF3E1}
.ck b{font-weight:600;font-size:13.5px}.ck .w{font-size:13px;color:#3A4766}.ck.ok .w{color:#5A6785}
.ck.bad .w b{color:#B01C1C}.ck.warn .w b{color:#8F4F00}.ck .w b{font-weight:650}
.ck .r{font:12px SCP;color:#5A6785}
.map{display:grid;grid-template-columns:repeat(7,1fr);gap:6px}
.m{border:1px solid rgba(0,30,98,.1);background:rgba(255,255,255,.75);padding:8px 9px;font-size:12.5px;font-weight:600;color:#3A4766;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.m small{display:block;font:500 10.5px PS;color:#8A96B3;letter-spacing:.04em}
.m.bad{background:#D12C2C;border-color:#D12C2C;color:#fff}.m.bad small{color:rgba(255,255,255,.8)}
.m.warn{background:#FDF3E1;border-color:#E9B35C;color:#7A4300}.m.warn small{color:#A35A00}
.m.mvm{border-style:dashed}
.mgrp{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;margin:14px 0 7px}.mgrp:first-of-type{margin-top:0}
.call{display:grid;gap:0;margin-top:16px;border-top:1px solid rgba(0,30,98,.1)}
.call div{display:grid;grid-template-columns:90px 1fr;gap:12px;padding:9px 0;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px}
.call div b{font-weight:650}.call .bad b{color:#B01C1C}.call .warn b{color:#8F4F00}.call span{color:#3A4766}
'''

def shell(name, systems_panel):
    det = [("high", "Possible covering of tracks", "WS-07", "28 Sep 09:20"), ("high", "Possible password guessing", "WS-07", "28 Sep 06:02"),
           ("high", "Same account failing on several computers", "6 systems", "26 Sep 22:14"), ("high", "New member of Domain Admins", "SRV-DC01", "25 Sep 11:02"),
           ("medium", "Suspicious PowerShell", "WS-09", "22 Sep 15:47")]
    dh = ''.join(f'<tr><td><span class="sv {s}">{"High" if s == "high" else "Med"}</span></td><td><b>{t}</b><span class="mono">{h} · {w}</span></td></tr>' for s, t, h, w in det)
    body = aside("Overview") + f'''<main>{head("Network overview", "Weekly report · 24 systems · collector SRV-DC01 · generated 29 Sep 2026 00:05")}
{ALERT}
<div class="kpis">{kpi("Systems reporting", "23 / 24", "WS-09 silent 6 days", [24,24,24,24,23,23,23,23,24,24,24,23], True)}
{kpi("Detections", "9", "on 6 systems", [3,5,2,4,6,3,2,5,7,4,5,9], True)}
{kpi("Events collected", "84.2k", "+3% vs. avg", [80,82,79,85,83,81,84,86,82,83,81,84])}
{kpi("Privileged actions", "3,912", "by 11 people", [3700,3810,3650,3990,3880,3900,3770,3950,3820,3890,3860,3912])}</div>
<div class="row" style="grid-template-columns:1fr 400px">
<div style="display:grid;gap:12px;align-content:start">{systems_panel}
<div class="panel"><div class="ph"><h2>{icon("trending-up", 17)}High-severity events</h2><span class="pm">Whole network · last 12 weeks</span></div>{trend(T["bad"], T["grid"], w=760, h=170)}</div></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("shield-alert", 17)}Latest detections</h2><span class="pm">9 this week</span></div><table>{dh}</table><div class="pm" style="margin-top:10px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div>
</div></main>'''
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

# D: network health checklist
checks = [("bad", "file-warning", "Logs intact", "<b>WS-07</b>: Security log cleared twice on 28 Sep by admin_jd", "23 of 24"),
          ("bad", "clock-alert", "Every system reporting", "<b>WS-09</b>: no data since 23 Sep 14:00", "23 of 24"),
          ("warn", "history", "Reports on time", "<b>WS-12</b>: report 9 hours late on Tue · nothing lost", "23 of 24"),
          ("warn", "shield-check", "Audit settings match STIG", "<b>alma-db01</b>: 3 audit rules missing", "23 of 24"),
          ("ok", "circle-check", "No events lost to log rollover", "All systems · 7,980 collection runs", "24 of 24"),
          ("ok", "hard-drive", "Original logs archived", "24 zips · 3.1 GB · SHA-256 in manifest", "24 of 24")]
ch = ''.join(f'<div class="ck {k}"><div class="i">{icon(i, 15)}</div><b>{t}</b><div class="w">{w}</div><div class="r">{r}</div></div>' for k, i, t, w, r in checks)
shell('L1d-checklist', f'''<div class="panel"><div class="ph"><h2>{icon("server", 17)}Network health</h2><a class="pm" style="color:#0B5FFF;font-weight:600">All 24 systems →</a></div>{ch}</div>''')

# E: system map
grpsd = [("Servers", ["SRV-DC01", "SRV-FS01", "alma-build01", "alma-db01"]),
         ("Workstations", [f'WS-{i:02d}' for i in range(1, 15)] + ['ubu-ws10', 'ubu-ws11', 'ubu-ws12', 'ubu-ws13']),
         ("Virtual machines", ["WS-03-VM1", "ubu-ws12-vm"])]
osmap = {s[0]: s[1] for s in SYS}
stt = {'WS-07': 'bad', 'WS-09': 'bad', 'WS-12': 'warn', 'alma-db01': 'warn'}
mp = ''
for g, names in grpsd:
    mp += f'<div class="mgrp">{g} · {len(names)}</div><div class="map">'
    mp += ''.join(f'<div class="m {stt.get(n, "")} {"mvm" if g.startswith("Virtual") else ""}">{n}<small>{osmap[n]}</small></div>' for n in names)
    mp += '</div>'
calls = [("bad", "WS-07", "Security log cleared twice on 28 Sep by admin_jd"), ("bad", "WS-09", "No data since 23 Sep 14:00"),
         ("warn", "WS-12", "One report arrived 9 hours late · nothing lost"), ("warn", "alma-db01", "3 audit rules missing")]
cl = ''.join(f'<div class="{k}"><b>{n}</b><span>{t}</span></div>' for k, n, t in calls)
shell('L1e-map', f'''<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems</h2><span class="pm"><span class="dot bad"></span>Problem &nbsp; <span class="dot warn"></span>Warning &nbsp; white = reporting normally</span></div>{mp}<div class="call">{cl}</div></div>''')
