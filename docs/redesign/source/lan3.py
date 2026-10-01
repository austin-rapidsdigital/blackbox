import os
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'lan2.py')).read().replace('l1b(); l2b()', ''))

C3 = '''
.hbar{display:flex;height:10px;gap:2px;margin:4px 0 10px}.hbar s{display:block;height:100%}
.hleg{display:flex;gap:22px;font-size:13px;color:#3A4766;margin-bottom:18px}.hleg b{font:700 20px PS;color:#0B1630;margin-right:6px;letter-spacing:-.3px}
.hleg i{display:inline-block;width:9px;height:9px;margin-right:7px;vertical-align:1px}
.att{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.ac{border:1px solid rgba(0,30,98,.1);border-left:3px solid #D12C2C;background:rgba(255,255,255,.7);padding:12px 14px}
.ac.warn{border-left-color:#E08A00}
.ac .t{display:flex;justify-content:space-between;align-items:baseline}.ac .t b{font-size:14.5px;font-weight:650}.ac .t span{font-size:12px;color:#5A6785}
.ac p{margin:5px 0 0;font-size:13.5px;font-weight:600}.ac.bad p{color:#B01C1C}.ac.warn p{color:#8F4F00}
.ac small{display:block;margin-top:3px;font-size:12.5px;color:#5A6785}
.okline{display:flex;align-items:center;gap:10px;margin-top:14px;padding:11px 14px;background:rgba(26,154,80,.06);border:1px solid rgba(26,154,80,.18);font-size:13.5px;color:#14532D}
.okline svg{color:#1A9A50}.okline a{margin-left:auto;color:#0B5FFF;font-weight:600;font-size:12.5px}
'''

def l1c():
    att = [("bad", "WS-07", "Windows 11", "Security log cleared twice", "28 Sep 12:38 and 12:40 by admin_jd · 2 high detections"),
           ("bad", "WS-09", "Windows 11", "No data for 6 days", "Last report 23 Sep 14:00 · check it is on and can reach SRV-DC01"),
           ("warn", "WS-12", "Windows 11", "Report arrived 9 hours late", "Tue 23 Sep · no events were lost"),
           ("warn", "alma-db01", "Alma 8 · Database", "3 audit rules missing", "Compared with the RHEL 8 STIG · see Audit settings")]
    ah = ''.join(f'<div class="ac {k}"><div class="t"><b>{n}</b><span>{o}</span></div><p>{p}</p><small>{d}</small></div>' for k, n, o, p, d in att)
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
<div style="display:grid;gap:12px;align-content:start">
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems</h2><a class="pm" style="color:#0B5FFF;font-weight:600">All 24 systems →</a></div>
<div class="hbar"><s style="flex:20;background:#1A9A50"></s><s style="flex:2;background:#E08A00"></s><s style="flex:2;background:#D12C2C"></s></div>
<div class="hleg"><span><i style="background:#1A9A50"></i><b>20</b>reporting normally</span><span><i style="background:#E08A00"></i><b>2</b>warnings</span><span><i style="background:#D12C2C"></i><b>2</b>problems</span></div>
<div class="att">{ah}</div></div>
<div class="panel"><div class="ph"><h2>{icon("trending-up", 17)}High-severity events</h2><span class="pm">Whole network · last 12 weeks</span></div>{trend(T["bad"], T["grid"], w=760, h=180)}</div>
</div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("shield-alert", 17)}Latest detections</h2><span class="pm">9 this week</span></div><table>{dh}</table><div class="pm" style="margin-top:10px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div>
</div></main>'''
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>L1c</title><style>{T["css"]}{EXTRA}{CALM}{C3}</style></head><body>{body}</body></html>'
    open(f'{SP}/L1c-overview.html', 'w').write(html)
l1c()
