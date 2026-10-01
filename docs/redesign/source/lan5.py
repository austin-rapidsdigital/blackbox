import os
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'lan4.py')).read().split('# D: network health checklist')[0])

grpsd = [("Servers", ["SRV-DC01", "SRV-FS01", "alma-build01", "alma-db01"]),
         ("Workstations", [f'WS-{i:02d}' for i in range(1, 15)] + ['ubu-ws10', 'ubu-ws11', 'ubu-ws12', 'ubu-ws13']),
         ("Virtual machines", ["WS-03-VM1", "ubu-ws12-vm"])]
osmap = {s[0]: s[1] for s in SYS}
stt = {'WS-07': 'bad', 'WS-09': 'bad', 'WS-12': 'warn', 'alma-db01': 'warn'}

C5 = '''
.ev6{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:12px}
.ec{padding:12px 14px;display:grid;grid-template-columns:1fr auto;grid-template-rows:auto auto;gap:2px 8px;align-items:center}
.ec .l{grid-column:1/3;font-size:12.5px;font-weight:550;color:#3A4766;display:flex;align-items:center;gap:7px;white-space:nowrap}.ec .l svg{flex:none}.ec .l svg{color:#5A6785}
.ec .v{grid-column:1;font:700 24px PS;letter-spacing:-.4px;color:#0A2A7A;line-height:1.15}
.ec .d{grid-column:2;grid-row:2;align-self:end;padding-bottom:4px;white-space:nowrap;font-size:11.5px;color:#5A6785;text-align:right}
.ec.bad .v{color:#C22020}.ec.bad .l svg{color:#D12C2C}.ec.warn .v{color:#A35A00}.ec.warn .l svg{color:#E08A00}.ec.zero .v{color:#9AA5BF}
.ec{border-top:2px solid transparent}.ec.bad{border-top-color:#D12C2C}.ec.warn{border-top-color:#E08A00}
.sysg{display:grid;grid-template-columns:1.25fr 1fr;gap:26px}
.sysg .map{grid-template-columns:repeat(6,1fr)}
.ck2{display:grid;grid-template-columns:24px 1fr auto;gap:10px;align-items:start;padding:9px 0;border-bottom:1px solid rgba(0,30,98,.07)}
.ck2:last-child{border-bottom:0}.ck2 .i{width:22px;height:22px;display:grid;place-items:center}
.ck2.ok .i{color:#1A9A50;background:#E6F5EC}.ck2.bad .i{color:#D12C2C;background:#FDECEC}.ck2.warn .i{color:#A35A00;background:#FDF3E1}
.ck2 b{font-weight:600;font-size:13px;display:block}.ck2 span{font-size:12.5px;color:#5A6785;display:block}.ck2.bad span em{color:#B01C1C}.ck2.warn span em{color:#8F4F00}.ck2 em{font-style:normal;font-weight:650}
.ck2 .r{font:12px SCP;color:#5A6785;padding-top:2px}
.sub2{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;margin:0 0 8px}
.dl{display:grid;gap:8px}
.dc{display:grid;grid-template-columns:4px 1fr auto;gap:0 14px;background:rgba(255,255,255,.7);border:1px solid rgba(0,30,98,.08)}
.dc:before{content:"";background:#D12C2C}.dc.medium:before{background:#E08A00}
.dc .b{padding:10px 0}.dc .b b{display:block;font-weight:650;font-size:13.5px}.dc .b span{display:block;font-size:12.5px;color:#5A6785;margin-top:2px}
.dc .m2{padding:10px 14px 10px 0;text-align:right;font:12px SCP;color:#3A4766;white-space:nowrap}.dc .m2 small{display:block;color:#8A96B3;margin-top:3px}
.sevtabs{display:flex;gap:6px}.sevtabs span{font-size:12px;font-weight:600;padding:3px 9px;border:1px solid rgba(0,30,98,.12);color:#3A4766;background:rgba(255,255,255,.6)}
.sevtabs span.on{background:#0A2A7A;color:#fff;border-color:#0A2A7A}.sevtabs span i{font-style:normal;opacity:.7;margin-left:5px}
.dayh{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;margin:12px 0 6px}.dayh:first-child{margin-top:0}
.hero{display:grid;grid-template-columns:1.15fr repeat(4,1fr);margin-bottom:12px;padding:0}
.hero>div{padding:16px 20px;border-left:1px solid rgba(0,30,98,.08)}.hero>div:first-child{border-left:0}
.hero .hbar{margin:8px 0 8px}.hero .hleg{margin:0;gap:14px;font-size:12px}.hero .hleg b{font-size:16px}
.ev8{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.legend span{white-space:nowrap}.hero .hleg span{white-space:nowrap}
.ev8 .ec{background:rgba(255,255,255,.7);border:1px solid rgba(0,30,98,.08);border-top-width:2px}
.ev8 .ec.bad{border-top-color:#D12C2C}.ev8 .ec.warn{border-top-color:#E08A00}
'''

DETS = [("high", "Possible covering of tracks", "admin_jd added tempuser to Administrators, then turned off Removable Storage auditing 18 min later.", "WS-07", "Mon 28 Sep", "09:20"),
        ("high", "Possible password guessing", "6 failed logons for administrator in 40 s from 10.1.1.99.", "WS-07", "Mon 28 Sep", "06:02"),
        ("medium", "Administrator activity outside working hours", "jsmith ran 14 sudo commands between 23:10 and 23:41.", "ubu-ws12", "Sun 27 Sep", "23:10"),
        ("high", "Same account failing on several computers", "svc_backup failed on 6 systems within 9 minutes.", "6 systems", "Sat 26 Sep", "22:14"),
        ("high", "New member of Domain Admins", "mjones was added by admin_jd.", "SRV-DC01", "Fri 25 Sep", "11:02"),
        ("medium", "Suspicious PowerShell", "A script downloads and runs code from 10.1.1.99.", "WS-09", "Tue 22 Sep", "15:47")]

EVENTS = [("bad", "eraser", "Logs cleared", "2", "WS-07"), ("bad", "user-plus", "New admins", "1", "SRV-DC01"),
          ("warn", "settings", "Policy changes", "3", "2 systems"), ("warn", "lock", "Lockouts", "4", "normal: 1"),
          ("warn", "moon", "After-hours admin", "14", "jsmith"), ("", "usb", "New USB devices", "3", "6 events"),
          ("warn", "terminal", "PowerShell", "3", "WS-09"), ("", "user-x", "Accounts disabled", "0", "")]

def ev_cards(items, cls='ev6'):
    out = ''
    for k, i, l, v, d in items:
        kk = 'zero' if v == '0' else k
        out += f'<div class="{"panel " if cls == "ev6" else ""}ec {kk}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>'
    return f'<div class="{cls}">{out}</div>' if cls == 'ev6' else out

def kpi4():
    return f'''<div class="kpis">{kpi("Systems reporting", "23 / 24", "WS-09 silent 6 days", [24,24,24,24,23,23,23,23,24,24,24,23], True)}
{kpi("Detections", "9", "4 high · 5 medium", [3,5,2,4,6,3,2,5,7,4,5,9], True)}
{kpi("Events collected", "84.2k", "+3% vs. avg", [80,82,79,85,83,81,84,86,82,83,81,84])}
{kpi("Privileged actions", "3,912", "by 11 people", [3700,3810,3650,3990,3880,3900,3770,3950,3820,3890,3860,3912])}</div>'''

def health_bar(big=True):
    return f'''<div class="hbar"><s style="flex:20;background:#1A9A50"></s><s style="flex:2;background:#E08A00"></s><s style="flex:2;background:#D12C2C"></s></div>
<div class="hleg"><span><i style="background:#1A9A50"></i><b>20</b>reporting normally</span><span><i style="background:#E08A00"></i><b>2</b>warnings</span><span><i style="background:#D12C2C"></i><b>2</b>problems</span></div>'''

CHECKS = [("bad", "file-warning", "Logs intact", "<em>WS-07</em>: Security log cleared twice on 28 Sep by admin_jd", "23/24"),
          ("bad", "clock-alert", "Every system reporting", "<em>WS-09</em>: no data since 23 Sep 14:00", "23/24"),
          ("warn", "history", "Reports on time", "<em>WS-12</em>: report 9 hours late on Tue · nothing lost", "23/24"),
          ("warn", "shield-check", "Audit settings match STIG", "<em>alma-db01</em>: 3 audit rules missing", "23/24"),
          ("ok", "circle-check", "No events lost to log rollover", "7,980 collection runs", "24/24"),
          ("ok", "hard-drive", "Original logs archived", "24 zips · 3.1 GB · SHA-256 in manifest", "24/24")]

def checklist():
    return ''.join(f'<div class="ck2 {k}"><div class="i">{icon(i, 14)}</div><div><b>{t}</b><span>{w}</span></div><div class="r">{r}</div></div>' for k, i, t, w, r in CHECKS)

def sysmap(cols=None, groups=True):
    out = ''
    for g, names in grpsd:
        out += f'<div class="mgrp">{g} · {len(names)}</div><div class="map"{f" style=grid-template-columns:repeat({cols},1fr)" if cols else ""}>'
        out += ''.join(f'<div class="m {stt.get(n, "")} {"mvm" if g.startswith("Virtual") else ""}">{n}<small>{osmap[n]}</small></div>' for n in names)
        out += '</div>'
    return out

def det_cards(n=6, by_day=True):
    out = ''; day = None
    for s, t, d, h, dy, tm in DETS[:n]:
        if by_day and dy != day:
            out += f'<div class="dayh">{dy}</div>'; day = dy
        out += f'<div class="dc {s}"><div class="b"><b>{t}</b><span>{d}</span></div><div class="m2">{h}<small>{tm if by_day else dy[4:] + " " + tm}</small></div></div>'
    return out

def weekly_cols(w=440, h=180, small=False):
    hi = [2, 1, 3, 2, 1, 0, 2, 4, 1, 2, 3, 4]; md = [3, 2, 2, 4, 3, 2, 1, 3, 4, 2, 3, 5]
    mx = 10; x0 = 26; bw = (w - x0 - 6) / 12; out = ''
    for v in (0, 5, 10):
        y = h - 22 - v / mx * (h - 36)
        out += f'<line x1="{x0}" x2="{w}" y1="{y:.1f}" y2="{y:.1f}" stroke="{T["grid"]}"/><text x="{x0 - 7}" y="{y + 4:.1f}" text-anchor="end" class="ax">{v}</text>'
    for i in range(12):
        x = x0 + i * bw + bw * .2; bwid = bw * .6
        yh = h - 22 - hi[i] / mx * (h - 36); ym = yh - md[i] / mx * (h - 36)
        last = i == 11
        out += f'<rect x="{x:.1f}" y="{yh:.1f}" width="{bwid:.1f}" height="{h - 22 - yh:.1f}" fill="#D12C2C" opacity="{1 if last else .55}"/>'
        out += f'<rect x="{x:.1f}" y="{ym:.1f}" width="{bwid:.1f}" height="{yh - ym:.1f}" fill="#E08A00" opacity="{1 if last else .45}"/>'
        if i % 2 == 1 or last:
            out += f'<text x="{x + bwid / 2:.1f}" y="{h - 6}" text-anchor="middle" class="ax" style="{"font-weight:700;fill:#0B1630" if last else ""}">{"This wk" if last else "W" + str(28 + i)}</text>'
    return f'<svg viewBox="0 0 {w} {h}" width="100%">{out}</svg>'

LEG = '<div class="legend"><span><i style="background:#D12C2C"></i>High</span><span><i style="background:#E08A00"></i>Medium</span><span>Faded = earlier weeks</span></div>'

def small_trend(title, vals, col, note):
    return f'<div class="panel"><div class="ph"><h2>{title}</h2><span class="pm">{note}</span></div>{spark(vals, col, w=300, h=70, fill=T["sparkfillbad"] if col == T["bad"] else T["sparkfill"])}<div class="lg" style="justify-content:space-between"><span>W28</span><span>This week</span></div></div>'

def page2(name, body):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

HEAD = head("Network overview", "Weekly report · 24 systems · collector SRV-DC01 · generated 29 Sep 2026 00:05")

# ---- M1: stacked sections ----
m1 = aside("Overview") + f'''<main>{HEAD}{ALERT}{kpi4()}
{ev_cards(EVENTS[:6])}
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("server", 17)}Systems · 24</h2><a class="pm" style="color:#0B5FFF;font-weight:600">Systems page →</a></div>
{health_bar()}
<div class="sysg"><div>{sysmap()}</div><div><div class="sub2">Network health</div>{checklist()}</div></div></div>
<div class="row" style="grid-template-columns:1.6fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Detections</h2><div class="sevtabs"><span class="on">All<i>9</i></span><span>High<i>4</i></span><span>Medium<i>5</i></span></div></div><div class="dl">{det_cards(4)}</div>
<div class="pm" style="margin-top:12px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("trending-up", 17)}Detections per week</h2><span class="pm">Last 12 weeks</span></div>{weekly_cols()}{LEG}
<div class="ck2 warn" style="margin-top:10px;border:0"><div class="i">{icon("trending-up", 14)}</div><div><b>9 this week, above the 12-week average of 6</b><span>Driven by WS-07 (3 detections)</span></div><div></div></div></div>
</div></main>'''
page2('M1-stacked', m1)

# ---- M2: systems left, detections feed right; trends strip at bottom ----
m2 = aside("Overview") + f'''<main>{HEAD}{ALERT}{kpi4()}
{ev_cards(EVENTS[:6])}
<div class="row" style="grid-template-columns:1.35fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems · 24</h2><a class="pm" style="color:#0B5FFF;font-weight:600">Systems page →</a></div>
{health_bar()}{checklist()}<div style="margin-top:16px">{sysmap(cols=6)}</div></div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Detections</h2><span class="pm"><span class="hi">4 high</span> · <span class="md">5 medium</span></span></div><div class="dl">{det_cards(6)}</div>
<div class="pm" style="margin-top:12px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div></div>
<div class="sub2" style="margin:6px 0 8px">Trends · last 12 weeks</div>
<div class="row" style="grid-template-columns:repeat(3,1fr)">
{small_trend("High-severity events", [2,1,3,2,1,0,2,4,1,2,3,7], T["bad"], "7 this week · avg 2")}
{small_trend("Failed logons", [380,402,355,420,398,410,377,415,389,401,395,418], T["accent"], "418 · normal")}
{small_trend("Privileged actions", [3700,3810,3650,3990,3880,3900,3770,3950,3820,3890,3860,3912], T["accent"], "3,912 · normal")}
</div></main>'''
page2('M2-split', m2)

# ---- M3: hero strip, events grid beside detections, systems last ----
hero = f'''<div class="panel hero"><div><div class="kl">Systems · 24</div><div class="hbar"><s style="flex:20;background:#1A9A50"></s><s style="flex:2;background:#E08A00"></s><s style="flex:2;background:#D12C2C"></s></div><div class="hleg"><span><i style="background:#1A9A50"></i><b>20</b>OK</span><span><i style="background:#E08A00"></i><b>2</b>warnings</span><span><i style="background:#D12C2C"></i><b>2</b>problems</span></div></div>
<div><div class="kl">Detections</div><div class="kv bad">9</div><div class="ks">4 high · 5 medium</div></div>
<div><div class="kl">Events collected</div><div class="kv">84.2k</div><div class="ks">+3% vs. avg</div></div>
<div><div class="kl">Privileged actions</div><div class="kv">3,912</div><div class="ks">by 11 people</div></div>
<div><div class="kl">Failed logons</div><div class="kv">418</div><div class="ks">normal for this network</div></div></div>'''
strip = f'''<div class="panel" style="margin-bottom:12px;display:grid;grid-template-columns:270px 1fr;gap:20px;align-items:center">
<div><h2 style="margin-bottom:6px">{icon("trending-up", 17)}Detections per week</h2><div class="ks">9 this week · 12-week average 6</div>{LEG}</div>{weekly_cols(w=1010, h=110)}</div>'''
m3 = aside("Overview") + f'''<main>{HEAD}{ALERT}{hero}{strip}
<div class="row" style="grid-template-columns:1fr 1.25fr">
<div class="panel"><div class="ph"><h2>{icon("triangle-alert", 17)}Important events</h2><span class="pm">This week</span></div><div class="ev8">{ev_cards(EVENTS, cls="ev8")}</div></div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Detections</h2><div class="sevtabs"><span class="on">All<i>9</i></span><span>High<i>4</i></span><span>Medium<i>5</i></span></div></div><div class="dl">{det_cards(4, by_day=False)}</div>
<div class="pm" style="margin-top:12px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div></div>
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems · 24</h2><a class="pm" style="color:#0B5FFF;font-weight:600">Systems page →</a></div>
<div class="sysg"><div>{sysmap()}</div><div><div class="sub2">Network health</div>{checklist()}</div></div></div>
</main>'''
page2('M3-briefing', m3)
