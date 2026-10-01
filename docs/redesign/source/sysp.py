import os, random
_d = os.path.dirname(os.path.abspath(__file__))
_src = open(os.path.join(_d, 'lan5.py')).read().split('# ---- M1')[0]
exec(_src)

UP = {'WS-03-VM1': 41, 'ubu-ws12-vm': 63}
WHY = {'WS-07': ('bad', 'Log cleared twice · 1 audit setting off'), 'WS-09': ('bad', 'No data for 6 days'),
       'WS-12': ('warn', 'Report 9 h late on Tue'), 'alma-db01': ('warn', '3 audit rules missing')}
AUD = {'alma-db01': ('warn', '3 rules missing'), 'WS-07': ('bad', 'Removable Storage off')}
OSF = {'WIN 11': 'Windows 11', 'WS 2025': 'Server 2025', 'UBU 24': 'Ubuntu 24.04', 'UBU 22': 'Ubuntu 22.04', 'ALMA 8': 'Alma 8.10'}
GROUP = {n: g for g, ns in grpsd for n in ns}

C6 = '''
.chips{display:flex;gap:6px;flex-wrap:wrap}.chips span{font-size:12.5px;font-weight:550;padding:5px 11px;border:1px solid rgba(0,30,98,.12);background:rgba(255,255,255,.6);color:#3A4766;white-space:nowrap}
.chips span.on{background:#0A2A7A;border-color:#0A2A7A;color:#fff}.chips span i{font-style:normal;opacity:.65;margin-left:6px}
.sumrow{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end;margin-bottom:12px}
table.dir{width:100%;border-collapse:collapse}
table.dir th{padding:0 12px 9px;white-space:nowrap}table.dir th.n,table.dir td.n{text-align:right}
table.dir td{padding:10px 12px;border-bottom:1px solid rgba(0,30,98,.07);white-space:nowrap;font-size:13px;vertical-align:middle}
table.dir td.n{font:12.5px SCP}
table.dir tr.g td{padding:18px 12px 7px;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;border-bottom:1px solid rgba(0,30,98,.14)}
table.dir tr.bad td:first-child{box-shadow:inset 3px 0 #D12C2C}table.dir tr.warn td:first-child{box-shadow:inset 3px 0 #E08A00}
table.dir td b{font-weight:600}
.mute{color:#8A96B3}.okc{color:#147A3D}.why.bad{color:#B01C1C;font-weight:600}.why.warn{color:#8F4F00;font-weight:600}
.upbar{display:inline-flex;align-items:center;gap:8px}.upbar s{display:inline-block;width:70px;height:6px;background:rgba(0,30,98,.08);position:relative}
.upbar s i{position:absolute;left:0;top:0;bottom:0;background:#7FA6E8}
.md2{display:grid;grid-template-columns:290px 1fr;gap:12px}
.slist{padding:10px 0}.slist .grp2{padding:12px 16px 6px;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785}
.slist a{display:grid;grid-template-columns:10px 1fr auto;gap:10px;align-items:center;padding:7px 16px;font-size:13px;color:#0B1630}
.slist a small{font-size:11.5px;color:#8A96B3}.slist a.sel{background:rgba(11,95,255,.08);box-shadow:inset 3px 0 #0B5FFF}
.slist a i{width:8px;height:8px;display:block}.slist a i.ok{background:#C4CCDC}.slist a i.bad{background:#D12C2C}.slist a i.warn{background:#E08A00}
.slist .search{margin:0 14px 6px;padding:8px 10px;border:1px solid rgba(0,30,98,.12);background:rgba(255,255,255,.7);font-size:12.5px;color:#8A96B3;display:flex;gap:8px;align-items:center}
.dh{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px}
.dh h3{margin:0;font-size:22px;font-weight:700;letter-spacing:-.3px}.dh p{margin:3px 0 0;color:#5A6785;font-size:13px}
.facts4{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid rgba(0,30,98,.08);background:rgba(255,255,255,.6);margin-bottom:12px}
.facts4 div{padding:11px 14px;border-left:1px solid rgba(0,30,98,.08);font-size:12px;color:#5A6785}.facts4 div:first-child{border-left:0}
.facts4 b{display:block;font:650 17px PS;color:#0B1630;margin-top:2px}.facts4 b.bad{color:#C22020}.facts4 b.warn{color:#A35A00}
.vs{display:grid;gap:9px}.vs>div{display:grid;grid-template-columns:120px 1fr 44px;gap:12px;align-items:center;font-size:12.5px}
.vs .tr2{height:8px;background:rgba(0,30,98,.06);position:relative}.vs .tr2 s{position:absolute;top:0;bottom:0;left:0;background:#0B5FFF;opacity:.75}
.vs .tr2 em{position:absolute;top:-3px;bottom:-3px;width:2px;background:#0B1630}.vs .tr2.hot s{background:#D12C2C}
.vs b{font:12.5px SCP;text-align:right}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.sc2{background:rgba(255,255,255,.75);border:1px solid rgba(0,30,98,.09);padding:12px 14px;border-top:3px solid #C9D7F2}
.sc2.bad{border-top-color:#D12C2C}.sc2.warn{border-top-color:#E08A00}
.sc2 .t{display:flex;justify-content:space-between;align-items:baseline}.sc2 .t b{font-size:14px;font-weight:650}.sc2 .t span{font-size:11.5px;color:#8A96B3}
.sc2 .w{font-size:12.5px;margin-top:2px;min-height:18px;color:#5A6785}.sc2.bad .w{color:#B01C1C;font-weight:600}.sc2.warn .w{color:#8F4F00;font-weight:600}
.sc2 .nums{display:grid;grid-template-columns:repeat(3,1fr);margin-top:10px;padding-top:9px;border-top:1px solid rgba(0,30,98,.07)}
.sc2 .nums div{font-size:11px;color:#8A96B3}.sc2 .nums b{display:block;font:600 14px PS;color:#0B1630}.sc2 .nums b.hi{color:#C22020}.sc2 .nums b.md{color:#A35A00}
'''

def page3(name, body):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

BYN = {s[0]: s for s in SYS}
SHEAD = head("Systems", "Weekly report · 24 systems · collector SRV-DC01")
CHIPS = '<div class="chips"><span class="on">All<i>24</i></span><span>Needs attention<i>4</i></span><span>Servers<i>4</i></span><span>Workstations<i>18</i></span><span>VMs<i>2</i></span><span>Windows<i>16</i></span><span>Linux<i>8</i></span></div>'

def uptime(n):
    if n in UP:
        return f'<span class="upbar"><s><i style="width:{UP[n]}%"></i></s><span class="mute">VM on {UP[n]}%</span></span>'
    if n == 'WS-09':
        return '<span class="upbar"><s><i style="width:14%;background:#D12C2C"></i></s><span class="why bad">1 of 7 days</span></span>'
    return '<span class="upbar"><s><i style="width:100%"></i></s><span class="mute">7 of 7 days</span></span>'

def dets(h, m):
    if not h and not m: return '<span class="mute">—</span>'
    return ' · '.join(x for x in [f'<span class="hi">{h} high</span>' if h else '', f'<span class="md">{m} med</span>' if m else ''] if x)

# ---------- S1: directory table ----------
def s1():
    rows = ''
    for g, names in grpsd:
        rows += f'<tr class="g"><td colspan="7">{g} · {len(names)}</td></tr>'
        for n in sorted(names, key=lambda x: (x not in WHY, x)):
            s = BYN[n]; k, why = WHY.get(n, ('', ''))
            a = AUD.get(n)
            st_ = f'<span class="why {k}">{why}</span>' if why else '<span class="mute">OK</span>'
            audit = f'<span class="why {a[0]}">{a[1]}</span>' if a else '<span class="okc">Matches STIG</span>'
            role = s[2] if s[2] != 'Workstation' else ''
            rows += (f'<tr class="{k}"><td><b>{n}</b></td><td>{OSF[s[1]]}<span class="mute">{" · " + role if role else ""}</span></td>'
                     f'<td>{uptime(n)}</td><td class="n">{fmt(s[5])}</td><td class="n">{dets(*s[6])}</td>'
                     f'<td class="n mute">{s[8]}</td><td>{st_}</td></tr>')
    body = aside("Systems") + f'''<main>{SHEAD}
<div class="panel" style="padding:14px 18px;margin-bottom:12px">{health_bar()}</div>
<div class="panel"><div class="ph">{CHIPS}<span class="btn">{icon("search", 15)}Find a system</span></div>
<table class="dir"><thead><tr><th>System</th><th>OS · role</th><th>Collected</th><th class="n">Events</th><th class="n">Detections</th><th class="n">Last report</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>
</main>'''
    page3('S1-directory', body)

# ---------- S2: master / detail ----------
def s2():
    lst = '<div class="search">' + icon("search", 14) + 'Find a system</div>'
    for g, names in grpsd:
        lst += f'<div class="grp2">{g} · {len(names)}</div>'
        for n in sorted(names, key=lambda x: (x not in WHY, x)):
            k = WHY.get(n, ('ok',))[0]
            sub = f'on {UP[n]}%' if n in UP else BYN[n][1]
            lst += f'<a class="{"sel" if n == "WS-07" else ""}"><i class="{k}"></i><span>{n}</span><small>{sub}</small></a>'
    vs = [("Privileged actions", 588, 292, True), ("Failed logons", 82, 17, True), ("Logons", 640, 485, False), ("USB events", 6, 1, True),
          ("Account changes", 7, 0, True), ("PowerShell", 2, 0, False)]
    vh = ''.join(f'<div><span>{l}</span><div class="tr2 {"hot" if hot else ""}"><s style="width:{min(v / (max(v, t) * 1.15) * 100, 100):.0f}%"></s><em style="left:{t / (max(v, t) * 1.15) * 100:.0f}%"></em></div><b>{fmt(v)}</b></div>' for l, v, t, hot in vs)
    tl = ''
    W = 1000
    for d in range(7):
        tl += f'<text x="{d * W / 7 + 2:.0f}" y="11" class="ax">{DAYS[d]} {23 + d}</text>'
    tl += f'<rect x="0" y="18" width="{W}" height="14" fill="#C9D7F2"/><rect x="{6.45 * W / 7:.0f}" y="18" width="6" height="14" fill="#D12C2C"/>'
    tls = f'<svg viewBox="0 0 {W} 36" width="100%">{tl}</svg>'
    ck = [("bad", "file-warning", "Logs intact", "Security log cleared at 12:38 and 12:40 on 28 Sep by admin_jd"),
          ("bad", "shield-check", "Audit settings match STIG", "Removable Storage auditing turned off on 28 Sep 09:38 (WN11-AU-000090)"),
          ("ok", "clock-alert", "Reporting", "Every hour, 168 collection runs, last 29 Sep 00:00"),
          ("ok", "circle-check", "No events lost to log rollover", "Security log holds 9 days")]
    ckh = ''.join(f'<div class="ck2 {k}"><div class="i">{icon(i, 14)}</div><div><b>{t}</b><span>{w}</span></div><div></div></div>' for k, i, t, w in ck)
    dh = ''.join(f'<div class="dc {s}"><div class="b"><b>{t}</b><span>{d}</span></div><div class="m2">{dy[4:]}<small>{tm}</small></div></div>' for s, t, d, h, dy, tm in DETS[:2] + [("medium", "Audit setting turned off", "Removable Storage auditing was turned off by admin_jd.", "WS-07", "Mon 28 Sep", "09:38")])
    body = aside("Systems") + f'''<main>{SHEAD}
<div class="md2"><div class="panel slist" style="padding:12px 0">{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div><h3>WS-07</h3><p>Windows 11 Enterprise 24H2 · Workstation · Engineering bay 2</p></div><span class="sv high">Needs attention</span></div>
<div class="facts4"><div>Events<b>4,259</b></div><div>Detections<b class="bad">2 high · 1 med</b></div><div>Collected<b>7 of 7 days</b></div><div>Audit settings<b class="bad">1 gap</b></div><div>Last report<b>29 Sep 00:00</b></div></div>
<div class="sub2">Collection this week</div>{tls}</div>
<div class="row" style="grid-template-columns:1fr 1fr;margin-bottom:12px">
<div class="panel"><div class="ph"><h2>{icon("shield-check", 17)}Health</h2></div>{ckh}</div>
<div class="panel"><div class="ph"><h2>{icon("layers", 17)}Activity vs. typical system</h2><span class="pm">Line = network median</span></div><div class="vs">{vh}</div></div></div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Detections on WS-07</h2><span class="pm">3 this week</span></div><div class="dl">{dh}</div></div>
</div></div></main>'''
    page3('S2-detail', body)

# ---------- S3: card grid ----------
def s3():
    order = sorted(SYS, key=lambda s: (s[0] not in WHY, list(WHY).index(s[0]) if s[0] in WHY else 0, GROUP[s[0]] != 'Servers', GROUP[s[0]] == 'Virtual machines', s[0]))
    cards = ''
    for s in order:
        n = s[0]; k, why = WHY.get(n, ('', ''))
        if not why:
            why = f'VM · on {UP[n]}% of the week' if n in UP else (s[2] if s[2] != 'Workstation' else '')
        h, m = s[6]
        cards += (f'<div class="sc2 {k}"><div class="t"><b>{n}</b><span>{OSF[s[1]]}</span></div><div class="w">{why}</div>'
                  f'<div class="nums"><div>Events<b>{fmt(s[5])}</b></div><div>High<b class="{"hi" if h else ""}">{h}</b></div><div>Medium<b class="{"md" if m else ""}">{m}</b></div></div></div>')
    body = aside("Systems") + f'''<main>{SHEAD}
<div class="panel" style="padding:14px 18px;margin-bottom:12px">{health_bar()}</div>
<div class="ph" style="margin:4px 0 12px">{CHIPS}<span class="chips"><span class="on">Needs attention first</span><span>Name</span><span>Most events</span></span></div>
<div class="cards">{cards}</div></main>'''
    page3('S3-cards', body)

s1(); s2(); s3()
