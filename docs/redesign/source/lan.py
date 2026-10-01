import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from glass import *
src = open(os.path.join(SP, 'g2.py')).read().split("page(T,'g2-arctic')")[0].split('\n', 1)[1]
exec(src)  # defines T (the G2 Arctic theme)
ramp = lambda t: lerp(T['heat0'], T['heat1'], t)

EXTRA = '''
.os{font:600 10.5px PS;letter-spacing:.06em;padding:1px 5px;border:1px solid rgba(0,30,98,.16);color:#3A4766;background:rgba(255,255,255,.6)}
.dot{display:inline-block;width:8px;height:8px;margin-right:8px;vertical-align:1px}
.dot.ok{background:#1A9A50}.dot.warn{background:#E08A00}.dot.bad{background:#D12C2C}.dot.off{background:#9AA5BF}
table.fleet td{padding:6px 7px;white-space:nowrap;vertical-align:middle;border-bottom:1px solid rgba(0,30,98,.07)}
table.fleet td b{display:inline;font-weight:600}
table.fleet td.n{text-align:right;font-family:SCP;font-size:12.5px}
table.fleet th.n{text-align:right}table.fleet th{padding:0 8px 8px}table.fleet td.note{max-width:150px;overflow:hidden;text-overflow:ellipsis;color:#A35A00;font-size:12px}table.fleet tr.sel td.note{color:#C22020}table.fleet td.note.sub{color:#5A6785}table.fleet th{white-space:nowrap}
.seg span{white-space:nowrap}.ks{white-space:nowrap}
table.fleet tr.sel td{background:rgba(11,95,255,.06)}
.cov{display:flex;gap:2px}.cov i{width:13px;height:14px;display:block}
.c0{background:#1A9A50}.c1{background:#E08A00}.c2{background:#D12C2C}.c3{background:rgba(0,30,98,.12)}
.hi{color:#C22020;font-weight:650}.md{color:#A35A00;font-weight:650}.z{color:#9AA5BF}
.sub{font-size:12px;color:#5A6785}
.vm{font:600 10px PS;letter-spacing:.06em;color:#0B5FFF;border:1px solid rgba(11,95,255,.35);padding:0 4px;margin-left:6px}
.seg{display:flex;border:1px solid rgba(0,30,98,.14);background:rgba(255,255,255,.7)}.seg span{padding:5px 11px;font-size:12.5px;font-weight:550;color:#5A6785}.seg span.on{background:#0A2A7A;color:#fff}
.tiles{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
.tile{padding:9px 10px;border:1px solid rgba(0,30,98,.1);background:rgba(255,255,255,.75);border-top:3px solid #1A9A50;min-width:0}
.tile.warn{border-top-color:#E08A00}.tile.bad{border-top-color:#D12C2C;background:rgba(253,236,236,.75)}.tile.off{border-top-color:#9AA5BF;background:rgba(240,242,247,.75)}
.tile b{font-size:13px;font-weight:650;display:flex;justify-content:space-between;align-items:center}.tile b small{font:500 11px SCP;color:#5A6785}
.tile span{display:block;font-size:11.5px;color:#5A6785;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tile .tn{display:flex;gap:10px;margin-top:4px;font:12px SCP;color:#5A6785}.tile .tn span{display:inline;font:inherit}.tile .tn{white-space:nowrap}
table.mx{border-collapse:separate;border-spacing:2px}table.mx th{font-size:10.5px;padding:0 6px 4px;text-align:center;white-space:nowrap}table.mx th:first-child{text-align:left}
table.mx{width:100%}table.mx td{padding:5px 8px;font:12px SCP;text-align:center;border:0}table.mx td:first-child{text-align:left;font:600 12.5px PS;padding-left:0;white-space:nowrap}
table.mx td.z0{color:#9AA5BF}
.legend{display:flex;gap:14px;font-size:11.5px;color:#5A6785;margin-top:8px}.legend i{display:inline-block;width:10px;height:10px;margin-right:5px;vertical-align:-1px}
.sys2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.sc{display:grid;grid-template-columns:44px 1fr auto;gap:14px;align-items:center}
.sc .ic{width:44px;height:44px;display:grid;place-items:center;border:1px solid rgba(0,30,98,.12);color:#0A2A7A;background:rgba(255,255,255,.7)}
.sc h3{margin:0;font-size:16px;font-weight:650}.sc p{margin:2px 0 0;font-size:12.5px;color:#5A6785}
.facts{display:grid;grid-template-columns:repeat(4,auto);gap:4px 22px;margin-top:14px;padding-top:12px;border-top:1px solid rgba(0,30,98,.08);font-size:12px;color:#5A6785}.facts b{display:block;font:600 14px PS;color:#0B1630}
.facts b.bad{color:#C22020}
.bars{display:grid;gap:7px}.bar{display:grid;grid-template-columns:96px 1fr 30px;gap:10px;align-items:center;font-size:12.5px}
.bar .tb{height:10px;display:flex;background:rgba(0,30,98,.06)}.bar .tb s{display:block;height:100%}.bar .tb s.h{background:#D12C2C}.bar .tb s.m{background:#E08A00}.bar .tb s.l{background:#7FA6E8}
'''

random.seed(11)
WIN = [f'WS-{i:02d}' for i in range(1, 15)]
SYS = []
for n in WIN:
    SYS.append([n, 'WIN 11', 'Workstation', False])
SYS += [['SRV-DC01', 'WS 2025', 'Collector', False], ['SRV-FS01', 'WS 2025', 'File server', False],
        ['ubu-ws10', 'UBU 24', 'Workstation', False], ['ubu-ws11', 'UBU 24', 'Workstation', False],
        ['ubu-ws12', 'UBU 22', 'Workstation', False], ['ubu-ws13', 'UBU 22', 'Workstation', False],
        ['alma-build01', 'ALMA 8', 'Build server', False], ['alma-db01', 'ALMA 8', 'Database', False],
        ['WS-03-VM1', 'WIN 11', 'VM on WS-03', True], ['ubu-ws12-vm', 'UBU 24', 'VM on ubu-ws12', True]]
STATE = {'WS-07': 'bad', 'WS-09': 'off', 'alma-db01': 'warn', 'WS-12': 'warn'}
NOTE = {'WS-07': 'Log cleared ×2', 'WS-09': 'Silent 6 days', 'alma-db01': 'auditd rules missing',
        'WS-12': 'Late 9 h on Tue'}
DETS = {'WS-07': (2, 1), 'ubu-ws12': (0, 1), 'WS-09': (0, 1), 'SRV-DC01': (1, 0), 'WS-02': (1, 0), 'WS-11': (1, 0)}
for s in SYS:
    n = s[0]
    s.append(STATE.get(n, 'ok'))
    ev = random.randint(900, 6000) if 'SRV' not in n else random.randint(18000, 30000)
    if s[3]: ev = random.randint(200, 900)
    s.append(ev)
    s.append(DETS.get(n, (0, 0)))
    cov = [0] * 7
    if n == 'WS-09': cov = [0, 3, 3, 3, 3, 3, 3]
    if n == 'WS-12': cov = [0, 1, 0, 0, 0, 0, 0]
    if n == 'WS-07': cov = [0, 0, 0, 0, 0, 0, 2]
    if n == 'alma-db01': cov = [0, 0, 0, 1, 0, 0, 0]
    if n == 'WS-03-VM1': cov = [0, 0, 3, 3, 0, 0, 0]
    s.append(cov)
    last = {'WS-09': '23 Sep 14:00', 'WS-03-VM1': '28 Sep 22:00'}.get(n, '29 Sep 00:0' + str(random.randint(0, 4)))
    s.append(last)
    s.append([random.randint(20, 100) for _ in range(12)])

def aside(active, sys_badge='!', det="9", counts=("3,912","64","418","31","52","47","6,204")):
    nav = [("layout-dashboard", "Overview", ""), ("server", "Systems", sys_badge), ("shield-alert", "Detections", det),
           ("search", "Search", ""), ("user-round", "People", "")]
    ev = list(zip(["key-round","usb","log-in","users","file-warning","terminal","activity"],
          ["Privileged activity","USB & removable","Failed logons","Accounts & groups","Audit integrity","PowerShell","Logon activity"], counts))
    h = ''.join(f'<a class="{"on" if t == active else ""}">{icon(i, 17)}<span>{t}</span>{f"<em>{b}</em>" if b else ""}</a>' for i, t, b in nav)
    e = ''.join(f'<a>{icon(i, 17)}<span>{t}</span><small>{n}</small></a>' for i, t, n in ev)
    return f'''<aside><div class="brand"><img src="logo.png" alt=""><div><b>Blackbox</b><span>GE Aerospace</span></div></div>
<div class="site"><span>Network</span><b>Lab 3 LAN</b></div><nav>{h}</nav><div class="grp">Events</div><nav>{e}</nav>
<div class="grp">Audit</div><nav><a>{icon("shield-check", 17)}<span>Audit health</span></a><a>{icon("trending-up", 17)}<span>Trends</span></a><a>{icon("scroll-text", 17)}<span>Original logs</span></a></nav></aside>'''

def head(title, crumb, extra=''):
    return f'''<div class="head"><div><div class="crumb">{crumb}</div><h1>{title}</h1></div>
<div class="tools">{extra}<span class="btn">{icon("calendar-range", 16)}22 – 29 Sep 2026</span><span class="btn">{icon("fingerprint", 16)}Verified</span><span class="btn primary">Export</span></div></div>'''

def kpi(l, v, s, vals, bad=False):
    col = T['bad'] if bad else T['accent']
    return f'<div class="panel kpi"><div class="kl">{l}</div><div class="kv {"bad" if bad else ""}">{v}</div><div class="kr"><span class="ks">{s}</span>{spark(vals, col, fill=T["sparkfillbad"] if bad else T["sparkfill"])}</div></div>'

def write(name, body, extra_css=''):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{extra_css}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

def fmt(n): return f'{n:,}'
def hd(h, m):
    a = f'<span class="hi">{h}</span>' if h else '<span class="z">0</span>'
    b = f'<span class="md">{m}</span>' if m else '<span class="z">0</span>'
    return a, b

ALERT = f'<div class="alertbar">{icon("triangle-alert", 18)}<b>2 systems need attention.</b><span>WS-07: Security log cleared twice · WS-09: no collection for 6 days</span><a>Details {icon("chevron-right", 14)}</a></div>'
DAYS = ['Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', 'Mon']

# ---------- L1: Fleet overview ----------
def l1():
    order = sorted(SYS, key=lambda s: ({'bad': 0, 'off': 1, 'warn': 2, 'ok': 3}[s[4]], -(s[6][0] * 10 + s[6][1]), s[0]))
    rows = ''
    for n, os_, role, vm, st, ev, (h, m), cov, last, sp in order:
        a, b = hd(h, m)
        c = ''.join(f'<i class="c{x}" title="{DAYS[i]}"></i>' for i, x in enumerate(cov))
        note = NOTE.get(n, '')
        rows += (f'<tr class="{"sel" if st == "bad" else ""}"><td><span class="dot {st}"></span><b>{n}</b>{"<span class=vm>VM</span>" if vm else ""}</td>'
                 f'<td><span class="os">{os_}</span></td><td><div class="cov">{c}</div></td>'
                 f'<td class="mono sub">{last}</td><td class="n">{fmt(ev)}</td><td class="n">{a}</td><td class="n">{b}</td>'
                 f'<td class="note{"" if note else " sub"}">{note or (role if role!="Workstation" else "")}</td><td>{spark(sp, T["accent"], w=44, h=18)}</td></tr>')
    det = [("high", "Possible covering of tracks", "WS-07", "28 Sep 09:20"), ("high", "Possible password guessing", "WS-07", "28 Sep 06:02"),
           ("high", "Same account failing on several computers", "6 systems", "26 Sep 22:14"), ("high", "New member of Domain Admins", "SRV-DC01", "25 Sep 11:02"),
           ("medium", "Suspicious PowerShell", "WS-09", "22 Sep 15:47"), ("medium", "Administrator activity outside working hours", "ubu-ws12", "27 Sep 23:10")]
    dh = ''.join(f'<tr><td><span class="sv {s}">{"High" if s == "high" else "Med"}</span></td><td><b>{t}</b><span class="mono">{h} · {w}</span></td></tr>' for s, t, h, w in det)
    bars = [("WS-07", 2, 1, 0), ("SRV-DC01", 1, 0, 2), ("WS-02", 1, 0, 0), ("WS-11", 1, 0, 1), ("ubu-ws12", 0, 1, 3), ("WS-09", 0, 1, 0)]
    bh = ''.join(f'<div class="bar"><span class="mono">{n}</span><div class="tb"><s class="h" style="width:{h*22}%"></s><s class="m" style="width:{m*22}%"></s><s class="l" style="width:{l*8}%"></s></div><span class="mono" style="text-align:right">{h+m}</span></div>' for n, h, m, l in bars)
    body = aside("Overview") + f'''<main>{head("Network overview", "Weekly report · 24 systems · collector SRV-DC01 · generated 29 Sep 2026 00:05")}
{ALERT}
<div class="kpis">{kpi("Systems reporting", "23 / 24", "WS-09 silent 6 days", [24,24,24,24,23,23,23,23,24,24,24,23], True)}
{kpi("Detections", "9", "on 6 systems", [3,5,2,4,6,3,2,5,7,4,5,9], True)}
{kpi("Events collected", "84.2k", "+3% vs. avg", [80,82,79,85,83,81,84,86,82,83,81,84])}
{kpi("Privileged actions", "3,912", "by 11 people", [3700,3810,3650,3990,3880,3900,3770,3950,3820,3890,3860,3912])}</div>
<div class="row" style="grid-template-columns:1fr 330px">
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems</h2><div style="display:flex;gap:10px;align-items:center"><div class="seg"><span class="on">All 24</span><span>Windows 16</span><span>Linux 8</span><span>Needs attention 4</span></div></div></div>
<table class="fleet"><thead><tr><th>System</th><th>OS</th><th>Last 7 days</th><th>Last report</th><th class="n">Events</th><th class="n">High</th><th class="n">Med</th><th>Note</th><th>Trend</th></tr></thead><tbody>{rows}</tbody></table>
<div class="legend"><span><i class="c0"></i>Collected</span><span><i class="c1"></i>Late</span><span><i class="c2"></i>Log cleared / lost</span><span><i class="c3"></i>No data</span></div></div>
<div style="display:grid;gap:12px;align-content:start">
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Latest detections</h2><span class="pm">9 this week</span></div><table>{dh}</table><div class="pm" style="margin-top:10px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div>
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Detections by system</h2><span class="pm">High · Medium · Low</span></div><div class="bars">{bh}</div></div>
<div class="panel"><div class="ph"><h2>{icon("trending-up", 17)}High-severity events</h2><span class="pm">Network · 12 weeks</span></div>{trend(T["bad"], T["grid"], w=300, h=160)}</div>
</div></div></main>'''
    write('L1-fleet', body)

# ---------- L2: Fleet matrix ----------
def l2():
    order = sorted(SYS, key=lambda s: ({'bad': 0, 'off': 1, 'warn': 2, 'ok': 3}[s[4]], s[0]))
    tiles = ''
    for n, os_, role, vm, st, ev, (h, m), cov, last, sp in order:
        a, b = hd(h, m)
        tiles += f'<div class="tile {st}"><b>{n}<small>{os_}</small></b><span>{NOTE.get(n, role)}</span><div class="tn">{fmt(ev)} ev · {a}H · {b}M</div></div>'
    cats = ['Privileged', 'Logons', 'Failed', 'USB', 'Accounts', 'PowerShell', 'Integrity', 'Detections']
    random.seed(3)
    rows = ''
    mxv = [600, 900, 90, 14, 8, 14, 12, 3]
    for n, os_, role, vm, st, ev, (h, m), cov, last, sp in order[:24]:
        vals = [random.randint(20, 420), random.randint(80, 700), random.randint(0, 30), random.choice([0, 0, 0, 1, 2, 5]),
                random.choice([0, 0, 0, 1, 2]), random.choice([0, 0, 0, 1, 3]) if os_.startswith('W') else 0, 0, h + m]
        if n == 'WS-07': vals = [588, 640, 82, 6, 7, 2, 12, 3]
        if n == 'SRV-DC01': vals = [560, 880, 61, 0, 6, 4, 1, 1]
        if n == 'ubu-ws12': vals[0] = 412; vals[3] = 8
        if n == 'WS-09': vals = [44, 61, 3, 0, 0, 11, 0, 1]
        cells = ''
        for i, v in enumerate(vals):
            t = min(v / mxv[i], 1)
            if i >= 6 and v:
                bg = lerp('#FDECEC', '#D12C2C', t); fg = '#fff' if t > .5 else '#8A1515'
            else:
                bg = ramp(t * .62) if v else 'rgba(0,30,98,.03)'; fg = '#fff' if t > .8 else '#0B1630'
            cells += f'<td class="{"z0" if not v else ""}" style="background:{bg};color:{fg if v else "#9AA5BF"}">{fmt(v) if v else "–"}</td>'
        rows += f'<tr><td><span class="dot {st}"></span>{n}</td>{cells}</tr>'
    # coverage heat: systems x days
    cov = ''
    for i, s in enumerate(order[:24]):
        y = 16 + i * 17
        cov += f'<text x="92" y="{y + 11}" text-anchor="end" class="ax">{s[0]}</text>'
        for d in range(7):
            for hh in range(0, 24, 2):
                x = 100 + d * 12 * 14.4 + hh // 2 * 14.4
                c = s[7][d]
                col = {0: lerp('#D7E3FA', '#0A2A7A', random.random() * .55 + (0.3 if 3 <= hh // 2 <= 8 else 0)), 1: '#E08A00', 2: '#D12C2C', 3: 'rgba(0,30,98,.07)'}[c]
                if c == 2 and hh < 12: col = lerp('#D7E3FA', '#0A2A7A', .4)
                cov += f'<rect x="{x}" y="{y}" width="13" height="14" fill="{col}"/>'
    for d in range(7):
        cov += f'<text x="{100 + d * 172.8}" y="10" class="ax">{DAYS[d]} {23 + d} Sep</text>'
    covsvg = f'<svg viewBox="0 0 1312 {16 + 24 * 17}" width="100%">{cov}</svg>'
    body = aside("Systems") + f'''<main>{head("Systems", "Weekly report · 24 systems · collector SRV-DC01", '<span class="btn">' + icon("list-filter", 16) + 'All systems</span>')}
{ALERT}
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("monitor", 17)}Fleet status</h2><span class="pm"><span class="dot bad"></span>1 integrity problem · <span class="dot off"></span>1 silent · <span class="dot warn"></span>2 warnings · <span class="dot ok"></span>20 healthy</span></div><div class="tiles">{tiles}</div></div>
<div class="row" style="grid-template-columns:1fr">
<div class="panel"><div class="ph"><h2>{icon("history", 17)}Collection timeline</h2><span class="pm">2-hour blocks · a gap means no data from that system</span></div>{covsvg}
<div class="legend"><span><i style="background:#3D5FA8"></i>Collected (darker = busier)</span><span><i style="background:#E08A00"></i>Late</span><span><i style="background:#D12C2C"></i>Log cleared</span><span><i style="background:rgba(0,30,98,.1)"></i>No data</span></div></div>
<div class="panel"><div class="ph"><h2>{icon("layers", 17)}Activity by system</h2><span class="pm">Events this week · darker is more · red is integrity</span></div>
<table class="mx"><thead><tr><th>System</th>{"".join(f"<th>{c}</th>" for c in cats)}</tr></thead><tbody>{rows}</tbody></table></div>
</div></main>'''
    write('L2-matrix', body)

# ---------- L3: Standalone with VM ----------
def l3():
    def card(ic, name, sub, st, facts, badge):
        f = ''.join(f'<div>{k}<b class="{c}">{v}</b></div>' for k, v, c in facts)
        return f'''<div class="panel"><div class="sc"><div class="ic">{icon(ic, 22)}</div><div><h3>{name} {badge}</h3><p>{sub}</p></div>
<span class="sv {st}" style="align-self:start;{'' if st=='high' else 'color:#147A3D'}">{"Needs attention" if st == "high" else "Healthy"}</span></div><div class="facts">{f}</div></div>'''
    c1 = card("monitor", "ENG-WS-21", "Windows 11 Enterprise 24H2 · Hyper-V host · standalone", "high",
              [("Events", "6,412", ""), ("Detections", "2 high", "bad"), ("Coverage", "7 / 7 days", ""), ("Audit settings", "2 gaps", "bad")], "")
    c2 = card("box", "ENG-WS-21-VM1", "Ubuntu 24.04 · guest VM · sends to host share", "ok",
              [("Events", "1,208", ""), ("Detections", "0", ""), ("Coverage", "5 / 7 days", ""), ("Audit settings", "OK", "")], '<span class="vm">VM</span>')
    det = DET[:2] + [("medium", "Administrator activity outside working hours", "jsmith ran 14 sudo commands between 23:10 and 23:41.", "ENG-WS-21-VM1", "27 Sep 23:10")]
    det[0] = (det[0][0], det[0][1], det[0][2], "ENG-WS-21", det[0][4]); det[1] = (det[1][0], det[1][1], det[1][2], "ENG-WS-21", det[1][4])
    rows = ''.join(f'<tr><td><span class="sv {s}">{"High" if s == "high" else "Medium"}</span></td><td><b>{t}</b><span>{d}</span></td><td class="mono">{h}</td><td class="mono">{w}</td></tr>' for s, t, d, h, w in det)
    tl = ''
    for i, (n, cov) in enumerate([("ENG-WS-21", [0] * 7), ("ENG-WS-21-VM1", [0, 0, 3, 3, 0, 0, 0])]):
        y = 18 + i * 22
        tl += f'<text x="112" y="{y + 12}" text-anchor="end" class="ax">{n}</text>'
        for d in range(7):
            for hh in range(12):
                col = lerp('#D7E3FA', '#0A2A7A', random.random() * .5 + (.35 if 3 <= hh <= 8 else 0)) if cov[d] == 0 else 'rgba(0,30,98,.07)'
                tl += f'<rect x="{120 + d * 168 + hh * 14}" y="{y}" width="12" height="18" fill="{col}"/>'
    for d in range(7): tl += f'<text x="{120 + d * 168}" y="11" class="ax">{DAYS[d]} {23+d} Sep</text>'
    tls = f'<svg viewBox="0 0 1300 64" width="100%">{tl}</svg>'
    body = aside("Overview", "", "3", ("203","6","17","4","9","5","412")).replace('<span>Network</span><b>Lab 3 LAN</b>', '<span>System</span><b>ENG-WS-21</b>') + f'''<main>{head("Overview", "Weekly report · standalone · 1 system + 1 VM · generated 29 Sep 2026 00:05")}
<div class="sys2">{c1}{c2}</div>
<div class="kpis">{kpi("Detections", "3", "2 high · 1 medium", [1,0,1,2,0,1,0,1,2,0,1,3], True)}
{kpi("Failed logons", "17", "normal for this system", [12,15,9,18,14,11,16,13,15,12,14,17])}
{kpi("Privileged actions", "203", "by 2 people", [180,190,170,210,200,195,185,205,190,198,192,203])}
{kpi("USB events", "6", "1 new device", [2,0,4,1,0,3,2,0,1,5,2,6])}</div>
<div class="row r1"><div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Detections</h2><span class="pm">Host and VM</span></div>
<table><thead><tr><th>Severity</th><th>Detection</th><th>System</th><th>When</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="panel"><div class="ph"><h2>{icon("shield-check", 17)}Audit trail</h2><span class="pm sev-bad">2 gaps</span></div>
<div class="ti ok"><div class="tic">{icon("shield-check", 16)}</div><div><b>No events lost to rollover</b><span>168 collection runs on the host, 120 on the VM</span></div></div>
<div class="ti bad"><div class="tic">{icon("file-warning", 16)}</div><div><b>2 audit settings below STIG</b><span>Removable Storage auditing off · PowerShell logging off</span></div></div>
<div class="ti ok"><div class="tic">{icon("hard-drive", 16)}</div><div><b>Original logs archived</b><span>logs-ENG-WS-21.zip · 96 MB</span></div></div></div></div>
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("history", 17)}Collection timeline</h2><span class="pm">2-hour blocks · the VM was powered off Thu–Fri, so it has no data then</span></div>{tls}</div>
<div class="row r2"><div class="panel"><div class="ph"><h2>{icon("activity", 17)}Activity by hour</h2><span class="pm">Host and VM · darker is busier</span></div>{heat(ramp, T)}</div>
<div class="panel"><div class="ph"><h2>{icon("trending-up", 17)}High-severity events</h2><span class="pm">Last 12 weeks</span></div>{trend(T["bad"], T["grid"])}</div></div>
</main>'''
    write('L3-standalone', body)

l1(); l2(); l3()
