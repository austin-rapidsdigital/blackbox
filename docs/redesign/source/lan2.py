import os, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'lan.py')).read().replace('l1(); l2(); l3()', ''))

CALM = '''
table.q{width:100%;border-collapse:collapse}
table.q th{padding:0 10px 9px;white-space:nowrap}table.q th.n,table.q td.n{text-align:right}
table.q td{padding:9px 10px;border-bottom:1px solid rgba(0,30,98,.07);white-space:nowrap;vertical-align:middle}
table.q td.n{font-family:SCP;font-size:12.5px}table.q td.d{text-align:right;font-size:12.5px}table.q th.d{text-align:right}
table.q td b{font-weight:600}
table.q .os2{color:#5A6785;font-size:12.5px}
table.q tr.grp td{padding:16px 12px 6px;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;border-bottom:1px solid rgba(0,30,98,.14)}
table.q tr.quiet td{color:#3A4766}
.stt{font-size:12.5px;font-weight:600}.stt.bad{color:#C22020}.stt.warn{color:#A35A00}.stt.ok{color:#5A6785;font-weight:500}
.more{display:flex;justify-content:space-between;align-items:center;padding:12px 12px 2px;font-size:12.5px;color:#5A6785}.more a{color:#0B5FFF;font-weight:600}
.tabs{display:flex;gap:22px;border-bottom:1px solid rgba(0,30,98,.12);margin:-2px 0 14px}.tabs span{padding:0 0 10px;font-size:13.5px;font-weight:550;color:#5A6785}.tabs span.on{color:#0B1630;border-bottom:2px solid #0B5FFF}
table.ax2{width:100%;border-collapse:collapse}table.ax2 th{padding:0 10px 9px;text-align:right;white-space:nowrap}table.ax2 th:first-child{text-align:left}
table.ax2 td{padding:7px 10px;text-align:right;font:12.5px SCP;color:#3A4766;border-bottom:1px solid rgba(0,30,98,.06)}table.ax2 td:first-child{text-align:left;font:600 13px PS;color:#0B1630}
table.ax2 td.o{background:rgba(11,95,255,.10);color:#0A2A7A;font-weight:700}table.ax2 td.r{background:#FDECEC;color:#B01C1C;font-weight:700}table.ax2 td.zz{color:#B5BED3}
table.ax2 tr.med td{border-top:1px solid rgba(0,30,98,.18);color:#5A6785;font-size:12px}table.ax2 tr.med td:first-child{font:500 12px PS;color:#5A6785}
'''

def write2(name, body):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

STATUS = {'WS-07': ('bad', 'Log cleared twice'), 'WS-09': ('bad', 'Silent 6 days'),
          'WS-12': ('warn', '9 h late on Tue'), 'alma-db01': ('warn', '3 audit rules missing')}

def l1b():
    att = [s for s in SYS if s[0] in STATUS]
    att.sort(key=lambda s: list(STATUS).index(s[0]))
    rest = sorted([s for s in SYS if s[0] not in STATUS], key=lambda s: (-(s[6][0] * 10 + s[6][1]), s[0]))
    def row(s, quiet):
        n, os_, role, vm, st, ev, (h, m), cov, last, sp = s
        det = f'<span class="hi">{h} high</span>' if h else ''
        det += (' · ' if h and m else '') + (f'<span class="md">{m} med</span>' if m else '')
        if not det: det = '<span class="z">—</span>'
        k, txt = STATUS.get(n, ('ok', 'OK'))
        rl = role if role != 'Workstation' else ''
        return (f'<tr class="{"quiet" if quiet else ""}"><td><b>{n}</b>{"<span class=vm>VM</span>" if vm else ""}</td><td class="os2">{os_.title().replace("Win", "Windows").replace("Ws", "Server").replace("Ubu", "Ubuntu").replace("Alma", "Alma")}{" · " + rl if rl else ""}</td>'
                f'<td class="n">{last}</td><td class="n">{fmt(ev)}</td><td class="d">{det}</td><td><span class="stt {k}">{txt}</span></td></tr>')
    rows = '<tr class="grp"><td colspan="6">Needs attention · 4</td></tr>' + ''.join(row(s, False) for s in att)
    rows += '<tr class="grp"><td colspan="6">Reporting normally · 20</td></tr>' + ''.join(row(s, True) for s in rest[:8])
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
<div class="row" style="grid-template-columns:1fr 340px">
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems</h2><span class="pm">Problems first</span></div>
<table class="q"><thead><tr><th>System</th><th>OS · role</th><th class="n">Last report</th><th class="n">Events</th><th class="d">Detections</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>
<div class="more"><span>12 more systems reporting normally</span><a>All 24 systems →</a></div></div>
<div style="display:grid;gap:12px;align-content:start">
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Latest detections</h2><span class="pm">9 this week</span></div><table>{dh}</table><div class="pm" style="margin-top:10px;color:#0B5FFF;font-weight:600">All 9 detections →</div></div>
<div class="panel"><div class="ph"><h2>{icon("trending-up", 17)}High-severity events</h2><span class="pm">12 weeks</span></div>{trend(T["bad"], T["grid"], w=300, h=170)}</div>
</div></div></main>'''
    write2('L1b-overview', body)

def l2b():
    order = sorted(SYS, key=lambda s: ({'bad': 0, 'off': 1, 'warn': 2, 'ok': 3}[s[4]], s[0]))
    cats = ['Privileged', 'Logons', 'Failed logons', 'USB', 'Accounts', 'PowerShell', 'Integrity', 'Detections']
    random.seed(3)
    data = []
    for s in order:
        n, os_ = s[0], s[1]
        h, m = s[6]
        vals = [random.randint(150, 420), random.randint(100, 700), random.randint(3, 30), random.choice([0, 0, 0, 1, 2]),
                random.choice([0, 0, 0, 1, 2]), random.choice([0, 0, 0, 1, 3]) if os_.startswith('W') else 0, 0, h + m]
        if n == 'WS-07': vals = [588, 640, 82, 6, 7, 2, 12, 3]
        if n == 'SRV-DC01': vals = [560, 880, 61, 0, 6, 4, 1, 1]
        if n == 'ubu-ws12': vals[3] = 8
        if n == 'WS-09': vals = [44, 61, 3, 0, 0, 11, 0, 1]
        data.append((s, vals))
    med = [sorted(v[i] for _, v in data)[len(data) // 2] for i in range(8)]
    rows = ''
    for s, vals in data:
        cells = ''
        for i, v in enumerate(vals):
            if v == 0: cls = 'zz'; txt = '0'
            elif i >= 6: cls = 'r'; txt = fmt(v)
            elif v >= max(3 * med[i], 5): cls = 'o'; txt = fmt(v)
            else: cls = ''; txt = fmt(v)
            cells += f'<td class="{cls}">{txt}</td>'
        rows += f'<tr><td>{s[0]}</td>{cells}</tr>'
    rows += '<tr class="med"><td>Typical (median)</td>' + ''.join(f'<td>{fmt(x)}</td>' for x in med) + '</tr>'
    tabs = '<div class="tabs"><span class="on">Activity</span><span>Coverage</span><span>Audit settings</span></div>'
    body = aside("Systems") + f'''<main>{head("Systems", "Weekly report · 24 systems · collector SRV-DC01")}
<div class="panel">{tabs}<div class="ph"><h2>{icon("layers", 17)}Events per system this week</h2><span class="pm"><span class="dot" style="background:rgba(11,95,255,.35)"></span>Well above typical &nbsp; <span class="dot bad"></span>Integrity problem or detection</span></div>
<table class="ax2"><thead><tr><th>System</th>{"".join(f"<th>{c}</th>" for c in cats)}</tr></thead><tbody>{rows}</tbody></table></div>
</main>'''
    write2('L2b-activity', body)

    # Coverage tab: healthy = one flat light bar; only problems coloured
    W = 1060; x0 = 120; dw = (W - x0) / 7
    svg = ''
    for d in range(7):
        svg += f'<text x="{x0 + d * dw + 4:.0f}" y="12" class="ax">{DAYS[d]} {23 + d}</text><line x1="{x0 + d * dw:.0f}" x2="{x0 + d * dw:.0f}" y1="18" y2="{22 + 24 * 24}" stroke="rgba(0,30,98,.08)"/>'
    gaps = {'WS-07': [(6.45, 6.5, '#D12C2C', 'Log cleared 12:38'), (6.5, 6.52, '#D12C2C', '')],
            'WS-09': [(0.6, 7, None, 'No data since Tue 14:00')],
            'WS-12': [(0.0, 1.0, '#E08A00', 'Delivered 9 h late')],
            'WS-03-VM1': [(2, 4, None, 'Powered off')],
            'ubu-ws12-vm': [(4.5, 5.2, None, 'Powered off')]}
    for i, s in enumerate(order):
        y = 24 + i * 24
        n = s[0]
        svg += f'<text x="{x0 - 12}" y="{y + 12}" text-anchor="end" class="ax" style="font-weight:{600 if n in gaps else 400};fill:{"#0B1630" if n in gaps else "#5A6785"}">{n}</text>'
        svg += f'<rect x="{x0}" y="{y + 2}" width="{W - x0}" height="12" fill="#C9D7F2"/>'
        for a, b, col, lab in gaps.get(n, []):
            xa, xb = x0 + a * dw, x0 + b * dw
            if col is None:
                svg += f'<rect x="{xa:.0f}" y="{y + 2}" width="{xb - xa:.0f}" height="12" fill="#F3F5FA"/><rect x="{xa:.0f}" y="{y + 2}" width="{xb - xa:.0f}" height="12" fill="none" stroke="#B5BED3" stroke-dasharray="3 3"/>'
            else:
                svg += f'<rect x="{xa:.0f}" y="{y + 2}" width="{max(xb - xa, 4):.0f}" height="12" fill="{col}"/>'
            if lab:
                red = col == '#D12C2C'
                tx = xa + 6 if b - a > 1.5 else (xa - 6 if red else xb + 6)
                svg += f'<text x="{tx:.0f}" y="{y + 12}" text-anchor="{"end" if red else "start"}" class="ax" style="font-weight:600;fill:{col or "#5A6785"}">{lab}</text>'
    cov = f'<svg viewBox="0 0 {W} {28 + 24 * 24}" width="100%">{svg}</svg>'
    tabs = '<div class="tabs"><span>Activity</span><span class="on">Coverage</span><span>Audit settings</span></div>'
    body = aside("Systems") + f'''<main>{head("Systems", "Weekly report · 24 systems · collector SRV-DC01")}
<div class="panel">{tabs}<div class="ph"><h2>{icon("history", 17)}When each system sent data</h2><span class="pm">A solid bar means complete · gaps and colours mark problems</span></div>{cov}
<div class="legend"><span><i style="background:#C9D7F2"></i>Collected</span><span><i style="background:#F3F5FA;outline:1px dashed #B5BED3"></i>No data</span><span><i style="background:#E08A00"></i>Late</span><span><i style="background:#D12C2C"></i>Log cleared</span></div></div>
</main>'''
    write2('L2c-coverage', body)

l1b(); l2b()
