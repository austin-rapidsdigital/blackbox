import os, re, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'evp2.py')).read().replace('fe1(); fe2(); fe3()', ''))

C11 = '''
.fbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.dd{display:inline-flex;align-items:center;gap:6px;padding:6px 9px;border:1px solid rgba(0,30,98,.16);background:#fff;font-size:12.5px;color:#3A4766;white-space:nowrap}
.dd b{font-weight:600;color:#0B1630}.dd svg{color:#8A96B3}.dd.on{border-color:#0B5FFF;background:rgba(11,95,255,.06)}.dd.on b{color:#0A2A7A}
.dd.txt{flex:1;min-width:160px;color:#8A96B3}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;background:#0A2A7A;color:#fff;font-size:12px;font-weight:600}
.pager{display:flex;justify-content:space-between;align-items:center;padding-top:12px;font-size:12.5px;color:#5A6785}
.pager span.p{display:inline-flex;gap:4px}.pager span.p i{font-style:normal;padding:3px 9px;border:1px solid rgba(0,30,98,.12);background:#fff}.pager span.p i.on{background:#0A2A7A;color:#fff;border-color:#0A2A7A}
.res .r{font-size:12px;font-weight:600}.res .r.bad{color:#22304F;font-weight:500}.res .r.ok{color:#147A3D}.res .r.lock{color:#8F4F00}
.dstrip{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.sec{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;margin:18px 0 8px;display:flex;justify-content:space-between}
.colf th{position:relative}.colf th u{display:block;margin-top:5px;text-decoration:none;font:500 11.5px PS;letter-spacing:0;text-transform:none;color:#8A96B3;border:1px solid rgba(0,30,98,.12);background:#fff;padding:3px 6px}
.colf th u.on{color:#0A2A7A;border-color:#0B5FFF;background:rgba(11,95,255,.06);font-weight:600}
.grprow td{background:rgba(0,30,98,.035);font-weight:600}
'''

def page9(name, body):
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>Failed logons</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}{C11}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

random.seed(21)
ALL = [("28 Sep 06:02:41", "WS-07", "administrator", "10.1.1.99", "Remote Desktop", "Bad password", "high"),
       ("28 Sep 06:02:39", "WS-07", "administrator", "10.1.1.99", "Remote Desktop", "Bad password", "high"),
       ("28 Sep 06:01:58", "ubu-ws10", "root", "10.1.1.99", "SSH", "Bad password", "high"),
       ("28 Sep 08:54:12", "WS-07", "admin_jd", "10.1.1.42", "Remote Desktop", "Bad password", ""),
       ("27 Sep 23:08:40", "ubu-ws12", "jsmith", "local", "sudo", "Bad password", ""),
       ("27 Sep 16:21:03", "WS-04", "bwilliams", "console", "Console", "Bad password", ""),
       ("26 Sep 22:14:09", "SRV-DC01", "svc_backup", "10.1.1.24", "Network", "Bad password", "high"),
       ("26 Sep 22:14:07", "SRV-FS01", "svc_backup", "10.1.1.24", "Network", "Bad password", "high"),
       ("25 Sep 13:40:55", "WS-08", "lnguyen", "console", "Console", "Bad password", ""),
       ("24 Sep 09:10:44", "SRV-FS01", "lnguyen", "10.1.1.31", "Network", "Password expired", ""),
       ("23 Sep 08:31:02", "WS-05", "kpatel", "console", "Console", "Bad password", ""),
       ("22 Sep 08:02:15", "WS-11", "rgarcia", "console", "Console", "Locked out", "medium")]

def rowsfor(rows):
    out = ''
    for t, s, a, src, how, why, sev in rows:
        rc = 'bad' if why == 'Bad password' else 'lock'
        sv = f'<span class="sv {sev}">{SEVL(sev)}</span>' if sev else '<span class="mute">—</span>'
        out += f'<tr><td class="mono">{t}</td><td><b>{s}</b></td><td>{a}</td><td class="mono">{src}</td><td>{how}</td><td><span class="r {rc}">{why}</span></td><td>{sv}</td></tr>'
    return out
TH = '<thead><tr><th>Time</th><th>System</th><th>Account</th><th>Source</th><th>Logon type</th><th>Reason</th><th>Severity</th></tr></thead>'
PAGER = '<div class="pager"><span>Showing 1–12 of 418</span><span class="p"><i class="on">1</i><i>2</i><i>3</i><i>…</i><i>35</i></span><span>Export CSV</span></div>'

def stacked_day(w=640, h=170):
    bad = [44, 52, 50, 47, 40, 63, 58]; exp = [6, 7, 6, 6, 7, 9, 6]; lock = [2, 2, 2, 2, 2, 4, 3]
    mx = 80; x0 = 30; bw = (w - x0) / 7; out = ''
    for v in (0, 40, 80):
        y = h - 22 - v / mx * (h - 34)
        out += f'<line x1="{x0}" x2="{w}" y1="{y:.1f}" y2="{y:.1f}" stroke="{T["grid"]}"/><text x="{x0 - 6}" y="{y + 4:.1f}" text-anchor="end" class="ax">{v}</text>'
    for i in range(7):
        x = x0 + i * bw + bw * .22; ww = bw * .56; y = h - 22
        for v, c in ((bad[i], '#0B5FFF'), (exp[i], '#7FA6E8'), (lock[i], '#E08A00')):
            hh = v / mx * (h - 34); y -= hh
            out += f'<rect x="{x:.1f}" y="{y:.1f}" width="{ww:.1f}" height="{hh:.1f}" fill="{c}"/>'
        if i == 6:
            out += f'<rect x="{x - 3:.1f}" y="{y - 3:.1f}" width="{ww + 6:.1f}" height="{h - 22 - y + 3:.1f}" fill="none" stroke="#D12C2C" stroke-width="1.5"/>'
        out += f'<text x="{x + ww / 2:.1f}" y="{h - 6}" text-anchor="middle" class="ax">{DAYS[i]}</text>'
    return f'<svg viewBox="0 0 {w} {h}" width="100%">{out}</svg><div class="legend"><span><i style="background:#0B5FFF"></i>Bad password</span><span><i style="background:#7FA6E8"></i>Expired</span><span><i style="background:#E08A00"></i>Locked out</span>'+('<span><i style="background:none;outline:1.5px solid #D12C2C"></i>Above normal</span>' if w > 500 else '')+'</div>'

def topsrc():
    rows = [("10.1.1.99", 31, True), ("10.1.1.24", 18, True), ("WS-11 console", 9, False), ("WS-05 console", 7, False), ("10.1.1.31", 5, False), ("10.1.1.42", 4, False)]
    return '<div class="mini">' + ''.join(f'<div><span>{l}</span><s style="width:{v / 31 * 100:.0f}%;{"background:#D12C2C" if hot else ""}"></s><b>{v}</b></div>' for l, v, hot in rows) + '</div>'

def detstrip():
    ds = [("high", "Password guessing from 10.1.1.99", "31 failures on WS-07 and ubu-ws10 in 8 minutes; 3 accounts tried; no success.", "Mon 06:01"),
          ("high", "Same account failing on several computers", "svc_backup failed on 6 systems within 9 minutes from 10.1.1.24.", "Sat 22:14"),
          ("medium", "Account locked out twice", "rgarcia was locked out on WS-11 at 08:02 and 08:19.", "Tue 08:02")]
    return ''.join(f'<div class="dc {s}"><div class="b"><b>{t}</b><span>{d}</span></div><div class="m2">{w}</div></div>' for s, t, d, w in ds)

def filters(active=True):
    dn = icon("chevron-down", 13)
    return f'''<div class="fbar"><span class="dd txt">{icon("search", 14)}Filter text…</span>
<span class="dd {"on" if active else ""}">Severity <b>{"High" if active else "Any"}</b>{dn}</span><span class="dd">System <b>Any</b>{dn}</span><span class="dd">Account <b>Any</b>{dn}</span>
<span class="dd">Source <b>Any</b>{dn}</span><span class="dd">Type <b>Any</b>{dn}</span><span class="dd">Reason <b>Any</b>{dn}</span><span class="dd">Day <b>All</b>{dn}</span></div>'''

# ---------- V1: stacked sections, filter bar ----------
def v1():
    body = aside("Failed logons") + f'''<main>{FHEAD}{FKP}
<div class="row" style="grid-template-columns:1.5fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("calendar-range", 17)}Failed logons per day</h2><span class="pm">By reason</span></div>{stacked_day()}</div>
<div class="panel"><div class="ph"><h2>{icon("log-in", 17)}Top sources</h2><span class="pm">Red = flagged</span></div>{topsrc()}</div></div>
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("shield-alert", 17)}Flagged this week</h2><span class="pm">3 of 418 failed logons are part of something unusual</span></div><div class="dstrip">{detstrip()}</div></div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}All failed logons · 418</h2><span class="pm">Click a row for the full event</span></div>{filters(False)}
<table class="res">{TH}<tbody>{rowsfor(ALL)}</tbody></table>{PAGER}</div>
</main>'''
    page9('V1-stacked', body)

# ---------- V2: same top, events with facet rail ----------
def v2():
    flds = [("Severity", [("High", 49), ("Medium", 2), ("None", 367)]), ("Reason", [("Bad password", 362), ("Password expired", 37), ("Locked out", 19)]),
            ("Logon type", [("Console", 171), ("Network", 132), ("Remote Desktop", 88), ("SSH", 21), ("sudo", 6)]),
            ("Account", [("administrator", 27), ("svc_backup", 18), ("rgarcia", 9), ("kpatel", 7), ("lnguyen", 5)]),
            ("System", [("WS-07", 41), ("SRV-DC01", 33), ("WS-11", 14), ("SRV-FS01", 12), ("ubu-ws10", 9)])]
    fh = ''
    for name, vals in flds:
        mx = max(v for _, v in vals)
        fh += f'<h4>{name}<small>{len(vals)}</small></h4>' + ''.join(f'<a><span>{l}</span><s style="width:{v / mx * 100:.0f}%"></s><small>{v}</small></a>' for l, v in vals)
    body = aside("Failed logons") + f'''<main>{FHEAD}{FKP}
<div class="row" style="grid-template-columns:1fr 1fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("calendar-range", 17)}Per day</h2></div>{stacked_day(w=420, h=150)}</div>
<div class="panel"><div class="ph"><h2>{icon("log-in", 17)}Top sources</h2></div>{topsrc()}</div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Flagged · 3</h2></div><div class="dl">{detstrip()}</div></div></div>
<div class="md2" style="grid-template-columns:250px 1fr"><div class="panel fields" style="padding:6px 0 14px">{fh}</div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}All failed logons</h2><span class="pm"><span class="pill">Reason: Bad password ✕</span> &nbsp;362 of 418</span></div>
<div style="margin-bottom:10px">{hist(h=56)}</div>
<table class="res">{TH}<tbody>{rowsfor([r for r in ALL if r[5] == "Bad password"])}</tbody></table>{PAGER.replace("of 418", "of 362")}</div></div>
</main>'''
    page9('V2-facets', body)

# ---------- V3: compact top, grouped table with column filters ----------
def v3():
    heat = week_heat(560)
    groups = [("10.1.1.99 · KALI · not a known system", "31 failures · 3 accounts · 2 systems", "high", ALL[:3]),
              ("10.1.1.24 · svc_backup", "18 failures · 6 systems", "high", ALL[6:8]),
              ("Consoles (keyboard at the system)", "171 failures · 38 accounts", "", [ALL[5], ALL[8], ALL[10], ALL[11]])]
    tb = ''
    for g, sub, sev, rows in groups:
        sv = f'<span class="sv {sev}">{SEVL(sev)}</span>' if sev else ''
        tb += f'<tr class="grprow"><td colspan="5">{icon("chevron-down", 13)} {g} <span class="mute" style="font-weight:400">· {sub}</span></td><td></td><td>{sv}</td></tr>' + rowsfor(rows)
    th = '''<thead class="colf"><tr><th>Time<u>All week</u></th><th>System<u>Any</u></th><th>Account<u>Any</u></th><th>Source<u>Any</u></th><th>Logon type<u>Any</u></th><th>Reason<u>Any</u></th><th>Severity<u>Any</u></th></tr></thead>'''
    body = aside("Failed logons") + f'''<main>{FHEAD}{FKP}
<div class="row" style="grid-template-columns:1fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("activity", 17)}When failures happen</h2><span class="pm">Darker = more · red = flagged</span></div>{heat}</div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Flagged · 3</h2></div><div class="dl">{detstrip()}</div></div></div>
<div class="panel"><div class="toolbar"><h2>{icon("list-filter", 17)}All failed logons · 418</h2><div class="chips"><span>No grouping</span><span class="on">Group by source</span><span>Group by account</span><span>Group by system</span></div></div>
<table class="res">{th}<tbody>{tb}</tbody></table>{PAGER.replace("Showing 1–12 of 418", "Showing 3 of 23 sources")}</div>
</main>'''
    page9('V3-grouped', body)

v1(); v2(); v3()
