import os, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'searchp.py')).read().replace('q1(); q2(); q3()', ''))

PPL = [  # name, kind, systems, logons, admin, after, failed, dets, last, note, sev
    ("admin_jd", "Administrator", 6, 13, 188, 0, 0, 4, "28 Sep 12:40", "Cleared a log and changed auditing", "bad"),
    ("jsmith", "Administrator", 2, 22, 131, 14, 1, 1, "27 Sep 23:41", "14 sudo commands after hours", "warn"),
    ("svc_backup", "Service account", 6, 840, 0, 0, 18, 1, "29 Sep 00:00", "Failed on 6 systems in 9 minutes", "warn"),
    ("mjones", "User · new admin", 3, 19, 22, 0, 2, 1, "28 Sep 16:05", "Added to Domain Admins on 25 Sep", "warn"),
    ("tempuser", "New account", 1, 1, 4, 0, 0, 1, "28 Sep 09:31", "Created and made admin on 28 Sep", "bad"),
    ("svc_patch", "Service account", 3, 210, 71, 0, 0, 0, "29 Sep 00:00", "", ""),
    ("kpatel", "User", 2, 31, 0, 0, 3, 0, "28 Sep 17:12", "", ""),
    ("lnguyen", "User", 1, 27, 0, 0, 0, 0, "28 Sep 16:48", "", ""),
    ("rgarcia", "User", 1, 25, 0, 0, 4, 0, "28 Sep 15:30", "", ""),
    ("bwilliams", "User", 2, 24, 0, 0, 0, 0, "27 Sep 11:02", "", ""),
    ("dchen", "Administrator", 4, 18, 64, 0, 0, 0, "28 Sep 14:20", "", ""),
    ("administrator", "Built-in admin", 1, 0, 0, 0, 6, 1, "28 Sep 06:02", "Target of password guessing", "bad")]

C9 = '''
.plist a{display:grid;grid-template-columns:30px 1fr auto;gap:10px;align-items:center;padding:8px 16px;color:#0B1630}
.plist a.sel{background:rgba(11,95,255,.08);box-shadow:inset 3px 0 #0B5FFF}
.av{width:30px;height:30px;display:grid;place-items:center;font:650 12px PS;color:#0A2A7A;background:rgba(11,95,255,.1);border:1px solid rgba(11,95,255,.2)}
.av.bad{color:#B01C1C;background:#FDECEC;border-color:#F5C2C2}.av.warn{color:#8F4F00;background:#FDF3E1;border-color:#F3D9A8}
.plist a b{display:block;font-size:13px;font-weight:600}.plist a span{display:block;font-size:11.5px;color:#8A96B3}.plist a small{font:12px SCP;color:#8A96B3}
.plist .grp2{padding:12px 16px 6px;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785}
.ph2{display:flex;gap:16px;align-items:center}.ph2 .av{width:52px;height:52px;font-size:18px}
.mini{display:grid;gap:7px}.mini div{display:grid;grid-template-columns:96px 1fr 40px;gap:10px;align-items:center;font-size:12.5px}
.mini s{display:block;height:8px;background:#0B5FFF;opacity:.7}.mini b{font:12.5px SCP;text-align:right}
table.pt{width:100%;border-collapse:collapse}table.pt th{padding:0 12px 9px;white-space:nowrap}table.pt th.n{text-align:right}
table.pt td{padding:10px 12px;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px;white-space:nowrap}table.pt td.n{text-align:right;font:12.5px SCP}
table.pt td .who{display:flex;gap:10px;align-items:center}table.pt td .who b{font-weight:600;display:block}table.pt td .who span{font-size:11.5px;color:#8A96B3}
table.pt tr.bad td:first-child{box-shadow:inset 3px 0 #D12C2C}table.pt tr.warn td:first-child{box-shadow:inset 3px 0 #E08A00}
.rk{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}
.rc{padding:14px 16px;background:rgba(255,255,255,.75);border:1px solid rgba(0,30,98,.09);border-top:3px solid #E08A00}.rc.bad{border-top-color:#D12C2C}
.rc .t{display:flex;gap:12px;align-items:center}.rc .t b{font-size:15px;font-weight:650;display:block}.rc .t span{font-size:12px;color:#5A6785}
.rc p{margin:10px 0;font-size:13px;font-weight:600}.rc.bad p{color:#B01C1C}.rc p{color:#8F4F00}
.rc .nums{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid rgba(0,30,98,.07);padding-top:9px}.rc .nums div{font-size:11px;color:#8A96B3}.rc .nums b{display:block;font:600 14px PS;color:#0B1630}
'''

def page6(name, body):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

PHEAD = head("People", "Weekly report · 41 accounts active on 24 systems")
ini = lambda n: n[:2].upper()

def week_heat(w=520):
    random.seed(9); out = ''; cw = (w - 40) / 24
    for d, day in enumerate(['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']):
        out += f'<text x="32" y="{d * 18 + 25}" text-anchor="end" class="ax">{day}</text>'
        for h in range(24):
            v = 0
            if d < 5 and 8 <= h < 17: v = random.random() * .6 + .2
            if d == 0 and h in (6, 9, 12): v = 1
            if d == 3 and h in (10, 11): v = .9
            col = lerp('#EEF2FA', '#0A2A7A', v) if v else 'rgba(0,30,98,.04)'
            if d == 0 and h in (6, 12): col = '#D12C2C'
            out += f'<rect x="{40 + h * cw:.1f}" y="{d * 18 + 13}" width="{cw - 2:.1f}" height="15" fill="{col}"/>'
    for h in range(0, 24, 6): out += f'<text x="{40 + h * cw:.0f}" y="9" class="ax">{h:02d}:00</text>'
    return f'<svg viewBox="0 0 {w} 142" width="100%">{out}</svg>'

# ---------- P1: list + profile ----------
def p1():
    groups = [("Needs a look", [p for p in PPL if p[10]]), ("Administrators", [p for p in PPL if not p[10] and 'Admin' in p[1]]),
              ("Service accounts", [p for p in PPL if not p[10] and 'Service' in p[1]]), ("Users", [p for p in PPL if not p[10] and p[1] == 'User'])]
    lst = '<div class="search">' + icon("search", 14) + 'Find a person</div>'
    for g, ps in groups:
        lst += f'<div class="grp2">{g} · {len(ps)}</div>'
        for p in ps:
            lst += f'<a class="{"sel" if p[0] == "admin_jd" else ""}"><div class="av {p[10]}">{ini(p[0])}</div><div><b>{p[0]}</b><span>{p[1]}</span></div><small>{p[2]} sys</small></a>'
    sysb = ''.join(f'<div><span>{s}</span><s style="width:{v / 21 * 100:.0f}%"></s><b>{v}</b></div>' for s, v in [("WS-07", 21), ("SRV-DC01", 11), ("WS-11", 6), ("WS-04", 5), ("WS-02", 3), ("ubu-ws10", 1)])
    acts = [("bad", "eraser", "Cleared the Security log twice", "WS-07 · Mon 12:38, 12:40"), ("bad", "user-plus", "Added tempuser to Administrators", "WS-07 · Mon 09:20"),
            ("bad", "settings", "Turned off Removable Storage auditing", "WS-07 · Mon 09:38"), ("warn", "user-plus", "Added mjones to Domain Admins", "SRV-DC01 · Fri 11:02"),
            ("warn", "settings", "Changed logon auditing to Success only", "WS-11 · Wed 10:05")]
    ah = ''.join(f'<div class="ck2 {k}"><div class="i">{icon(i, 14)}</div><div><b>{t}</b><span>{d}</span></div><div></div></div>' for k, i, t, d in acts)
    body = aside("People") + f'''<main>{PHEAD}
<div class="md2" style="grid-template-columns:280px 1fr"><div class="panel plist slist" style="padding:12px 0">{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div class="ph2"><div class="av bad">AJ</div><div><h3>admin_jd</h3><p>Administrator · domain account LAB3\\admin_jd · first seen 14 Mar 2026</p></div></div><span class="sv high">Needs a look</span></div>
<div class="facts4"><div>Systems used<b>6</b></div><div>Logons<b>13</b></div><div>Admin actions<b>188</b></div><div>After hours<b>0</b></div><div>Detections<b class="bad">4 high</b></div></div></div>
<div class="row" style="grid-template-columns:1.2fr 1fr;margin-bottom:12px">
<div class="panel"><div class="ph"><h2>{icon("triangle-alert", 17)}Notable actions</h2><span class="pm">5 this week</span></div>{ah}</div>
<div style="display:grid;gap:12px;align-content:start"><div class="panel"><div class="ph"><h2>{icon("activity", 17)}When they were active</h2><span class="pm">Red = detection</span></div>{week_heat(360)}</div>
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems used</h2><span class="pm">Events</span></div><div class="mini">{sysb}</div></div></div></div>
</div></div></main>'''
    page6('P1-profile', body)

# ---------- P2: table ----------
def p2():
    rows = ''
    for n, k, sy, lo, ad, af, fa, de, last, note, sev in PPL:
        nt = f'<span class="why {sev}">{note}</span>' if note else ''
        def z(v, cls=''):
            return f'<span class="{cls}">{v}</span>' if v else '<span class="mute">0</span>'
        rows += (f'<tr class="{sev}"><td><div class="who"><div class="av {sev}">{ini(n)}</div><div><b>{n}</b><span>{k}</span></div></div></td>'
                 f'<td class="n">{sy}</td><td class="n">{lo}</td><td class="n">{z(ad)}</td><td class="n">{z(af, "md")}</td><td class="n">{z(fa)}</td>'
                 f'<td class="n">{z(de, "hi")}</td><td class="mono mute" style="font-size:12px">{last}</td><td>{nt}</td></tr>')
    chips = '<div class="chips"><span class="on">All<i>41</i></span><span>Needs a look<i>6</i></span><span>Administrators<i>4</i></span><span>Service accounts<i>2</i></span><span>New this week<i>1</i></span></div>'
    body = aside("People") + f'''<main>{PHEAD}
<div class="panel"><div class="toolbar">{chips}<span class="btn">{icon("search", 15)}Find a person</span></div>
<table class="pt"><thead><tr><th>Person</th><th class="n">Systems</th><th class="n">Logons</th><th class="n">Admin actions</th><th class="n">After hours</th><th class="n">Failed logons</th><th class="n">Detections</th><th>Last seen</th><th>Why</th></tr></thead><tbody>{rows}</tbody></table>
<div class="more"><span>29 more people with routine activity</span><a>Show all →</a></div></div>
</main>'''
    page6('P2-table', body)

# ---------- P3: ranked cards + compact table ----------
def p3():
    top = [p for p in PPL if p[10]]
    cards = ''
    for n, k, sy, lo, ad, af, fa, de, last, note, sev in top:
        cards += (f'<div class="rc {sev}"><div class="t"><div class="av {sev}">{ini(n)}</div><div><b>{n}</b><span>{k}</span></div></div><p>{note}</p>'
                  f'<div class="nums"><div>Systems<b>{sy}</b></div><div>Admin<b>{ad}</b></div><div>Failed<b>{fa}</b></div><div>Detections<b class="{"hi" if de else ""}">{de}</b></div></div></div>')
    rest = [p for p in PPL if not p[10]]
    rows = ''.join(f'<tr><td><div class="who"><div class="av">{ini(n)}</div><div><b>{n}</b><span>{k}</span></div></div></td><td class="n">{sy}</td><td class="n">{lo}</td><td class="n">{ad}</td><td class="n">{fa}</td><td class="mono mute" style="font-size:12px">{last}</td></tr>' for n, k, sy, lo, ad, af, fa, de, last, note, sev in rest)
    body = aside("People") + f'''<main>{PHEAD}
<div class="ph" style="margin-bottom:10px"><h2>{icon("triangle-alert", 17)}Worth a look · 6 people</h2><span class="pm">Ranked by detections, then unusual activity</span></div>
<div class="rk">{cards}</div>
<div class="panel"><div class="toolbar"><h2>{icon("users", 17)}Everyone else · 35 people</h2><span class="btn">{icon("search", 15)}Find a person</span></div>
<table class="pt"><thead><tr><th>Person</th><th class="n">Systems</th><th class="n">Logons</th><th class="n">Admin actions</th><th class="n">Failed logons</th><th>Last seen</th></tr></thead><tbody>{rows}</tbody></table>
<div class="more"><span>29 more</span><a>Show all →</a></div></div>
</main>'''
    page6('P3-ranked', body)

p1(); p2(); p3()
