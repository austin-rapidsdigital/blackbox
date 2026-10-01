import os
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'sysp.py')).read().replace('s1(); s2(); s3()', ''))

D9 = [("high", "Possible covering of tracks", "admin_jd added tempuser to Administrators, then turned off Removable Storage auditing 18 min later.", "WS-07", "admin_jd", "Mon 28 Sep", "09:20", 3, "Tampering"),
      ("high", "Possible password guessing", "6 failed logons for administrator in 40 s from 10.1.1.99.", "WS-07", "administrator", "Mon 28 Sep", "06:02", 6, "Logons"),
      ("high", "Security log cleared", "The Security log was cleared twice, at 12:38 and 12:40.", "WS-07", "admin_jd", "Mon 28 Sep", "12:38", 2, "Tampering"),
      ("medium", "Administrator activity outside working hours", "jsmith ran 14 sudo commands between 23:10 and 23:41.", "ubu-ws12", "jsmith", "Sun 27 Sep", "23:10", 14, "After hours"),
      ("high", "Same account failing on several computers", "svc_backup failed on 6 systems within 9 minutes.", "6 systems", "svc_backup", "Sat 26 Sep", "22:14", 18, "Logons"),
      ("high", "New member of Domain Admins", "mjones was added to Domain Admins by admin_jd.", "SRV-DC01", "admin_jd", "Fri 25 Sep", "11:02", 1, "Accounts"),
      ("medium", "New USB storage device", "Kingston DataTraveler (0951:1666) first seen on WS-02.", "WS-02", "mjones", "Thu 24 Sep", "14:31", 2, "USB"),
      ("medium", "Audit policy changed", "Logon auditing changed from Success and Failure to Success only.", "WS-11", "admin_jd", "Wed 23 Sep", "10:05", 1, "Tampering"),
      ("medium", "Suspicious PowerShell", "A script downloads and runs code from 10.1.1.99.", "WS-09", "SYSTEM", "Tue 22 Sep", "15:47", 3, "PowerShell")]

C7 = '''
.facet{padding:14px 0}.facet h4{margin:0;padding:12px 16px 6px;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785}
.facet a{display:grid;grid-template-columns:16px 1fr auto;gap:8px;align-items:center;padding:5px 16px;font-size:13px;color:#0B1630}
.facet a small{font:12px SCP;color:#8A96B3}.facet a u{width:13px;height:13px;border:1px solid rgba(0,30,98,.3);display:block;text-decoration:none;background:#fff}
.facet a.on u{background:#0A2A7A;border-color:#0A2A7A;box-shadow:inset 0 0 0 2px #fff}
.facet a b.hi{color:#C22020;font-weight:600}.facet a b.md{color:#A35A00;font-weight:600}
.dcx{display:grid;grid-template-columns:4px 1fr 150px 120px;gap:0 16px;background:rgba(255,255,255,.72);border:1px solid rgba(0,30,98,.08);align-items:stretch}
.dcx:before{content:"";background:#D12C2C}.dcx.medium:before{background:#E08A00}
.dcx .b{padding:12px 0}.dcx .b b{display:block;font-weight:650;font-size:14px}.dcx .b span{display:block;font-size:13px;color:#3A4766;margin-top:3px}
.dcx .b .tags{display:flex;gap:6px;margin-top:8px}.tag{font-size:11px;font-weight:600;color:#3A4766;border:1px solid rgba(0,30,98,.12);padding:1px 7px;background:rgba(255,255,255,.7)}
.dcx .c{padding:12px 0;font-size:12.5px;color:#5A6785}.dcx .c b{display:block;font:600 13px PS;color:#0B1630}
.dcx .w{padding:12px 16px 12px 0;text-align:right;font:12.5px SCP;color:#3A4766}.dcx .w small{display:block;color:#8A96B3;margin-top:3px}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.dlist a{display:grid;grid-template-columns:4px 1fr;gap:0 12px;border-bottom:1px solid rgba(0,30,98,.07);color:#0B1630}
.dlist a:before{content:"";background:#D12C2C}.dlist a.medium:before{background:#E08A00}
.dlist a div{padding:10px 14px 10px 0}.dlist a b{display:block;font-size:13px;font-weight:600}.dlist a span{display:block;font:11.5px SCP;color:#8A96B3;margin-top:2px}
.dlist a.sel{background:rgba(11,95,255,.08)}
.dlist .dayh{padding:0 16px;margin:14px 0 6px}
.seq{position:relative;padding-left:22px}.seq:before{content:"";position:absolute;left:6px;top:6px;bottom:6px;width:2px;background:rgba(0,30,98,.12)}
.seq div{position:relative;padding:0 0 14px}.seq div:before{content:"";position:absolute;left:-20px;top:5px;width:10px;height:10px;background:#fff;border:2px solid #0A2A7A}
.seq div.k:before{background:#D12C2C;border-color:#D12C2C}
.seq b{font:600 12.5px SCP;color:#0B1630;margin-right:10px}.seq span{font-size:13px;color:#3A4766}.seq small{display:block;font:11.5px SCP;color:#8A96B3;margin-top:2px}
.why2{background:rgba(11,95,255,.05);border:1px solid rgba(11,95,255,.15);padding:12px 14px;font-size:13px;color:#22304F;line-height:1.55}
.kv2{display:grid;grid-template-columns:110px 1fr;gap:7px 12px;font-size:13px}.kv2 span{color:#5A6785}.kv2 b{font-weight:600}
table.ev{width:100%;border-collapse:collapse;font-size:12.5px}table.ev th{padding:0 10px 7px}table.ev td{padding:7px 10px;border-bottom:1px solid rgba(0,30,98,.07);white-space:nowrap}table.ev td.mono{font-size:12px}
table.dt{width:100%;border-collapse:collapse}table.dt th{padding:0 12px 9px;white-space:nowrap}table.dt td{padding:11px 12px;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px;vertical-align:top}
table.dt td b{font-weight:600;display:block;white-space:nowrap}table.dt td span.s{display:block;font-size:12.5px;color:#5A6785;margin-top:2px}table.dt td.n{text-align:right;font:12.5px SCP}table.dt th.n{text-align:right}
table.dt td.mono{font-size:12.5px;white-space:nowrap}
'''

def page4(name, body):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

DHEAD = head("Detections", "Weekly report · 24 systems · 9 detections · 5 high, 4 medium")
SEVL = lambda s: "High" if s == "high" else "Medium"

def facets():
    def grp(title, items):
        return f'<h4>{title}</h4>' + ''.join(f'<a class="{"on" if on else ""}"><u></u><span>{l}</span><small>{c}</small></a>' for l, c, on in items)
    return (grp("Severity", [('<b class="hi">High</b>', 5, True), ('<b class="md">Medium</b>', 4, True)]) +
            grp("Type", [("Tampering", 3, True), ("Logons", 2, True), ("Accounts", 1, True), ("After hours", 1, True), ("USB", 1, True), ("PowerShell", 1, True)]) +
            grp("System", [("WS-07", 3, True), ("SRV-DC01", 1, True), ("ubu-ws12", 1, True), ("WS-02", 1, True), ("WS-09", 1, True), ("WS-11", 1, True), ("6 systems", 1, True)]) +
            grp("Person", [("admin_jd", 4, True), ("jsmith", 1, True), ("svc_backup", 1, True), ("mjones", 1, True), ("administrator", 1, True), ("SYSTEM", 1, True)]))

# ---------- D1: filter rail + cards ----------
def d1():
    order = sorted(D9, key=lambda d: (d[0] != 'high', d[5][4:], d[6]), reverse=False)
    order = [d for d in D9 if d[0] == 'high'] + [d for d in D9 if d[0] != 'high']
    cards = '<div class="dayh">High · 5</div>'
    first_med = True
    for s, t, d, sysn, who, day, tm, n, typ in order:
        if s == 'medium' and first_med:
            cards += '<div class="dayh" style="margin-top:16px">Medium · 4</div>'; first_med = False
        cards += (f'<div class="dcx {s}"><div class="b"><b>{t}</b><span>{d}</span><div class="tags"><span class="tag">{typ}</span><span class="tag">{n} event{"s" if n != 1 else ""}</span></div></div>'
                  f'<div class="c">System<b>{sysn}</b><span style="display:block;margin-top:6px">Person</span><b>{who}</b></div><div class="w">{day}<small>{tm}</small></div></div>')
    body = aside("Detections") + f'''<main>{DHEAD}
<div class="md2" style="grid-template-columns:240px 1fr"><div class="panel facet" style="padding:6px 0 14px">{facets()}</div>
<div class="panel"><div class="toolbar"><div class="chips"><span class="on">Severity</span><span>Newest</span><span>System</span></div><span class="btn">{icon("search", 15)}Filter detections</span></div>
<div class="dl">{cards}</div></div></div></main>'''
    page4('D1-queue', body)

# ---------- D2: list + detail ----------
def d2():
    lst = ''; day = None
    for i, (s, t, d, sysn, who, dy, tm, n, typ) in enumerate(sorted(D9, key=lambda x: (x[5][4:6], x[6]), reverse=True)):
        if dy != day:
            lst += f'<div class="dayh">{dy}</div>'; day = dy
        lst += f'<a class="{s} {"sel" if t.startswith("Possible covering") else ""}"><div><b>{t}</b><span>{sysn} · {tm}</span></div></a>'
    seq = [("09:20:14", "admin_jd added tempuser to Administrators", "Event 4732 · Security", True),
           ("09:22:40", "tempuser logged on (Remote Desktop) from 10.1.1.42", "Event 4624 · logon type 10", False),
           ("09:31:05", "tempuser copied files to E:\\ (Kingston DataTraveler)", "Event 4663 · Removable Storage", False),
           ("09:38:02", "admin_jd turned off Removable Storage auditing", "Event 4719 · audit policy change", True)]
    sq = ''.join(f'<div class="{"k" if k else ""}"><b>{t}</b><span>{a}</span><small>{e}</small></div>' for t, a, e, k in seq)
    evrows = [("28 Sep 09:20:14", "4732", "Member added to security group", "admin_jd", "Administrators ← tempuser"),
              ("28 Sep 09:22:40", "4624", "Logon", "tempuser", "Type 10 · 10.1.1.42"),
              ("28 Sep 09:31:05", "4663", "Object access", "tempuser", "E:\\export\\drawings.zip"),
              ("28 Sep 09:38:02", "4719", "Audit policy changed", "admin_jd", "Removable Storage: Success, Failure → No auditing")]
    evh = ''.join(f'<tr><td class="mono">{a}</td><td class="mono">{b}</td><td>{c}</td><td>{d}</td><td class="mute">{e}</td></tr>' for a, b, c, d, e in evrows)
    body = aside("Detections") + f'''<main>{DHEAD}
<div class="md2" style="grid-template-columns:300px 1fr"><div class="panel dlist" style="padding:4px 0 10px"><div class="chips" style="padding:12px 16px 0"><span class="on">All<i>9</i></span><span>High<i>5</i></span><span>Medium<i>4</i></span></div>{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div><h3>Possible covering of tracks</h3><p>WS-07 · Mon 28 Sep 2026, 09:20 – 09:38 · 4 related events</p></div><span class="sv high">High</span></div>
<div class="why2"><b>Why this was flagged:</b> someone was given administrator rights and, within 30 minutes, auditing was turned down on the same system. Together these can hide what the new administrator did.</div></div>
<div class="row" style="grid-template-columns:1.3fr 1fr;margin-bottom:12px">
<div class="panel"><div class="ph"><h2>{icon("history", 17)}What happened</h2><span class="pm">In order</span></div><div class="seq">{sq}</div></div>
<div class="panel"><div class="ph"><h2>{icon("user-round", 17)}Involved</h2></div><div class="kv2"><span>System</span><b>WS-07 · Windows 11</b><span>Done by</span><b>admin_jd</b><span>Affected</span><b>tempuser (new admin)</b><span>Source</span><b>10.1.1.42</b><span>Device</span><b>Kingston DataTraveler</b></div>
<div class="sub2" style="margin-top:16px">Related this week</div><div class="dl">
<div class="dc"><div class="b"><b>Security log cleared</b><span>WS-07 · Mon 12:38</span></div><div></div></div></div></div></div>
<div class="panel"><div class="ph"><h2>{icon("scroll-text", 17)}Events</h2><span class="pm">From the original logs · logs-WS-07.zip</span></div>
<table class="ev"><thead><tr><th>Time</th><th>ID</th><th>Event</th><th>Account</th><th>Details</th></tr></thead><tbody>{evh}</tbody></table></div>
</div></div></main>'''
    page4('D2-investigate', body)

# ---------- D3: timeline + table ----------
def d3():
    W = 780; x0 = 56; dw = (W - x0) / 7
    svg = ''
    for d in range(7):
        x = x0 + d * dw
        svg += f'<rect x="{x:.0f}" y="18" width="{dw * 6 / 24 + dw * 6 / 24:.0f}" height="84" fill="rgba(0,30,98,.03)"/>' if False else ''
        svg += f'<line x1="{x:.0f}" x2="{x:.0f}" y1="16" y2="104" stroke="rgba(0,30,98,.1)"/><text x="{x + 6:.0f}" y="12" class="ax">{DAYS[d]} {23 + d - 1 if d else 22} Sep</text>'
    for lane, (lab, y) in enumerate([("High", 42), ("Medium", 82)]):
        svg += f'<text x="{x0 - 10}" y="{y + 4}" text-anchor="end" class="ax" style="font-weight:600">{lab}</text><line x1="{x0}" x2="{W}" y1="{y}" y2="{y}" stroke="rgba(0,30,98,.08)"/>'
    dayidx = {'Tue 22 Sep': 0, 'Wed 23 Sep': 1, 'Thu 24 Sep': 2, 'Fri 25 Sep': 3, 'Sat 26 Sep': 4, 'Sun 27 Sep': 5, 'Mon 28 Sep': 6}
    for s, t, d, sysn, who, dy, tm, n, typ in D9:
        hh, mm = map(int, tm.split(':'))
        x = x0 + dayidx[dy] * dw + (hh + mm / 60) / 24 * dw
        y = 42 if s == 'high' else 82
        col = '#D12C2C' if s == 'high' else '#E08A00'
        svg += f'<rect x="{x - 6:.0f}" y="{y - 6}" width="12" height="12" fill="{col}" stroke="#fff" stroke-width="1.5"/>'
    tl = f'<svg viewBox="0 0 {W} 108" width="100%">{svg}</svg>'
    rows = ''
    for s, t, d, sysn, who, dy, tm, n, typ in sorted(D9, key=lambda x: (x[5][4:6], x[6]), reverse=True):
        rows += f'<tr><td><span class="sv {s}">{SEVL(s)}</span></td><td><b>{t}</b><span class="s">{d}</span></td><td>{typ}</td><td><b>{sysn}</b></td><td>{who}</td><td class="n">{n}</td><td class="mono">{dy[4:]} {tm}</td><td class="go">{icon("chevron-right", 16)}</td></tr>'
    by = [("Tampering", 3), ("Logons", 2), ("Accounts", 1), ("After hours", 1), ("USB", 1), ("PowerShell", 1)]
    byh = ''.join(f'<div class="bar"><span>{l}</span><div class="tb"><s class="l" style="width:{c / 3 * 100:.0f}%;background:#0B5FFF;opacity:.7"></s></div><span class="mono" style="text-align:right">{c}</span></div>' for l, c in by)
    body = aside("Detections") + f'''<main>{DHEAD}
<div class="row" style="grid-template-columns:1fr 300px">
<div class="panel"><div class="ph"><h2>{icon("calendar-range", 17)}When they happened</h2><span class="pm">One square per detection</span></div>{tl}</div>
<div class="panel"><div class="ph"><h2>{icon("layers", 17)}By type</h2></div><div class="bars">{byh}</div></div></div>
<div class="panel"><div class="toolbar"><div class="chips"><span class="on">All<i>9</i></span><span>High<i>5</i></span><span>Medium<i>4</i></span></div><div class="chips"><span>{icon("server", 13)} Any system</span><span>{icon("user-round", 13)} Anyone</span><span>{icon("search", 13)} Filter</span></div></div>
<table class="dt"><thead><tr><th>Severity</th><th>Detection</th><th>Type</th><th>System</th><th>Person</th><th class="n">Events</th><th>When</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
</main>'''
    page4('D3-timeline', body)

d1(); d2(); d3()
