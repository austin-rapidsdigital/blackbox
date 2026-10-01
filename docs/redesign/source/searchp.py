import os, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'detp.py')).read().replace('d1(); d2(); d3()', ''))

C8 = '''
.qbar{display:flex;align-items:center;gap:10px;padding:0 14px;height:46px;border:1px solid rgba(0,30,98,.18);background:#fff;font:14px SCP;color:#0B1630}
.qbar svg{color:#5A6785}.qbar .k{color:#0B5FFF}.qbar .v{color:#0B1630;font-weight:600}.qbar .op{color:#A35A00}
.qbar .go2{margin-left:auto;font:600 13px PS;background:#0A2A7A;color:#fff;padding:7px 14px}
.qhelp{display:flex;gap:16px;font-size:12px;color:#5A6785;margin-top:8px}.qhelp code{font:12px SCP;color:#0A2A7A;background:rgba(11,95,255,.07);padding:1px 5px}
.fields h4{margin:0;padding:12px 16px 4px;font-size:12.5px;font-weight:650;color:#0B1630;display:flex;justify-content:space-between}.fields h4 small{font:500 11.5px SCP;color:#8A96B3}
.fields a{display:grid;grid-template-columns:1fr 46px 28px;gap:8px;align-items:center;padding:3px 16px;font-size:12.5px;color:#3A4766}
.fields a s{height:6px;background:rgba(11,95,255,.55);display:block}.fields a small{font:11.5px SCP;color:#8A96B3;text-align:right}
table.res{width:100%;border-collapse:collapse;font-size:12.5px}table.res th{padding:0 10px 8px;white-space:nowrap}
table.res td{padding:8px 10px;border-bottom:1px solid rgba(0,30,98,.07);white-space:nowrap;vertical-align:top}
table.res td.msg{white-space:normal;color:#22304F}table.res td.mono{font-size:12px}table.res tr.open td{background:rgba(11,95,255,.05);border-bottom:0}
table.res tr.raw td{background:rgba(11,95,255,.05);padding:0 10px 12px 10px}
.rawbox{font:11.5px/1.6 SCP;color:#22304F;background:#fff;border:1px solid rgba(0,30,98,.1);padding:10px 12px;display:grid;grid-template-columns:150px 1fr;gap:0 14px}
.rawbox span{color:#5A6785}
.hl{background:rgba(255,196,0,.35);padding:0 1px}
.builder{display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-size:15px;color:#22304F}
.builder .pick{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;border:1px solid rgba(0,30,98,.18);background:#fff;font-weight:600;color:#0A2A7A}
.builder .pick svg{color:#5A6785}
.saved{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px}
.saved a{display:flex;gap:10px;align-items:center;padding:10px 12px;border:1px solid rgba(0,30,98,.1);background:rgba(255,255,255,.7);font-size:13px;font-weight:550;color:#0B1630}
.saved a svg{color:#0B5FFF;flex:none}
.qs{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.qcard{padding:14px 16px;border:1px solid rgba(0,30,98,.1);background:rgba(255,255,255,.72)}.qcard.on{border-color:#0B5FFF;box-shadow:inset 0 0 0 1px #0B5FFF;background:rgba(11,95,255,.05)}
.qcard b{display:flex;gap:9px;align-items:center;font-size:13.5px;font-weight:650}.qcard b svg{color:#0B5FFF}.qcard span{display:block;font-size:12.5px;color:#5A6785;margin-top:4px}
.ans{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.ans div{border:1px solid rgba(0,30,98,.08);background:rgba(255,255,255,.7);padding:12px 14px;font-size:12.5px;color:#5A6785}.ans b{display:block;font:700 22px PS;color:#0A2A7A;letter-spacing:-.3px}
.pivot td{padding:9px 10px}
'''

def page5(name, body):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

QHEAD = head("Search", "Weekly report · 84,212 events from 24 systems · searched in your browser, nothing leaves this file")

EVR = [("28 Sep 12:40:09", "WS-07", "1102", "Security log cleared", "admin_jd", "The Security log was cleared.", "high"),
       ("28 Sep 12:38:51", "WS-07", "1102", "Security log cleared", "admin_jd", "The Security log was cleared.", "high"),
       ("28 Sep 09:38:02", "WS-07", "4719", "Audit policy changed", "admin_jd", "Removable Storage: Success, Failure → No auditing", "high"),
       ("28 Sep 09:20:14", "WS-07", "4732", "Added to security group", "admin_jd", "tempuser added to Administrators", "high"),
       ("28 Sep 08:55:30", "WS-07", "4624", "Logon", "admin_jd", "Remote Desktop from 10.1.1.42", ""),
       ("25 Sep 11:02:47", "SRV-DC01", "4728", "Added to security group", "admin_jd", "mjones added to Domain Admins", "high"),
       ("25 Sep 10:58:12", "SRV-DC01", "4624", "Logon", "admin_jd", "Console", ""),
       ("23 Sep 10:05:40", "WS-11", "4719", "Audit policy changed", "admin_jd", "Logon: Success, Failure → Success", "medium"),
       ("23 Sep 09:59:03", "WS-11", "4624", "Logon", "admin_jd", "Remote Desktop from 10.1.1.42", ""),
       ("22 Sep 16:20:18", "WS-04", "4672", "Admin rights used", "admin_jd", "SeDebugPrivilege, SeBackupPrivilege", "")]

def hist(w=1100, h=70, hi=None):
    random.seed(5); vals = [random.randint(0, 3) for _ in range(84)]
    for i in (75, 77, 80, 81): vals[i] = 5 + i % 3
    vals[37] = 4; vals[12] = 3
    mx = 8; bw = w / 84; out = ''
    for i, v in enumerate(vals):
        if v:
            bh = v / mx * (h - 16)
            out += f'<rect x="{i * bw + .5:.1f}" y="{h - 14 - bh:.1f}" width="{bw - 1.5:.1f}" height="{bh:.1f}" fill="#0B5FFF" opacity=".7"/>'
    for d in range(7):
        out += f'<text x="{d * w / 7 + 2:.0f}" y="{h - 2}" class="ax">{DAYS[d]} {22 + d}</text>'
    return f'<svg viewBox="0 0 {w} {h}" width="100%">{out}</svg>'

# ---------- Q1: Splunk-style query ----------
def q1():
    flds = [("Person", "1", [("admin_jd", 47)]), ("System", "6", [("WS-07", 21), ("SRV-DC01", 11), ("WS-11", 6), ("WS-04", 5), ("WS-02", 3)]),
            ("Event", "9", [("Logon", 18), ("Admin rights used", 12), ("Audit policy changed", 3), ("Added to group", 2), ("Log cleared", 2)]),
            ("Event ID", "9", [("4624", 18), ("4672", 12), ("4719", 3), ("1102", 2)]), ("Logon type", "2", [("Remote Desktop", 13), ("Console", 5)])]
    fh = ''
    for name, n, vals in flds:
        mx = max(v for _, v in vals)
        fh += f'<h4>{name}<small>{n} values</small></h4>' + ''.join(f'<a><span>{l}</span><s style="width:{v / mx * 100:.0f}%"></s><small>{v}</small></a>' for l, v in vals)
    rows = ''
    for i, (t, h, eid, ev, who, msg, sev) in enumerate(EVR):
        sv = f'<span class="sv {sev}">{SEVL(sev)}</span>' if sev else '<span class="mute">—</span>'
        rows += f'<tr class="{"open" if i == 2 else ""}"><td class="mono">{t}</td><td><b>{h}</b></td><td class="mono">{eid}</td><td>{ev}</td><td><span class="hl">{who}</span></td><td class="msg">{msg}</td><td>{sv}</td></tr>'
        if i == 2:
            rows += '''<tr class="raw"><td colspan="7"><div class="rawbox"><span>Log</span>Security · WS-07 · logs-WS-07.zip
<span>Record ID</span>482113<span>Subject</span>WS07\\admin_jd (S-1-5-21-…-1104)<span>Category</span>Object Access<span>Subcategory</span>Removable Storage {6A5F…}
<span>Changes</span>Success removed, Failure removed</div></td></tr>'''
    body = aside("Search") + f'''<main>{QHEAD}
<div class="panel" style="margin-bottom:12px"><div class="qbar">{icon("search", 17)}<span><span class="k">person:</span><span class="v">admin_jd</span> <span class="op">AND</span> <span class="k">time:</span><span class="v">this week</span></span><span class="go2">Search</span></div>
<div class="qhelp"><span>Try</span><code>system:WS-07</code><code>id:4624</code><code>usb</code><code>"Domain Admins"</code><code>after-hours</code><span style="margin-left:auto">47 events match · 0.04 s</span></div>
<div style="margin-top:14px">{hist()}</div></div>
<div class="md2" style="grid-template-columns:260px 1fr"><div class="panel fields" style="padding:6px 0 14px">{fh}</div>
<div class="panel"><div class="toolbar"><h2>{icon("list-filter", 17)}47 events</h2><div class="chips"><span class="on">Newest</span><span>Oldest</span><span>Export CSV</span></div></div>
<table class="res"><thead><tr><th>Time</th><th>System</th><th>ID</th><th>Event</th><th>Person</th><th>Details</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table></div></div>
</main>'''
    page5('Q1-query', body)

# ---------- Q2: guided builder ----------
def q2():
    rows = ''
    for t, h, eid, ev, who, msg, sev in EVR:
        sv = f'<span class="sv {sev}">{SEVL(sev)}</span>' if sev else ''
        rows += f'<tr><td class="mono">{t}</td><td><b>{h}</b></td><td>{ev}</td><td>{who}</td><td class="msg">{msg}</td><td>{sv}</td></tr>'
    saved = [("key-round", "Everything one person did"), ("usb", "USB devices on servers"), ("moon", "Admin work after hours"), ("log-in", "Failed logons by source"),
             ("user-plus", "Changes to admin groups"), ("eraser", "Logs cleared or audit changed"), ("terminal", "PowerShell that downloads"), ("monitor", "Remote Desktop logons")]
    sh = ''.join(f'<a>{icon(i, 16)}{t}</a>' for i, t in saved)
    dn = icon("chevron-down", 14)
    body = aside("Search") + f'''<main>{QHEAD}
<div class="panel" style="margin-bottom:12px"><div class="builder">Show <span class="pick">{icon("layers", 15)}All events{dn}</span> by <span class="pick">{icon("user-round", 15)}admin_jd{dn}</span> on <span class="pick">{icon("server", 15)}Any system{dn}</span> during <span class="pick">{icon("calendar-range", 15)}This week{dn}</span> containing <span class="pick" style="font-weight:500;color:#8A96B3;min-width:200px">{icon("search", 15)}any text</span></div>
<div class="sub2" style="margin-top:18px">Common searches</div><div class="saved" style="margin-top:0">{sh}</div></div>
<div class="panel"><div class="toolbar"><h2>{icon("list-filter", 17)}47 events by admin_jd on 6 systems</h2><div class="chips"><span class="on">Newest</span><span>Group by system</span><span>Export CSV</span></div></div>
<div style="margin-bottom:12px">{hist(h=60)}</div>
<table class="res"><thead><tr><th>Time</th><th>System</th><th>Event</th><th>Person</th><th>Details</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table></div>
</main>'''
    page5('Q2-guided', body)

# ---------- Q3: questions + pivot answers ----------
def q3():
    qs = [("user-round", "What did a person do?", "Every action by one account, on every system"), ("server", "Who used a system?", "Logons and admin work on one computer"),
          ("usb", "Where was a USB device used?", "Every system a drive was plugged into"), ("log-in", "Where are failed logons coming from?", "Grouped by source address and account"),
          ("moon", "What happened after hours?", "Admin activity outside working hours"), ("search", "Search all events", "Free text, event IDs, file names")]
    qh = ''.join(f'<div class="qcard {"on" if i == 0 else ""}"><b>{icon(ic, 16)}{t}</b><span>{d}</span></div>' for i, (ic, t, d) in enumerate(qs))
    piv = [("WS-07", "Windows 11", 21, "Logon ×6, admin rights ×9, added tempuser to Administrators, turned off USB auditing, cleared Security log ×2", "28 Sep 12:40"),
           ("SRV-DC01", "Server 2025", 11, "Logon ×4, admin rights ×6, added mjones to Domain Admins", "25 Sep 11:02"),
           ("WS-11", "Windows 11", 6, "Logon ×2, admin rights ×3, changed logon auditing", "23 Sep 10:05"),
           ("WS-04", "Windows 11", 5, "Logon ×2, admin rights ×3", "22 Sep 16:20"),
           ("WS-02", "Windows 11", 3, "Logon ×2, admin rights ×1", "24 Sep 08:41"),
           ("ubu-ws10", "Ubuntu 24.04", 1, "SSH logon from 10.1.1.42", "26 Sep 13:12")]
    ph = ''.join(f'<tr><td><b>{s}</b><span class="mute" style="display:block;font-size:12px">{o}</span></td><td class="n">{n}</td><td class="msg">{d}</td><td class="mono">{l}</td><td class="go">{icon("chevron-right", 16)}</td></tr>' for s, o, n, d, l in piv)
    body = aside("Search") + f'''<main>{QHEAD}
<div class="panel" style="margin-bottom:12px"><div class="qs">{qh}</div></div>
<div class="panel"><div class="ph"><div class="builder" style="font-size:16px">What did <span class="pick">{icon("user-round", 15)}admin_jd{icon("chevron-down", 14)}</span> do this week?</div><span class="chips"><span>Export CSV</span></span></div>
<div class="ans"><div><b>47</b>events</div><div><b>6</b>systems</div><div><b class="bad" style="color:#C22020">4</b>detections involve admin_jd</div><div><b>13</b>Remote Desktop logons, all from 10.1.1.42</div></div>
<div class="sub2">By system</div>
<table class="res pivot"><thead><tr><th>System</th><th class="n" style="text-align:right">Events</th><th>What happened</th><th>Last</th><th></th></tr></thead><tbody>{ph}</tbody></table>
<div class="pm" style="margin-top:12px;color:#0B5FFF;font-weight:600">Show all 47 events →</div></div>
</main>'''
    page5('Q3-questions', body)

q1(); q2(); q3()
