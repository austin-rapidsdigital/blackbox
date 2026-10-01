import os, re
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'logsp.py')).read().replace('o1(); o2(); o3()', ''))

C15 = '''
.ov{position:fixed;inset:0;background:rgba(5,15,45,.35);z-index:5}
.drawer{position:fixed;top:0;right:0;bottom:0;width:560px;background:#F7F9FD;border-left:1px solid rgba(0,30,98,.15);box-shadow:-20px 0 50px rgba(0,30,98,.18);z-index:6;padding:22px 24px;overflow:hidden}
.drawer h3{margin:0;font-size:18px;font-weight:700}.drawer .x{position:absolute;right:20px;top:20px;font-size:13px;color:#5A6785;border:1px solid rgba(0,30,98,.15);padding:3px 9px;background:#fff}
.kv3{display:grid;grid-template-columns:140px 1fr;gap:0;border:1px solid rgba(0,30,98,.1);background:#fff;margin-top:14px}
.kv3 span,.kv3 b{padding:7px 12px;border-bottom:1px solid rgba(0,30,98,.06);font-size:12.5px}.kv3 span{color:#5A6785;background:rgba(0,30,98,.025)}.kv3 b{font-weight:500;font-family:SCP;font-size:12px;color:#0B1630}
.raw{margin-top:14px;font:11.5px/1.55 SCP;background:#0B1630;color:#C9D7F2;padding:12px 14px;white-space:pre;overflow:hidden}
.raw .t{color:#7FA6E8}.raw .v{color:#FFD58A}
.acts{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.menu{position:absolute;right:28px;top:84px;width:330px;background:#fff;border:1px solid rgba(0,30,98,.18);box-shadow:0 18px 40px rgba(0,30,98,.18);z-index:6}
.menu a{display:grid;grid-template-columns:22px 1fr;gap:10px;padding:11px 14px;border-bottom:1px solid rgba(0,30,98,.07);color:#0B1630;font-size:13px}
.menu a svg{color:#0B5FFF}.menu a b{display:block;font-weight:600}.menu a span{display:block;font-size:12px;color:#5A6785;margin-top:1px}
.pop{position:absolute;right:120px;top:84px;width:420px;background:#fff;border:1px solid rgba(0,30,98,.18);box-shadow:0 18px 40px rgba(0,30,98,.18);z-index:6;padding:16px 18px}
.pop h4{margin:0 0 4px;font-size:14px;display:flex;gap:8px;align-items:center;color:#147A3D}.pop p{margin:0 0 10px;font-size:12.5px;color:#3A4766}
.pop .ln{display:grid;grid-template-columns:18px 1fr;gap:8px;font-size:12.5px;padding:5px 0;border-top:1px solid rgba(0,30,98,.06)}.pop .ln svg{color:#1A9A50}
.sign{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.fld{display:block;font-size:12px;color:#5A6785}.fld div{margin-top:4px;border:1px solid rgba(0,30,98,.18);background:#fff;padding:8px 10px;font-size:13px;color:#0B1630;min-height:36px}
.fld div.big{min-height:84px;color:#3A4766}
.signed{display:flex;gap:12px;align-items:center;padding:12px 14px;background:rgba(26,154,80,.06);border:1px solid rgba(26,154,80,.2);font-size:13px;color:#14532D}
table.idx{width:100%;border-collapse:collapse}table.idx th{padding:0 12px 9px;white-space:nowrap}table.idx th.n,table.idx td.n{text-align:right}
table.idx td{padding:12px;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px;white-space:nowrap}table.idx td.n{font:12.5px SCP}
table.idx tr.cur td{background:rgba(11,95,255,.05)}
.rv{font-size:12px;font-weight:600}.rv.ok{color:#147A3D}.rv.no{color:#8A96B3;font-weight:500}
.clean{display:flex;gap:16px;align-items:center;padding:18px 20px}.clean .ic{width:44px;height:44px;display:grid;place-items:center;background:#E6F5EC;color:#1A9A50;border:1px solid #BFE3CC}
.clean b{font-size:16px;font-weight:650;display:block}.clean span{font-size:13px;color:#5A6785}
.paper{background:#fff;width:820px;margin:24px auto;padding:44px 52px;box-shadow:0 8px 30px rgba(0,0,0,.12);font-size:12.5px;color:#111}
.paper h1{font-size:22px;margin:0}.paper h2{font-size:14px;margin:22px 0 8px;border-bottom:1.5px solid #111;padding-bottom:4px;color:#111}
.paper table{width:100%;border-collapse:collapse}.paper td,.paper th{border-bottom:1px solid #ccc;padding:5px 6px;text-align:left;font-size:11.5px}.paper th{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:#444}
.paper .hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #001E62;padding-bottom:12px}
.paper .hdr img{width:40px}.paper .kp{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border:1px solid #bbb;margin-top:14px}.paper .kp div{padding:8px 10px;border-left:1px solid #bbb;font-size:11px;color:#444}.paper .kp div:first-child{border-left:0}.paper .kp b{display:block;font-size:18px;color:#111}
.paper .sig{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-top:26px}.paper .sig div{border-top:1px solid #111;padding-top:4px;font-size:10.5px;color:#444}
'''

def pg(name, body, extra=''):
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}{C11}{C12}{C13}{C14}{C15}{extra}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

# ---------- R1: reports index ----------
def r1():
    rows = [("22 – 29 Sep 2026", "24", "84,212", 5, 4, "1 log cleared · 1 silent", "bad", "Not reviewed", "no"),
            ("15 – 22 Sep 2026", "24", "81,904", 2, 2, "Complete", "ok", "J. Ramirez · 23 Sep", "ok"),
            ("8 – 15 Sep 2026", "24", "83,117", 1, 3, "Complete", "ok", "J. Ramirez · 16 Sep", "ok"),
            ("1 – 8 Sep 2026", "23", "79,550", 3, 1, "1 late", "warn", "J. Ramirez · 9 Sep", "ok"),
            ("25 Aug – 1 Sep 2026", "23", "80,233", 0, 2, "Complete", "ok", "K. Osei · 2 Sep", "ok"),
            ("18 – 25 Aug 2026", "23", "82,018", 1, 1, "Complete", "ok", "K. Osei · 26 Aug", "ok")]
    tb = ''
    for i, (w, s, e, h, m, c, ck, rv, rk) in enumerate(rows):
        col = {"ok": "#147A3D", "bad": "#B01C1C", "warn": "#8F4F00"}[ck]
        tb += f'<tr class="{"cur" if i == 0 else ""}"><td><b>{w}</b></td><td class="n">{s}</td><td class="n">{e}</td><td class="n"><span class="{"hi" if h else "z"}">{h}</span></td><td class="n"><span class="{"md" if m else "z"}">{m}</span></td><td style="color:{col};font-weight:600;font-size:12.5px">{c}</td><td><span class="btn" style="padding:4px 10px;font-size:12.5px">Open {icon("chevron-right", 13)}</span></td></tr>'
    trend = weekly_cols(w=1060, h=110)
    body = f'''<aside><div class="brand"><img src="logo.png" alt=""><div><b>Blackbox</b><span>GE Aerospace</span></div></div>
<div class="site"><span>Network</span><b>Lab 3 LAN</b></div><nav><a class="on">{icon("scroll-text", 17)}<span>All reports</span><small>52</small></a></nav></aside>
<main><div class="head"><div><div class="crumb">\\\\SRV-DC01\\BlackboxReports · weekly, every Monday 00:05</div><h1>Audit reports</h1></div><div class="tools"><span class="btn">{icon("search", 15)}Find a report</span></div></div>
<div class="panel" style="margin-bottom:12px;display:grid;grid-template-columns:260px 1fr;gap:20px;align-items:center"><div><h2>{icon("trending-up", 17)}Detections per week</h2><div class="ks" style="margin-top:6px">Last 12 reports</div>{LEG}</div>{trend}</div>
<div class="panel"><div class="toolbar"><h2>{icon("scroll-text", 17)}Reports · newest first</h2><div class="chips"><span class="on">All<i>52</i></span><span>Incomplete<i>4</i></span></div></div>
<table class="idx"><thead><tr><th>Week</th><th class="n">Systems</th><th class="n">Events</th><th class="n">High</th><th class="n">Medium</th><th>Audit trail</th><th></th></tr></thead><tbody>{tb}</tbody></table>
<div class="more"><span>46 older reports</span><a>Show all →</a></div></div></main>'''
    pg('R1-index', body)

# ---------- R2: standalone overview (M2 style, 1 system + VM) ----------
def r2():
    ev = [("bad", "eraser", "Logs cleared", "0", ""), ("bad", "user-plus", "New admins", "1", "tempuser"), ("warn", "settings", "Policy changes", "1", "USB auditing"),
          ("", "lock", "Lockouts", "0", ""), ("warn", "moon", "After-hours admin", "14", "jsmith · VM"), ("", "usb", "New USB devices", "1", "Kingston")]
    cards = '<div class="ev6">' + ''.join(f'<div class="panel ec {"zero" if v == "0" else k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in ev) + '</div>'
    def card(ic, name, sub, st, facts, badge):
        f = ''.join(f'<div>{k}<b class="{c}">{v}</b></div>' for k, v, c in facts)
        return f'''<div class="panel"><div class="sc"><div class="ic">{icon(ic, 22)}</div><div><h3>{name} {badge}</h3><p>{sub}</p></div>
<span class="sv {st}" style="align-self:start;{'' if st == 'high' else 'color:#147A3D'}">{"Needs attention" if st == "high" else "Healthy"}</span></div><div class="facts">{f}</div></div>'''
    c1 = card("monitor", "ENG-WS-21", "Windows 11 Enterprise 24H2 · Hyper-V host · standalone", "high",
              [("Events", "6,412", ""), ("Detections", "2 high", "bad"), ("Collected", "7 of 7 days", ""), ("Audit settings", "1 gap", "bad")], "")
    c2 = card("box", "ENG-WS-21-VM1", "Ubuntu 24.04 · guest VM · on 41% of the week", "ok",
              [("Events", "1,208", ""), ("Detections", "1 medium", ""), ("Collected", "while on", ""), ("Audit settings", "Match STIG", "")], '<span class="vm">VM</span>')
    ck = ''.join(f'<div class="ck2 {k}"><div class="i">{icon(i, 14)}</div><div><b>{t}</b><span>{w}</span></div><div class="r">{r}</div></div>' for k, i, t, w, r in [
        ("ok", "file-warning", "Logs intact", "No logs cleared", "2/2"), ("ok", "clock-alert", "Every system reporting", "VM reported whenever it was on", "2/2"),
        ("bad", "shield-check", "Audit settings match STIG", "<em>ENG-WS-21</em>: Removable Storage auditing off", "1/2"), ("ok", "hard-drive", "Original logs archived", "2 zips · 136 MB", "2/2")])
    dets = det_cards(3)
    body = aside("Overview", "", "3", ("203", "6", "17", "4", "9", "5", "412")).replace('<span>Network</span><b>Lab 3 LAN</b>', '<span>System</span><b>ENG-WS-21</b>') + f'''<main>{head("Overview", "Weekly report · standalone · 1 system + 1 VM · generated 29 Sep 2026 00:05")}
<div class="sys2">{c1}{c2}</div>
{cards}
<div class="row" style="grid-template-columns:1.35fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("shield-check", 17)}Health</h2></div>{ck}</div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Detections</h2><span class="pm"><span class="hi">2 high</span> · <span class="md">1 medium</span></span></div><div class="dl">{dets}</div></div></div>
<div class="sub2" style="margin:6px 0 8px">Trends · last 12 weeks</div>
<div class="row" style="grid-template-columns:repeat(3,1fr)">
{small_trend("High-severity events", [0,1,0,0,1,0,0,1,0,0,1,2], T["bad"], "2 this week · avg 0.4")}
{small_trend("Failed logons", [12,15,9,18,14,11,16,13,15,12,14,17], T["accent"], "17 · normal")}
{small_trend("Privileged actions", [180,190,170,210,200,195,185,205,190,198,192,203], T["accent"], "203 · normal")}</div></main>'''
    pg('R2-standalone', body)

# ---------- R3: event detail drawer ----------
def r3():
    base = open(f'{SP}/V1-stacked.html').read()
    drawer = f'''<div class="ov"></div><div class="drawer"><span class="x">✕ Close</span>
<div class="pm" style="margin-bottom:4px">Failed logon · event 4625 · Security log</div><h3>administrator failed to log on to WS-07</h3>
<div style="margin-top:6px"><span class="sv high">High</span> <span class="pm" style="margin-left:10px">part of “Password guessing from 10.1.1.99”</span></div>
<div class="kv3"><span>Time</span><b>Mon 28 Sep 2026 06:02:41.338 (UTC−5)</b><span>System</span><b>WS-07 · Windows 11</b><span>Account</span><b>WS07\\administrator</b>
<span>Source address</span><b>10.1.1.99 (KALI) · port 51842</b><span>Logon type</span><b>10 · Remote Desktop</b><span>Reason</span><b>0xC000006A · bad password</b>
<span>Process</span><b>C:\\Windows\\System32\\svchost.exe</b><span>Record ID</span><b>482007</b><span>Original log</span><b>logs-WS-07.zip › Security.evtx</b></div>
<div class="raw"><span class="t">&lt;EventID&gt;</span>4625<span class="t">&lt;/EventID&gt;</span>
<span class="t">&lt;Data Name="TargetUserName"&gt;</span><span class="v">administrator</span><span class="t">&lt;/Data&gt;</span>
<span class="t">&lt;Data Name="Status"&gt;</span><span class="v">0xc000006d</span><span class="t">&lt;/Data&gt;</span>
<span class="t">&lt;Data Name="SubStatus"&gt;</span><span class="v">0xc000006a</span><span class="t">&lt;/Data&gt;</span>
<span class="t">&lt;Data Name="LogonType"&gt;</span><span class="v">10</span><span class="t">&lt;/Data&gt;</span>
<span class="t">&lt;Data Name="IpAddress"&gt;</span><span class="v">10.1.1.99</span><span class="t">&lt;/Data&gt;</span>
<span class="t">&lt;Data Name="WorkstationName"&gt;</span><span class="v">KALI</span><span class="t">&lt;/Data&gt;</span></div>
<div class="acts"><span class="btn">{icon("search", 14)}Everything from 10.1.1.99</span><span class="btn">{icon("user-round", 14)}administrator's page</span><span class="btn">{icon("server", 14)}WS-07's page</span><span class="btn">{icon("shield-alert", 14)}Open detection</span></div>
<div class="sub2" style="margin-top:18px">2 minutes either side on WS-07</div>
<table class="res" style="font-size:12px"><tbody>
<tr><td class="mono">06:01:12</td><td>Logon failed · administrator · 10.1.1.99</td></tr>
<tr style="background:rgba(11,95,255,.07)"><td class="mono"><b>06:02:41</b></td><td><b>This event</b></td></tr>
<tr><td class="mono">06:02:43</td><td>Logon failed · administrator · 10.1.1.99</td></tr>
<tr><td class="mono">06:03:58</td><td>Logon failed · admin · 10.1.1.99</td></tr></tbody></table></div>'''
    base = base.replace('</body>', drawer + '</body>').replace('<style>', f'<style>{C15}')
    open(f'{SP}/R3-event.html', 'w').write(base)

# ---------- R4: Export menu + Verified popover ----------
def r4(which):
    base = open(f'{SP}/M2-split.html').read()
    if which == 'export':
        over = f'''<div class="menu">
<a>{icon("scroll-text", 17)}<div><b>Print or save as PDF</b><span>A clean printable summary with sign-off lines</span></div></a>
<a>{icon("list-filter", 17)}<div><b>Detections as CSV</b><span>9 rows · for a POA&amp;M or ticket</span></div></a>
<a>{icon("layers", 17)}<div><b>All events as CSV</b><span>84,212 rows · for Excel</span></div></a>
<a>{icon("shield-check", 17)}<div><b>Audit health as CSV</b><span>Every system × every STIG check</span></div></a>
<a>{icon("hard-drive", 17)}<div><b>Open the report folder</b><span>Original logs, manifest, summary.json</span></div></a></div>'''
        name = 'R4-export'
    else:
        over = f'''<div class="pop"><h4>{icon("circle-check", 17)}This report has not been changed</h4>
<p>Every file in the report folder matches the SHA-256 list made when the report was written.</p>
<div class="ln">{icon("circle-check", 14)}<span>report.html, summary.json, events.json</span></div>
<div class="ln">{icon("circle-check", 14)}<span>23 original-log zips (3.1 GB)</span></div>
<div class="ln">{icon("circle-check", 14)}<span>Continues from the previous report with no gap (ended 22 Sep 00:05)</span></div>
<div class="ln">{icon("circle-check", 14)}<span>Written by Blackbox 0.9.0 on SRV-DC01, 29 Sep 2026 00:05</span></div>
<p style="margin:10px 0 0;font-size:12px;color:#5A6785">To check it yourself: <code style="font:12px SCP;color:#0A2A7A">blackbox verify</code> in the report folder.</p></div>'''
        name = 'R5-verified'
    base = base.replace('</body>', over + '</body>').replace('<style>', f'<style>{C15}')
    open(f'{SP}/{name}.html', 'w').write(base)

# ---------- R6: ISSO review sign-off ----------
def r6():
    body = aside("").replace('<div class="grp">Audit</div><nav>', f'<div class="grp">Audit</div><nav><a class="on">{icon("circle-check", 17)}<span>Review</span><em>1</em></a>') + f'''<main>{head("Review", "Weekly report · record that someone looked at this report, and what they found")}
<div class="row" style="grid-template-columns:1.2fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("circle-check", 17)}Sign off this report</h2><span class="pm">Saved to review.json in the report folder, then hashed</span></div>
<div class="sign"><label class="fld">Reviewed by<div>J. Ramirez (ISSO)</div></label><label class="fld">Date<div>29 Sep 2026</div></label></div>
<label class="fld" style="margin-top:12px">Detections<div style="padding:0">
<table class="res" style="font-size:12.5px"><tbody>
<tr><td><span class="sv high">High</span></td><td>Possible covering of tracks · WS-07</td><td style="white-space:nowrap"><b>Escalated</b> · INC-4471</td></tr>
<tr><td><span class="sv high">High</span></td><td>Password guessing · WS-07</td><td style="white-space:nowrap"><b>Escalated</b> · INC-4471</td></tr>
<tr><td><span class="sv high">High</span></td><td>Same account failing on 6 systems</td><td style="white-space:nowrap"><b>Explained</b> · password rotated</td></tr>
<tr><td><span class="sv high">High</span></td><td>New member of Domain Admins</td><td><span class="mute">Choose…</span></td></tr>
<tr><td><span class="sv medium">Medium</span></td><td>Suspicious PowerShell · WS-09</td><td><span class="mute">Choose…</span></td></tr></tbody></table></div></label>
<label class="fld" style="margin-top:12px">Notes<div class="big">WS-07 removed from network pending investigation. WS-09 powered off by user; reconnected 30 Sep.</div></label>
<div style="display:flex;gap:8px;margin-top:14px"><span class="btn primary">Sign off</span><span class="btn">Save draft</span><span class="pm" style="align-self:center;margin-left:8px">3 of 5 detections have an outcome</span></div></div>
<div style="display:grid;gap:12px;align-content:start">
<div class="panel"><div class="ph"><h2>{icon("history", 17)}Earlier reviews</h2></div>
<div class="signed">{icon("circle-check", 18)}<div><b>15 – 22 Sep</b> · signed by J. Ramirez on 23 Sep · 2 detections, both explained</div></div>
<div class="signed" style="margin-top:8px">{icon("circle-check", 18)}<div><b>8 – 15 Sep</b> · signed by J. Ramirez on 16 Sep · 1 detection, escalated</div></div></div>
<div class="panel"><div class="ph"><h2>{icon("shield-check", 17)}Why</h2></div><div style="font-size:13px;color:#3A4766;line-height:1.6">AU-6 asks for audit records to be reviewed and findings reported. This page is the record: who reviewed which week, when, and what they decided for each detection. It is printed on the PDF and listed on the reports index.</div></div></div></div></main>'''
    pg('R6-review', body)

# ---------- R7: clean week ----------
def r7():
    ev = [("", "eraser", "Logs cleared", "0", ""), ("", "user-plus", "New admins", "0", ""), ("", "settings", "Policy changes", "0", ""),
          ("", "lock", "Lockouts", "1", "normal: 1"), ("", "moon", "After-hours admin", "0", ""), ("", "usb", "New USB devices", "0", "")]
    cards = '<div class="ev6">' + ''.join(f'<div class="panel ec {"zero" if v == "0" else k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in ev) + '</div>'
    k4 = f'''<div class="kpis">{kpi("Systems reporting", "24 / 24", "all reporting", [24,24,24,24,23,23,23,23,24,24,24,24])}
{kpi("Detections", "0", "none this week", [3,5,2,4,6,3,2,5,7,4,5,0])}
{kpi("Events collected", "81.9k", "normal", [80,82,79,85,83,81,84,86,82,83,81,82])}
{kpi("Privileged actions", "3,804", "by 9 people", [3700,3810,3650,3990,3880,3900,3770,3950,3820,3890,3860,3804])}</div>'''
    ck = ''.join(f'<div class="ck2 ok"><div class="i">{icon(i, 14)}</div><div><b>{t}</b><span>{w}</span></div><div class="r">24/24</div></div>' for i, t, w in [
        ("file-warning", "Logs intact", "No logs cleared"), ("clock-alert", "Every system reporting", "VMs reported whenever on"), ("history", "Reports on time", "All on time"),
        ("shield-check", "Audit settings match STIG", "All systems"), ("circle-check", "No events lost to log rollover", "8,064 runs"), ("hard-drive", "Original logs archived", "24 zips · 3.0 GB")])
    body = aside("Overview", "", "0").replace('<em>!</em>', '') + f'''<main>{head("Network overview", "Weekly report · 24 systems · collector SRV-DC01 · generated 22 Sep 2026 00:05")}
{k4}{cards}
<div class="row" style="grid-template-columns:1.35fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Systems · 24</h2></div><div class="hbar"><s style="flex:1;background:#1A9A50"></s></div><div class="hleg"><span><i style="background:#1A9A50"></i><b>24</b>reporting normally</span></div>{ck}</div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("shield-alert", 17)}Detections</h2></div>
<div class="clean"><div class="ic">{icon("shield-check", 22)}</div><div><b>Nothing unusual this week</b><span>No activity matched a detection rule. All 81,904 events are still on the event pages and in Search.</span></div></div></div></div></main>'''
    pg('R7-clean', body)

# ---------- R8: print / PDF ----------
def r8():
    det = ''.join(f'<tr><td>{SEVL(s)}</td><td>{t}</td><td>{h}</td><td>{dy} {tm}</td></tr>' for (s, t, d, h, dy, tm) in DETS[:5])
    body = f'''<div class="paper"><div class="hdr"><div><div style="font-size:11px;color:#444;letter-spacing:.08em;text-transform:uppercase">GE Aerospace Blackbox · weekly audit report</div><h1>Lab 3 LAN · 22 – 29 Sep 2026</h1>
<div style="font-size:11.5px;color:#444;margin-top:4px">24 systems · collector SRV-DC01 · generated 29 Sep 2026 00:05 · report hash 6c0f4a9e…a1b2</div></div><img src="logo.png"></div>
<div class="kp"><div>Systems reporting<b>23 / 24</b></div><div>Detections<b>9</b></div><div>Events<b>84,212</b></div><div>Audit settings<b>19 / 24 match</b></div></div>
<h2>Detections</h2><table><thead><tr><th>Severity</th><th>Detection</th><th>System</th><th>When</th></tr></thead><tbody>{det}</tbody></table>
<h2>Audit trail</h2><table><tbody>
<tr><td>Logs intact</td><td>23 of 24 · WS-07 Security log cleared 28 Sep 12:38 by admin_jd</td></tr>
<tr><td>Every system reporting</td><td>23 of 24 · WS-09 no data since 23 Sep 14:00</td></tr>
<tr><td>Audit settings match STIG</td><td>19 of 24 · 4 with gaps, 1 warning (see Audit health)</td></tr>
<tr><td>Events lost to rollover</td><td>None</td></tr><tr><td>Original logs archived</td><td>23 zips, 3.1 GB, SHA-256 verified</td></tr></tbody></table>
<div class="sig"><div>ISSO</div><div>Date</div><div>ISSM</div></div>
<div style="margin-top:22px;font-size:10px;color:#666">Page 1 of 3 · full detail is in report.html in the same folder</div></div>'''
    pg('R8-print', body, 'body{display:block;background:#D9DEE8}')

r1(); r2(); r3(); r4('export'); r4('verify'); r6(); r7(); r8()
