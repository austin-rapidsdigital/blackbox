import os, re
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'evp.py')).read().replace('e1(); e2(); e3()', ''))

def page8(name, body):
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>Failed logons</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

FHEAD = head("Failed logons", "Weekly report · Events · 418 failed logons on 17 systems")
FKP = f'''<div class="ev6" style="grid-template-columns:repeat(4,1fr)">{"".join(f'<div class="panel ec {k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in [("", "log-in", "Failed logons", "418", "normal: 380–420"), ("bad", "triangle-alert", "Password-guessing bursts", "2", "10.1.1.99, svc_backup"), ("warn", "lock", "Accounts locked out", "4", "normal: 1"), ("", "server", "Sources", "23", "addresses and consoles")])}</div>'''

SRC = [("10.1.1.99", "KALI · not a known system", "administrator, admin, root", "WS-07, ubu-ws10", 31, "Mon 06:01", True, "Password guessing", "bad"),
       ("10.1.1.24", "SRV-FS01 · backup job", "svc_backup", "6 systems", 18, "Sat 22:14", True, "Same account on 6 systems", "bad"),
       ("WS-11 console", "keyboard at WS-11", "rgarcia", "WS-11", 9, "Tue 08:02", True, "Locked out twice", "warn"),
       ("10.1.1.42", "WS-12", "admin_jd", "WS-07, SRV-DC01", 4, "Mon 08:54", False, "", ""),
       ("WS-05 console", "keyboard at WS-05", "kpatel", "WS-05", 7, "Wed 08:31", False, "Typo, then success", ""),
       ("10.1.1.31", "WS-03", "lnguyen", "SRV-FS01", 5, "Thu 09:10", False, "Expired password", ""),
       ("ubu-ws12 (ssh)", "ubu-ws12", "jsmith", "ubu-ws12", 3, "Sun 23:08", False, "", ""),
       ("16 other sources", "", "21 accounts", "12 systems", 341, "", False, "Routine: 1–3 failures each", "")]

def fe1():
    dr = ''
    for src, what, acc, sy, n, last, flag, note, sev in SRC:
        dr += f'<tr class="{"nw" if sev == "bad" else ""}"><td><b>{src}</b><small>{what}</small></td><td>{acc}</td><td>{sy}</td><td class="n">{n}</td><td class="mono mute" style="font-size:12px">{last}</td><td class="{"why " + sev if sev else "mute"}">{note}</td></tr>'
    vals = [52, 61, 58, 55, 49, 76, 67]
    pd = '<div class="dpd">' + ''.join(f'<div><s class="{"hot" if v > 65 else ""}" style="height:{v / 76 * 62:.0f}px"></s>{d}</div>' for d, v in zip(DAYS, vals)) + '</div>'
    evl = [("28 Sep 06:02:41", "WS-07", "administrator", "10.1.1.99", "6 failures in 40 s · bad password", "bad"),
           ("28 Sep 06:01:58", "ubu-ws10", "root", "10.1.1.99", "SSH · bad password ×4", "bad"),
           ("26 Sep 22:14:09", "SRV-DC01", "svc_backup", "10.1.1.24", "Failed on 6 systems within 9 min · bad password", "bad"),
           ("22 Sep 08:02:15", "WS-11", "rgarcia", "console", "Account locked out", "warn"),
           ("23 Sep 08:31:02", "WS-05", "kpatel", "console", "Bad password, then success", ""),
           ("24 Sep 09:10:44", "SRV-FS01", "lnguyen", "10.1.1.31", "Password expired", "")]
    er = ''.join(f'<tr><td class="mono">{t}</td><td><b>{s}</b></td><td>{a}</td><td class="mono">{src}</td><td class="{"why " + k if k else ""}" style="white-space:normal">{m}</td></tr>' for t, s, a, src, m, k in evl)
    body = aside("Failed logons") + f'''<main>{FHEAD}{FKP}
<div class="row" style="grid-template-columns:1fr 270px">
<div class="panel"><div class="ph"><h2>{icon("log-in", 17)}Where failures came from · 23 sources</h2><span class="pm">Unusual first</span></div>
<table class="ev2"><thead><tr><th>Source</th><th>Accounts tried</th><th>Systems</th><th class="n">Failures</th><th>Last</th><th>Note</th></tr></thead><tbody>{dr}</tbody></table></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("calendar-range", 17)}Per day</h2><span class="pm">Red = above normal</span></div>{pd}</div></div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}Events</h2><a class="pm" style="color:#0B5FFF;font-weight:600">Open in Search →</a></div>
<table class="ev2"><thead><tr><th>Time</th><th>System</th><th>Account</th><th>Source</th><th>What happened</th></tr></thead><tbody>{er}</tbody></table></div>
</main>'''
    page8('F1-summary', body)

def fe2():
    lst = '<div class="search">' + icon("search", 14) + 'Find a source or account</div><div class="grp2">Worth a look · 3</div>'
    for src, what, acc, sy, n, last, flag, note, sev in SRC[:3]:
        lst += f'<a class="{"sel" if src == "10.1.1.99" else ""}"><div class="av {sev}">{icon("log-in", 15)}</div><div><b>{src}</b><span>{note}</span></div><small>{n}</small></a>'
    lst += '<div class="grp2">Routine · 20</div>'
    for src, what, acc, sy, n, last, flag, note, sev in SRC[3:7]:
        lst += f'<a><div class="av">{icon("log-in", 15)}</div><div><b>{src}</b><span>{acc}</span></div><small>{n}</small></a>'
    lst += '<a><div class="av">+</div><div><b>16 more</b><span>1–3 failures each</span></div><small>341</small></a>'
    tl = [("Mon 28 Sep 06:01", "First seen: SSH logon attempt for root", "ubu-ws10", False),
          ("Mon 28 Sep 06:01", "4 SSH password failures for root", "ubu-ws10", True),
          ("Mon 28 Sep 06:02", "6 failures for administrator in 40 seconds", "WS-07 · Remote Desktop", True),
          ("Mon 28 Sep 06:04", "21 more failures for administrator, admin", "WS-07", True),
          ("Mon 28 Sep 06:09", "Stopped · no successful logon from 10.1.1.99", "", False)]
    sq = ''.join(f'<div class="{"k" if k else ""}"><b>{t}</b><span>{a}</span><small>{s}</small></div>' for t, a, s, k in tl)
    acc = ''.join(f'<div><span>{l}</span><s style="width:{v / 27 * 100:.0f}%"></s><b>{v}</b></div>' for l, v in [("administrator", 27), ("root", 4), ("admin", 2)])
    body = aside("Failed logons") + f'''<main>{FHEAD}{FKP}
<div class="md2" style="grid-template-columns:300px 1fr"><div class="panel plist slist" style="padding:12px 0">{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div class="ph2"><div class="av bad">{icon("log-in", 22)}</div><div><h3>10.1.1.99</h3><p>Computer name KALI · not one of your 24 systems · seen only on Mon 28 Sep</p></div></div><span class="sv high">Password guessing</span></div>
<div class="facts4"><div>Failures<b class="bad">31</b></div><div>Accounts tried<b>3</b></div><div>Systems<b>2</b></div><div>Successful logons<b>0</b></div><div>Detections<b class="bad">1 high</b></div></div></div>
<div class="row" style="grid-template-columns:1.4fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("history", 17)}What it did</h2></div><div class="seq">{sq}</div></div>
<div style="display:grid;gap:12px;align-content:start"><div class="panel"><div class="ph"><h2>{icon("user-round", 17)}Accounts tried</h2></div><div class="mini">{acc}</div></div>
<div class="panel"><div class="ph"><h2>{icon("shield-alert", 17)}Related</h2></div><div class="dl"><div class="dc"><div class="b"><b>Possible password guessing</b><span>WS-07 · Mon 06:02</span></div><div></div></div></div></div></div></div>
</div></div></main>'''
    page8('F2-detail', body)

def fe3():
    days = [("Mon 28 Sep", "67 failures", [("06:01", "Password guessing from 10.1.1.99 (KALI): 31 failures, 3 accounts", "WS-07, ubu-ws10", "bad"), ("08:54", "admin_jd mistyped password twice", "WS-07", "")], 34),
            ("Sun 27 Sep", "76 failures", [("23:08", "jsmith failed sudo password 3 times", "ubu-ws12", "")], 73),
            ("Sat 26 Sep", "49 failures", [("22:14", "svc_backup failed on 6 systems within 9 minutes", "10.1.1.24", "bad")], 31),
            ("Thu 24 Sep", "58 failures", [("09:10", "lnguyen password expired", "SRV-FS01", "")], 57),
            ("Tue 22 Sep", "52 failures", [("08:02", "rgarcia locked out (twice)", "WS-11", "warn")], 50)]
    fh = ''
    for d, c, items, more in days:
        ih = ''.join(f'<div class="it {"k " + k if k else ""}"><span class="tm">{t}</span><span>{m}</span><span class="sy">{s}</span></div>' for t, m, s, k in items)
        fh += f'<div class="day"><b>{d}<small>{c}</small></b><div>{ih}<div class="more2">+ {more} routine failures (typos, expired passwords)</div></div></div>'
    def top(title, rows):
        mx = max(v for _, v in rows)
        return f'<div class="panel"><div class="ph"><h2>{title}</h2></div><div class="mini">' + ''.join(f'<div><span>{l}</span><s style="width:{v / mx * 100:.0f}%"></s><b>{v}</b></div>' for l, v in rows) + '</div></div>'
    body = aside("Failed logons") + f'''<main>{FHEAD}{FKP}
<div class="row" style="grid-template-columns:1fr 330px">
<div class="panel feed"><div class="ph"><h2>{icon("history", 17)}This week, day by day</h2><span class="chips"><span class="on">Notable only</span><span>Everything</span></span></div>{fh}</div>
<div style="display:grid;gap:12px;align-content:start">{top("Sources", [("10.1.1.99", 31), ("10.1.1.24", 18), ("WS-11 console", 9), ("WS-05 console", 7), ("10.1.1.31", 5)])}
{top("Accounts", [("administrator", 27), ("svc_backup", 18), ("rgarcia", 9), ("kpatel", 7), ("lnguyen", 5)])}
{top("Systems", [("WS-07", 41), ("SRV-DC01", 33), ("WS-11", 14), ("SRV-FS01", 12), ("ubu-ws10", 9)])}</div></div>
</main>'''
    page8('F3-feed', body)

fe1(); fe2(); fe3()
