import os, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'peoplep.py')).read().replace('p1(); p2(); p3()', ''))

DEV = [("Kingston DataTraveler 3.0", "0951:1666", "WS-02, WS-07", "mjones, tempuser", 14, "24 Sep", True, "212 files copied"),
       ("SanDisk Cruzer Blade", "0781:5567", "ubu-ws12", "jsmith", 8, "Before this week", False, ""),
       ("Seagate Expansion HDD", "0bc2:2322", "WS-07", "admin_jd", 6, "Before this week", False, ""),
       ("Samsung T7 SSD", "04e8:4001", "SRV-FS01", "dchen", 9, "27 Sep", True, "Plugged into a server"),
       ("Generic USB keyboard", "046d:c31c", "WS-05, WS-08", "kpatel, lnguyen", 12, "Before this week", False, "Not storage"),
       ("Apple iPhone", "05ac:12a8", "WS-11", "rgarcia", 5, "26 Sep", True, "Blocked by policy"),
       ("Lexar JumpDrive", "05dc:a81d", "WS-03", "bwilliams", 4, "Before this week", False, ""),
       ("Verbatim Store 'n' Go", "18a5:0302", "ubu-ws10", "kpatel", 6, "Before this week", False, "")]

C10 = '''
.dpd{display:grid;grid-template-columns:repeat(7,1fr);gap:6px;align-items:end;height:90px;padding-top:6px}
.dpd div{display:flex;flex-direction:column;align-items:center;gap:4px;font-size:11px;color:#8A96B3}.dpd s{display:block;width:70%;background:#0B5FFF;opacity:.7}
.dpd s.hot{background:#D12C2C;opacity:.9}
.new{font-size:10.5px;font-weight:700;letter-spacing:.04em;color:#B01C1C;border:1px solid #F5C2C2;background:#FDECEC;padding:0 5px;margin-left:8px}
table.ev2{width:100%;border-collapse:collapse}table.ev2 th{padding:0 12px 9px;white-space:nowrap}table.ev2 th.n{text-align:right}
table.ev2 td{padding:10px 12px;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px;white-space:nowrap;vertical-align:top}table.ev2 td.n{text-align:right;font:12.5px SCP}
table.ev2 td b{font-weight:600}table.ev2 td small{display:block;font:11.5px SCP;color:#8A96B3;margin-top:2px}
table.ev2 tr.nw td{background:rgba(209,44,44,.035)}
.feed .day{display:grid;grid-template-columns:110px 1fr;gap:16px;padding:14px 0;border-bottom:1px solid rgba(0,30,98,.08)}
.feed .day>b{font-size:13px;font-weight:650}.feed .day>b small{display:block;font:500 12px PS;color:#8A96B3;margin-top:2px}
.feed .it{display:grid;grid-template-columns:52px 1fr auto;gap:12px;padding:5px 0;font-size:13px;align-items:baseline}
.feed .it .tm{font:12px SCP;color:#5A6785}.feed .it .sy{font:12px SCP;color:#8A96B3}
.feed .it.k{font-weight:600}.feed .it.k.bad span:nth-child(2){color:#B01C1C}.feed .it.k.warn span:nth-child(2){color:#8F4F00}
.feed .more2{font-size:12px;color:#8A96B3;padding:3px 0 0 64px}
'''

def page7(name, body):
    import re
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>USB &amp; removable</span>|<svg[^>]*>(?:(?!</svg>).)*</svg><span>USB & removable</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

EHEAD = head("USB & removable", "Weekly report · Events · 64 events on 9 systems")
KP = f'''<div class="ev6" style="grid-template-columns:repeat(4,1fr)">{"".join(f'<div class="panel ec {k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in [("", "usb", "USB events", "64", "+12 vs. avg"), ("bad", "triangle-alert", "New devices", "3", "first seen this week"), ("", "server", "Systems", "9", "of 24"), ("warn", "hard-drive", "Files copied to USB", "212", "1 device")])}</div>'''

def perday():
    vals = [6, 9, 14, 7, 3, 2, 23]
    return '<div class="dpd">' + ''.join(f'<div><s class="{"hot" if v > 20 else ""}" style="height:{v / 23 * 62:.0f}px"></s>{d}</div>' for d, v in zip(DAYS, vals)) + '</div>'

EVL = [("28 Sep 09:31:05", "WS-07", "tempuser", "Copied 212 files to E:\\ (Kingston DataTraveler)", "bad"),
       ("28 Sep 09:29:40", "WS-07", "tempuser", "Kingston DataTraveler 3.0 connected", ""),
       ("27 Sep 14:12:03", "SRV-FS01", "dchen", "Samsung T7 SSD connected (new device)", "warn"),
       ("26 Sep 10:44:18", "WS-11", "rgarcia", "Apple iPhone blocked by device policy", "warn"),
       ("24 Sep 14:31:22", "WS-02", "mjones", "Kingston DataTraveler 3.0 connected (new device)", "warn"),
       ("24 Sep 09:02:51", "ubu-ws12", "jsmith", "SanDisk Cruzer Blade mounted at /media/jsmith/SANDISK", "")]

# ---------- E1: summary + tables ----------
def e1():
    dr = ''
    for n, vid, sy, pp, ev, fs, new, note, *_ in [d + () for d in DEV]:
        dr += f'<tr class="{"nw" if new else ""}"><td><b>{n}</b>{"<span class=new>NEW</span>" if new else ""}<small>{vid}</small></td><td>{sy}</td><td>{pp}</td><td class="n">{ev}</td><td class="mute">{fs}</td><td class="{"why bad" if new else "mute"}">{note}</td></tr>'
    er = ''.join(f'<tr><td class="mono">{t}</td><td><b>{s}</b></td><td>{p}</td><td class="{"why " + k if k else ""}" style="white-space:normal">{m}</td></tr>' for t, s, p, m, k in EVL)
    body = aside("USB & removable") + f'''<main>{EHEAD}{KP}
<div class="row" style="grid-template-columns:1fr 270px">
<div class="panel"><div class="ph"><h2>{icon("usb", 17)}Devices · 9</h2><span class="pm">New devices first</span></div>
<table class="ev2"><thead><tr><th>Device</th><th>Systems</th><th>People</th><th class="n">Events</th><th>First seen</th><th>Note</th></tr></thead><tbody>{dr}</tbody></table></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("calendar-range", 17)}Per day</h2><span class="pm">Red = above normal</span></div>{perday()}</div></div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}Events</h2><a class="pm" style="color:#0B5FFF;font-weight:600">Open in Search →</a></div>
<table class="ev2"><thead><tr><th>Time</th><th>System</th><th>Person</th><th>What happened</th></tr></thead><tbody>{er}</tbody></table></div>
</main>'''
    page7('E1-summary', body)

# ---------- E2: list + detail ----------
def e2():
    lst = '<div class="search">' + icon("search", 14) + 'Find a device</div><div class="grp2">New this week · 3</div>'
    for d in [x for x in DEV if x[6]] :
        lst += f'<a class="{"sel" if d[0].startswith("Kingston") else ""}"><div class="av bad">{icon("usb", 15)}</div><div><b>{d[0]}</b><span>{d[2]}</span></div><small>{d[4]}</small></a>'
    lst += '<div class="grp2">Seen before · 5</div>'
    for d in [x for x in DEV if not x[6]]:
        lst += f'<a><div class="av">{icon("usb", 15)}</div><div><b>{d[0]}</b><span>{d[2]}</span></div><small>{d[4]}</small></a>'
    tl = [("Thu 24 Sep 14:31", "WS-02", "mjones", "First connected · drive letter E:", False),
          ("Thu 24 Sep 15:02", "WS-02", "mjones", "Removed", False),
          ("Mon 28 Sep 09:29", "WS-07", "tempuser", "Connected · drive letter E:", False),
          ("Mon 28 Sep 09:31", "WS-07", "tempuser", "Copied 212 files (E:\\export\\…), 1.4 GB", True),
          ("Mon 28 Sep 09:38", "WS-07", "admin_jd", "Removable Storage auditing turned off, so later copies were not recorded", True),
          ("Mon 28 Sep 10:12", "WS-07", "tempuser", "Removed", False)]
    sq = ''.join(f'<div class="{"k" if k else ""}"><b>{t}</b><span>{a}</span><small>{s} · {p}</small></div>' for t, s, p, a, k in tl)
    body = aside("USB & removable") + f'''<main>{EHEAD}{KP}
<div class="md2" style="grid-template-columns:300px 1fr"><div class="panel plist slist" style="padding:12px 0">{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div class="ph2"><div class="av bad">{icon("usb", 22)}</div><div><h3>Kingston DataTraveler 3.0</h3><p>USB storage · 0951:1666 · serial 60A44C3F… · first seen Thu 24 Sep</p></div></div><span class="sv high">New device</span></div>
<div class="facts4"><div>Systems<b>2</b></div><div>People<b>2</b></div><div>Events<b>14</b></div><div>Files copied<b class="bad">212</b></div><div>Detections<b class="bad">1 high</b></div></div></div>
<div class="row" style="grid-template-columns:1.4fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("history", 17)}Where and when it was used</h2></div><div class="seq">{sq}</div></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("shield-alert", 17)}Related</h2></div><div class="dl">
<div class="dc"><div class="b"><b>Possible covering of tracks</b><span>WS-07 · Mon 09:20 · tempuser was made an admin, then USB auditing was turned off</span></div><div></div></div></div></div></div>
</div></div></main>'''
    page7('E2-detail', body)

# ---------- E3: day feed + top values ----------
def e3():
    days = [("Mon 28 Sep", "23 events", [("09:29", "Kingston DataTraveler connected", "WS-07 · tempuser", ""), ("09:31", "212 files copied to Kingston DataTraveler", "WS-07 · tempuser", "bad"),
                                          ("10:12", "Kingston DataTraveler removed", "WS-07 · tempuser", "")], 20),
            ("Sun 27 Sep", "2 events", [("14:12", "New device: Samsung T7 SSD on a server", "SRV-FS01 · dchen", "warn")], 1),
            ("Sat 26 Sep", "3 events", [("10:44", "Apple iPhone blocked by policy", "WS-11 · rgarcia", "warn")], 2),
            ("Fri 25 Sep", "7 events", [("11:20", "SanDisk Cruzer Blade mounted", "ubu-ws12 · jsmith", "")], 6),
            ("Thu 24 Sep", "14 events", [("14:31", "New device: Kingston DataTraveler 3.0", "WS-02 · mjones", "warn"), ("09:02", "SanDisk Cruzer Blade mounted", "ubu-ws12 · jsmith", "")], 12)]
    fh = ''
    for d, c, items, more in days:
        ih = ''.join(f'<div class="it {"k " + k if k else ""}"><span class="tm">{t}</span><span>{m}</span><span class="sy">{s}</span></div>' for t, m, s, k in items)
        fh += f'<div class="day"><b>{d}<small>{c}</small></b><div>{ih}{f"<div class=more2>+ {more} routine events</div>" if more else ""}</div></div>'
    def top(title, rows):
        mx = max(v for _, v in rows)
        return f'<div class="panel"><div class="ph"><h2>{title}</h2></div><div class="mini">' + ''.join(f'<div><span>{l}</span><s style="width:{v / mx * 100:.0f}%"></s><b>{v}</b></div>' for l, v in rows) + '</div></div>'
    body = aside("USB & removable") + f'''<main>{EHEAD}{KP}
<div class="row" style="grid-template-columns:1fr 330px">
<div class="panel feed"><div class="ph"><h2>{icon("history", 17)}This week, day by day</h2><span class="chips"><span class="on">Notable only</span><span>Everything</span></span></div>{fh}</div>
<div style="display:grid;gap:12px;align-content:start">{top("Devices", [("Kingston DT 3.0", 14), ("USB keyboard", 12), ("Samsung T7", 9), ("SanDisk Cruzer", 8), ("Seagate HDD", 6)])}
{top("Systems", [("WS-07", 18), ("WS-02", 9), ("SRV-FS01", 9), ("ubu-ws12", 8), ("WS-11", 5)])}
{top("People", [("tempuser", 11), ("jsmith", 8), ("dchen", 9), ("mjones", 6), ("rgarcia", 5)])}</div></div>
</main>'''
    page7('E3-feed', body)

e1(); e2(); e3()
