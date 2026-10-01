import os, re, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'trendp.py')).read().replace('t1(); t2(); t3()', ''))

C14 = '''
table.ar{width:100%;border-collapse:collapse}table.ar th{padding:0 12px 9px;white-space:nowrap}table.ar th.n,table.ar td.n{text-align:right}
table.ar td{padding:10px 12px;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px;white-space:nowrap}table.ar td.n{font:12.5px SCP}
table.ar td.h{font:11.5px SCP;color:#8A96B3}table.ar td b{font-weight:600}
.vok{color:#147A3D;font-weight:600;font-size:12.5px;display:inline-flex;gap:6px;align-items:center}.vbad{color:#B01C1C;font-weight:600;font-size:12.5px}.vwarn{color:#8F4F00;font-weight:600;font-size:12.5px}
.how{display:grid;gap:10px}.how div{display:grid;grid-template-columns:26px 1fr;gap:10px;font-size:13px;color:#3A4766}
.how div i{font:700 12px PS;font-style:normal;width:22px;height:22px;display:grid;place-items:center;background:#0A2A7A;color:#fff}
.how code{font:12px SCP;color:#0A2A7A;background:rgba(11,95,255,.07);padding:1px 5px}
.path{font:12.5px SCP;color:#22304F;background:rgba(255,255,255,.75);border:1px solid rgba(0,30,98,.1);padding:9px 12px;margin-top:8px}
table.fl{width:100%;border-collapse:collapse}table.fl th{padding:0 10px 8px}table.fl td{padding:8px 10px;border-bottom:1px solid rgba(0,30,98,.07);font-size:12.5px;white-space:nowrap}
table.fl td.mono{font-size:12px}table.fl td.n{text-align:right;font:12px SCP}table.fl th.n{text-align:right}
'''

def page12(name, body):
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>Original logs</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}{C11}{C12}{C13}{C14}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

OHEAD = head("Original logs", "Weekly report · the raw Windows and Linux logs this report was built from, saved in this report's folder")
OKP = '<div class="ev6" style="grid-template-columns:repeat(4,1fr)">' + ''.join(f'<div class="panel ec {k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in [
    ("", "hard-drive", "Archives", "23", "one zip per system"), ("", "scroll-text", "Total size", "3.1 GB", "compressed"),
    ("", "fingerprint", "Hashes verified", "23 / 23", "SHA-256 match"), ("bad", "clock-alert", "Missing", "1", "WS-09 · no data since 23 Sep")]) + '</div>'

random.seed(13)
ARC = []
for s in SYS:
    n = s[0]
    if n == 'WS-09':
        ARC.append((n, s[1], None, None, None)); continue
    win = not s[1].startswith(('UBU', 'ALMA'))
    mb = random.randint(40, 160) if 'SRV' not in n else random.randint(320, 520)
    if s[3]: mb = random.randint(12, 30)
    files = 'Security, System, Application, PowerShell' if win else 'audit.log, auth.log, syslog'
    ARC.append((n, s[1], mb, files, ''.join(random.choice('0123456789abcdef') for _ in range(8))))

def ar_rows(limit=None):
    out = ''
    rows = sorted(ARC, key=lambda a: (a[2] is not None, a[0]))
    for n, os_, mb, files, h in rows[:limit]:
        if mb is None:
            out += f'<tr><td><b>{n}</b></td><td>{OSF[os_]}</td><td class="mute">—</td><td class="n mute">—</td><td class="h">—</td><td><span class="vbad">Missing</span></td></tr>'
            continue
        out += f'<tr><td><b>{n}</b></td><td>{OSF[os_]}</td><td class="mute" style="font-size:12.5px">{files}</td><td class="n">{mb} MB</td><td class="h">{h[:6]}…</td><td><span class="vok">{icon("circle-check", 14)}Verified</span></td></tr>'
    return out

HOW = f'''<div class="how"><div><i>1</i><span>Open the report folder. Each system has a <code>logs-SYSTEM.zip</code> next to <code>report.html</code>.</span></div>
<div><i>2</i><span>Windows logs are <code>.evtx</code>: double-click to open in Event Viewer. Linux logs are plain text.</span></div>
<div><i>3</i><span>To prove nothing was changed: <code>blackbox verify</code> checks every file against <code>manifest.sha256</code>.</span></div></div>
<div class="path">\\\\SRV-DC01\\BlackboxReports\\2026-09-29_0005_Lab3\\</div>'''

# ---------- O1: table + how-to ----------
def o1():
    body = aside("Original logs") + f'''<main>{OHEAD}{OKP}
<div class="row" style="grid-template-columns:1fr 360px">
<div class="panel"><div class="ph"><h2>{icon("hard-drive", 17)}Archives in this report</h2><span class="pm">22 Sep 00:05 – 29 Sep 00:05</span></div>
<table class="ar"><thead><tr><th>System</th><th>OS</th><th>Logs inside</th><th class="n">Size</th><th>SHA-256</th><th>Check</th></tr></thead><tbody>{ar_rows(14)}</tbody></table>
<div class="more"><span>10 more systems · all verified</span><a>Show all →</a></div></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("circle-check", 17)}How to use them</h2></div>{HOW}</div></div>
</main>'''
    page12('O1-table', body)

# ---------- O2: coverage timeline ----------
def o2():
    W = 1060; x0 = 120; dw = (W - x0) / 7; svg = ''
    for d in range(7):
        svg += f'<text x="{x0 + d * dw + 4:.0f}" y="12" class="ax">{DAYS[d]} {22 + d}</text><line x1="{x0 + d * dw:.0f}" x2="{x0 + d * dw:.0f}" y1="18" y2="{22 + 24 * 22}" stroke="rgba(0,30,98,.08)"/>'
    gaps = {'WS-09': [(0.6, 7, 'none', 'No logs after Tue 14:00')], 'WS-03-VM1': [(2, 4, 'off', 'Powered off')], 'ubu-ws12-vm': [(4.5, 5.2, 'off', ''), (0, .7, 'off', '')],
            'WS-07': [(6.52, 6.53, 'clr', 'Security log cleared 12:38 · nothing lost')]}
    order = sorted(SYS, key=lambda s: (s[0] not in gaps, s[0]))
    for i, s in enumerate(order):
        y = 24 + i * 22; n = s[0]
        svg += f'<text x="{x0 - 12}" y="{y + 11}" text-anchor="end" class="ax" style="font-weight:{600 if n in gaps else 400};fill:{"#0B1630" if n in gaps else "#5A6785"}">{n}</text>'
        svg += f'<rect x="{x0}" y="{y + 2}" width="{W - x0}" height="11" fill="#C9D7F2"/>'
        for a, b, k, lab in gaps.get(n, []):
            xa, xb = x0 + a * dw, x0 + b * dw
            if k == 'clr':
                svg += f'<rect x="{xa - 2:.0f}" y="{y}" width="4" height="15" fill="#D12C2C"/><text x="{xa - 8:.0f}" y="{y + 11}" text-anchor="end" class="ax" style="fill:#B01C1C;font-weight:600;paint-order:stroke;stroke:#fff;stroke-width:3">{lab}</text>'
            else:
                svg += f'<rect x="{xa:.0f}" y="{y + 2}" width="{xb - xa:.0f}" height="11" fill="#F3F5FA" stroke="#B5BED3" stroke-dasharray="3 3"/>'
                if lab: svg += f'<text x="{xa + 6:.0f}" y="{y + 11}" class="ax" style="font-weight:600;paint-order:stroke;stroke:#fff;stroke-width:3;fill:{"#B01C1C" if k == "none" else "#5A6785"}">{lab}</text>'
    cov = f'<svg viewBox="0 0 {W} {28 + 24 * 22}" width="100%">{svg}</svg>'
    body = aside("Original logs") + f'''<main>{OHEAD}{OKP}
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("history", 17)}What the archives cover</h2><span class="pm">Solid = original logs saved for that time</span></div>{cov}
<div class="legend"><span><i style="background:#C9D7F2"></i>Saved</span><span><i style="background:#F3F5FA;outline:1px dashed #B5BED3"></i>No logs (system off or silent)</span><span><i style="background:#D12C2C"></i>Log cleared on the system</span></div></div>
<div class="row" style="grid-template-columns:1fr 360px">
<div class="panel"><div class="ph"><h2>{icon("hard-drive", 17)}Files</h2><span class="pm">23 zips · 3.1 GB</span></div><table class="ar"><thead><tr><th>System</th><th>OS</th><th>Logs inside</th><th class="n">Size</th><th>SHA-256</th><th>Check</th></tr></thead><tbody>{ar_rows(5)}</tbody></table>
<div class="more"><span>18 more</span><a>Show all →</a></div></div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("circle-check", 17)}How to use them</h2></div>{HOW}</div></div>
</main>'''
    page12('O2-coverage', body)

# ---------- O3: list + detail ----------
def o3():
    lst = '<div class="search">' + icon("search", 14) + 'Find a system</div>'
    for g, names in grpsd:
        lst += f'<div class="grp2">{g} · {len(names)}</div>'
        for n in sorted(names, key=lambda x: (x != 'WS-09', x)):
            a = [x for x in ARC if x[0] == n][0]
            lst += f'<a class="{"sel" if n == "WS-07" else ""}"><i class="{"bad" if a[2] is None else "ok"}"></i><span>{n}</span><small>{"missing" if a[2] is None else str(a[2]) + " MB"}</small></a>'
    files = [("Security.evtx", "Security", "22 Sep 00:05 – 29 Sep 00:05", "43,086", "101 MB", "3f9a1c…", "Cleared 28 Sep · nothing lost"),
             ("System.evtx", "System", "22 Sep 00:05 – 29 Sep 00:05", "6,310", "12 MB", "c4e2d9…", ""),
             ("Application.evtx", "Application", "22 Sep 00:05 – 29 Sep 00:05", "4,977", "9 MB", "07d3aa…", ""),
             ("PowerShell-Operational.evtx", "PowerShell", "22 Sep 00:05 – 29 Sep 00:05", "212", "2 MB", "e19c40…", ""),
             ("archive.json", "—", "", "", "4 KB", "5b72f1…", "File list + hashes")]
    fh = ''.join(f'<tr><td class="mono"><b>{f}</b></td><td>{c}</td><td class="mono mute">{w.replace(" 00:05","")}</td><td class="n">{e}</td><td class="n">{s}</td><td class="mono mute">{h}</td><td class="{"why bad" if "Cleared" in n else "mute"}">{n}</td></tr>' for f, c, w, e, s, h, n in files)
    body = aside("Original logs") + f'''<main>{OHEAD}{OKP}
<div class="md2" style="grid-template-columns:280px 1fr"><div class="panel slist" style="padding:12px 0">{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div class="ph2"><div class="av">{icon("hard-drive", 20)}</div><div><h3>logs-WS-07.zip</h3><p>Windows 11 · 124 MB · 22 Sep 00:05 – 29 Sep 00:05</p></div></div><span class="vok">{icon("circle-check", 15)}Hash verified</span></div>
<div class="path">SHA-256 6c0f4a9e2b17d83c5e9a0f1b74c2d6e8a3b5f7091c2d4e6f8a0b2c4d6e8f0a1b2</div></div>
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("scroll-text", 17)}Inside the zip</h2><span class="pm">5 files</span></div>
<table class="fl"><thead><tr><th>File</th><th>Log</th><th>Covers</th><th class="n">Events</th><th class="n">Size</th><th>Hash</th><th>Note</th></tr></thead><tbody>{fh}</tbody></table></div>
<div class="panel"><div class="ph"><h2>{icon("circle-check", 17)}How to use them</h2></div>{HOW}</div>
</div></div></main>'''
    page12('O3-detail', body)

o1(); o2(); o3()
