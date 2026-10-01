import os, re, random
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'healthp.py')).read().replace('a1(); a2(); a3()', ''))

C13 = '''
.sm{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.smc .t{display:flex;justify-content:space-between;align-items:baseline}.smc .t b{font-size:13px;font-weight:600}.smc .t span{font:12px SCP;color:#5A6785}
.smc .v{font:700 22px PS;color:#0A2A7A;letter-spacing:-.3px;margin:2px 0}.smc .v small{font:600 12px PS;margin-left:8px}
.up{color:#C22020}.dn{color:#147A3D}.flat{color:#8A96B3}
.mv{display:grid;grid-template-columns:150px 110px 1fr 100px;gap:16px;align-items:center;padding:11px 0;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px}
.mv b{font-weight:600}.mv .d{font:600 13px PS;text-align:right}.mv .why{color:#3A4766}
.wk{width:100%;border-collapse:separate;border-spacing:2px}.wk th{font-size:10.5px;color:#5A6785;font-weight:600;padding:0 0 4px;text-align:center;letter-spacing:0;text-transform:none}
.wk td{height:22px;text-align:center;font:11px SCP;padding:0}.wk td.nm{text-align:left;font:600 12.5px PS;padding-right:8px;white-space:nowrap}
table.wt{width:100%;border-collapse:collapse}table.wt th{padding:0 8px 8px;text-align:right}table.wt th:first-child{text-align:left}
table.wt td{padding:8px;border-bottom:1px solid rgba(0,30,98,.07);text-align:right;font:12.5px SCP}table.wt td:first-child{text-align:left;font:600 13px PS}
table.wt tr.cur td{background:rgba(11,95,255,.06);font-weight:700}
'''

def page11(name, body):
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>Trends</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}{C11}{C12}{C13}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

THEAD = head("Trends", "Last 12 weeks · 7 Jul – 29 Sep 2026 · built from the summary in each earlier report")
WEEKS = [f"W{28 + i}" for i in range(12)]
MET = [("Detections", [3, 5, 2, 4, 6, 3, 2, 5, 7, 4, 5, 9], True), ("High-severity events", [2, 1, 3, 2, 1, 0, 2, 4, 1, 2, 3, 7], True),
       ("Failed logons", [380, 402, 355, 420, 398, 410, 377, 415, 389, 401, 395, 418], False), ("Privileged actions", [3700, 3810, 3650, 3990, 3880, 3900, 3770, 3950, 3820, 3890, 3860, 3912], False),
       ("USB events", [41, 38, 52, 44, 47, 39, 55, 48, 42, 50, 46, 64], True), ("After-hours admin", [4, 2, 6, 3, 0, 5, 2, 4, 3, 1, 2, 14], True),
       ("Account changes", [12, 9, 15, 11, 8, 13, 10, 14, 9, 12, 11, 31], True), ("Systems reporting", [24, 24, 24, 24, 23, 23, 23, 23, 24, 24, 24, 23], True)]

def chart(vals, w=300, h=90, hot=False, axis=False):
    mx = max(vals) * 1.15; mn = 0; n = len(vals); x0 = 4; bw = (w - x0) / n; out = ''
    avg = sum(vals[:-1]) / (n - 1)
    ya = h - 14 - avg / mx * (h - 20)
    for i, v in enumerate(vals):
        bh = v / mx * (h - 20); x = x0 + i * bw + bw * .18
        last = i == n - 1
        col = ('#D12C2C' if hot and v > avg * 1.4 else '#0B5FFF') if last else '#0B5FFF'
        out += f'<rect x="{x:.1f}" y="{h - 14 - bh:.1f}" width="{bw * .64:.1f}" height="{bh:.1f}" fill="{col}" opacity="{1 if last else .35}"/>'
    out += f'<line x1="0" x2="{w}" y1="{ya:.1f}" y2="{ya:.1f}" stroke="#0A2A7A" stroke-dasharray="3 3" opacity=".6"/>'
    out += f'<text x="2" y="{h - 2}" class="ax">{WEEKS[0]}</text><text x="{w - 2}" y="{h - 2}" text-anchor="end" class="ax" style="font-weight:700;fill:#0B1630">This week</text>'
    return f'<svg viewBox="0 0 {w} {h}" width="100%">{out}</svg>'

def delta(vals):
    avg = sum(vals[:-1]) / 11; d = (vals[-1] - avg) / avg * 100 if avg else 0
    return avg, d

# ---------- T1: small multiples ----------
def t1():
    cards = ''
    for name, vals, bad_up in MET:
        avg, d = delta(vals)
        cls = 'flat' if abs(d) < 15 else ('up' if (d > 0) == bad_up and name != "Systems reporting" else 'dn')
        if name == "Systems reporting": cls = 'flat'
        cards += f'<div class="panel smc"><div class="t"><b>{name}</b><span>avg {avg:,.0f}</span></div><div class="v">{vals[-1]:,}<small class="{cls}">{"+" if d >= 0 else ""}{d:.0f}%</small></div>{chart(vals, hot=bad_up)}</div>'
    body = aside("Trends") + f'''<main>{THEAD}
<div class="ph" style="margin-bottom:10px"><h2>{icon("trending-up", 17)}This week against the last 12</h2><span class="pm">Dashed line = 12-week average · red bar = well above average</span></div>
<div class="sm">{cards}</div>
<div class="panel" style="margin-top:12px"><div class="ph"><h2>{icon("server", 17)}Detections per system, by week</h2><span class="pm">Darker = more</span></div>{sysweeks()}</div>
</main>'''
    page11('T1-multiples', body)

def sysweeks():
    random.seed(4)
    rows = [("WS-07", [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 3]), ("SRV-DC01", [1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1]), ("ubu-ws12", [0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1]),
            ("WS-02", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), ("WS-09", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), ("WS-11", [1, 2, 0, 1, 2, 1, 0, 2, 3, 1, 2, 1]),
            ("alma-db01", [0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0]), ("WS-05", [1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0])]
    out = '<table class="wk"><thead><tr><th></th>' + ''.join(f'<th>{w if i < 11 else "This wk"}</th>' for i, w in enumerate(WEEKS)) + '</tr></thead><tbody>'
    for n, vals in rows:
        out += f'<tr><td class="nm">{n}</td>' + ''.join(f'<td style="background:{lerp("#EEF2FA", "#0A2A7A", min(v / 3, 1)) if v else "rgba(0,30,98,.03)"};color:{"#fff" if v >= 2 else "#3A4766"}">{v or ""}</td>' for v in vals) + '</tr>'
    return out + '</tbody></table>'

# ---------- T2: big chart + table ----------
def t2():
    name, vals, _ = MET[0]
    hi = MET[1][1]
    w, h = 1080, 230; mx = 12; x0 = 34; bw = (w - x0) / 12; out = ''
    for v in (0, 4, 8, 12):
        y = h - 24 - v / mx * (h - 36)
        out += f'<line x1="{x0}" x2="{w}" y1="{y:.1f}" y2="{y:.1f}" stroke="{T["grid"]}"/><text x="{x0 - 8}" y="{y + 4:.1f}" text-anchor="end" class="ax">{v}</text>'
    for i in range(12):
        x = x0 + i * bw + bw * .25; ww = bw * .5; hv = min(hi[i], vals[i]); mv = vals[i] - hv
        y1 = h - 24 - hv / mx * (h - 36); y2 = y1 - mv / mx * (h - 36)
        op = 1 if i == 11 else .5
        out += f'<rect x="{x:.1f}" y="{y1:.1f}" width="{ww:.1f}" height="{h - 24 - y1:.1f}" fill="#D12C2C" opacity="{op}"/><rect x="{x:.1f}" y="{y2:.1f}" width="{ww:.1f}" height="{y1 - y2:.1f}" fill="#E08A00" opacity="{op}"/>'
        out += f'<text x="{x + ww / 2:.1f}" y="{h - 6}" text-anchor="middle" class="ax" style="{"font-weight:700;fill:#0B1630" if i == 11 else ""}">{"This week" if i == 11 else WEEKS[i]}</text>'
    avg = sum(vals[:-1]) / 11; ya = h - 24 - avg / mx * (h - 36)
    out += f'<line x1="{x0}" x2="{w}" y1="{ya:.1f}" y2="{ya:.1f}" stroke="#0A2A7A" stroke-dasharray="4 4"/><text x="{x0 + 6}" y="{ya - 5:.1f}" class="ax" style="fill:#0A2A7A;font-weight:600">12-week average {avg:.1f}</text>'
    big = f'<svg viewBox="0 0 {w} {h}" width="100%">{out}</svg>'
    tabs = '<div class="chips">' + ''.join(f'<span class="{"on" if i == 0 else ""}">{m[0]}</span>' for i, m in enumerate(MET)) + '</div>'
    rows = ''
    for i in range(11, 3, -1):
        rows += f'<tr class="{"cur" if i == 11 else ""}"><td>{"This week" if i == 11 else WEEKS[i]}</td>' + ''.join(f'<td>{m[1][i]:,}</td>' for m in MET) + '</tr>'
    body = aside("Trends") + f'''<main>{THEAD}
<div class="panel" style="margin-bottom:12px"><div style="margin-bottom:14px">{tabs}</div><div class="ph"><h2>{icon("trending-up", 17)}Detections per week</h2><span class="pm"><span class="hi">■ High</span> · <span class="md">■ Medium</span> · this week in full colour</span></div>{big}</div>
<div class="panel"><div class="ph"><h2>{icon("list-filter", 17)}Week by week</h2><span class="pm">Export CSV</span></div>
<table class="wt"><thead><tr><th>Week</th>{"".join(f"<th>{m[0]}</th>" for m in MET)}</tr></thead><tbody>{rows}</tbody></table></div>
</main>'''
    page11('T2-chart', body)

# ---------- T3: what changed ----------
def t3():
    movers = []
    for name, vals, bad_up in MET:
        avg, d = delta(vals); movers.append((abs(d), name, vals, avg, d, bad_up))
    movers.sort(reverse=True)
    why = {"After-hours admin": "jsmith on ubu-ws12, Sun 23:10–23:41", "High-severity events": "WS-07 on Monday (3 detections)", "Account changes": "admin_jd added 2 admins",
           "Detections": "WS-07 accounts for 3 of 9", "USB events": "212 files copied on WS-07", "Systems reporting": "WS-09 silent since 23 Sep",
           "Failed logons": "Within normal range", "Privileged actions": "Within normal range"}
    mh = ''
    for _, name, vals, avg, d, bad_up in movers:
        cls = 'flat' if abs(d) < 15 else ('up' if (d > 0) == bad_up else 'dn')
        mh += f'<div class="mv"><b>{name}</b><span>{spark(vals, "#D12C2C" if cls == "up" else "#0B5FFF", w=120, h=30)}</span><span class="why">{why[name]}</span><span class="d {cls}">{vals[-1]:,} <span style="font-weight:500;color:#8A96B3">vs {avg:,.0f}</span></span></div>'
    body = aside("Trends") + f'''<main>{THEAD}
<div class="row" style="grid-template-columns:1.5fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("trending-up", 17)}What changed this week</h2><span class="pm">Biggest change from the 12-week average first</span></div>{mh}</div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("shield-alert", 17)}Detections per week</h2><span class="pm">12 weeks</span></div>{weekly_cols(w=440, h=190)}{LEG}</div></div>
<div class="panel"><div class="ph"><h2>{icon("server", 17)}Detections per system, by week</h2><span class="pm">Darker = more</span></div>{sysweeks()}</div>
</main>'''
    page11('T3-changes', body)

t1(); t2(); t3()
