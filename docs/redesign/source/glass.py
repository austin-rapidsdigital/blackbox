import re, random, sys, os
SP=os.path.dirname(os.path.abspath(__file__))
def icon(name, size=18, sw=1.6, cls="ico"):
    s=open(f'{SP}/icons/{name}.svg').read()
    s=re.sub(r'<!--.*?-->','',s,flags=re.S).strip()
    s=re.sub(r'class="[^"]*"',f'class="{cls}"',s)
    s=re.sub(r'width="24"',f'width="{size}"',s); s=re.sub(r'height="24"',f'height="{size}"',s)
    s=s.replace('stroke-width="2"',f'stroke-width="{sw}"')
    return re.sub(r'\s+',' ',s)

def spark(vals, color, w=120, h=34, fill=None):
    mx=max(vals); mn=min(vals); n=len(vals)
    pts=[(i*(w-4)/(n-1)+2, h-4-(v-mn)/(mx-mn or 1)*(h-10)) for i,v in enumerate(vals)]
    d='M'+' L'.join(f'{x:.1f},{y:.1f}' for x,y in pts)
    area=''
    if fill: area=f'<path d="{d} L{pts[-1][0]:.1f},{h} L{pts[0][0]:.1f},{h} Z" fill="{fill}"/>'
    lx,ly=pts[-1]
    return f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" aria-hidden="true">{area}<path d="{d}" fill="none" stroke="{color}" stroke-width="1.6" stroke-linejoin="round"/><circle cx="{lx:.1f}" cy="{ly:.1f}" r="2.6" fill="{color}"/></svg>'

def heat(ramp, axis, cw=24, ch=22, gap=2, rx=1):
    random.seed(7)
    days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun']; x0=36; out=''
    for d,day in enumerate(days):
        out+=f'<text x="{x0-8}" y="{14+d*(ch+gap)+14}" text-anchor="end" class="ax">{day}</text>'
        for h in range(24):
            work=1 if (6<=h<18 and d<5) else 0
            v=random.random()*0.22+work*(0.35+random.random()*0.4)
            if d==6 and h in (9,12): v=1.0
            if d==5 and h==23: v=0.85
            if d==4 and h==22: v=0.7
            out+=f'<rect x="{x0+h*(cw+gap)}" y="{14+d*(ch+gap)}" width="{cw}" height="{ch}" rx="{rx}" fill="{ramp(min(v,1))}"/>'
    for h in range(0,24,6):
        out+=f'<text x="{x0+h*(cw+gap)}" y="9" class="ax">{h:02d}:00</text>'
    W=x0+24*(cw+gap)
    return f'<svg viewBox="0 0 {W} {14+7*(ch+gap)}" width="100%" role="img" aria-label="Activity by hour and day">{out}</svg>'

def lerp(a,b,t):
    a=[int(a[i:i+2],16) for i in (1,3,5)]; b=[int(b[i:i+2],16) for i in (1,3,5)]
    return '#%02X%02X%02X'%tuple(int(a[i]+(b[i]-a[i])*t) for i in range(3))

def trend(color, grid, label_cls='ax', w=430, h=190):
    vals=[2,1,3,2,1,0,2,4,1,2,3,7]
    weeks=[f'W{28+i}' for i in range(12)]
    mx=8; x0=28; pw=(w-x0-12)/11
    pts=[(x0+i*pw, h-24-v/mx*(h-40)) for i,v in enumerate(vals)]
    d='M'+' L'.join(f'{x:.1f},{y:.1f}' for x,y in pts)
    g=''.join(f'<line x1="{x0}" x2="{w-8}" y1="{h-24-v/mx*(h-40):.1f}" y2="{h-24-v/mx*(h-40):.1f}" stroke="{grid}"/><text x="{x0-8}" y="{h-20-v/mx*(h-40):.1f}" text-anchor="end" class="{label_cls}">{v}</text>' for v in (0,4,8))
    xl=''.join(f'<text x="{x:.1f}" y="{h-6}" text-anchor="middle" class="{label_cls}">{wk}</text>' for (x,_),wk in zip(pts,weeks) if weeks.index(wk)%2==1)
    dots=''.join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}"/>' for x,y in pts[-1:])
    ann=f'<text x="{pts[-1][0]-8:.1f}" y="{pts[-1][1]-4:.1f}" text-anchor="end" class="val">7 this week</text>'
    return f'<svg viewBox="0 0 {w} {h}" width="100%" role="img" aria-label="High-severity events per week, last 12 weeks">{g}<path d="{d}" fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round"/>{dots}{ann}{xl}</svg>'

DET=[("high","Possible covering of tracks","admin_jd added tempuser to Administrators, then removed Removable Storage auditing 18 min later.","WS-07","28 Sep 09:20"),
("high","Possible password guessing","6 failed logons for administrator in 40 s from 10.1.1.99 (KALI).","WS-07","28 Sep 06:02"),
("high","Same account failing on several computers","svc_backup failed on 3 computers within 9 minutes.","3 systems","26 Sep 22:14"),
("medium","Administrator activity outside working hours","jsmith ran 14 sudo commands between 23:10 and 23:41.","ubu-ws12","27 Sep 23:10"),
("medium","Suspicious PowerShell","Script downloads and runs code: IEX (New-Object Net.WebClient).DownloadString(…)","WS-09","24 Sep 15:47")]

def page(theme, name):
    T=theme
    nav=[("layout-dashboard","Overview",True,""),("shield-alert","Detections",False,"5"),("search","Search",False,""),("server","Systems",False,"!"),("user-round","People",False,"")]
    ev=[("key-round","Privileged activity","412"),("usb","USB & removable","18"),("log-in","Failed logons","61"),("users","Accounts & groups","9"),("file-warning","Audit integrity","14"),("terminal","PowerShell","11"),("activity","Logon activity","747")]
    navh=''.join(f'<a class="{ "on" if on else ""}">{icon(i,17)}<span>{t}</span>{f"<em>{b}</em>" if b else ""}</a>' for i,t,on,b in nav)
    evh=''.join(f'<a>{icon(i,17)}<span>{t}</span><small>{n}</small></a>' for i,t,n in ev)
    kpis=[("Detections","5","3 high · 2 medium",[1,2,1,3,2,1,0,2,4,1,2,5],"bad"),
          ("High-severity events","7","+5 vs. 12-week avg",[2,1,3,2,1,0,2,4,1,2,3,7],"bad"),
          ("Failed logons","61","normal for this site",[44,52,40,61,58,47,39,55,49,62,51,61],""),
          ("Privileged actions","412","by 4 people",[380,402,355,420,398,410,377,415,389,401,395,412],"")]
    kh=''
    for l,v,s,vals,cls in kpis:
        col=T['bad'] if cls else T['accent']
        kh+=f'<div class="panel kpi"><div class="kl">{l}</div><div class="kv {cls}">{v}</div><div class="kr"><span class="ks">{s}</span>{spark(vals,col,fill=T["sparkfill"] if not cls else T["sparkfillbad"])}</div></div>'
    rows=''.join(f'<tr><td><span class="sv {s}">{"High" if s=="high" else "Medium"}</span></td><td><b>{t}</b><span>{d}</span></td><td class="mono">{h}</td><td class="mono">{w}</td><td class="go">{icon("chevron-right",16)}</td></tr>' for s,t,d,h,w in DET)
    trail=[("bad","file-warning","Security log cleared twice","WS-07 · 28 Sep 12:38 and 12:40 by admin_jd"),
           ("warn","clock-alert","WS-09 silent for 6 days","Last collection 23 Sep 14:00"),
           ("ok","shield-check","No events lost to rollover","337 collection runs"),
           ("ok","hard-drive","Original logs archived","3 zips · 412 MB · SHA-256 in manifest")]
    trh=''.join(f'<div class="ti {k}"><div class="tic">{icon(i,16)}</div><div><b>{t}</b><span>{d}</span></div></div>' for k,i,t,d in trail)
    top=[("admin_jd","WS-07",188,"2 detections"),("jsmith","ubu-ws12",131,"after hours"),("svc_patch","3 systems",71,""),("mjones","WS-07",22,"")]
    tph=''.join(f'<div class="tr"><div><b>{n}</b>{f"<i>{f}</i>" if f else ""}<span>{h}</span></div><div class="tb"><s style="width:{c/188*100:.0f}%"></s></div><div class="tv mono">{c}</div></div>' for n,h,c,f in top)
    ramp=lambda t: lerp(T['heat0'],T['heat1'],t)
    def lst(rows,mx):
        return ''.join(f'<div class="tr"><div><b>{n}</b>{f"<i>{f}</i>" if f else ""}<span>{h}</span></div><div class="tb"><s style="width:{c/mx*100:.0f}%"></s></div><div class="tv mono">{c}</div></div>' for n,h,c,f in rows)
    fls=lst([("10.1.1.99","KALI · 3 accounts",31,"detection"),("console","WS-07 keyboard",17,""),("10.1.1.24","svc_backup · 3 systems",9,"detection")],31)
    usb=lst([("SanDisk Cruzer Blade","ubu-ws12",8,""),("Kingston DataTraveler","WS-07",6,"new"),("Seagate Expansion","WS-07",4,"")],8)
    body=f'''
<aside><div class="brand"><img src="logo.png" alt=""><div><b>Blackbox</b><span>GE Aerospace</span></div></div>
<div class="site"><span>Site</span><b>Lab 3</b></div>
<nav>{navh}</nav><div class="grp">Events</div><nav>{evh}</nav>
<div class="grp">Audit</div><nav><a>{icon("shield-check",17)}<span>Audit health</span></a><a>{icon("trending-up",17)}<span>Trends</span></a><a>{icon("scroll-text",17)}<span>Original logs</span></a></nav></aside>
<main>
<div class="head"><div><div class="crumb">Weekly report · 3 systems · generated 29 Sep 2026 00:05</div><h1>Overview</h1></div>
<div class="tools"><span class="btn">{icon("calendar-range",16)}22 – 29 Sep 2026</span><span class="btn">{icon("fingerprint",16)}Verified</span><span class="btn primary">Export</span></div></div>
<div class="alertbar">{icon("triangle-alert",18)}<b>Audit trail incomplete.</b><span>Security log cleared twice on WS-07 · WS-09 silent for 6 days</span><a>Details {icon("chevron-right",14)}</a></div>
<div class="kpis">{kh}</div>
<div class="row r1"><div class="panel"><div class="ph"><h2>{icon("shield-alert",17)}Detections</h2><span class="pm">5 this week</span></div>
<table><thead><tr><th>Severity</th><th>Detection</th><th>System</th><th>When</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="panel"><div class="ph"><h2>{icon("shield-check",17)}Audit trail</h2><span class="pm sev-bad">Incomplete</span></div>{trh}</div></div>
<div class="row r2"><div class="panel"><div class="ph"><h2>{icon("activity",17)}Activity by hour</h2><span class="pm">Privileged actions and failed logons · darker is busier</span></div>{heat(ramp,T)}
<div class="lg">Less <i style="background:{ramp(.08)}"></i><i style="background:{ramp(.35)}"></i><i style="background:{ramp(.6)}"></i><i style="background:{ramp(.85)}"></i><i style="background:{ramp(1)}"></i> More</div></div>
<div class="panel"><div class="ph"><h2>{icon("trending-up",17)}High-severity events</h2><span class="pm">Last 12 weeks</span></div>{trend(T["bad"],T["grid"])}</div></div>
<div class="row r3"><div class="panel"><div class="ph"><h2>{icon("key-round",17)}Top administrator accounts</h2><span class="pm">Privileged actions</span></div>{tph}</div>
<div class="panel"><div class="ph"><h2>{icon("log-in",17)}Failed logons by source</h2><span class="pm">61 total</span></div>{fls}</div>
<div class="panel"><div class="ph"><h2>{icon("usb",17)}USB devices</h2><span class="pm">18 events</span></div>{usb}</div></div>
</main>'''
    html=f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html','w').write(html)

BASE='''
@font-face{font-family:PS;src:url(fonts/public-sans-latin-wght-normal.woff2);font-weight:100 900}
@font-face{font-family:SCP;src:url(fonts/source-code-pro-latin-wght-normal.woff2);font-weight:200 900}
*{box-sizing:border-box}html,body{margin:0}
body{font:14px/1.5 PS,sans-serif;-webkit-font-smoothing:antialiased;display:grid;grid-template-columns:236px 1fr;min-height:100vh}
.mono{font-family:SCP;font-size:12.5px;white-space:nowrap}
aside{padding:18px 0;position:relative;z-index:1}
.brand{display:flex;gap:11px;align-items:center;padding:0 18px 16px}.brand img{width:32px;height:32px;background:#fff;border-radius:50%;padding:2px}
.brand b{display:block;font-size:15px;font-weight:650;line-height:1.15}.brand span{font-size:12px;opacity:.6}
.site{margin:0 14px 10px;padding:8px 10px;display:flex;justify-content:space-between;font-size:12.5px}
.grp{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;padding:18px 18px 6px}
nav a{display:flex;align-items:center;gap:11px;padding:7px 18px;font-size:13.5px;position:relative}
nav a span{flex:1}nav a small{font-family:SCP;font-size:11.5px;opacity:.6}
nav a em{font-style:normal;font-size:11px;font-weight:700;padding:0 6px;line-height:17px}
main{padding:22px 28px 40px;position:relative;z-index:1;min-width:0}
.head{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:16px}
.crumb{font-size:12.5px}h1{font-size:24px;font-weight:700;letter-spacing:-.3px;margin:2px 0 0}
.tools{display:flex;gap:8px}.btn{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;font-size:13px;font-weight:550}
.alertbar{display:flex;align-items:center;gap:10px;padding:10px 14px;margin-bottom:14px;font-size:13.5px}
.alertbar a{margin-left:auto;display:inline-flex;align-items:center;gap:4px;font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px}
.panel{padding:16px 18px;min-width:0}
.kl{font-size:12.5px;font-weight:550}.kv{font-size:32px;font-weight:700;letter-spacing:-.8px;line-height:1.15;margin-top:4px}
.kr{display:flex;align-items:flex-end;justify-content:space-between;gap:10px}.ks{font-size:12.5px}.kf{font-size:10.5px;text-align:right;margin-top:-2px;letter-spacing:.06em;text-transform:uppercase}
.row{display:grid;gap:12px;margin-bottom:12px}.r1{grid-template-columns:2fr 1fr}.r2{grid-template-columns:1.5fr 1fr}.r3{grid-template-columns:1fr 1fr 1fr}
.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
h2{display:flex;align-items:center;gap:9px;font-size:14px;font-weight:650;margin:0}.pm{font-size:12px}
table{width:100%;border-collapse:collapse}th{text-align:left;font-size:11px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;padding:0 10px 8px}
td{padding:11px 10px;vertical-align:top}td b{font-weight:600;display:block}td span{font-size:12.5px}td.go{width:20px;padding-top:13px}
.sv{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:650;letter-spacing:.02em}.sv:before{content:"";width:8px;height:8px}
.ti{display:grid;grid-template-columns:30px 1fr;gap:10px;padding:10px 0}.tic{width:30px;height:30px;display:grid;place-items:center}
.ti b{font-weight:600;display:block;font-size:13.5px}.ti span{font-size:12.5px}
.tr{display:grid;grid-template-columns:1.5fr 1fr 36px;gap:10px;align-items:center;padding:9px 0}
.tr b{font-weight:600}.tr i{font-style:normal;font-size:11px;font-weight:650;margin-left:8px;padding:0 6px;white-space:nowrap;display:inline-block}.tr span{display:block;font-size:12px}
.tb{height:6px}.tb s{display:block;height:100%}.tv{text-align:right}
.lg{display:flex;align-items:center;gap:3px;font-size:11.5px;margin-top:6px}.lg i{width:16px;height:10px;display:inline-block}
.ax{font:11px PS}.val{font:600 11.5px PS}
'''
