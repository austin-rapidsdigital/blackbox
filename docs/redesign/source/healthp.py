import os, re
_d = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(_d, 'evp4.py')).read().split('# ---------- Privileged activity')[0])

C12 = '''
table.mxs{border-collapse:separate;border-spacing:3px;width:100%}
table.mxs th{font-size:10.5px;font-weight:650;letter-spacing:.04em;text-transform:none;color:#5A6785;padding:0 2px 6px;text-align:center;vertical-align:bottom;white-space:normal;line-height:1.25}
table.mxs th:first-child{text-align:left}
table.mxs td{height:22px;padding:0 4px;vertical-align:middle;text-align:center;font:600 11px PS}
table.mxs td.nm{text-align:left;font:600 12.5px PS;color:#0B1630;white-space:nowrap;padding-right:8px}
table.mxs td.p{background:rgba(26,154,80,.07);color:#1A9A50;font-weight:500}table.mxs td.f{background:#D12C2C;color:#fff}table.mxs td.w{background:#FDF3E1;color:#8F4F00}table.mxs td.na{background:rgba(0,30,98,.04);color:#B5BED3}
table.mxs tr.g td{padding:10px 0 2px;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:#5A6785;text-align:left;height:auto}
.fd{background:rgba(255,255,255,.75);border:1px solid rgba(0,30,98,.09);border-left:4px solid #D12C2C;padding:14px 16px;display:grid;grid-template-columns:1fr auto;gap:6px 20px}
.fd.warn{border-left-color:#E08A00}.fd.ok{border-left-color:#1A9A50}
.fd b{font-size:14px;font-weight:650}.fd .id{font:12px SCP;color:#5A6785;margin-left:8px;font-weight:500}
.fd p{margin:0;font-size:13px;color:#3A4766;grid-column:1}.fd .sys{grid-column:2;grid-row:1/3;text-align:right;font-size:12.5px;color:#5A6785}.fd .sys b{display:block;font-size:22px;color:#C22020}
.fd.warn .sys b{color:#A35A00}
.fd .tags{grid-column:1;display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}
.fd .tags span{font:12px SCP;padding:1px 7px;border:1px solid rgba(209,44,44,.3);background:#FDECEC;color:#8A1515}.fd.warn .tags span{border-color:#F3D9A8;background:#FDF3E1;color:#7A4300}
.fd .fix{grid-column:1;font-size:12.5px;color:#22304F;background:rgba(11,95,255,.05);border:1px solid rgba(11,95,255,.12);padding:7px 10px;margin-top:4px}
.fd .fix code{font:12px SCP;color:#0A2A7A}
table.stig{width:100%;border-collapse:collapse}table.stig th{padding:0 10px 8px}table.stig td{padding:9px 10px;border-bottom:1px solid rgba(0,30,98,.07);font-size:13px;vertical-align:top}
table.stig td.mono{font-size:12px;white-space:nowrap}table.stig .st{font-weight:650;font-size:12px;white-space:nowrap}
table.stig .st.ok{color:#147A3D}table.stig .st.bad{color:#B01C1C}table.stig .st.warn{color:#8F4F00}table.stig .st.na{color:#8A96B3}
table.stig tr.bad td{background:rgba(209,44,44,.04)}
.ring{display:flex;gap:18px;align-items:center}.ring b{font:700 30px PS;color:#0A2A7A;letter-spacing:-.5px}.ring span{font-size:12.5px;color:#5A6785}
'''

def page10(name, body):
    body = re.sub(r'<a>(<svg[^>]*>(?:(?!</svg>).)*</svg><span>Audit health</span>)', lambda m: '<a class="on">' + m.group(1), body, count=1, flags=re.S)
    html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title><style>{T["css"]}{EXTRA}{CALM}{C3}{C4}{C5}{C6}{C7}{C8}{C9}{C10}{C11}{C12}</style></head><body>{body}</body></html>'
    open(f'{SP}/{name}.html', 'w').write(html)

AHEAD = head("Audit health", "Weekly report · audit settings compared with the STIG for each system's OS · Blackbox only reports, it never changes settings")
AKP = '<div class="ev6" style="grid-template-columns:repeat(4,1fr)">' + ''.join(f'<div class="panel ec {k}"><div class="l">{icon(i, 15)}{l}</div><div class="v">{v}</div><div class="d">{d}</div></div>' for k, i, l, v, d in [
    ("bad", "shield-check", "Systems matching STIG", "19 / 24", "4 gaps · 1 warning"), ("bad", "eraser", "Logs cleared", "1", "WS-07"),
    ("", "circle-check", "Events lost to rollover", "0", "7,980 runs"), ("warn", "hard-drive", "Logs too small", "1", "WS-13 holds 4 days")]) + '</div>'

COLS = ["Logon", "Account mgmt", "Policy change", "Privilege use", "Process creation", "Removable storage", "PowerShell logging", "Log size", "Reporting", "Logs intact"]
FAIL = {'WS-07': {5: 'f', 9: 'f'}, 'WS-09': {8: 'f'}, 'WS-12': {8: 'w'}, 'WS-13': {6: 'f', 7: 'w'}, 'alma-db01': {3: 'f', 4: 'f', 2: 'w'}}
LINUXNA = {6}

def matrix():
    out = '<table class="mxs"><thead><tr><th>System</th>' + ''.join(f'<th>{c}</th>' for c in COLS) + '</tr></thead><tbody>'
    for g, names in grpsd:
        out += f'<tr class="g"><td colspan="11">{g}</td></tr>'
        for n in sorted(names, key=lambda x: (x not in FAIL, x)):
            lin = not osmap[n].startswith(('WIN', 'WS'))
            out += f'<tr><td class="nm">{n}</td>'
            for i in range(len(COLS)):
                if lin and i in LINUXNA: out += '<td class="na">n/a</td>'; continue
                k = FAIL.get(n, {}).get(i, 'p')
                out += f'<td class="{k}">{ {"p": "✓", "f": "✕", "w": "!"}[k] }</td>'
            out += '</tr>'
    return out + '</tbody></table>'

FINDINGS = [("bad", "Removable Storage auditing is off", "WN11-AU-000090", "Turned off on 28 Sep 09:38 by admin_jd. USB file copies after that time were not recorded.", ["WS-07"], "Group Policy › Advanced Audit › Object Access › Audit Removable Storage: Success and Failure"),
            ("bad", "Security log was cleared", "—", "Cleared twice on 28 Sep (12:38, 12:40) by admin_jd. Events before then are only in the original-log archive.", ["WS-07"], ""),
            ("bad", "No data for 6 days", "—", "Last report 23 Sep 14:00. Check the system is on and can reach SRV-DC01.", ["WS-09"], ""),
            ("bad", "PowerShell Script Block Logging is off", "WN11-CC-000326", "PowerShell scripts on this system are not being recorded.", ["WS-13"], "Group Policy › Windows PowerShell › Turn on PowerShell Script Block Logging: Enabled"),
            ("bad", "auditd rules missing", "RHEL-08-030000 et al.", "3 required rules are not loaded: execve (privileged), sudoers changes, module loading.", ["alma-db01"], "Run <code>blackbox check --audit-rules --missing</code> for the exact lines"),
            ("warn", "Security log holds only 4 days", "WN11-AU-000500", "At the current rate the log rolls over in 4 days. Blackbox collects hourly, so nothing is lost yet.", ["WS-13"], "Raise the Security log size to at least 1 GB"),
            ("warn", "Report arrived late", "—", "Tue 23 Sep report arrived 9 hours late. No events were lost.", ["WS-12"], "")]

def fcards(items):
    out = ''
    for k, t, sid, d, sy, fix in items:
        out += f'<div class="fd {k}"><div><b>{t}</b>{f"<span class=id>{sid}</span>" if sid != "—" else ""}</div><div class="sys"><b>{len(sy)}</b>system{"s" if len(sy) != 1 else ""}</div><p>{d}</p><div class="tags">{"".join(f"<span>{s}</span>" for s in sy)}</div>{f"<div class=fix>How to fix: {fix}</div>" if fix else ""}</div>'
    return out

# ---------- A1: matrix ----------
def a1():
    body = aside("Audit health") + f'''<main>{AHEAD}{AKP}
<div class="row" style="grid-template-columns:1.45fr 1fr">
<div class="panel"><div class="ph"><h2>{icon("layers", 17)}Every system, every check</h2><span class="pm"><span style="color:#147A3D">✓</span> matches STIG · <span style="color:#C22020">✕</span> gap · <span style="color:#A35A00">!</span> warning</span></div>{matrix()}</div>
<div class="panel" style="align-self:start"><div class="ph"><h2>{icon("triangle-alert", 17)}Gaps · 7</h2><span class="pm">Click a cell or a gap</span></div><div class="dl">{fcards(FINDINGS[:4])}</div>
<div class="pm" style="margin-top:12px;color:#0B5FFF;font-weight:600">All 7 →</div></div></div>
</main>'''
    page10('A1-matrix', body)

# ---------- A2: findings first ----------
def a2():
    body = aside("Audit health") + f'''<main>{AHEAD}{AKP}
<div class="panel" style="margin-bottom:12px"><div class="ph"><h2>{icon("shield-check", 17)}Systems</h2><a class="pm" style="color:#0B5FFF;font-weight:600">Show every check for every system →</a></div>
<div class="hbar"><s style="flex:19;background:#1A9A50"></s><s style="flex:1;background:#E08A00"></s><s style="flex:4;background:#D12C2C"></s></div>
<div class="hleg"><span><i style="background:#1A9A50"></i><b>19</b>match the STIG</span><span><i style="background:#E08A00"></i><b>1</b>warning</span><span><i style="background:#D12C2C"></i><b>4</b>with gaps</span></div></div>
<div class="sec" style="margin-top:4px">Gaps · 5</div><div class="dl">{fcards(FINDINGS[:5])}</div>
<div class="sec">Warnings · 2</div><div class="dl">{fcards(FINDINGS[5:])}</div>
<div class="sec">Passing everywhere · 11 checks</div>
<div class="panel" style="padding:12px 16px;font-size:13px;color:#3A4766">Logon, Account management, Policy change, Privilege use, Process creation (Windows), Log size (23 of 24), No events lost to rollover, Original logs archived, Audit policy unchanged except WS-07, Linux auditd running, Time in sync</div>
</main>'''
    page10('A2-findings', body)

# ---------- A3: list + detail (per system STIG table) ----------
def a3():
    lst = '<div class="search">' + icon("search", 14) + 'Find a system</div>'
    for g, names in grpsd:
        lst += f'<div class="grp2">{g} · {len(names)}</div>'
        for n in sorted(names, key=lambda x: (x not in FAIL, x)):
            f = FAIL.get(n, {}); k = 'bad' if 'f' in f.values() else ('warn' if f else 'ok')
            cnt = sum(1 for v in f.values() if v == 'f')
            lst += f'<a class="{"sel" if n == "WS-07" else ""}"><i class="{k}"></i><span>{n}</span><small>{f"{cnt} gap" + ("s" if cnt > 1 else "") if cnt else ("warning" if f else "OK")}</small></a>'
    rows = [("ok", "Logon / Logoff", "WN11-AU-000045, -050", "Success and Failure", "Success and Failure"),
            ("ok", "Account Management", "WN11-AU-000030, -035", "Success and Failure", "Success and Failure"),
            ("ok", "Audit Policy Change", "WN11-AU-000100", "Success", "Success"),
            ("ok", "Sensitive Privilege Use", "WN11-AU-000115, -120", "Success and Failure", "Success and Failure"),
            ("ok", "Process Creation", "WN11-AU-000050", "Success", "Success"),
            ("bad", "Removable Storage", "WN11-AU-000090", "Success and Failure", "No auditing · changed 28 Sep 09:38 by admin_jd"),
            ("ok", "PowerShell Script Block Logging", "WN11-CC-000326", "Enabled", "Enabled"),
            ("ok", "Security log size", "WN11-AU-000500", "Holds a week", "Holds 9 days (1 GB)"),
            ("bad", "Logs intact", "—", "Not cleared", "Cleared 28 Sep 12:38 and 12:40 by admin_jd"),
            ("ok", "Reporting", "—", "Every hour", "168 runs, none missed")]
    tb = ''.join(f'<tr class="{k}"><td><b>{c}</b></td><td class="mono mute">{sid}</td><td>{req}</td><td>{have}</td><td><span class="st {k}">{ {"ok": "Matches", "bad": "Gap", "warn": "Warning"}[k] }</span></td></tr>' for k, c, sid, req, have in rows)
    body = aside("Audit health") + f'''<main>{AHEAD}{AKP}
<div class="md2" style="grid-template-columns:280px 1fr"><div class="panel slist" style="padding:12px 0">{lst}</div>
<div><div class="panel" style="margin-bottom:12px"><div class="dh"><div><h3>WS-07</h3><p>Windows 11 Enterprise 24H2 · compared with Windows 11 STIG V2R8 · checked 29 Sep 00:00</p></div><span class="sv high">2 gaps</span></div>
<div class="facts4"><div>Checks<b>10</b></div><div>Matching<b>8</b></div><div>Gaps<b class="bad">2</b></div><div>Log holds<b>9 days</b></div><div>Last check<b>29 Sep 00:00</b></div></div></div>
<div class="panel"><div class="ph"><h2>{icon("shield-check", 17)}Settings on WS-07</h2><span class="pm">Report only · Blackbox never changes these</span></div>
<table class="stig"><thead><tr><th>Check</th><th>STIG ID</th><th>Required</th><th>On this system</th><th>Result</th></tr></thead><tbody>{tb}</tbody></table></div>
</div></div></main>'''
    page10('A3-detail', body)

a1(); a2(); a3()
