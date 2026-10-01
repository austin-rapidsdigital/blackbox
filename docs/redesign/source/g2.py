import sys; sys.path.insert(0,sys.argv[1]); from glass import *
T=dict(accent="#0B5FFF",bad="#D12C2C",grid="rgba(0,30,98,.08)",heat0="#E9EFFB",heat1="#0A2A7A",
sparkfill="rgba(11,95,255,.10)",sparkfillbad="rgba(209,44,44,.10)")
T['css']=BASE+'''
body{color:#0B1630;background:#E8EEF8;background-image:radial-gradient(900px 520px at 85% -5%,rgba(11,95,255,.22),transparent 60%),radial-gradient(800px 600px at 15% 110%,rgba(0,30,98,.16),transparent 60%),linear-gradient(135deg,#EEF3FB,#E3EAF6)}
aside{background:linear-gradient(180deg,rgba(0,24,80,.94),rgba(0,18,60,.96));backdrop-filter:blur(18px);color:#fff;border-right:1px solid rgba(255,255,255,.08)}
.brand span{color:rgba(255,255,255,.6)}
.site{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);color:#fff}.site span{color:rgba(255,255,255,.55)}
.grp{color:rgba(255,255,255,.4)}
nav a{color:rgba(255,255,255,.78)}nav a svg{color:rgba(255,255,255,.6)}nav a small{color:rgba(255,255,255,.45)}
nav a.on{background:rgba(255,255,255,.1);color:#fff}nav a.on:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:#5AA9FF}nav a.on svg{color:#fff}
nav a em{background:#FF6B6B;color:#fff}
.crumb,.pm,.kl,.ks,td span,.ti span,.tr span,th,.lg{color:#5A6785}
.btn{background:rgba(255,255,255,.7);border:1px solid rgba(0,30,98,.14);color:#0B1630;backdrop-filter:blur(10px)}.btn svg{color:#5A6785}
.btn.primary{background:#0A2A7A;border-color:#0A2A7A;color:#fff}
.alertbar{background:rgba(255,236,236,.8);border:1px solid rgba(209,44,44,.25);border-left:3px solid #D12C2C;color:#6B1111;backdrop-filter:blur(10px)}.alertbar svg{color:#D12C2C}.alertbar a{color:#A31D1D}
.panel{background:linear-gradient(180deg,rgba(255,255,255,.82),rgba(255,255,255,.64));border:1px solid rgba(255,255,255,.9);outline:1px solid rgba(0,30,98,.08);backdrop-filter:blur(18px);box-shadow:0 1px 2px rgba(0,30,98,.06),0 12px 32px rgba(0,30,98,.07)}
.kv{color:#0A2A7A}.kv.bad{color:#D12C2C}
h2{color:#0B1630}h2 svg{color:#0B5FFF}
th{border-bottom:1px solid rgba(0,30,98,.14)}td{border-bottom:1px solid rgba(0,30,98,.07)}tr:last-child td{border-bottom:0}td.go svg{color:#8A96B3}
.sv.high{color:#C22020}.sv.high:before{background:#D12C2C}.sv.medium{color:#A35A00}.sv.medium:before{background:#E08A00}
.pm.sev-bad{color:#D12C2C;font-weight:650}
.ti+.ti{border-top:1px solid rgba(0,30,98,.07)}.tic{border:1px solid rgba(0,30,98,.12)}
.ti.bad .tic{color:#D12C2C;background:#FDECEC;border-color:#F5C2C2}.ti.warn .tic{color:#A35A00;background:#FDF3E1;border-color:#F3D9A8}.ti.ok .tic{color:#147A3D;background:#E6F5EC;border-color:#BFE3CC}
.tr+.tr{border-top:1px solid rgba(0,30,98,.07)}.tr i{color:#B01C1C;background:#FDECEC;border:1px solid #F5C2C2}
.tb{background:rgba(0,30,98,.07)}.tb s{background:linear-gradient(90deg,#0A2A7A,#0B5FFF)}
.ax{fill:#6B7794}.val{fill:#C22020}
'''
page(T,'g2-arctic')
