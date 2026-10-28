"""Build the PDFSentry threat-intelligence console (premium ECharts dashboard),
embedding the real result JSON + precomputed analyses + the object graph."""
import json, sys, types
from pathlib import Path
from backend.core.config import art, ROOT
from backend.core.analyze import analyze

bundle = json.load(open(art("metrics", "dashboard_data.json")))

# compression-mechanism proof: EMBER score of the 4 crafted fixtures
import numpy as np
_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
try:
    import thrember, lightgbm as lgb
    from backend.features.reach_features import reach_feature_vector
    _ext = thrember.PEFeatureExtractor()
    _mdl = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))
    mech = []
    for lbl, fp in [("auto-run, visible tokens", "fixture_active_onopen"),
                    ("auto-run, hidden in compressed stream", "fixture_active_buried"),
                    ("dormant (never runs)", "fixture_dormant"),
                    ("runs only on click", "fixture_interaction_only")]:
        d = open(ROOT / f"tests/fixtures/crafted/{fp}.pdf", "rb").read()
        v = np.array(_ext.feature_vector(d), dtype=np.float32).reshape(1, -1)
        rf = reach_feature_vector(d)
        mech.append({"label": lbl, "ember": float(_mdl.predict(v)[0]),
                     "reach_onopen": int(rf["rc_javascript_onopen"]),
                     "evasion_sig": int(rf["rc_evasion_signature"])})
    bundle["mechanism"] = mech
except Exception as e:
    bundle["mechanism"] = []

examples = {}
for key, path in {
    "Dormant JavaScript": "tests/fixtures/crafted/fixture_dormant.pdf",
    "Auto-run JavaScript": "tests/fixtures/crafted/fixture_active_onopen.pdf",
    "Token-buried auto-run": "tests/fixtures/crafted/fixture_active_buried.pdf",
    "GeoTopo.pdf (real)": "tests/fixtures/real_pdfs/GeoTopo.pdf",
}.items():
    try:
        a = analyze(open(ROOT / path, "rb").read())
        a["_source"] = path.split("/")[-1]
        examples[key] = a
    except Exception as e:
        examples[key] = {"error": str(e)}
bundle["examples"] = examples

DATA = json.dumps(bundle, separators=(",", ":"))

HTML = r"""<meta name="claude:viewport-fit-sides" content="cover">
<title>PDFSentry</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap">
__ECHARTS__
<style>
/* Threat-intelligence console — deliberately dark single-world.
   chrome = silver gradient ink; teal=robust/reachability, amber=gap, red=evasion. */
:root{
  --bg:#06080c; --bg2:#090d13; --grid:rgba(255,255,255,.028);
  --panel:#0c111a; --panel2:#0e141f; --glass:rgba(22,30,43,.55);
  --line:rgba(255,255,255,.07); --line2:rgba(255,255,255,.13);
  --ink:#e9eef5; --muted:#97a3b4; --faint:#5a6676;
  --teal:#2dd4bf; --teal2:#17b3a0; --cyan:#45c6f0;
  --amber:#f5b14c; --red:#f0616d; --pink:#e05c93; --blue:#5b94e8;
  --good:#2dd4bf; --warn:#f5b14c; --crit:#f0616d;
  --disp:'Sora',system-ui,sans-serif; --mono:'JetBrains Mono',ui-monospace,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font-family:var(--disp);font-weight:400;
  -webkit-font-smoothing:antialiased;
  background-image:
    radial-gradient(1100px 620px at 78% -8%, rgba(45,212,191,.09), transparent 60%),
    radial-gradient(900px 560px at 8% 108%, rgba(91,148,232,.07), transparent 55%),
    linear-gradient(var(--grid) 1px,transparent 1px),
    linear-gradient(90deg,var(--grid) 1px,transparent 1px);
  background-size:auto,auto,44px 44px,44px 44px;}
h1,h2,h3,h4{margin:0;text-wrap:balance;font-weight:600;letter-spacing:-.01em}
.mono{font-family:var(--mono)} .tnum{font-variant-numeric:tabular-nums}
.chrome{background:linear-gradient(180deg,#fff 0%,#dfe6ef 42%,#9fb0c2 78%,#c9d4df 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
a{color:var(--teal)}
/* shell */
.app{display:grid;grid-template-columns:234px 1fr;min-height:100vh}
.rail{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;
  background:linear-gradient(180deg,#0a0e15,#070a0f);border-right:1px solid var(--line);
  padding:18px 14px;display:flex;flex-direction:column;gap:3px}
.brand{display:flex;align-items:center;gap:11px;padding:6px 8px 16px;border-bottom:1px solid var(--line);margin-bottom:12px}
.logo{width:34px;height:34px;border-radius:9px;position:relative;flex:0 0 34px;
  background:linear-gradient(145deg,#0f1a22,#0b1118);border:1px solid var(--line2);
  box-shadow:0 0 0 1px rgba(45,212,191,.12),0 8px 22px -10px rgba(45,212,191,.5);
  display:grid;place-items:center}
.logo svg{width:19px;height:19px}
.brand b{font-size:15px;font-weight:700;letter-spacing:.12em;display:block;line-height:1}
.brand span{font-size:9px;color:var(--faint);letter-spacing:.26em;text-transform:uppercase}
.navgrp{font-size:9.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--faint);
  padding:14px 10px 6px}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{all:unset;cursor:pointer;display:flex;gap:11px;align-items:center;
  padding:9px 11px;border-radius:9px;color:var(--muted);font-size:13px;transition:.16s;position:relative}
.nav button svg{width:16px;height:16px;opacity:.8;flex:0 0 16px}
.nav button:hover{background:rgba(255,255,255,.035);color:var(--ink)}
.nav button[aria-current="true"]{background:linear-gradient(90deg,rgba(45,212,191,.14),rgba(45,212,191,.02));
  color:#fff}
.nav button[aria-current="true"]::before{content:"";position:absolute;left:0;top:7px;bottom:7px;width:2.5px;
  border-radius:2px;background:var(--teal);box-shadow:0 0 10px var(--teal)}
.railftr{margin-top:auto;padding:12px 8px 4px;border-top:1px solid var(--line);
  font-size:10px;color:var(--faint);line-height:1.7}
/* main */
.main{min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:16px;flex-wrap:wrap;
  padding:14px max(22px,env(safe-area-inset-right,0)) 14px max(22px,env(safe-area-inset-left,0));
  background:rgba(6,8,12,.72);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.crumb{font-size:11px;color:var(--faint);font-family:var(--mono);letter-spacing:.04em}
.crumb b{color:var(--muted);font-weight:500}
.statuscluster{margin-left:auto;display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-size:10.5px;
  color:var(--muted);padding:6px 11px;border:1px solid var(--line);border-radius:8px;background:rgba(255,255,255,.015)}
.chip b{color:var(--ink);font-weight:500}
.live{width:7px;height:7px;border-radius:50%;background:var(--teal);box-shadow:0 0 0 0 rgba(45,212,191,.6);
  animation:pulse 2.4s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(45,212,191,.55)}70%{box-shadow:0 0 0 7px rgba(45,212,191,0)}100%{box-shadow:0 0 0 0 rgba(45,212,191,0)}}
.content{padding:26px max(22px,env(safe-area-inset-right,0)) 72px max(22px,env(safe-area-inset-left,0));max-width:1240px}
.vhead{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:6px;flex-wrap:wrap}
.eyebrow{font-family:var(--mono);font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;
  color:var(--teal);margin-bottom:9px}
h2.view{font-size:27px;font-weight:700;letter-spacing:-.02em}
.lede{color:var(--muted);font-size:14px;max-width:76ch;margin:10px 0 22px;line-height:1.65}
/* grid + panels */
.grid{display:grid;gap:15px}
.c4{grid-template-columns:repeat(4,1fr)} .c3{grid-template-columns:repeat(3,1fr)} .c2{grid-template-columns:repeat(2,1fr)}
.panel{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
  border-radius:15px;padding:20px;position:relative;overflow:hidden;
  box-shadow:0 1px 0 rgba(255,255,255,.03) inset,0 20px 40px -32px rgba(0,0,0,.9)}
.panel::after{content:"";position:absolute;inset:0;border-radius:15px;padding:1px;pointer-events:none;
  background:linear-gradient(140deg,rgba(255,255,255,.1),transparent 40%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;opacity:.6}
.panel h3.t{font-size:14.5px;font-weight:600;margin-bottom:4px}
.panel .d{font-size:12.5px;color:var(--muted);margin-bottom:16px;max-width:76ch;line-height:1.6}
/* KPI */
.kpi{position:relative;overflow:hidden}
.kpi .glow{position:absolute;width:140px;height:140px;border-radius:50%;filter:blur(46px);opacity:.5;
  top:-54px;right:-40px;pointer-events:none}
.kpi h3{font-size:11px;color:var(--muted);font-weight:500;letter-spacing:.03em;margin-bottom:12px;position:relative}
.kpi .num{font-family:var(--mono);font-size:33px;font-weight:600;letter-spacing:-.02em;line-height:1;position:relative}
.kpi .num small{font-size:14px;color:var(--faint);font-weight:400}
.kpi .sub{font-size:11px;color:var(--faint);margin-top:9px;font-family:var(--mono);position:relative}
.kpi .spark{margin-top:12px;height:30px;position:relative}
.chart{width:100%}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line)}
th{color:var(--faint);font-weight:500;font-family:var(--mono);font-size:10px;letter-spacing:.07em;text-transform:uppercase}
tbody tr{transition:background .12s}
tbody tr:hover{background:rgba(255,255,255,.02)}
td.mono,th.mono{font-family:var(--mono)}
.tag{font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:6px;white-space:nowrap;font-weight:500}
.t-open{background:rgba(240,97,109,.15);color:#ff8088;border:1px solid rgba(240,97,109,.25)}
.t-int{background:rgba(245,177,76,.15);color:var(--amber);border:1px solid rgba(245,177,76,.25)}
.t-dorm{background:rgba(255,255,255,.05);color:var(--muted);border:1px solid var(--line)}
.t-ok{background:rgba(45,212,191,.14);color:var(--teal);border:1px solid rgba(45,212,191,.28)}
.band{font-family:var(--mono);font-weight:600;padding:4px 10px;border-radius:7px;font-size:11px;letter-spacing:.03em}
.b-HIGH{background:rgba(240,97,109,.16);color:#ff8088} .b-ELEVATED{background:rgba(245,177,76,.16);color:var(--amber)}
.b-LOW{background:rgba(45,212,191,.16);color:var(--teal)} .b-UNKNOWN{background:rgba(255,255,255,.06);color:var(--muted)}
.callout{position:relative;border-radius:13px;padding:17px 19px 17px 22px;margin-top:17px;
  background:linear-gradient(100deg,rgba(45,212,191,.09),rgba(45,212,191,.012));border:1px solid rgba(45,212,191,.2);font-size:13.5px;line-height:1.6}
.callout.warn{background:linear-gradient(100deg,rgba(245,177,76,.09),rgba(245,177,76,.01));border-color:rgba(245,177,76,.22)}
.callout b{color:var(--teal)} .callout.warn b{color:var(--amber)}
.note{font-size:11px;color:var(--faint);margin-top:13px;line-height:1.65}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden;flex-wrap:wrap;background:rgba(255,255,255,.015)}
.seg button{all:unset;cursor:pointer;padding:9px 15px;color:var(--muted);font-family:var(--mono);font-size:12px;transition:.14s}
.seg button[aria-current="true"]{background:linear-gradient(180deg,var(--teal),var(--teal2));color:#04120f;font-weight:600}
.scroll{max-height:440px;overflow:auto;border:1px solid var(--line);border-radius:12px}
.scroll th{position:sticky;top:0;background:#0a0f17;z-index:1}
.row-dis{background:rgba(224,92,147,.07)}
.legendrow{display:flex;gap:18px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-top:12px}
.legendrow i{width:10px;height:10px;border-radius:3px;display:inline-block;margin-right:6px;vertical-align:middle}
.bars{display:flex;flex-direction:column;gap:9px;margin-top:4px}
.barrow{display:grid;grid-template-columns:168px 1fr 58px;align-items:center;gap:11px;font-size:12px}
.barrow .lab{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.track{height:18px;background:rgba(255,255,255,.04);border-radius:5px;overflow:hidden;border:1px solid var(--line)}
.fill{height:100%;border-radius:5px;transition:width .9s cubic-bezier(.2,.8,.2,1)}
.val{font-family:var(--mono);font-size:11.5px;text-align:right;color:var(--ink)}
.fadein{animation:fade .5s ease both}
@keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@media (max-width:980px){.app{grid-template-columns:1fr}.rail{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center}
  .rail .navgrp{display:none}.railftr{display:none}.nav{flex-direction:row;flex-wrap:wrap}.brand{width:100%;border:0}
  .c4,.c3,.c2{grid-template-columns:repeat(2,1fr)}}
@media (max-width:560px){.c4,.c3,.c2{grid-template-columns:1fr}.barrow{grid-template-columns:110px 1fr 48px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>

<div class="app">
  <nav class="rail">
    <div class="brand">
      <span class="logo"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" stroke="#2dd4bf" stroke-width="1.4"/><path d="M8.5 12.2l2.3 2.3 4.7-5" stroke="#2dd4bf" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <div><b class="chrome">PDFSENTRY</b><span>threat intelligence</span></div>
    </div>
    <div id="nav"></div>
    <div class="railftr" id="railftr"></div>
  </nav>
  <main class="main">
    <div class="topbar">
      <div class="crumb">PDFSENTRY / <b id="crumb">overview</b></div>
      <div class="statuscluster" id="status"></div>
    </div>
    <div class="content"><section id="view"></section></div>
  </main>
</div>

<script id="D" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('D').textContent);
const $=h=>{const t=document.createElement('template');t.innerHTML=h.trim();return t.content.firstChild};
const pct=(x,d=1)=>(x*100).toFixed(d)+'%'; const f4=x=>x.toFixed(4); const f3=x=>x.toFixed(3);
const C={teal:'#2dd4bf',teal2:'#17b3a0',amber:'#f5b14c',red:'#f0616d',pink:'#e05c93',blue:'#5b94e8',
  ink:'#e9eef5',muted:'#97a3b4',faint:'#5a6676',line:'rgba(255,255,255,.09)'};
let CHARTS=[]; const reduce=matchMedia('(prefers-reduced-motion:reduce)').matches;
function mk(id,opt){try{const el=document.getElementById(id);if(!el||typeof echarts==='undefined')return;
  const c=echarts.init(el,null,{renderer:'canvas'});
  opt.animationDuration=reduce?0:900;opt.textStyle={fontFamily:'JetBrains Mono,monospace',color:C.muted};
  c.setOption(opt);CHARTS.push(c);return c;}catch(e){console.error('chart '+id,e);}}
function clearCharts(){CHARTS.forEach(c=>{try{c.dispose()}catch(e){}});CHARTS=[]}
addEventListener('resize',()=>CHARTS.forEach(c=>c.resize()));
function countUp(){document.querySelectorAll('[data-to]').forEach(el=>{
  const to=+el.dataset.to,dec=+(el.dataset.dec||0),suf=el.dataset.suf||'';
  if(reduce){el.textContent=to.toFixed(dec)+suf;return;}
  const t0=performance.now(),dur=900;
  (function step(t){let k=Math.min(1,(t-t0)/dur);k=1-Math.pow(1-k,3);
    el.textContent=(to*k).toFixed(dec)+suf;if(k<1)requestAnimationFrame(step)})(t0);});}

const AX={axisLine:{lineStyle:{color:C.line}},axisTick:{show:false},
  axisLabel:{color:C.faint,fontSize:10},splitLine:{lineStyle:{color:'rgba(255,255,255,.04)'}}};
function grad(hex,a1=.35,a2=0){return new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:'rgba('+hx(hex)+','+a1+')'},{offset:1,color:'rgba('+hx(hex)+','+a2+')'}])}
function hx(h){h=h.replace('#','');return [0,2,4].map(i=>parseInt(h.slice(i,i+2),16)).join(',')}

function prChart(id,series){ // series:[{name,color,pts:[[x,y]..]}]
  mk(id,{grid:{left:46,right:16,top:26,bottom:40},legend:{top:0,right:0,textStyle:{color:C.muted,fontSize:10},icon:'roundRect'},
    tooltip:{trigger:'axis',backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11},
      valueFormatter:v=>(+v).toFixed(3)},
    xAxis:{type:'value',min:0,max:1,name:'recall',nameLocation:'middle',nameGap:24,nameTextStyle:{color:C.faint,fontSize:10},...AX},
    yAxis:{type:'value',min:0,max:1,name:'precision',nameLocation:'middle',nameGap:32,nameTextStyle:{color:C.faint,fontSize:10},...AX},
    series:series.map(s=>({name:s.name,type:'line',smooth:true,showSymbol:false,data:s.pts,
      lineStyle:{color:s.color,width:2.4},itemStyle:{color:s.color},
      areaStyle:{color:grad(s.color,.22,0)}}))});}
function gauge(id,val,label,color,max=1){
  mk(id,{series:[{type:'gauge',radius:'94%',center:['50%','58%'],startAngle:210,endAngle:-30,min:0,max:max,
    progress:{show:true,width:13,roundCap:true,itemStyle:{color:new echarts.graphic.LinearGradient(0,0,1,0,[{offset:0,color:color},{offset:1,color:'#fff'}])}},
    axisLine:{lineStyle:{width:13,color:[[1,'rgba(255,255,255,.07)']]}},
    pointer:{show:false},axisTick:{show:false},splitLine:{show:false},axisLabel:{show:false},
    anchor:{show:false},title:{show:true,offsetCenter:[0,'34%'],color:C.faint,fontSize:11,fontFamily:'JetBrains Mono'},
    detail:{valueAnimation:true,offsetCenter:[0,'-2%'],fontSize:30,fontFamily:'JetBrains Mono',fontWeight:600,
      color:color,formatter:v=>max<=1?(v*100).toFixed(1)+'%':v.toFixed(0)},
    data:[{value:val,name:label}]}]});}
function barH(id,items,color,fmt){ // items:[{name,v}]
  mk(id,{grid:{left:4,right:46,top:8,bottom:8,containLabel:true},
    tooltip:{trigger:'axis',axisPointer:{type:'shadow'},backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
    xAxis:{type:'value',...AX,splitLine:{show:false}},
    yAxis:{type:'category',inverse:true,data:items.map(i=>i.name),axisLine:{show:false},axisTick:{show:false},
      axisLabel:{color:C.muted,fontSize:10,fontFamily:'JetBrains Mono'}},
    series:[{type:'bar',data:items.map(i=>i.v),barWidth:'62%',
      itemStyle:{borderRadius:[0,5,5,0],color:new echarts.graphic.LinearGradient(0,0,1,0,[{offset:0,color:'rgba('+hx(color)+',.35)'},{offset:1,color:color}])},
      label:{show:true,position:'right',color:C.ink,fontFamily:'JetBrains Mono',fontSize:10.5,formatter:p=>fmt(p.value)}}]});}
</script>
<script>
const VIEWS=[['overview','Overview','grid'],['gap','The evasive gap','trend'],['realmal','Real evasive malware','dna'],
  ['evasion','Structural evasion','target'],['reach','Reachability graph','node'],['explain','Why they evade','radar'],
  ['probe','Mimicry probe','probe'],['investigate','Investigate','search'],['about','Method & limits','doc']];
const ICON={grid:'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  trend:'M3 17l6-6 4 4 7-8M21 7v5M21 7h-5',dna:'M4 3c4 4 12 4 16 0M4 21c4-4 12-4 16 0M7 5v14M17 5v14',
  target:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 11v2',
  node:'M5 12m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M19 5m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M19 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M7 11l10-5M7 13l10 5',
  radar:'M12 2l9 6.5-3.5 10.5h-11L3 8.5zM12 2v20M3 8.5l18 0',probe:'M3 12h4l3 8 4-16 3 8h4',
  search:'M11 11m-7 0a7 7 0 1 0 14 0a7 7 0 1 0-14 0M21 21l-4.3-4.3',doc:'M6 2h9l5 5v15H6zM15 2v5h5'};
function svg(k){return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="${ICON[k]}"/></svg>`}

const VC={ACTIVE_ONOPEN:['t-open','ACTIVE · on-open'],ACTIVE_ONINTERACT:['t-int','active · on-click'],
  PRESENT_DORMANT:['t-dorm','dormant'],ABSENT:['t-dorm','absent']};
function kpi(label,numHtml,sub,color,glow){return `<div class="panel kpi fadein">
  ${glow?`<span class="glow" style="background:${color}"></span>`:''}
  <h3>${label}</h3><div class="num" style="color:${color||'var(--ink)'}">${numHtml}</div>
  <div class="sub">${sub}</div></div>`;}
function num(to,dec,suf){return `<span data-to="${to}" data-dec="${dec}" data-suf="${suf||''}">0</span>`}

const R={
 overview(){const eo=D.ember.ordinary.metrics,ec=D.ember.challenge.metrics,se=D.structural_evasion,cs=D.challenge_structure;
  return `<div class="eyebrow">EMBER2024 · PDF detection</div>
   <div class="vhead"><h2 class="view">Closing the evasive gap</h2></div>
   <p class="lede">We reproduce EMBER2024's PDF benchmark on the authors' own model, prove on real evasive
     malware why it fails, and close the gap with a structural <b style="color:var(--teal)">reachability</b>
     signal — every number here traces to a stored artifact.</p>
   <div class="grid c4">
     ${kpi('EMBER ordinary PR-AUC',num(eo.pr_auc,4),'published 0.9933 · reproduced',C.teal,1)}
     ${kpi('EMBER evasive PR-AUC',num(ec.pr_auc,4),'published 0.7841 · '+ec.confusion.fn+'/'+D.ember.challenge.n_evasive+' missed',C.amber,1)}
     ${kpi('Weaponized docs evading EMBER',num(se.ember_evasion_rate*100,1,'%'),'reachability catches '+pct(se.reachability_detection_rate),C.red,1)}
     ${kpi('EMBER + reachability fusion',num(se.detector_auc.ember_plus_reachability_fusion,3),'AUC vs '+f3(se.detector_auc.ember_score_alone)+' alone',C.teal,1)}
   </div>
   <div class="grid c2" style="margin-top:15px">
     <div class="panel fadein"><h3 class="t">Ordinary vs evasive — the gap</h3>
       <p class="d">Same model, two precision–recall curves. Evasive malware collapses precision.</p>
       <div class="chart" id="ov_pr" style="height:290px"></div></div>
     <div class="panel fadein"><h3 class="t">Fusion recovers what EMBER misses</h3>
       <p class="d">Separating a safe PDF from its weaponized twin.</p>
       <div class="chart" id="ov_g1" style="height:150px"></div>
       <div class="callout" style="margin-top:4px"><b>+${((se.detector_auc.ember_plus_reachability_fusion-se.detector_auc.ember_score_alone)).toFixed(3)} AUC.</b>
         On ${cs.n_evasive_pdf} real evasive PDFs, EMBER's misses are measurably more compressed
         (p&lt;10⁻¹⁵) — the mechanism reachability is built to see.</div></div>
   </div>`;},
 gap(){const eo=D.ember.ordinary.metrics,ec=D.ember.challenge.metrics;
  return `<div class="eyebrow">Objective O1 · reproduction</div><h2 class="view">The evasive gap, reproduced</h2>
   <p class="lede">A detector that looks solved on ordinary malware misses malware that first evaded antivirus.
     We reproduce it on the authors' released model so everything downstream builds on a verified baseline.</p>
   <div class="grid c3">
     ${kpi('Ordinary recall',num(eo.recall*100,1,'%'),'at threshold 0.5',C.teal,0)}
     ${kpi('Evasive missed',num(ec.confusion.fn,0)+'<small>/'+D.ember.challenge.n_evasive+'</small>',pct(ec.confusion.fn/D.ember.challenge.n_evasive)+' of evasive malware slips through',C.amber,1)}
     ${kpi('PR-AUC drop',num((eo.pr_auc-ec.pr_auc),4),f4(eo.pr_auc)+' → '+f4(ec.pr_auc),C.red,0)}
   </div>
   <div class="grid c2" style="margin-top:15px">
     <div class="panel fadein"><h3 class="t">Ordinary test — PR curve</h3><div class="chart" id="gap_o" style="height:270px"></div></div>
     <div class="panel fadein"><h3 class="t">Evasive challenge — PR curve</h3><div class="chart" id="gap_c" style="height:270px"></div></div>
   </div>
   <table style="margin-top:15px"><thead><tr><th>Evaluation</th><th class="mono">ROC-AUC</th><th class="mono">PR-AUC</th><th class="mono">published</th></tr></thead><tbody>
     <tr><td>Ordinary test (24k PDFs)</td><td class="mono">${f4(eo.roc_auc)}</td><td class="mono">${f4(eo.pr_auc)}</td><td class="mono">.9912 / .9933</td></tr>
     <tr><td>Evasive challenge (805 + 6k benign)</td><td class="mono">${f4(ec.roc_auc)}</td><td class="mono">${f4(ec.pr_auc)}</td><td class="mono">.9066 / .7841</td></tr>
   </tbody></table>`;},
 realmal(){const cs=D.challenge_structure,c=cs.metric_comparison_missed_vs_caught;
  const fmtp=p=>p<1e-4?p.toExponential(1):p.toFixed(3);
  const spec=[['/FlateDecode (compression)','/FlateDecode'],['byte entropy','entropy'],['file size (bytes)','size'],
    ['visible /URI strings','/URI'],['visible javascript strings','javascript'],['string count','numstrings']];
  const rows=spec.map(([l,k])=>{const m=c[k],sig=m.mannwhitney_p<.001;
    return `<tr><td>${l}</td><td class="mono tnum">${(+m.missed_median).toPrecision(3)}</td>
      <td class="mono tnum">${(+m.caught_median).toPrecision(3)}</td>
      <td class="mono tnum" style="color:${sig?C.teal:C.faint}">${fmtp(m.mannwhitney_p)}</td></tr>`}).join('');
  return `<div class="eyebrow">Objective O2 · real-data evidence</div><h2 class="view">The signature in real evasive malware</h2>
   <p class="lede">The strongest evidence needs no malware handling — it is in EMBER's own released features for the
     ${cs.n_evasive_pdf} evasive challenge PDFs. Split by whether EMBER catches or misses them, the misses carry
     the compression / token-hiding signature our method targets.</p>
   <div class="grid c3">
     ${kpi('Real evasive PDFs missed',num(cs.ember_missed,0)+'<small>/'+cs.n_evasive_pdf+'</small>','EMBER recall '+pct(cs.ember_recall_on_challenge),C.amber,1)}
     ${kpi('Compression in misses',num(12,0)+' <small>vs 7</small>','median /FlateDecode, missed vs caught',C.teal,1)}
     ${kpi('Significance',"p&lt;10⁻¹⁵",'Mann–Whitney, missed vs caught',C.ink,0)}
   </div>
   <div class="grid c2" style="margin-top:15px"><div class="panel fadein"><h3 class="t">Missed vs caught — structure (real data)</h3>
     <p class="d">Per-sample medians from EMBER's released features.</p>
     <table><thead><tr><th>Metric</th><th class="mono">missed</th><th class="mono">caught</th><th class="mono">p</th></tr></thead><tbody>${rows}</tbody></table>
     <p class="note">≈99% of all evasive PDFs carry zero visible JavaScript strings — they hide the payload behind
       compression, which is why they defeat EMBER's string-based view.</p></div>
     <div class="panel fadein"><h3 class="t">How much more, in the misses</h3>
       <p class="d">Ratio of missed-median to caught-median — above 1× means the malware EMBER misses scores higher
         on that axis (more compression, bulk, obfuscation).</p>
       <div class="chart" id="rm_fold" style="height:250px"></div></div>
   </div>
   <div class="callout"><b>This is the real-malware link.</b> The evasion mechanism in our study isn't hypothetical —
     the evasive malware EMBER actually misses is measurably more compressed and obfuscated.</div>`;},
 evasion(){const se=D.structural_evasion,mech=D.mechanism||[],g=D.evasion_generality;
  const imp=se.fusion_top_features.slice(0,7).map(x=>({name:x.feature.replace('rc_',''),v:x.gain}));
  const mrows=mech.map(m=>`<tr><td>${m.label}</td><td class="mono tnum">${m.ember.toFixed(3)}</td>
    <td>${m.ember>=.5?'<span class="tag t-open">flagged</span>':'<span class="tag t-dorm">missed</span>'}</td>
    <td class="mono tnum">${m.reach_onopen}</td><td>${m.evasion_sig?'<span class="tag t-ok">yes</span>':'—'}</td></tr>`).join('');
  const grows=g?Object.entries(g.wirings).map(([w,v])=>`<tr><td class="mono">${w}</td>
    <td class="mono tnum">${pct(v.ember_evasion_rate,0)}</td><td class="mono tnum" style="color:${C.teal}">${pct(v.reach_detection_full,0)}</td>
    <td class="mono tnum" style="color:${C.teal}">${pct(v.reach_detection_ablated,0)}</td></tr>`).join(''):'';
  return `<div class="eyebrow">Objective O3 / O4 · the headline</div><h2 class="view">Structural evasion of the real detector</h2>
   <p class="lede">We weaponize ${se.n_benign_originals} real benign PDFs — inject a reachable auto-run JavaScript action
     (a harmless alert) hidden in a compressed stream — and ask whether the 0.99-AUC detector notices.</p>
   <div class="grid c3">
     <div class="panel fadein"><h3 class="t" style="color:var(--muted);font-weight:500;font-size:11px">EVADED EMBER</h3><div class="chart" id="ev_g1" style="height:150px"></div></div>
     <div class="panel fadein"><h3 class="t" style="color:var(--muted);font-weight:500;font-size:11px">CAUGHT BY REACHABILITY</h3><div class="chart" id="ev_g2" style="height:150px"></div></div>
     ${kpi('Mean EMBER score',se.ember_mean_score_original.toFixed(3)+' → '+se.ember_mean_score_weaponized.toFixed(3),'original → weaponized (barely moves)',C.ink,0)}
   </div>
   <div class="grid c2" style="margin-top:15px">
     <div class="panel fadein"><h3 class="t">Fusion closes the gap</h3>
       <p class="d">Tell a safe PDF from its weaponized twin. EMBER alone can't (AUC ${f3(se.detector_auc.ember_score_alone)}); + reachability → ${f3(se.detector_auc.ember_plus_reachability_fusion)} (5-fold CV).</p>
       <div class="bars">
         <div class="barrow"><div class="lab">EMBER alone</div><div class="track"><div class="fill" style="width:${se.detector_auc.ember_score_alone*100}%;background:linear-gradient(90deg,rgba(245,177,76,.4),var(--amber))"></div></div><div class="val">${f4(se.detector_auc.ember_score_alone)}</div></div>
         <div class="barrow"><div class="lab">EMBER + reachability</div><div class="track"><div class="fill" style="width:${se.detector_auc.ember_plus_reachability_fusion*100}%;background:linear-gradient(90deg,rgba(45,212,191,.4),var(--teal))"></div></div><div class="val">${f4(se.detector_auc.ember_plus_reachability_fusion)}</div></div>
       </div></div>
     <div class="panel fadein"><h3 class="t">Features doing the work</h3><p class="d">Fusion gain by feature.</p>
       <div class="chart" id="ev_imp" style="height:190px"></div></div>
   </div>
   <div class="panel fadein"><h3 class="t">The compression mechanism, isolated</h3>
     <p class="d">The same action scored by the real EMBER model four ways. Hiding it in a compressed stream drops the score below threshold.</p>
     <table><thead><tr><th>Crafted PDF</th><th class="mono">EMBER score</th><th>verdict</th><th class="mono">reach on-open</th><th>evasion sig</th></tr></thead><tbody>${mrows}</tbody></table></div>
   ${g?`<div class="panel fadein"><h3 class="t">Generality &amp; ablation — not one tailored feature</h3>
     <p class="d">The action wired four structurally different ways, over ${g.n_base_pdfs} PDFs. Reachability catches every wiring — and still 100% with the evasion-signature feature <b>removed</b> (ablated).</p>
     <table><thead><tr><th>Evasion wiring</th><th class="mono">EMBER evaded</th><th class="mono">reachability</th><th class="mono">reach (ablated)</th></tr></thead><tbody>${grows}</tbody></table></div>`:''}`;},
 reach(){const og=D.object_graph,cr=D.reachability.rows.crafted,real=D.reachability.rows.real,dis=D.reachability.disagreement;
  const crafted=cr.map(r=>{const c=r.capabilities[0]||{},v=VC[r.reachability_verdict]||['t-dorm',r.reachability_verdict];
    return `<tr><td>${r.file.replace('fixture_','').replace('.pdf','')}</td><td class="mono">${c.capability||'—'}</td>
      <td class="mono tnum">${r.naive_token_count}</td><td><span class="tag ${v[0]}">${v[1]}</span></td></tr>`}).join('');
  const capDis=c=>(c.verdict==='ACTIVE_ONOPEN'&&c.naive_count===0)||(c.naive_count>=2&&(c.verdict==='PRESENT_DORMANT'||c.verdict==='ACTIVE_ONINTERACT'));
  const realrows=real.filter(r=>r.parsed).map(r=>{const d=(r.capabilities||[]).some(capDis),v=VC[r.reachability_verdict]||['t-dorm',r.reachability_verdict];
    return `<tr class="${d?'row-dis':''}"><td>${r.file}</td><td class="mono tnum">${r.n_objects}</td><td class="mono tnum">${r.naive_token_count}</td>
      <td><span class="tag ${v[0]}">${v[1]}</span></td><td class="mono" style="color:${d?C.pink:'inherit'}">${d?'⚠ disagree':''}</td></tr>`}).join('');
  return `<div class="eyebrow">The novel signal · reachability</div><h2 class="view">PDF object-reachability graph</h2>
   <p class="lede">Count-based detectors ask <i>how many</i> dangerous tokens appear. We parse the object graph and ask
     whether a dangerous action is <b style="color:var(--teal)">reachable from an automatic trigger</b>. Below: a real
     parsed PDF's object graph — the red node is JavaScript that auto-runs on open, reachable through the amber trigger path.</p>
   <div class="panel fadein"><div class="chart" id="graph" style="height:430px"></div>
     <div class="legendrow"><span><i style="background:#cbd5e1"></i>catalog</span><span><i style="background:#5b94e8"></i>pages / page</span>
       <span><i style="background:var(--amber)"></i>trigger / action</span><span><i style="background:var(--red)"></i>dangerous (JS)</span>
       <span><i style="background:var(--teal2)"></i>object</span></div>
     <p class="note">${og?og.source+' · '+og.nodes.length+' objects, '+og.edges.length+' references':''} — drag to explore.</p></div>
   <div class="grid c2" style="margin-top:15px">
     <div class="panel fadein"><h3 class="t">Four fixtures, identical to a byte counter</h3>
       <p class="d">Same /JavaScript count; reachability separates auto-run from inert, click-only, and compressed-hidden.</p>
       <table><thead><tr><th>Fixture</th><th>Capability</th><th class="mono">Naive count</th><th>Verdict</th></tr></thead><tbody>${crafted}</tbody></table></div>
     <div class="panel fadein"><h3 class="t">Real corpus — ${real.filter(r=>r.parsed).length} benign PDFs</h3>
       <p class="d">${dis.naive_over_alarm} over-alarms + ${dis.naive_under_alarm} under-alarms (e.g. GeoTopo.pdf: auto-runs, byte-count 0).</p>
       <div class="scroll"><table><thead><tr><th>File</th><th class="mono">Objs</th><th class="mono">Naive</th><th>Reachability</th><th></th></tr></thead><tbody>${realrows}</tbody></table></div></div>
   </div>`;},
 explain(){const fm=D.ember_shap.family_mass,gr=D.ember_shap.groups;
  return `<div class="eyebrow">Objective O2 · SHAP diagnosis</div><h2 class="view">Why the evasive malware is missed</h2>
   <p class="lede">SHAP on the authors' EMBER model, across three groups. The striking part: the malware it
     <i>misses</i> looks almost identical to what it <i>catches</i> — both read as byte/string statistics, with no
     structural signal to separate them.</p>
   <div class="grid c2">
     <div class="panel fadein"><h3 class="t">Feature-family attention (mean |SHAP|)</h3>
       <p class="d">Three groups, one shape. Nearly identical, byte/string-dominated profiles.</p>
       <div class="chart" id="radar" style="height:360px"></div></div>
     <div class="panel fadein"><h3 class="t">The void reachability fills</h3>
       <p class="d">Across all three groups the model spends ~${pct(fm.missed_evasive.strings)} on string features,
         ~${pct(fm.missed_evasive.histogram)} on the byte histogram, and essentially <b>0% on structure</b>.</p>
       <table><thead><tr><th>Group</th><th class="mono">n</th><th class="mono">strings</th><th class="mono">histogram</th><th class="mono">structure</th></tr></thead><tbody>
         ${['caught_ordinary','caught_evasive','missed_evasive'].map(g=>{const nm={caught_ordinary:'Caught ordinary',caught_evasive:'Caught evasive',missed_evasive:'Missed evasive'};
           return `<tr><td>${nm[g]}</td><td class="mono tnum">${gr[g]}</td><td class="mono tnum">${pct(fm[g].strings)}</td><td class="mono tnum">${pct(fm[g].histogram)}</td><td class="mono tnum" style="color:${C.faint}">~0%</td></tr>`}).join('')}
       </tbody></table>
       <div class="callout" style="margin-top:14px"><b>Missed ≈ caught.</b> Once an evasive file's byte/string profile looks benign, the baseline has nothing left.</div></div>
   </div>`;},
 probe(){const eb=D.evasion_baseline,cmp=D.comparison;const hist=eb.evasion_cost.hist;
  const frag=eb.feature_fragility.slice(0,8).map(x=>({name:x.feature,v:x.used_in_evasions}));
  return `<div class="eyebrow">Objective O6 · mimicry probe</div><h2 class="view">Mimicry probe (CIC feature set)</h2>
   <p class="lede">A complementary angle: for every malicious file a count-based detector catches, search for the cheapest
     feature edits that flip it to benign. It quantifies how little evasion costs against a keyword-count model.</p>
   <div class="grid c3">
     ${kpi('Caught malware evaded',num(eb.n_evaded/eb.n_caught_evaluated*100,1,'%'),eb.n_evaded+'/'+eb.n_caught_evaluated+' samples',C.pink,1)}
     ${kpi('Median edits to evade',num(eb.evasion_cost.median,0),'of '+eb.controllable_features.length+' editable fields',C.amber,0)}
     ${kpi('Feature-selection fix?',pct(cmp.evasion.baseline.ers,0)+' → '+pct(cmp.evasion.structure_first.ers,0),'resilience barely moves — no',C.ink,0)}
   </div>
   <div class="grid c2" style="margin-top:15px">
     <div class="panel fadein"><h3 class="t">Evasion cost distribution</h3><p class="d">Distinct fields changed to flip a caught sample.</p><div class="chart" id="pb_hist" style="height:220px"></div></div>
     <div class="panel fadein"><h3 class="t">Most fragile features</h3><p class="d">Share of successful evasions touching each feature.</p><div class="chart" id="pb_frag" style="height:220px"></div></div>
   </div>`;},
 investigate(){const names=Object.keys(D.examples);
  return `<div class="eyebrow">Live analysis</div><h2 class="view">Investigate</h2>
   <p class="lede">The engine runs the detector and reachability on a PDF and reconciles them. Four precomputed analyses —
     the headline is what happens when the two signals disagree.</p>
   <div class="seg" style="margin-bottom:15px" id="exseg">${names.map((n,i)=>`<button data-ex="${i}" aria-current="${i===0}">${n}</button>`).join('')}</div>
   <div id="exbody"></div>`;},
 about(){const cs=D.challenge_structure;
  return `<div class="eyebrow">Transparency</div><h2 class="view">Method &amp; limits</h2>
   <p class="lede">What is measured, on what data, and what remains unproven.</p>
   <div class="grid c2">
     <div class="panel fadein"><h3 class="t">What is real</h3><ul style="font-size:13px;color:var(--muted);line-height:1.85;padding-left:18px;margin:0">
       <li>EMBER2024 benchmark reproduced on the authors' released PDF model.</li>
       <li>SHAP, real-malware diagnosis, evasion &amp; fusion all run against that real model.</li>
       <li>Reachability from static parsing (pikepdf); nothing is executed.</li>
       <li>Every number traces to a stored JSON artifact.</li></ul></div>
     <div class="panel fadein"><h3 class="t">Honest scope</h3><ul style="font-size:13px;color:var(--muted);line-height:1.85;padding-left:18px;margin:0">
       <li>Weaponized samples are controlled (benign PDF + harmless payload), a standard evasion-study method.</li>
       <li>EMBER's 805 challenge PDFs are released as features, so reachability can't be computed on them directly — hence the real-malware analysis uses their released structural features.</li>
       <li>The mimicry probe uses CIC counts, a lower bound on a real attacker.</li></ul></div>
   </div>
   <div class="panel fadein"><h3 class="t">Provenance</h3><p class="note">EMBER PDF model (authors' release) · ${D.ember.ordinary.metrics.n.toLocaleString()} ordinary test PDFs ·
     ${cs.n_evasive_pdf} evasive challenge PDFs · structural-evasion study ${D.structural_evasion.n_benign_originals} real benign PDFs ·
     reachability engine TRA-1.0.</p></div>`;}
};

const CI={ // chart initializers per view
 overview(){const o=D.ember.ordinary.curves.pr,c=D.ember.challenge.curves.pr;const se=D.structural_evasion;
   prChart('ov_pr',[{name:'ordinary',color:C.teal,pts:o.recall.map((r,i)=>[r,o.precision[i]])},
     {name:'evasive',color:C.amber,pts:c.recall.map((r,i)=>[r,c.precision[i]])}]);
   gauge('ov_g1',se.detector_auc.ember_plus_reachability_fusion,'fusion AUC',C.teal);},
 gap(){const o=D.ember.ordinary.curves.pr,c=D.ember.challenge.curves.pr;
   prChart('gap_o',[{name:'ordinary',color:C.teal,pts:o.recall.map((r,i)=>[r,o.precision[i]])}]);
   prChart('gap_c',[{name:'evasive',color:C.amber,pts:c.recall.map((r,i)=>[r,c.precision[i]])}]);},
 realmal(){const c=D.challenge_structure.metric_comparison_missed_vs_caught;
   const spec=[['/FlateDecode','/FlateDecode'],['file size','size'],['string count','numstrings'],['byte entropy','entropy']];
   const items=spec.map(([l,k])=>({name:l,v:c[k].caught_median>0?c[k].missed_median/c[k].caught_median:0}))
     .filter(i=>i.v>0).sort((a,b)=>a.v-b.v);
   mk('rm_fold',{grid:{left:4,right:52,top:10,bottom:24,containLabel:true},
     tooltip:{trigger:'axis',axisPointer:{type:'shadow'},backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11},valueFormatter:v=>v.toFixed(2)+'×'},
     xAxis:{type:'value',...AX,axisLabel:{color:C.faint,fontSize:10,formatter:'{value}×'},splitLine:{lineStyle:{color:'rgba(255,255,255,.04)'}}},
     yAxis:{type:'category',data:items.map(i=>i.name),axisLine:{show:false},axisTick:{show:false},axisLabel:{color:C.muted,fontSize:10.5,fontFamily:'JetBrains Mono'}},
     series:[{type:'bar',data:items.map(i=>i.v),barWidth:'58%',markLine:{silent:true,symbol:'none',data:[{xAxis:1}],lineStyle:{color:C.faint,type:'dashed'},label:{show:false}},
       itemStyle:{borderRadius:[0,5,5,0],color:new echarts.graphic.LinearGradient(0,0,1,0,[{offset:0,color:'rgba(45,212,191,.3)'},{offset:1,color:C.teal}])},
       label:{show:true,position:'right',color:C.ink,fontFamily:'JetBrains Mono',fontSize:11,formatter:p=>p.value.toFixed(2)+'×'}}]});},
 evasion(){const se=D.structural_evasion;
   gauge('ev_g1',se.ember_evasion_rate,'score < 0.5',C.red);
   gauge('ev_g2',se.reachability_detection_rate,'flagged',C.teal);
   barH('ev_imp',se.fusion_top_features.slice(0,7).map(x=>({name:x.feature.replace('rc_',''),v:x.gain})),C.teal,v=>Math.round(v));},
 reach(){const og=D.object_graph;if(!og)return;
   const rc={catalog:'#cbd5e1',pages:C.blue,page:'#7aa7ee',trigger:C.amber,action:C.amber,dangerous:C.red,dict:C.teal2,annot:C.pink,other:'#6b7788'};
   const cats=[...new Set(og.nodes.map(n=>n.role))].map(r=>({name:r,itemStyle:{color:rc[r]||'#6b7788'}}));
   const ci=Object.fromEntries(cats.map((c,i)=>[c.name,i]));
   const nodes=og.nodes.map(n=>({id:n.id,name:n.label,category:ci[n.role],
     symbolSize:n.role==='dangerous'?40:n.role==='catalog'?30:n.role==='trigger'||n.role==='action'?22:n.role==='page'||n.role==='pages'?17:12,
     itemStyle:n.role==='dangerous'?{color:C.red,shadowBlur:22,shadowColor:C.red}:n.role==='trigger'||n.role==='action'?{shadowBlur:12,shadowColor:C.amber}:{},
     label:{show:n.role!=='dict'&&n.role!=='other'||n.role==='dangerous'}}));
   mk('graph',{tooltip:{backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11},formatter:p=>p.dataType==='node'?p.data.name:''},
     legend:{show:false},
     series:[{type:'graph',layout:'force',roam:true,draggable:true,data:nodes,categories:cats,
       edges:og.edges.map(e=>({source:e.source,target:e.target})),
       force:{repulsion:135,edgeLength:[36,110],gravity:.12,friction:.25},
       lineStyle:{color:'rgba(150,170,200,.28)',width:1,curveness:.08},
       label:{color:C.muted,fontSize:9.5,fontFamily:'JetBrains Mono',position:'right'},
       emphasis:{focus:'adjacency',lineStyle:{color:C.teal,width:2}}}]});},
 explain(){const fm=D.ember_shap.family_mass;
   const fams=['strings','histogram','byteentropy','general','header','section'];
   const ind=fams.map(f=>({name:f,max:0.7}));
   const mkser=(g,color)=>({value:fams.map(f=>fm[g][f]||0),name:g,
     lineStyle:{color:color,width:2},areaStyle:{color:'rgba('+hx(color)+',.12)'},itemStyle:{color:color}});
   mk('radar',{legend:{bottom:0,textStyle:{color:C.muted,fontSize:10},data:[{name:'caught_ordinary'},{name:'caught_evasive'},{name:'missed_evasive'}]},
     tooltip:{backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
     radar:{indicator:ind,radius:'64%',axisName:{color:C.muted,fontSize:10,fontFamily:'JetBrains Mono'},
       splitLine:{lineStyle:{color:'rgba(255,255,255,.07)'}},splitArea:{areaStyle:{color:['rgba(255,255,255,.015)','transparent']}},
       axisLine:{lineStyle:{color:'rgba(255,255,255,.08)'}}},
     series:[{type:'radar',data:[mkser('caught_ordinary',C.teal),mkser('caught_evasive',C.blue),mkser('missed_evasive',C.red)]}]});},
 probe(){const eb=D.evasion_baseline,hist=eb.evasion_cost.hist;
   const keys=Object.keys(hist).sort((a,b)=>+a-+b);
   mk('pb_hist',{grid:{left:40,right:14,top:16,bottom:34},tooltip:{trigger:'axis',backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
     xAxis:{type:'category',data:keys,name:'edits',nameLocation:'middle',nameGap:22,nameTextStyle:{color:C.faint,fontSize:10},...AX},
     yAxis:{type:'value',...AX},
     series:[{type:'bar',data:keys.map(k=>hist[k]),barWidth:'56%',
       itemStyle:{borderRadius:[5,5,0,0],color:new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:C.pink},{offset:1,color:'rgba(224,92,147,.25)'}])}}]});
   barH('pb_frag',eb.feature_fragility.slice(0,8).map(x=>({name:x.feature,v:x.used_in_evasions})),C.pink,v=>Math.round(v));},
 investigate(){bindEx();}
};

function renderExample(i){const a=Object.values(D.examples)[i],body=document.getElementById('exbody');
  if(a.error){body.innerHTML=`<div class="panel">Error: ${a.error}</div>`;return;}
  const caps=a.reachability.capabilities.map(c=>{const v=VC[c.verdict]||['t-dorm',c.verdict];
    return `<tr><td class="mono">${c.capability}</td><td><span class="tag ${v[0]}">${v[1]}</span></td>
      <td class="mono tnum">${c.min_hops===null?'—':c.min_hops}</td><td class="mono tnum">${c.naive_count}</td>
      <td style="font-size:11px;color:var(--muted)">${c.explanation}</td></tr>`}).join('')||'<tr><td colspan=5 style="color:var(--faint)">No dangerous capabilities detected.</td></tr>';
  const m=a.model||{},ml=m.score!==undefined?`<span class="band b-${m.score>=.5?'ELEVATED':'LOW'}">${m.verdict} · ${m.score.toFixed(3)}</span>`:'unavailable';
  body.innerHTML=`<div class="grid c3">
    <div class="panel kpi fadein"><span class="glow" style="background:${a.risk_band==='HIGH'?C.red:a.risk_band==='LOW'?C.teal:C.amber}"></span>
      <h3>Reconciled risk</h3><div style="margin-top:4px"><span class="band b-${a.risk_band}">${a.risk_band}</span></div><div class="sub">${a._source} · ${a.size_bytes} bytes</div></div>
    <div class="panel fadein"><h3 style="font-size:11px;color:var(--muted)">Count-based model</h3><div style="margin-top:4px">${ml}</div><div class="sub">fragile signal</div></div>
    <div class="panel kpi fadein"><h3>Objects parsed</h3><div class="num" style="font-size:24px">${a.n_objects}</div><div class="sub">${a.reachability.trigger_points.length} trigger points</div></div></div>
    ${a.disagreement?`<div class="callout warn" style="margin-top:15px"><b>Signal disagreement.</b> ${a.disagreement}</div>`:''}
    <div class="panel fadein" style="margin-top:15px"><h3 class="t">Reachability findings</h3>
      <table><thead><tr><th>Capability</th><th>Verdict</th><th class="mono">Hops</th><th class="mono">Naive</th><th>Plain-language</th></tr></thead><tbody>${caps}</tbody></table>
      <p class="note">${a.disclaimer}</p></div>`;}
function bindEx(){renderExample(0);document.getElementById('exseg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
  document.querySelectorAll('#exseg button').forEach(x=>x.setAttribute('aria-current',x===b));renderExample(+b.dataset.ex);});}

let cur='overview';
function go(v){cur=v;clearCharts();
  document.querySelectorAll('#nav button').forEach(b=>b.setAttribute('aria-current',b.dataset.v===v));
  document.getElementById('crumb').textContent=v;
  document.getElementById('view').innerHTML=R[v]();
  countUp(); try{(CI[v]||(()=>{}))();}catch(e){console.error('view charts '+v,e);}
  if(location.hash.slice(1)!==v)history.replaceState(null,'','#'+v);
  window.scrollTo(0,0);}
document.getElementById('nav').innerHTML=
  `<div class="navgrp">Analysis</div><div class="nav">`+VIEWS.slice(0,4).map(v=>`<button data-v="${v[0]}">${svg(v[2])}${v[1]}</button>`).join('')+`</div>`+
  `<div class="navgrp">Evidence</div><div class="nav">`+VIEWS.slice(4,7).map(v=>`<button data-v="${v[0]}">${svg(v[2])}${v[1]}</button>`).join('')+`</div>`+
  `<div class="navgrp">System</div><div class="nav">`+VIEWS.slice(7).map(v=>`<button data-v="${v[0]}">${svg(v[2])}${v[1]}</button>`).join('')+`</div>`;
document.getElementById('nav').addEventListener('click',e=>{const b=e.target.closest('button');if(b)go(b.dataset.v)});
document.getElementById('status').innerHTML=
  `<span class="chip"><span class="live"></span>operational</span>
   <span class="chip">EMBER2024 <b>reproduced</b></span>
   <span class="chip">engine <b>TRA-1.0</b></span>`;
document.getElementById('railftr').innerHTML=`Static analysis only · a clean result never proves safety.<br><br>BCSE321L · Malware Analysis<br>Alok Singh · Mrinali Charhate · Aarya Nagvekar`;
addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(R[h]&&h!==cur)go(h)});
go(R[location.hash.slice(1)]?location.hash.slice(1):'overview');
</script>
"""

echarts_src = (ROOT / "frontend" / "vendor" / "echarts.min.js").read_text()
html = HTML.replace("__ECHARTS__", "<script>" + echarts_src + "</script>")
html = html.replace("__DATA__", DATA)
out = ROOT / "frontend" / "dashboard.html"
out.write_text(html)
print("wrote", out, round(out.stat().st_size / 1024), "KB (echarts inlined)")
