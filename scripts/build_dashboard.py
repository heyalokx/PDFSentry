"""Build the self-contained PDFSentry dashboard, embedding real result JSON
plus a few precomputed live analyses."""
import json
from pathlib import Path
from backend.core.config import art, ROOT
from backend.core.analyze import analyze

bundle = json.load(open(art("metrics", "dashboard_data.json")))

# precompute a few live analyses for the Investigate tab
examples = {}
for key, path in {
    "Dormant JavaScript (crafted)": "tests/fixtures/crafted/fixture_dormant.pdf",
    "Auto-run JavaScript (crafted)": "tests/fixtures/crafted/fixture_active_onopen.pdf",
    "Token-buried auto-run (crafted)": "tests/fixtures/crafted/fixture_active_buried.pdf",
    "GeoTopo.pdf (real benign)": "tests/fixtures/real_pdfs/GeoTopo.pdf",
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
<style>
/* Layout: fixed left nav rail + status bar; scannable graphite workbench.
   Teal accent = robust/reachability; magenta = fragile/count-based. */
:root{
  --bg:#f4f6f8; --panel:#ffffff; --panel2:#f0f2f5; --line:#d8dee6;
  --fg:#111820; --muted:#5b6672; --faint:#8893a0;
  --accent:#0c8f7e; --accent2:#c0356b; --grid:#e3e8ee;
  --hi:#d93636; --el:#b3730a; --lo:#1a9e63;
  --mono:'IBM Plex Mono',ui-monospace,Menlo,monospace;
  --sans:'IBM Plex Sans',system-ui,-apple-system,sans-serif;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0a0e14; --panel:#121823; --panel2:#0f1520; --line:#20293a;
  --fg:#e6edf3; --muted:#8a93a3; --faint:#5a6675;
  --accent:#35d0ba; --accent2:#ff5c9d; --grid:#1a2230;
  --hi:#ff5c5c; --el:#ffb020; --lo:#36d399; color-scheme:dark;
}}
:root[data-theme="dark"]{
  --bg:#0a0e14; --panel:#121823; --panel2:#0f1520; --line:#20293a;
  --fg:#e6edf3; --muted:#8a93a3; --faint:#5a6675;
  --accent:#35d0ba; --accent2:#ff5c9d; --grid:#1a2230;
  --hi:#ff5c5c; --el:#ffb020; --lo:#36d399; color-scheme:dark;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.5}
h1,h2,h3{text-wrap:balance;margin:0}
.mono{font-family:var(--mono)}
.tnum{font-variant-numeric:tabular-nums}
.shell{display:flex;min-height:100%}
/* nav rail */
.rail{position:sticky;top:env(safe-area-inset-top,0);align-self:flex-start;
  height:100vh;width:210px;flex:0 0 210px;background:var(--panel2);
  border-right:1px solid var(--line);padding:20px 12px;display:flex;flex-direction:column;gap:4px}
.brand{display:flex;align-items:center;gap:9px;padding:4px 8px 16px}
.brand .dot{width:11px;height:11px;border-radius:3px;background:var(--accent);
  box-shadow:0 0 12px var(--accent)}
.brand b{font-weight:600;letter-spacing:.3px;font-size:15px}
.brand span{font-size:10px;color:var(--faint);letter-spacing:.14em;text-transform:uppercase}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{all:unset;cursor:pointer;display:flex;gap:10px;align-items:center;
  padding:9px 11px;border-radius:8px;color:var(--muted);font-size:13.5px;transition:.15s}
.nav button:hover{background:var(--panel);color:var(--fg)}
.nav button[aria-current="true"]{background:var(--panel);color:var(--fg);
  box-shadow:inset 2px 0 0 var(--accent)}
.nav .idx{font-family:var(--mono);font-size:10px;color:var(--faint);width:14px}
.rail .foot{margin-top:auto;font-size:10.5px;color:var(--faint);padding:8px;line-height:1.6}
/* main */
.main{flex:1;min-width:0;padding-left:max(22px,env(safe-area-inset-left,0px));
  padding-right:max(22px,env(safe-area-inset-right,0px));padding-block:22px 64px;max-width:1120px}
.topbar{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:baseline;margin-bottom:22px}
.topbar .status{margin-left:auto;display:flex;gap:14px;font-size:11px;color:var(--muted);font-family:var(--mono)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;font-family:var(--mono);
  padding:3px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.pill .d{width:7px;height:7px;border-radius:50%}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent)}
h2.view{font-size:23px;font-weight:600;margin:2px 0 4px}
.lede{color:var(--muted);font-size:14px;max-width:70ch;margin-bottom:22px}
.grid{display:grid;gap:14px}
.cards4{grid-template-columns:repeat(4,1fr)}
.cards3{grid-template-columns:repeat(3,1fr)}
.cards2{grid-template-columns:repeat(2,1fr)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 17px}
.card h3{font-size:12px;color:var(--muted);font-weight:500;letter-spacing:.02em;margin-bottom:8px}
.stat{font-family:var(--mono);font-size:30px;font-weight:600;letter-spacing:-.01em}
.stat small{font-size:13px;color:var(--faint);font-weight:400}
.sub{font-size:11.5px;color:var(--faint);margin-top:5px;font-family:var(--mono)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:16px}
.panel h3.t{font-size:15px;font-weight:600;margin-bottom:3px}
.panel .d{font-size:12.5px;color:var(--muted);margin-bottom:16px;max-width:74ch}
.callout{border-left:3px solid var(--accent2);background:color-mix(in srgb,var(--accent2) 8%,transparent);
  padding:14px 16px;border-radius:0 10px 10px 0;margin-top:16px}
.callout b{color:var(--accent2)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}
th{color:var(--faint);font-weight:500;font-family:var(--mono);font-size:10.5px;
  letter-spacing:.06em;text-transform:uppercase}
td.mono,th.mono{font-family:var(--mono)}
.tagv{font-family:var(--mono);font-size:10.5px;padding:2px 7px;border-radius:5px;white-space:nowrap}
.v-open{background:color-mix(in srgb,var(--hi) 18%,transparent);color:var(--hi)}
.v-inter{background:color-mix(in srgb,var(--el) 18%,transparent);color:var(--el)}
.v-dorm{background:color-mix(in srgb,var(--faint) 18%,transparent);color:var(--muted)}
.v-abs{color:var(--faint)}
.band{font-family:var(--mono);font-weight:600;padding:3px 9px;border-radius:6px;font-size:11px}
.b-HIGH{background:color-mix(in srgb,var(--hi) 20%,transparent);color:var(--hi)}
.b-ELEVATED{background:color-mix(in srgb,var(--el) 20%,transparent);color:var(--el)}
.b-LOW{background:color-mix(in srgb,var(--lo) 20%,transparent);color:var(--lo)}
.b-UNKNOWN{background:color-mix(in srgb,var(--faint) 20%,transparent);color:var(--muted)}
.barrow{display:grid;grid-template-columns:150px 1fr 54px;align-items:center;gap:10px;margin:7px 0;font-size:12px}
.barrow .lab{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.track{height:16px;background:var(--panel2);border-radius:4px;overflow:hidden}
.fill{height:100%;border-radius:4px}
.val{font-family:var(--mono);font-size:11px;color:var(--fg);text-align:right}
.scroll{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.scroll table{font-size:11.5px}
.scroll th{position:sticky;top:0;background:var(--panel2);z-index:1}
.row-dis{background:color-mix(in srgb,var(--accent2) 7%,transparent)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-top:10px}
.legend i{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle}
select,.seg button{font-family:var(--mono);font-size:12px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.seg button{all:unset;cursor:pointer;padding:7px 13px;color:var(--muted)}
.seg button[aria-current="true"]{background:var(--accent);color:#04120f;font-weight:600}
svg{display:block;max-width:100%}
.axis{stroke:var(--grid)} .axistext{fill:var(--faint);font-family:var(--mono);font-size:9px}
.note{font-size:11px;color:var(--faint);margin-top:12px;line-height:1.6}
.kbd{font-family:var(--mono);font-size:11px;background:var(--panel2);border:1px solid var(--line);
  padding:1px 6px;border-radius:4px;color:var(--muted)}
.feat-pill{display:inline-block;font-family:var(--mono);font-size:10.5px;color:var(--muted);
  background:var(--panel2);border:1px solid var(--line);padding:2px 7px;border-radius:5px;margin:2px}
@media (max-width:860px){
  .rail{position:static;height:auto;width:100%;flex-basis:auto;flex-direction:row;
    flex-wrap:wrap;border-right:0;border-bottom:1px solid var(--line)}
  .rail .foot{display:none}.brand{width:100%}
  .nav{flex-direction:row;flex-wrap:wrap}.shell{flex-direction:column}
  .cards4,.cards3,.cards2,.two{grid-template-columns:1fr 1fr}
}
@media (max-width:480px){.cards4,.cards3,.cards2,.two{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>

<div class="shell">
  <nav class="rail">
    <div class="brand"><span class="dot"></span><div><b>PDFSentry</b><br><span>reachability intel</span></div></div>
    <div class="nav" id="nav"></div>
    <div class="foot" id="railfoot"></div>
  </nav>
  <main class="main">
    <div class="topbar">
      <div><div class="eyebrow">PDF malware intelligence</div></div>
      <div class="status" id="status"></div>
    </div>
    <section id="view"></section>
  </main>
</div>

<script id="D" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('D').textContent);
const $ = (h)=>{const t=document.createElement('template');t.innerHTML=h.trim();return t.content.firstChild;};
const pct = x => (x*100).toFixed(1)+'%';
const f4 = x => x.toFixed(4);
const VIEWS = [
  ['overview','Overview'], ['evasion','Evasion collapse'], ['reach','Reachability'],
  ['explain','Explainability'], ['investigate','Investigate'], ['about','Method & limits']
];
const VCLASS={ACTIVE_ONOPEN:'v-open',ACTIVE_ONINTERACT:'v-inter',PRESENT_DORMANT:'v-dorm',ABSENT:'v-abs'};
const VSHORT={ACTIVE_ONOPEN:'ACTIVE · on-open',ACTIVE_ONINTERACT:'active · on-click',PRESENT_DORMANT:'dormant',ABSENT:'absent'};

function hbars(items, key, max, color, fmt){
  return items.map(it=>{
    const w = Math.max(1, (it[key]/max)*100);
    return `<div class="barrow"><div class="lab" title="${it.feature}">${it.feature}</div>
      <div class="track"><div class="fill" style="width:${w}%;background:${color}"></div></div>
      <div class="val">${fmt(it[key])}</div></div>`;
  }).join('');
}

/* ---- line chart (ROC / PR) ---- */
function lineChart(series, xlab, ylab){
  const W=440,H=260,P=38;
  const sx=v=>P+v*(W-P-10), sy=v=>H-P-v*(H-P-14);
  const grid=[0,.25,.5,.75,1];
  let g=grid.map(t=>`<line class="axis" x1="${sx(t)}" y1="${P-4}" x2="${sx(t)}" y2="${H-P}"/>
    <line class="axis" x1="${P}" y1="${sy(t)}" x2="${W-10}" y2="${sy(t)}"/>
    <text class="axistext" x="${sx(t)}" y="${H-P+13}" text-anchor="middle">${t}</text>
    <text class="axistext" x="${P-6}" y="${sy(t)+3}" text-anchor="end">${t}</text>`).join('');
  const path=series.pts.map((p,i)=>(i?'L':'M')+sx(p[0])+' '+sy(p[1])).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" role="img">
    ${g}
    <path d="${path}" fill="none" stroke="var(--accent)" stroke-width="2.2"/>
    <text class="axistext" x="${W/2}" y="${H-4}" text-anchor="middle">${xlab}</text>
    <text class="axistext" x="12" y="${H/2}" text-anchor="middle" transform="rotate(-90 12 ${H/2})">${ylab}</text>
  </svg>`;
}

const RENDER = {
 overview(){
  const pm=D.baseline.point_metrics, bp=D.baseline.bootstrap.pr_auc, rp=D.baseline.bootstrap.roc_auc;
  const ev=D.comparison.evasion.baseline, ds=D.dataset;
  const reachDis=D.reachability.disagreement;
  return `
   <h2 class="view">The paradox this project measures</h2>
   <p class="lede">A LightGBM detector trained on the ${ds.final_rows.toLocaleString()}-file
     CIC-Evasive-PDFMal2022 set scores almost perfectly — and is still evaded on two in three
     of the malware it catches, by editing a median of three fields. PDFSentry measures that gap
     and proposes a signal that survives it.</p>
   <div class="grid cards4">
     <div class="card"><h3>PR-AUC (test)</h3><div class="stat tnum">${f4(pm.pr_auc)}</div>
       <div class="sub">95% CI ${f4(bp.ci_low)}–${f4(bp.ci_high)}</div></div>
     <div class="card"><h3>ROC-AUC (test)</h3><div class="stat tnum">${f4(pm.roc_auc)}</div>
       <div class="sub">95% CI ${f4(rp.ci_low)}–${f4(rp.ci_high)}</div></div>
     <div class="card"><h3>F1 · recall</h3><div class="stat tnum">${f4(pm.f1)}</div>
       <div class="sub">recall ${pct(pm.recall)} · prec ${pct(pm.precision)}</div></div>
     <div class="card" style="border-color:var(--accent2)"><h3>Evasion-resilience score</h3>
       <div class="stat tnum" style="color:var(--accent2)">${pct(ev.ers)}</div>
       <div class="sub">${ev.n_evaded}/${ev.n_caught} caught malware evaded</div></div>
   </div>
   <div class="callout">
     <b>Read the last two tiles together.</b> The model wins the benchmark (PR-AUC ${f4(pm.pr_auc)})
     yet only ${pct(ev.ers)} of the malware it catches resists a constrained, author-side evasion
     search. Benchmark accuracy and evasion resilience are different axes — the Review-2 scope only
     ever measured the first.
   </div>
   <div class="two" style="margin-top:16px">
     <div class="panel" style="margin:0"><h3 class="t">Precision–recall curve</h3>
       <p class="d">Test split, ${pm.n.toLocaleString()} files, prevalence ${pct(pm.prevalence)}.</p>
       <div id="prc"></div></div>
     <div class="panel" style="margin:0"><h3 class="t">Where the two signals disagree</h3>
       <p class="d">Across ${D.reachability.n_crafted+D.reachability.n_real} real + crafted PDFs,
         a byte-counting view and the reachability view reach different conclusions in
         ${reachDis.naive_over_alarm+reachDis.naive_under_alarm} cases.</p>
       <div class="grid cards2" style="gap:10px">
         <div class="card" style="background:var(--panel2)"><h3>Count over-alarms</h3>
           <div class="stat tnum" style="font-size:24px">${reachDis.naive_over_alarm}</div>
           <div class="sub">tokens present, nothing auto-runs</div></div>
         <div class="card" style="background:var(--panel2)"><h3>Count under-alarms</h3>
           <div class="stat tnum" style="font-size:24px;color:var(--hi)">${reachDis.naive_under_alarm}</div>
           <div class="sub">auto-runs, tokens hidden from byte scan</div></div>
       </div>
       <p class="note">Dataset: ${ds.label_counts.malicious.toLocaleString()} malicious ·
         ${ds.label_counts.benign.toLocaleString()} benign · ${ds.parse_failure_rows.toLocaleString()}
         files with parser-failure sentinels · ${ds.malformed_header_rows} malformed headers.</p>
     </div>
   </div>`;
 },
 evasion(){
  const eb=D.evasion_baseline, cmp=D.comparison;
  const hist=eb.evasion_cost.hist;
  const maxc=Math.max(...Object.values(hist));
  const bars=Object.entries(hist).map(([k,v])=>{
    const h=Math.max(4,(v/maxc)*120);
    return `<div style="display:flex;flex-direction:column;align-items:center;gap:6px;flex:1">
      <div class="mono" style="font-size:10px;color:var(--muted)">${v}</div>
      <div style="width:70%;height:${h}px;background:var(--accent2);border-radius:4px 4px 0 0"></div>
      <div class="mono" style="font-size:10px;color:var(--faint)">${k}</div></div>`;
  }).join('');
  const maxFrag=eb.feature_fragility[0].used_in_evasions;
  const frag=eb.feature_fragility.slice(0,10).map(x=>({feature:x.feature,v:x.used_in_evasions,share:x.share}));
  return `
   <h2 class="view">Evasion collapse</h2>
   <p class="lede">For every malicious file the detector catches, a constrained counterfactual search
     looks for the cheapest set of author-side edits — removing capability tokens, trimming metadata —
     that flips the verdict to benign. Edits run entirely in feature space on integer counts; derived
     features recompute after each edit, so nothing can be gamed in isolation.</p>
   <div class="grid cards3">
     <div class="card"><h3>Caught malware probed</h3><div class="stat tnum">${eb.n_caught_evaluated}</div></div>
     <div class="card" style="border-color:var(--accent2)"><h3>Successfully evaded</h3>
       <div class="stat tnum" style="color:var(--accent2)">${eb.n_evaded}
       <small>(${pct(eb.n_evaded/eb.n_caught_evaluated)})</small></div></div>
     <div class="card"><h3>Median edits to evade</h3><div class="stat tnum">${eb.evasion_cost.median}
       <small>of ${eb.controllable_features.length} editable</small></div></div>
   </div>
   <div class="two" style="margin-top:16px">
     <div class="panel" style="margin:0"><h3 class="t">Evasion cost distribution</h3>
       <p class="d">Number of distinct fields an author must change to flip a caught sample.
         Most fall at ${eb.evasion_cost.median} edits.</p>
       <div style="display:flex;align-items:flex-end;gap:8px;height:150px;padding:0 4px">${bars}</div>
       <div class="mono" style="text-align:center;font-size:10px;color:var(--faint);margin-top:6px">edits required →</div>
     </div>
     <div class="panel" style="margin:0"><h3 class="t">Most fragile features</h3>
       <p class="d">Share of successful evasions that touched each feature. The detector leans on
         exactly the removable keyword counts an author controls.</p>
       ${hbars(frag,'v',maxFrag,'var(--accent2)',v=>Math.round(v))}
     </div>
   </div>
   <div class="panel"><h3 class="t">You can't feature-select your way out</h3>
     <p class="d">A second detector drops the raw keyword counts and keeps only structural and derived
       features. Clean accuracy barely moves — and so does resilience. Every count-based feature
       answers the same author edit, so removing some doesn't help. That is the argument for a
       different <em>kind</em> of signal (reachability), not a different feature subset.</p>
     <table><thead><tr><th>Detector</th><th class="mono">Clean PR-AUC</th><th class="mono">ΔPR-AUC (paired)</th>
       <th class="mono">Evasion-resilience</th><th class="mono">Median cost</th></tr></thead><tbody>
       <tr><td>Baseline (all features)</td><td class="mono">${f4(cmp.clean.baseline.pr_auc)}</td>
         <td class="mono">—</td><td class="mono">${pct(cmp.evasion.baseline.ers)}</td>
         <td class="mono">${cmp.evasion.baseline.median_cost}</td></tr>
       <tr><td>Structure-first (keyword counts dropped)</td><td class="mono">${f4(cmp.clean.structure_first.pr_auc)}</td>
         <td class="mono">${cmp.clean.paired_pr_auc_delta.delta>=0?'+':''}${f4(cmp.clean.paired_pr_auc_delta.delta)}</td>
         <td class="mono">${pct(cmp.evasion.structure_first.ers)}</td>
         <td class="mono">${cmp.evasion.structure_first.median_cost}</td></tr>
     </tbody></table>
     <p class="note">Paired bootstrap ΔPR-AUC 95% CI
       ${f4(cmp.clean.paired_pr_auc_delta.ci_low)} to ${f4(cmp.clean.paired_pr_auc_delta.ci_high)};
       dropping fragile features costs no meaningful accuracy and barely changes resilience.</p>
   </div>`;
 },
 reach(){
  const craft=D.reachability.rows.crafted;
  const real=D.reachability.rows.real;
  const dis=D.reachability.disagreement;
  const craftRows=craft.map(r=>{
    const c=r.capabilities[0]||{};
    return `<tr><td>${r.file.replace('fixture_','').replace('.pdf','')}</td>
      <td class="mono">${c.capability||'—'}</td>
      <td class="mono tnum">${r.naive_token_count}</td>
      <td><span class="tagv ${VCLASS[r.reachability_verdict]}">${VSHORT[r.reachability_verdict]||r.reachability_verdict}</span></td></tr>`;
  }).join('');
  const capDisagrees=c=>(c.verdict==='ACTIVE_ONOPEN'&&c.naive_count===0)
      ||(c.naive_count>=2&&(c.verdict==='PRESENT_DORMANT'||c.verdict==='ACTIVE_ONINTERACT'));
  const realRows=real.filter(r=>r.parsed).map(r=>{
    const disRow = (r.capabilities||[]).some(capDisagrees);
    return `<tr class="${disRow?'row-dis':''}"><td>${r.file}</td>
      <td class="mono tnum">${r.n_objects}</td>
      <td class="mono tnum">${r.naive_token_count}</td>
      <td><span class="tagv ${VCLASS[r.reachability_verdict]}">${VSHORT[r.reachability_verdict]||r.reachability_verdict}</span></td>
      <td class="mono">${disRow?'⚠ disagree':''}</td></tr>`;
  }).join('');
  return `
   <h2 class="view">Reachability over recognition</h2>
   <p class="lede">Count-based features ask <em>"how many dangerous tokens appear?"</em>. The
     Trigger-Reachability Analyzer parses the object graph and asks <em>"is a dangerous action
     actually reachable from an automatic trigger, and in how many hops?"</em> — a signal an author
     cannot remove without removing the attack itself.</p>
   <div class="panel" style="margin-top:0"><h3 class="t">Four crafted fixtures, identical to a byte counter</h3>
     <p class="d">All harmless (the only script is an <span class="mono">app.alert</span>). A counter sees
       the same <span class="mono">/JavaScript</span> token count; reachability separates what auto-runs
       from what is inert, needs a click, or is hidden in a compressed stream.</p>
     <table><thead><tr><th>Fixture</th><th>Capability</th><th class="mono">Naive byte count</th>
       <th>Reachability verdict</th></tr></thead><tbody>${craftRows}</tbody></table>
     <div class="legend">
       <span><i style="background:var(--hi)"></i>auto-runs on open</span>
       <span><i style="background:var(--el)"></i>runs on click</span>
       <span><i style="background:var(--faint)"></i>present but dormant</span>
     </div>
   </div>
   <div class="panel"><h3 class="t">Real corpus — ${real.filter(r=>r.parsed).length} benign PDFs parsed</h3>
     <p class="d">Rows where the byte count and reachability disagree are highlighted:
       ${dis.naive_over_alarm} over-alarms (many tokens, nothing auto-runs) and
       ${dis.naive_under_alarm} under-alarms (auto-runs with tokens hidden from the byte scan,
       e.g. <span class="mono">GeoTopo.pdf</span>).</p>
     <div class="scroll"><table><thead><tr><th>File</th><th class="mono">Objs</th>
       <th class="mono">Naive count</th><th>Reachability</th><th></th></tr></thead>
       <tbody>${realRows}</tbody></table></div>
   </div>`;
 },
 explain(){
  const g=D.shap.global_importance.slice(0,10);
  const p=D.shap.permutation_importance.slice(0,10);
  const mg=g[0].mean_abs_shap, mp=p[0].importance;
  const fn=D.shap.group_importance.false_negative;
  return `
   <h2 class="view">Explainability</h2>
   <p class="lede">SHAP (TreeExplainer) and permutation importance agree on which features drive the
     detector — and they are the same removable keyword counts the evasion search exploits. SHAP
     explains model behaviour, not attacker intent; correlated features share credit.</p>
   <div class="two">
     <div class="panel" style="margin:0"><h3 class="t">Global mean |SHAP|</h3>
       <p class="d">Average absolute contribution across the test split.</p>
       ${hbars(g.map(x=>({feature:x.feature,v:x.mean_abs_shap})),'v',mg,'var(--accent)',v=>v.toFixed(2))}
     </div>
     <div class="panel" style="margin:0"><h3 class="t">Permutation importance (cross-check)</h3>
       <p class="d">ROC-AUC drop when each feature is shuffled — computed independently of SHAP.</p>
       ${hbars(p.map(x=>({feature:x.feature,v:x.importance})),'v',mp,'var(--accent)',v=>v.toFixed(3))}
     </div>
   </div>
   <div class="callout"><b>The two methods converge.</b> Metadata size, keyword concentration,
     JavaScript counts and PDF size lead both rankings — independent confirmation that the model's
     evidence is exactly the fragile surface the evasion map maps. ${fn.n} malicious test files are
     missed outright (false negatives), before any evasion is attempted.</div>`;
 },
 investigate(){
  const names=Object.keys(D.examples);
  const opts=names.map((n,i)=>`<button data-ex="${i}" aria-current="${i===0}">${n}</button>`).join('');
  return `
   <h2 class="view">Investigate</h2>
   <p class="lede">The live backend runs the count-based model and the reachability engine on an
     uploaded PDF and reconciles them. Below are four precomputed analyses; the headline is what
     happens when the two signals disagree.</p>
   <div class="seg" style="margin-bottom:14px;flex-wrap:wrap" id="exseg">${opts}</div>
   <div id="exbody"></div>`;
 },
 about(){
  const ds=D.dataset;
  return `
   <h2 class="view">Method &amp; limits</h2>
   <p class="lede">What is measured, on what data, and what remains unproven. Honesty about scope is
     part of the contribution.</p>
   <div class="two">
     <div class="panel" style="margin:0"><h3 class="t">What is real here</h3>
       <ul style="font-size:13px;color:var(--muted);line-height:1.8;padding-left:18px">
         <li>Detector trained on the real CIC-Evasive-PDFMal2022 set (${ds.final_rows.toLocaleString()} files).</li>
         <li>Every metric, CI, SHAP value and evasion number traces to a stored JSON artifact.</li>
         <li>Reachability verdicts computed by static parsing of real PDFs (pikepdf), never executed.</li>
         <li>Evasion search is feature-space only — no PDF is generated, no payload produced.</li>
       </ul></div>
     <div class="panel" style="margin:0"><h3 class="t">What is NOT claimed</h3>
       <ul style="font-size:13px;color:var(--muted);line-height:1.8;padding-left:18px">
         <li>EMBER2024 reproduction is <b>blocked</b> — its data is unreachable from this environment.</li>
         <li>CIC has no timestamps, so temporal drift (as in EMBER) is not available and not shown.</li>
         <li>Reachability is not yet a feature in the trained detector (CIC ships counts, not raw PDFs);
           it is demonstrated on parsed files and the live analyzer.</li>
         <li>Feature-space evasion is a lower bound on a real attacker's options, not a full adversarial eval.</li>
       </ul></div>
   </div>
   <div class="panel"><h3 class="t">Provenance</h3>
     <p class="note">Dataset SHA-256 <span class="mono">${ds.raw_sha256.slice(0,32)}…</span> ·
       baseline model hash <span class="mono">${D.baseline.model_hash}</span> ·
       split seed ${D.split.seed} · stratified ${D.split.test_fraction*100}% holdout
       (train ${D.split.n_train.toLocaleString()} / test ${D.split.n_test.toLocaleString()}).
       ${ds.deviations[ds.deviations.length-1]}</p></div>`;
 }
};

function renderExample(i){
  const a = Object.values(D.examples)[i];
  const body=document.getElementById('exbody');
  if(a.error){body.innerHTML=`<div class="panel">Error: ${a.error}</div>`;return;}
  const caps=a.reachability.capabilities.map(c=>`<tr>
    <td class="mono">${c.capability}</td>
    <td><span class="tagv ${VCLASS[c.verdict]}">${VSHORT[c.verdict]||c.verdict}</span></td>
    <td class="mono tnum">${c.min_hops===null?'—':c.min_hops}</td>
    <td class="mono tnum">${c.naive_count}</td>
    <td style="font-size:11px;color:var(--muted)">${c.explanation}</td></tr>`).join('')
    || '<tr><td colspan=5 style="color:var(--faint)">No dangerous capabilities detected.</td></tr>';
  const m=a.model||{};
  const modelLine = m.score!==undefined
    ? `<span class="band b-${m.score>=0.5?'ELEVATED':'LOW'}">${m.verdict} · ${m.score.toFixed(3)}</span>`
    : 'unavailable';
  body.innerHTML=`
   <div class="grid cards3">
     <div class="card"><h3>Reconciled risk</h3><div style="margin-top:4px"><span class="band b-${a.risk_band}">${a.risk_band}</span></div>
       <div class="sub">${a._source} · ${a.size_bytes} bytes</div></div>
     <div class="card"><h3>Count-based model</h3><div style="margin-top:4px">${modelLine}</div>
       <div class="sub">fragile signal</div></div>
     <div class="card"><h3>Objects parsed</h3><div class="stat tnum" style="font-size:22px">${a.n_objects}</div>
       <div class="sub">${a.reachability.trigger_points.length} trigger points</div></div>
   </div>
   ${a.disagreement?`<div class="callout"><b>Signal disagreement.</b> ${a.disagreement}</div>`:''}
   <div class="panel"><h3 class="t">Reachability findings</h3>
     <table><thead><tr><th>Capability</th><th>Verdict</th><th class="mono">Hops</th>
       <th class="mono">Naive count</th><th>Plain-language</th></tr></thead><tbody>${caps}</tbody></table>
     <p class="note">${a.disclaimer}</p></div>`;
}

let current='overview';
function go(v){
  current=v;
  document.querySelectorAll('#nav button').forEach(b=>b.setAttribute('aria-current', b.dataset.v===v));
  document.getElementById('view').innerHTML = RENDER[v]();
  if(v==='overview'){
    const pr=D.baseline.curves.pr;
    const pts=pr.recall.map((r,i)=>[r,pr.precision[i]]);
    document.getElementById('prc').innerHTML=lineChart({pts},'recall','precision');
  }
  if(v==='investigate'){
    renderExample(0);
    document.getElementById('exseg').addEventListener('click',e=>{
      const b=e.target.closest('button'); if(!b)return;
      document.querySelectorAll('#exseg button').forEach(x=>x.setAttribute('aria-current',x===b));
      renderExample(+b.dataset.ex);
    });
  }
  if(location.hash.slice(1)!==v) history.replaceState(null,'','#'+v);
  window.scrollTo(0,0);
}

document.getElementById('nav').innerHTML = VIEWS.map((v,i)=>
  `<button data-v="${v[0]}" aria-current="${i===0}"><span class="idx">${String(i+1).padStart(2,'0')}</span>${v[1]}</button>`).join('');
document.getElementById('nav').addEventListener('click',e=>{const b=e.target.closest('button');if(b)go(b.dataset.v);});
document.getElementById('status').innerHTML =
  `<span class="pill"><span class="d" style="background:var(--lo)"></span>model ${D.baseline.model_hash}</span>
   <span class="pill">CIC-PDFMal2022</span><span class="pill">engine TRA-1.0</span>`;
document.getElementById('railfoot').innerHTML =
  `Static analysis only.<br>A clean result never proves safety.<br>— BCSE497J · Alok Singh`;
window.addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(RENDER[h]&&h!==current)go(h);});
go(RENDER[location.hash.slice(1)]?location.hash.slice(1):'overview');
</script>
"""

out = ROOT / "frontend" / "dashboard.html"
out.write_text(HTML.replace("__DATA__", DATA))
print("wrote", out, out.stat().st_size, "bytes")
