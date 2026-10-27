"""Build the self-contained PDFSentry dashboard, embedding real result JSON
plus a few precomputed live analyses."""
import json
from pathlib import Path
from backend.core.config import art, ROOT
from backend.core.analyze import analyze

bundle = json.load(open(art("metrics", "dashboard_data.json")))

# compression-mechanism proof: EMBER score of the 4 crafted fixtures
import sys, types, numpy as np
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
  ['overview','Overview'], ['gap','The evasive gap'], ['evasion','Structural evasion'],
  ['reach','Reachability'], ['explain','Why they evade'], ['probe','Mimicry probe'],
  ['investigate','Investigate'], ['about','Method & limits']
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
  const eo=D.ember.ordinary.metrics, ec=D.ember.challenge.metrics;
  const se=D.structural_evasion;
  return `
   <h2 class="view">Closing the evasive gap in EMBER2024</h2>
   <p class="lede">The EMBER2024 PDF detector scores 0.99 on ordinary malware but collapses on
     evasive samples. We reproduce that gap exactly on the authors' own model, diagnose it with
     SHAP, and close it with a structural <em>reachability</em> signal — tested against the real
     published model, start to finish.</p>
   <div class="grid cards4">
     <div class="card"><h3>EMBER ordinary PR-AUC</h3><div class="stat tnum">${f4(eo.pr_auc)}</div>
       <div class="sub">published 0.9933 · reproduced</div></div>
     <div class="card" style="border-color:var(--el)"><h3>EMBER evasive PR-AUC</h3>
       <div class="stat tnum" style="color:var(--el)">${f4(ec.pr_auc)}</div>
       <div class="sub">published 0.7841 · ${ec.confusion.fn}/${D.ember.challenge.n_evasive} missed</div></div>
     <div class="card" style="border-color:var(--hi)"><h3>Weaponized docs evading EMBER</h3>
       <div class="stat tnum" style="color:var(--hi)">${pct(se.ember_evasion_rate)}</div>
       <div class="sub">reachability catches ${pct(se.reachability_detection_rate)}</div></div>
     <div class="card" style="border-color:var(--accent)"><h3>EMBER + reachability (fusion)</h3>
       <div class="stat tnum" style="color:var(--accent)">${f4(se.detector_auc.ember_plus_reachability_fusion)}</div>
       <div class="sub">AUC vs ${f4(se.detector_auc.ember_score_alone)} for EMBER alone</div></div>
   </div>
   <div class="callout">
     <b>The whole thesis in one line.</b> A detector at ${f4(eo.pr_auc)} PR-AUC on ordinary malware
     is blind to ${pct(se.ember_evasion_rate)} of structurally weaponized documents, because it reads
     bytes and strings, not structure. Adding one family of reachability features lifts separation
     from AUC ${f4(se.detector_auc.ember_score_alone)} to ${f4(se.detector_auc.ember_plus_reachability_fusion)}.
   </div>
   <div class="two" style="margin-top:16px">
     <div class="panel" style="margin:0"><h3 class="t">EMBER reproduction</h3>
       <p class="d">Authors' released PDF model, their evaluation protocol. Our numbers match the
         published benchmark within bootstrap noise — the baseline is verified, not assumed.</p>
       <table><thead><tr><th>Evaluation</th><th class="mono">ROC-AUC</th><th class="mono">PR-AUC</th><th class="mono">published</th></tr></thead><tbody>
         <tr><td>Ordinary test</td><td class="mono">${f4(eo.roc_auc)}</td><td class="mono">${f4(eo.pr_auc)}</td><td class="mono">.9912 / .9933</td></tr>
         <tr><td>Evasive challenge</td><td class="mono">${f4(ec.roc_auc)}</td><td class="mono">${f4(ec.pr_auc)}</td><td class="mono">.9066 / .7841</td></tr>
       </tbody></table>
       <p class="note">Challenge = ${D.ember.challenge.n_evasive} evasive PDFs + ${D.ember.challenge.n_benign.toLocaleString()} benign (authors' protocol).</p></div>
     <div class="panel" style="margin:0"><h3 class="t">Ordinary vs evasive — the gap</h3>
       <p class="d">Same model, two precision–recall curves. Evasive malware drags precision down
         where ordinary malware never does.</p>
       <div id="prc"></div></div>
   </div>`;
 },
 gap(){
  const eo=D.ember.ordinary.metrics, ec=D.ember.challenge.metrics;
  const fm=D.ember_shap.family_mass;
  return `
   <h2 class="view">The evasive gap, reproduced</h2>
   <p class="lede">EMBER2024's own result: a PDF detector that looks solved on ordinary malware
     misses a large share of malware that first evaded antivirus. We reproduce it on the authors'
     model so everything downstream builds on a verified baseline.</p>
   <div class="grid cards3">
     <div class="card"><h3>Ordinary recall</h3><div class="stat tnum">${pct(eo.recall)}</div>
       <div class="sub">at threshold 0.5</div></div>
     <div class="card" style="border-color:var(--el)"><h3>Evasive missed (FN)</h3>
       <div class="stat tnum" style="color:var(--el)">${ec.confusion.fn}<small>/${D.ember.challenge.n_evasive}</small></div>
       <div class="sub">${pct(ec.confusion.fn/D.ember.challenge.n_evasive)} of evasive malware slips through</div></div>
     <div class="card"><h3>PR-AUC drop</h3><div class="stat tnum">${f4(eo.pr_auc-ec.pr_auc)}</div>
       <div class="sub">${f4(eo.pr_auc)} → ${f4(ec.pr_auc)}</div></div>
   </div>
   <div class="two" style="margin-top:16px">
     <div class="panel" style="margin:0"><h3 class="t">Ordinary PR curve</h3><div id="prc_ord"></div></div>
     <div class="panel" style="margin:0"><h3 class="t">Evasive-challenge PR curve</h3><div id="prc_ch"></div></div>
   </div>
   <div class="panel"><h3 class="t">Why they evade — a preview</h3>
     <p class="d">SHAP (next: "Why they evade") shows the baseline spends
       ${pct(fm.missed_evasive.strings)} of its attention on string features and
       ${pct(fm.missed_evasive.histogram)} on the byte histogram, with essentially nothing on
       structure. The malware it misses looks byte- and string-normal — so there is nothing left
       for the model to catch it with. That absence is the opening reachability fills.</p></div>`;
 },
 evasion(){
  const se=D.structural_evasion, mech=D.mechanism||[];
  const imp=se.fusion_top_features.slice(0,8).map(x=>({feature:x.feature,v:x.gain}));
  const maxg=imp[0].v;
  const mechRows=mech.map(m=>`<tr><td>${m.label}</td>
    <td class="mono tnum">${m.ember.toFixed(3)}</td>
    <td>${m.ember>=0.5?'<span class="tagv v-open">flagged</span>':'<span class="tagv v-dorm">missed</span>'}</td>
    <td class="mono tnum">${m.reach_onopen}</td>
    <td>${m.evasion_sig?'<span class="tagv v-open">yes</span>':'<span class="v-abs">—</span>'}</td></tr>`).join('');
  return `
   <h2 class="view">Structural evasion of the real detector</h2>
   <p class="lede">We take ${se.n_benign_originals} real benign PDFs the EMBER model is confident
     about, and weaponize each one: inject a reachable auto-run JavaScript action (a harmless
     <span class="mono">app.alert</span>), hidden inside a compressed object stream so the bytes stay
     document-like. The file now auto-runs code on open — a genuine structural threat — and we ask
     whether the 0.99-AUC detector notices.</p>
   <div class="grid cards3">
     <div class="card" style="border-color:var(--hi)"><h3>Evaded EMBER</h3>
       <div class="stat tnum" style="color:var(--hi)">${pct(se.ember_evasion_rate)}</div>
       <div class="sub">scored benign despite live payload</div></div>
     <div class="card" style="border-color:var(--accent)"><h3>Caught by reachability</h3>
       <div class="stat tnum" style="color:var(--accent)">${pct(se.reachability_detection_rate)}</div>
       <div class="sub">every weaponized file flagged</div></div>
     <div class="card"><h3>Mean EMBER score</h3>
       <div class="stat tnum" style="font-size:22px">${se.ember_mean_score_original.toFixed(3)} → ${se.ember_mean_score_weaponized.toFixed(3)}</div>
       <div class="sub">original → weaponized (barely moves)</div></div>
   </div>
   <div class="panel"><h3 class="t">Fusion closes the gap — EMBER + reachability</h3>
     <p class="d">Task: tell a safe PDF from its weaponized twin. EMBER's score alone can't
       (AUC ${f4(se.detector_auc.ember_score_alone)}); adding the reachability features makes it
       near-perfect (5-fold CV AUC ${f4(se.detector_auc.ember_plus_reachability_fusion)}).</p>
     <div class="barrow"><div class="lab">EMBER alone</div>
       <div class="track"><div class="fill" style="width:${se.detector_auc.ember_score_alone*100}%;background:var(--el)"></div></div>
       <div class="val">${f4(se.detector_auc.ember_score_alone)}</div></div>
     <div class="barrow"><div class="lab">EMBER + reachability</div>
       <div class="track"><div class="fill" style="width:${se.detector_auc.ember_plus_reachability_fusion*100}%;background:var(--accent)"></div></div>
       <div class="val">${f4(se.detector_auc.ember_plus_reachability_fusion)}</div></div>
     <p class="note" style="margin-top:14px">Features doing the work (fusion gain):</p>
     ${hbars(imp,'v',maxg,'var(--accent)',v=>Math.round(v))}
   </div>
   <div class="panel"><h3 class="t">The compression mechanism, isolated</h3>
     <p class="d">The same JavaScript action, scored by the real EMBER model four ways. Visible tokens
       are flagged; hiding the identical action in a compressed stream drops the score below the
       threshold — while reachability tracks it regardless.</p>
     <table><thead><tr><th>Crafted PDF</th><th class="mono">EMBER score</th><th>EMBER verdict</th>
       <th class="mono">reach on-open</th><th>evasion signature</th></tr></thead><tbody>${mechRows}</tbody></table>
     <p class="note">Harmless payload throughout; nothing is executed. Compression-based token hiding
       is a real in-the-wild technique — the benign file GeoTopo.pdf does exactly this by accident.</p></div>
   ${(()=>{const g=D.evasion_generality; if(!g)return'';
     const rows=Object.entries(g.wirings).map(([w,v])=>`<tr><td class="mono">${w}</td>
       <td class="mono tnum">${pct(v.ember_evasion_rate)}</td>
       <td class="mono tnum" style="color:var(--accent)">${pct(v.reach_detection_full)}</td>
       <td class="mono tnum" style="color:var(--accent)">${pct(v.reach_detection_ablated)}</td></tr>`).join('');
     return `<div class="panel"><h3 class="t">It isn't one tailored feature — generality &amp; ablation</h3>
     <p class="d">The same auto-run action wired four structurally different ways (direct, action-chain,
       document-level name tree, page-open), each hidden in a compressed stream, over ${g.n_base_pdfs}
       base PDFs. Reachability catches every wiring — <b>and still 100% with the purpose-built
       evasion-signature feature removed</b> (ablated column), using only "is a dangerous action
       reachable on open". The result is the graph traversal, not a gotcha feature.</p>
     <table><thead><tr><th>Evasion wiring</th><th class="mono">EMBER evaded</th>
       <th class="mono">reachability</th><th class="mono">reachability (ablated)</th></tr></thead>
       <tbody>${rows}</tbody></table></div>`;})()}`;
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
  const fm=D.ember_shap.family_mass, gr=D.ember_shap.groups;
  const FAMS=["strings","histogram","byteentropy","general","header","section"];
  const COL={strings:"var(--accent)",histogram:"var(--accent2)",byteentropy:"var(--el)",
             general:"var(--muted)",header:"var(--lo)",section:"var(--faint)"};
  function stack(mass){
    const seg=FAMS.filter(f=>mass[f]>0.002).map(f=>
      `<div title="${f} ${pct(mass[f])}" style="width:${mass[f]*100}%;background:${COL[f]}"></div>`).join('');
    return `<div style="display:flex;height:26px;border-radius:5px;overflow:hidden;background:var(--panel2)">${seg}</div>`;
  }
  return `
   <h2 class="view">Why the evasive malware is missed</h2>
   <p class="lede">SHAP on the authors' EMBER model (Review-2 O2). Each bar is how the model splits
     its attention across EMBER feature families, for three groups. The striking part: the malware
     it <em>misses</em> looks almost identical to the malware it <em>catches</em> — both read as
     byte/string statistics, with no structural signal to separate them.</p>
   <div class="panel" style="margin-top:0">
     ${["caught_ordinary","caught_evasive","missed_evasive"].map(g=>{
       const names={caught_ordinary:"Caught ordinary malware",caught_evasive:"Caught evasive malware",missed_evasive:"MISSED evasive malware"};
       return `<div style="margin-bottom:16px"><div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:6px">
         <b>${names[g]}</b><span class="mono" style="color:var(--faint)">n=${gr[g]}</span></div>
         ${stack(fm[g])}
         <div class="mono" style="font-size:10.5px;color:var(--faint);margin-top:4px">
           strings ${pct(fm[g].strings)} · histogram ${pct(fm[g].histogram)} · byte-entropy ${pct(fm[g].byteentropy)} · structure ~0%</div></div>`;
     }).join('')}
     <div class="legend">${FAMS.map(f=>`<span><i style="background:${COL[f]}"></i>${f}</span>`).join('')}</div>
   </div>
   <div class="callout"><b>Missed and caught evasive malware are nearly indistinguishable to the model.</b>
     Both are ~${pct(fm.missed_evasive.strings)} string + ${pct(fm.missed_evasive.histogram)} histogram
     features, with essentially no structural evidence. Once an evasive file's byte/string profile
     looks benign, the baseline has nothing left — which is exactly the void reachability fills.</div>`;
 },
 probe(){
  const eb=D.evasion_baseline, cmp=D.comparison;
  const hist=eb.evasion_cost.hist, maxc=Math.max(...Object.values(hist));
  const bars=Object.entries(hist).map(([k,v])=>{
    const h=Math.max(4,(v/maxc)*110);
    return `<div style="display:flex;flex-direction:column;align-items:center;gap:6px;flex:1">
      <div class="mono" style="font-size:10px;color:var(--muted)">${v}</div>
      <div style="width:70%;height:${h}px;background:var(--accent2);border-radius:4px 4px 0 0"></div>
      <div class="mono" style="font-size:10px;color:var(--faint)">${k}</div></div>`;}).join('');
  const frag=eb.feature_fragility.slice(0,8).map(x=>({feature:x.feature,v:x.used_in_evasions}));
  return `
   <h2 class="view">Mimicry probe (Review-2 O6)</h2>
   <p class="lede">A second, complementary angle on the same fragility, run on the CIC-Evasive-PDFMal2022
     feature set: for every malicious file a count-based detector catches, search for the cheapest set
     of author-side feature edits that flips it to benign. It quantifies how little effort evasion
     costs against a keyword-count model.</p>
   <div class="grid cards3">
     <div class="card" style="border-color:var(--accent2)"><h3>Caught malware evaded</h3>
       <div class="stat tnum" style="color:var(--accent2)">${pct(eb.n_evaded/eb.n_caught_evaluated)}</div>
       <div class="sub">${eb.n_evaded}/${eb.n_caught_evaluated} samples</div></div>
     <div class="card"><h3>Median edits to evade</h3><div class="stat tnum">${eb.evasion_cost.median}</div>
       <div class="sub">of ${eb.controllable_features.length} editable fields</div></div>
     <div class="card"><h3>Feature-selection fix?</h3><div class="stat tnum" style="font-size:22px">${pct(cmp.evasion.baseline.ers)} → ${pct(cmp.evasion.structure_first.ers)}</div>
       <div class="sub">resilience barely moves — no</div></div>
   </div>
   <div class="two" style="margin-top:16px">
     <div class="panel" style="margin:0"><h3 class="t">Evasion cost distribution</h3>
       <p class="d">Distinct fields an author must change to flip a caught sample.</p>
       <div style="display:flex;align-items:flex-end;gap:8px;height:140px;padding:0 4px">${bars}</div>
       <div class="mono" style="text-align:center;font-size:10px;color:var(--faint);margin-top:6px">edits required →</div></div>
     <div class="panel" style="margin:0"><h3 class="t">Most fragile features</h3>
       <p class="d">Share of successful evasions touching each feature — the removable keyword counts.</p>
       ${hbars(frag,'v',frag[0].v,'var(--accent2)',v=>Math.round(v))}</div>
   </div>`;
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
         <li>EMBER2024 benchmark reproduced on the authors' released PDF model and protocol.</li>
         <li>SHAP, evasion and fusion all run against that real model — not a re-trained stand-in.</li>
         <li>Reachability verdicts from static parsing of real PDFs (pikepdf); nothing is executed.</li>
         <li>Every number on this page traces to a stored JSON artifact.</li>
       </ul></div>
     <div class="panel" style="margin:0"><h3 class="t">Honest scope</h3>
       <ul style="font-size:13px;color:var(--muted);line-height:1.8;padding-left:18px">
         <li>Weaponized samples are <b>controlled</b> (benign PDF + harmless reachable payload), not wild malware — a standard evasion-study methodology (cf. EvadeML).</li>
         <li>EMBER's 805 challenge PDFs are released as features only, so reachability can't be computed on them directly; the evasion study uses real PDFs we control.</li>
         <li>The mimicry probe uses the CIC feature set (counts), a lower bound on a real attacker.</li>
       </ul></div>
   </div>
   <div class="panel"><h3 class="t">Provenance</h3>
     <p class="note">EMBER PDF model (authors' release) · ordinary ${D.ember.ordinary.metrics.n.toLocaleString()} test PDFs ·
       ${D.ember.challenge.n_evasive} evasive challenge + ${D.ember.challenge.n_benign.toLocaleString()} benign ·
       structural-evasion study ${D.structural_evasion.n_benign_originals} real benign PDFs ·
       reachability engine TRA-1.0, ${D.reachability.n_real} real + ${D.reachability.n_crafted} crafted PDFs.</p></div>`;
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
  const prpts=c=>c.recall.map((r,i)=>[r,c.precision[i]]);
  if(v==='overview'){
    // overlay ordinary (accent) + challenge (amber) on one axis
    const o=D.ember.ordinary.curves.pr, ch=D.ember.challenge.curves.pr;
    document.getElementById('prc').innerHTML=lineChart({pts:prpts(o)},'recall','precision')
      .replace('</svg>', `<path d="${prpts(ch).map((p,i)=>(i?'L':'M')+(38+p[0]*(440-48))+' '+(260-38-p[1]*(260-38-14))).join(' ')}" fill="none" stroke="var(--el)" stroke-width="2.2"/></svg>`);
  }
  if(v==='gap'){
    document.getElementById('prc_ord').innerHTML=lineChart({pts:prpts(D.ember.ordinary.curves.pr)},'recall','precision');
    document.getElementById('prc_ch').innerHTML=lineChart({pts:prpts(D.ember.challenge.curves.pr)},'recall','precision');
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
  `<span class="pill"><span class="d" style="background:var(--lo)"></span>EMBER2024 PDF model</span>
   <span class="pill">reproduced</span><span class="pill">engine TRA-1.0</span>`;
document.getElementById('railfoot').innerHTML =
  `Static analysis only.<br>A clean result never proves safety.<br>— BCSE321L · Alok Singh, Mrinali Charhate, Aarya Nagvekar`;
window.addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(RENDER[h]&&h!==current)go(h);});
go(RENDER[location.hash.slice(1)]?location.hash.slice(1):'overview');
</script>
"""

out = ROOT / "frontend" / "dashboard.html"
out.write_text(HTML.replace("__DATA__", DATA))
print("wrote", out, out.stat().st_size, "bytes")
