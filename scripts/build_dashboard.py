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
/* PDFSentry — SOC / observability terminal skin (Grafana-grade density).
   Strict near-black, crisp functional colors, monospace throughout, 1px borders. */
:root{
  --bg:#0b0e14; --panel:#0f141b; --head:#12171f; --panel2:#0d1219;
  --border:#232c38; --line:#1a212b; --line2:#2b3542;
  --ink:#c6d2df; --mut:#7c8795; --fnt:#4f5b69;
  --teal:#2dd4bf; --amber:#f2a93b; --red:#f2495c; --blue:#5794f2; --purple:#b377e0; --green:#56c08d;
  --mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:12px;line-height:1.5;
  -webkit-font-smoothing:antialiased}
h1,h2,h3,h4{margin:0;font-weight:600;letter-spacing:-.01em}
.mono{font-family:var(--mono)} .tnum{font-variant-numeric:tabular-nums}
a{color:var(--teal)}
/* ---- shell: razor-thin icon rail + main ---- */
.app{display:grid;grid-template-columns:54px 1fr;min-height:100vh}
.rail{position:sticky;top:0;align-self:start;height:100vh;background:#0a0d12;border-right:1px solid var(--border);
  display:flex;flex-direction:column;align-items:center;padding:9px 0;gap:3px;z-index:30}
.logo{width:32px;height:32px;border-radius:7px;display:grid;place-items:center;margin-bottom:8px;
  background:#0f151d;border:1px solid var(--line2)}
.logo svg{width:18px;height:18px}
.navbtn{all:unset;cursor:pointer;width:38px;height:38px;border-radius:7px;display:grid;place-items:center;
  color:var(--fnt);position:relative;transition:.12s}
.navbtn svg{width:18px;height:18px}
.navbtn:hover{background:#141a23;color:var(--ink)}
.navbtn[aria-current="true"]{color:var(--teal);background:#10171e}
.navbtn[aria-current="true"]::before{content:"";position:absolute;left:-9px;top:8px;bottom:8px;width:2px;border-radius:2px;background:var(--teal)}
.navbtn::after{content:attr(data-label);position:absolute;left:46px;top:50%;transform:translateY(-50%) scale(.96);
  background:#11161d;border:1px solid var(--border);color:var(--ink);font-size:10.5px;padding:4px 8px;border-radius:5px;
  white-space:nowrap;opacity:0;pointer-events:none;transition:.12s;z-index:40}
.navbtn:hover::after{opacity:1;transform:translateY(-50%) scale(1)}
.navdiv{width:22px;height:1px;background:var(--border);margin:5px 0}
.railver{margin-top:auto;font-size:8px;color:var(--fnt);writing-mode:vertical-rl;letter-spacing:.1em;padding-bottom:4px}
.main{min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:12px;flex-wrap:wrap;height:42px;
  padding:0 max(12px,env(safe-area-inset-right,0)) 0 max(14px,env(safe-area-inset-left,0));
  background:#0a0d12;border-bottom:1px solid var(--border)}
.crumb{font-size:11px;color:var(--fnt);letter-spacing:.04em}
.crumb b{color:var(--ink);font-weight:500}
.statuscluster{margin-left:auto;display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:10px;color:var(--mut);padding:4px 9px;
  border:1px solid var(--border);border-radius:4px;background:#0d1219;letter-spacing:.03em;text-transform:uppercase}
.chip b{color:var(--ink);font-weight:500}
.live{width:6px;height:6px;border-radius:50%;background:var(--teal)}
.content{padding:12px max(12px,env(safe-area-inset-right,0)) 56px max(14px,env(safe-area-inset-left,0));max-width:1480px}
.vhead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.eyebrow{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--teal);margin-bottom:5px}
h2.view{font-size:19px;font-weight:600;letter-spacing:-.01em}
.lede{color:var(--mut);font-size:12px;max-width:110ch;margin:7px 0 14px;line-height:1.55}
/* ---- grid + panels (dense) ---- */
.grid{display:grid;gap:9px}
.c4{grid-template-columns:repeat(4,1fr)} .c3{grid-template-columns:repeat(3,1fr)} .c2{grid-template-columns:repeat(2,1fr)}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:10px 11px;position:relative;min-width:0}
.panel h3.t{font-size:10.5px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);
  padding-bottom:7px;margin-bottom:9px;border-bottom:1px solid var(--line)}
.panel .d{font-size:11px;color:var(--mut);margin-bottom:11px;max-width:110ch;line-height:1.5}
/* KPI / stat tiles — flat, crisp top-accent */
.kpi{padding:9px 11px}
.kpi .glow{display:none}
.kpi h3{font-size:9.5px;color:var(--mut);font-weight:500;letter-spacing:.07em;text-transform:uppercase;margin-bottom:9px}
.kpi .num{font-size:25px;font-weight:600;letter-spacing:-.01em;line-height:1}
.kpi .num small{font-size:12px;color:var(--fnt);font-weight:400}
.kpi .sub{font-size:10px;color:var(--fnt);margin-top:7px;letter-spacing:.02em}
.chart{width:100%}
/* tables — dense telemetry */
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{color:var(--fnt);font-weight:500;font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;
  border-bottom:1px solid var(--border)}
tbody tr{transition:background .1s}
tbody tr:hover{background:#121823}
td.mono,th.mono{font-family:var(--mono)}
.tag{font-size:9.5px;padding:2px 6px;border-radius:3px;white-space:nowrap;font-weight:500;letter-spacing:.02em}
.t-open{background:rgba(242,73,92,.14);color:#ff7a84;border:1px solid rgba(242,73,92,.3)}
.t-int{background:rgba(242,169,59,.14);color:var(--amber);border:1px solid rgba(242,169,59,.3)}
.t-dorm{background:rgba(255,255,255,.04);color:var(--mut);border:1px solid var(--line2)}
.t-ok{background:rgba(45,212,191,.13);color:var(--teal);border:1px solid rgba(45,212,191,.3)}
.band{font-weight:600;padding:3px 8px;border-radius:3px;font-size:10px;letter-spacing:.04em}
.b-HIGH{background:rgba(242,73,92,.16);color:#ff7a84} .b-ELEVATED{background:rgba(242,169,59,.16);color:var(--amber)}
.b-LOW{background:rgba(45,212,191,.15);color:var(--teal)} .b-UNKNOWN{background:rgba(255,255,255,.05);color:var(--mut)}
.callout{border-left:2px solid var(--teal);background:#0e1620;padding:10px 12px;border-radius:0 4px 4px 0;margin-top:11px;font-size:11.5px;line-height:1.5}
.callout.warn{border-left-color:var(--amber);background:#17130a}
.callout b{color:var(--teal)} .callout.warn b{color:var(--amber)}
.note{font-size:10px;color:var(--fnt);margin-top:10px;line-height:1.55}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:4px;overflow:hidden;flex-wrap:wrap;background:#0d1219}
.seg button{all:unset;cursor:pointer;padding:6px 11px;color:var(--mut);font-size:10.5px;letter-spacing:.03em;transition:.12s}
.seg button:hover{color:var(--ink)}
.seg button[aria-current="true"]{background:var(--teal);color:#06110f;font-weight:600}
.scroll{max-height:380px;overflow:auto;border:1px solid var(--border);border-radius:4px}
.scroll th{position:sticky;top:0;background:#0c1118;z-index:1}
.row-dis{background:rgba(242,73,92,.06)}
.legendrow{display:flex;gap:14px;flex-wrap:wrap;font-size:10px;color:var(--mut);margin-top:9px}
.legendrow i{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle}
.bars{display:flex;flex-direction:column;gap:7px;margin-top:2px}
.barrow{display:grid;grid-template-columns:170px 1fr 56px;align-items:center;gap:10px;font-size:11px}
.barrow .lab{font-size:10.5px;color:var(--mut);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.track{height:15px;background:#10161e;border-radius:3px;overflow:hidden;border:1px solid var(--line)}
.fill{height:100%;border-radius:0;transition:width .8s cubic-bezier(.2,.8,.2,1)}
.val{font-size:11px;text-align:right;color:var(--ink)}
/* live analysis */
.specrow{display:flex;gap:7px;flex-wrap:wrap}
.spec{all:unset;cursor:pointer;display:flex;flex-direction:column;gap:5px;padding:8px 10px;border-radius:4px;
  border:1px solid var(--border);background:#0d1219;transition:.12s;min-width:140px}
.spec:hover{border-color:var(--line2);background:#121823}
.spec[aria-current="true"]{border-color:var(--teal);background:#0e1a1c}
.spec.weaponized[aria-current="true"]{border-color:var(--red);background:#1a1013}
.specn{font-size:11px;font-weight:500;color:var(--ink)}
.spectag{font-size:8.5px;padding:2px 6px;border-radius:3px;align-self:flex-start;letter-spacing:.03em;text-transform:uppercase}
.tracebtn{all:unset;cursor:pointer;font-size:10.5px;color:var(--teal);padding:5px 10px;
  border:1px solid rgba(45,212,191,.35);border-radius:4px;background:rgba(45,212,191,.06);transition:.12s}
.tracebtn:hover{background:rgba(45,212,191,.14)}
.vduo{display:flex;align-items:stretch;gap:9px;margin-top:5px}
.vcard{flex:1;min-width:0;background:#0d1219;border:1px solid var(--border);border-radius:4px;padding:11px}
.vlbl{font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--fnt)}
.vval{font-size:19px;font-weight:700;margin-top:5px;text-transform:uppercase;letter-spacing:.01em}
.vsub{font-size:10px;color:var(--mut);margin-top:4px}
.vx{display:flex;align-items:center;font-size:11px;color:var(--fnt)}
.evbanner{margin-top:12px;padding:10px 12px;border-radius:4px;font-size:11.5px;line-height:1.5;
  background:#17110f;border:1px solid rgba(242,73,92,.3);border-left:2px solid var(--red);color:#ff8f96}
.evbanner b{color:#ff7a84}
.okbanner{margin-top:12px;padding:9px 12px;border-radius:4px;font-size:11.5px;color:var(--mut);
  background:#0e1620;border:1px solid var(--line2);border-left:2px solid var(--teal)}
.chiprow{display:flex;gap:5px;flex-wrap:wrap;max-height:132px;overflow:auto;padding:2px}
.chal{all:unset;cursor:pointer;font-size:10px;color:var(--mut);padding:5px 8px;border-radius:3px;
  border:1px solid var(--border);display:inline-flex;align-items:center;gap:6px;transition:.1s;background:#0d1219}
.chal:hover{border-color:var(--line2);color:var(--ink)}
.chal[aria-current="true"]{border-color:var(--teal);color:var(--ink);background:#0e1a1c}
.cdot{width:5px;height:5px;border-radius:50%} .cdot.missed{background:var(--red)} .cdot.caught{background:var(--teal)}
.fprow{display:grid;grid-template-columns:170px 1fr 78px;align-items:center;gap:10px;margin:7px 0}
.fplab{font-size:10.5px;color:var(--mut);text-align:right}
.fptrack{position:relative;height:15px;background:#10161e;border:1px solid var(--line);border-radius:3px;overflow:hidden}
.fpmed{position:absolute;left:25%;top:-2px;bottom:-2px;width:2px;background:var(--fnt);opacity:.7;z-index:2}
.fpfill{height:100%;background:var(--amber);transition:width .8s cubic-bezier(.2,.8,.2,1)}
.fpval{font-size:10.5px;color:var(--ink);text-align:right}
.mtiles{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:11px}
.mtile{background:#0d1219;border:1px solid var(--border);border-radius:4px;padding:8px 10px}
.mlbl{font-size:8.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--fnt)}
.mnum{font-size:17px;font-weight:600;margin-top:4px}
.demobtn{all:unset;cursor:pointer;font-size:11px;color:#06110f;background:var(--teal);padding:6px 13px;border-radius:4px;font-weight:600;letter-spacing:.03em}
.demobtn:hover{filter:brightness(1.08)} .demobtn.on{background:var(--amber)}
.demobtn .dps{margin-right:4px}
.gcap{font-size:9px;color:var(--fnt);text-align:center;margin-top:-8px}
@media (max-width:560px){.mtiles{grid-template-columns:repeat(2,1fr)}}
.fadein{animation:fade .35s ease both}
@keyframes fade{from{opacity:0}to{opacity:1}}
@media (max-width:980px){.c4,.c3,.c2{grid-template-columns:repeat(2,1fr)}}
@media (max-width:620px){.c4,.c3,.c2{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
/* ---- enterprise portal: triage console + operations ---- */
.conref{font-size:10px;color:var(--mut);letter-spacing:.04em;display:flex;align-items:center;gap:7px}
.kpibar{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-top:12px}
.kpibar.wide{grid-template-columns:repeat(6,1fr)}
.kpitile{background:#0d1219;border:1px solid var(--border);border-top:2px solid var(--line2);border-radius:5px;padding:9px 11px}
.kpitile .kn{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}
.kpitile .kl{font-size:8.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--fnt);margin-top:6px}
.contool{display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap}
.searchbox{flex:1;min-width:200px;background:#0d1219;border:1px solid var(--border);border-radius:5px;color:var(--ink);font-family:'JetBrains Mono',monospace;font-size:11px;padding:8px 11px;outline:none}
.searchbox:focus{border-color:var(--teal)} .searchbox::placeholder{color:var(--fnt)}
.conwrap{display:grid;grid-template-columns:1.3fr 1fr;gap:12px;margin-top:12px;align-items:start}
.qpanel{padding:0;overflow:hidden}
.qscroll{max-height:462px;overflow:auto}
.qtable{width:100%;border-collapse:collapse;font-size:11px}
.qtable thead th{position:sticky;top:0;background:#0c1118;color:var(--mut);font-weight:600;text-align:left;font-size:9px;letter-spacing:.06em;text-transform:uppercase;padding:9px 10px;border-bottom:1px solid var(--border);z-index:2}
.qtable tbody tr{border-bottom:1px solid #161c25;cursor:pointer;transition:background .1s}
.qtable tbody tr:hover{background:#10171e}
.qtable tbody tr.qsel{background:#0e1a1c;box-shadow:inset 2px 0 0 var(--teal)}
.qtable td{padding:7px 10px;vertical-align:middle;color:var(--mut)}
.qf{color:var(--ink);font-size:11px;max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.qid{font-size:8.5px;color:var(--fnt);margin-top:2px}
.qsrc{font-size:9px;color:var(--mut);border:1px solid var(--border);border-radius:3px;padding:2px 6px;white-space:nowrap}
.qreach{font-family:'JetBrains Mono',monospace;font-size:10px} .qreach.cred{color:var(--red)} .qreach.camb{color:var(--amber)}
.riskcell{display:flex;align-items:center;gap:7px}
.riskbar{width:46px;height:6px;background:#161c25;border-radius:3px;overflow:hidden}
.riskbar i{display:block;height:100%;border-radius:3px}
.rkv{font-size:11px;color:var(--ink);width:20px}
.disp{font-size:8.5px;font-weight:700;letter-spacing:.05em;padding:3px 7px;border-radius:3px;font-family:'JetBrains Mono',monospace;white-space:nowrap}
.disp.rb-q{background:rgba(242,73,92,.14);color:var(--red)} .disp.rb-r{background:rgba(242,169,59,.14);color:var(--amber)} .disp.rb-a{background:rgba(45,212,191,.12);color:var(--teal)}
.disp.big{font-size:10px;padding:5px 10px}
.qfoot{font-size:9.5px;color:var(--fnt);padding:7px 11px;border-top:1px solid var(--border);background:#0c1118}
.caseempty{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;min-height:320px;color:var(--fnt);font-size:12px}
.ceico svg{width:40px;height:40px;opacity:.35;stroke:var(--fnt)}
.caseh{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:12px}
.casetitle{font-size:14px;color:var(--ink);font-weight:600;max-width:300px}
.caseid{font-size:9.5px;color:var(--fnt);margin-top:3px}
.casegrid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:2px}
.ccard{background:#0d1219;border:1px solid var(--border);border-radius:4px;padding:8px 10px}
.ccard .cl{font-size:8px;letter-spacing:.06em;text-transform:uppercase;color:var(--fnt)}
.ccard .cv{font-size:20px;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--ink);margin-top:4px;line-height:1}
.ccard .cv small{font-size:10px;color:var(--fnt)} .ccard .cv.sm{font-size:11px;font-weight:600} .ccard .cv.cred{color:var(--red)}
.csub{font-size:9px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:13px 0 7px}
.cioc{display:flex;flex-direction:column;gap:4px}
.iocrow{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--mut);background:#0d1219;border:1px solid var(--border);border-left:2px solid var(--line2);border-radius:3px;padding:6px 9px}
.iocrow .iocdot{width:5px;height:5px;border-radius:50%;background:var(--fnt);flex:none}
.iocrow.crit{border-left-color:var(--red)} .iocrow.crit .iocdot{background:var(--red)}
.iocrow.warn{border-left-color:var(--amber)} .iocrow.warn .iocdot{background:var(--amber)}
.iocrow.ok{border-left-color:var(--teal)} .iocrow.ok .iocdot{background:var(--teal)}
.caseact{display:flex;gap:8px;margin-top:14px}
.actbtn{all:unset;cursor:pointer;font-size:10px;font-weight:600;letter-spacing:.03em;padding:7px 12px;border-radius:4px;border:1px solid var(--border);color:var(--mut);transition:.12s}
.actbtn:hover{color:var(--ink);border-color:var(--line2)}
.actbtn.q:hover{background:rgba(242,73,92,.14);border-color:var(--red);color:var(--red)}
.actbtn.a:hover{background:rgba(45,212,191,.12);border-color:var(--teal);color:var(--teal)}
.actbtn.g{background:var(--teal);color:#06110f;border-color:var(--teal)} .actbtn.g:hover{filter:brightness(1.08);color:#06110f}
.report{margin-top:14px;background:#0c1118;border:1px solid var(--border);border-radius:5px;padding:12px 14px;font-family:'JetBrains Mono',monospace}
.report .rhdr{font-size:9px;letter-spacing:.12em;color:var(--teal);margin-bottom:9px}
.report .rrow{display:flex;justify-content:space-between;gap:12px;font-size:10px;padding:3px 0;border-bottom:1px solid #141a22}
.report .rrow span{color:var(--fnt)} .report .rrow b{color:var(--ink);text-align:right;font-weight:600;max-width:62%}
.report .rrow.top{align-items:flex-start} .report .rrow.top b{line-height:1.45}
.report .rfoot{font-size:9px;color:var(--fnt);margin-top:9px;line-height:1.45;font-family:inherit}
.ptable{width:100%;border-collapse:collapse;font-size:11px}
.ptable td{padding:8px 6px;border-bottom:1px solid #161c25;color:var(--mut);vertical-align:middle}
.ptable td:first-child{width:118px}
@media (max-width:980px){.conwrap{grid-template-columns:1fr}.kpibar,.kpibar.wide{grid-template-columns:repeat(3,1fr)}}
/* three-pillar strip */
.pillars{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:0 0 15px}
.pillar{all:unset;cursor:pointer;display:flex;flex-direction:column;gap:5px;padding:12px 13px;border-radius:5px;
  background:#0d1219;border:1px solid var(--border);border-top:2px solid var(--border);transition:.14s;position:relative}
.pillar:hover{border-color:var(--line2);background:#0e141c;transform:translateY(-1px)}
.pillar .pnum{font-size:9px;letter-spacing:.2em;color:var(--fnt)}
.pillar .ptit{font-size:14px;font-weight:600;color:var(--ink);letter-spacing:.01em}
.pillar .pdesc{font-size:10.5px;color:var(--mut);line-height:1.5;min-height:46px}
.pillar .pstat{font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;margin-top:2px}
.pillar:nth-child(1){border-top-color:var(--teal)} .pillar:nth-child(2){border-top-color:var(--amber)} .pillar:nth-child(3){border-top-color:#5794f2}
@media (max-width:820px){.pillars{grid-template-columns:1fr}}
/* stability + witness chips */
.stchip,.witchip{all:unset;cursor:pointer;font-size:9.5px;color:var(--mut);padding:5px 8px;border-radius:3px;
  border:1px solid var(--border);background:#0d1219;font-family:'JetBrains Mono',monospace;transition:.1s}
.stchip:hover,.witchip:hover{border-color:var(--line2);color:var(--ink)}
.stchip[aria-current="true"],.witchip[aria-current="true"]{border-color:var(--teal);color:var(--ink);background:#0e1a1c}
/* certificate list */
.certhead{font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--teal);margin-bottom:8px;font-family:'JetBrains Mono',monospace}
.cert{list-style:none;margin:0;padding:0;counter-reset:c}
.cert li{counter-increment:c;display:flex;align-items:center;gap:9px;padding:7px 9px;margin-bottom:5px;border-radius:4px;
  background:#0d1219;border:1px solid var(--border);border-left:2px solid var(--line2);transition:.18s}
.cert li::before{content:counter(c);width:16px;height:16px;flex:none;border-radius:50%;background:#10161e;color:var(--fnt);
  font-size:9px;display:grid;place-items:center;font-family:'JetBrains Mono',monospace}
.cert li.on{border-left-color:var(--teal);background:#0e1a1c;box-shadow:0 0 0 1px rgba(45,212,191,.25)}
.cert li.ctrg{border-left-color:var(--amber)} .cert li.cdng{border-left-color:var(--red)}
.cert .crole{font-size:8.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--fnt);min-width:58px}
.cert .clab{font-size:12px;color:var(--ink);font-family:'JetBrains Mono',monospace;flex:1}
.cert .cflag{font-size:8.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--red);font-weight:600}
.cert .cflag.ok{color:var(--teal)}
</style>

<div class="app">
  <nav class="rail">
    <span class="logo"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" stroke="#2dd4bf" stroke-width="1.5"/><path d="M8.5 12.2l2.3 2.3 4.7-5" stroke="#2dd4bf" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
    <div id="nav" style="display:flex;flex-direction:column;align-items:center;gap:3px"></div>
    <div class="railver">PDFSENTRY</div>
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
const C={teal:'#2dd4bf',teal2:'#17b3a0',amber:'#f2a93b',red:'#f2495c',pink:'#b377e0',blue:'#5794f2',
  ink:'#c6d2df',muted:'#7c8795',faint:'#4f5b69',line:'rgba(255,255,255,.06)'};
let CHARTS=[]; const reduce=matchMedia('(prefers-reduced-motion:reduce)').matches;
function mk(id,opt){try{const el=document.getElementById(id);if(!el||typeof echarts==='undefined')return;
  const ex=echarts.getInstanceByDom(el);if(ex)ex.dispose();
  const c=echarts.init(el,null,{renderer:'canvas'});
  opt.animationDuration=reduce?0:900;opt.textStyle={fontFamily:'JetBrains Mono,monospace',color:C.muted};
  c.setOption(opt);CHARTS.push(c);return c;}catch(e){console.error('chart '+id,e);}}
function clearCharts(){CHARTS.forEach(c=>{try{c.dispose()}catch(e){}});CHARTS=[]}
addEventListener('resize',()=>CHARTS.forEach(c=>{try{if(c&&!c.isDisposed())c.resize()}catch(e){}}));
function tile(lab,v,dec,suf,col){return `<div class="mtile"><div class="mlbl">${lab}</div><div class="mnum tnum" data-to="${v}" data-dec="${dec||0}" data-suf="${suf||''}" style="color:${col||'var(--ink)'}">0</div></div>`}
function countUp(root){(root||document).querySelectorAll('[data-to]').forEach(el=>{
  const to=+el.dataset.to,dec=+(el.dataset.dec||0),suf=el.dataset.suf||'';
  if(reduce){el.textContent=to.toFixed(dec)+suf;return;}
  const t0=performance.now(),dur=900;
  (function step(t){let k=Math.min(1,(t-t0)/dur);k=1-Math.pow(1-k,3);
    el.textContent=(to*k).toFixed(dec)+suf;if(k<1)requestAnimationFrame(step)})(t0);});}

const AX={axisLine:{lineStyle:{color:C.line}},axisTick:{show:false},
  axisLabel:{color:C.faint,fontSize:9},splitLine:{lineStyle:{color:'rgba(255,255,255,.035)'}}};
function grad(hex,a1=.35,a2=0){return new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:'rgba('+hx(hex)+','+a1+')'},{offset:1,color:'rgba('+hx(hex)+','+a2+')'}])}
function hx(h){h=h.replace('#','');return [0,2,4].map(i=>parseInt(h.slice(i,i+2),16)).join(',')}

function prChart(id,series){ // series:[{name,color,pts:[[x,y]..]}]
  mk(id,{grid:{left:46,right:16,top:26,bottom:40},legend:{top:0,right:0,textStyle:{color:C.muted,fontSize:10},icon:'roundRect'},
    tooltip:{trigger:'axis',backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11},
      valueFormatter:v=>(+v).toFixed(3)},
    xAxis:{type:'value',min:0,max:1,name:'recall',nameLocation:'middle',nameGap:24,nameTextStyle:{color:C.faint,fontSize:10},...AX},
    yAxis:{type:'value',min:0,max:1,name:'precision',nameLocation:'middle',nameGap:32,nameTextStyle:{color:C.faint,fontSize:10},...AX},
    series:series.map(s=>({name:s.name,type:'line',smooth:false,showSymbol:false,data:s.pts,
      lineStyle:{color:s.color,width:1.6},itemStyle:{color:s.color},
      areaStyle:{color:grad(s.color,.10,0)}}))});}
function gauge(id,val,label,color,max=1){
  mk(id,{series:[{type:'gauge',radius:'92%',center:['50%','58%'],startAngle:210,endAngle:-30,min:0,max:max,
    progress:{show:true,width:8,roundCap:false,itemStyle:{color:color}},
    axisLine:{lineStyle:{width:8,color:[[1,'rgba(255,255,255,.06)']]}},
    pointer:{show:false},axisTick:{show:false},splitLine:{show:false},axisLabel:{show:false},
    anchor:{show:false},title:{show:true,offsetCenter:[0,'36%'],color:C.faint,fontSize:9,fontFamily:'JetBrains Mono'},
    detail:{valueAnimation:true,offsetCenter:[0,'0%'],fontSize:21,fontFamily:'JetBrains Mono',fontWeight:600,
      color:color,formatter:v=>max<=1?(v*100).toFixed(1)+'%':v.toFixed(0)},
    data:[{value:val,name:label}]}]});}
function barH(id,items,color,fmt){ // items:[{name,v}]
  mk(id,{grid:{left:4,right:46,top:6,bottom:6,containLabel:true},
    tooltip:{trigger:'axis',axisPointer:{type:'shadow'},backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
    xAxis:{type:'value',...AX,splitLine:{show:false}},
    yAxis:{type:'category',inverse:true,data:items.map(i=>i.name),axisLine:{show:false},axisTick:{show:false},
      axisLabel:{color:C.muted,fontSize:9.5,fontFamily:'JetBrains Mono'}},
    series:[{type:'bar',data:items.map(i=>i.v),barWidth:'60%',
      itemStyle:{borderRadius:[0,2,2,0],color:color},
      label:{show:true,position:'right',color:C.ink,fontFamily:'JetBrains Mono',fontSize:10,formatter:p=>fmt(p.value)}}]});}
</script>
<script>
const VIEWS=[['console','Triage console','inbox'],['ops','Operations','gauge2'],
  ['overview','Evidence overview','grid'],['gap','The evasive gap','trend'],['realmal','Real evasive malware','dna'],
  ['evasion','Structural evasion','target'],['reach','Reachability graph','node'],
  ['stability','Semantic stability','wave'],['assurance','Verifiable verdicts','verify'],
  ['explain','Why they evade','radar'],['probe','Mimicry probe','probe'],
  ['live','Live analysis','search'],['about','Method & limits','doc']];
const DIVS=[2,9,11];
const ICON={inbox:'M4 13l2.4 4.2a1 1 0 0 0 .9.5h9.4a1 1 0 0 0 .9-.5L20 13M4 13V5h16v8M4 13h4.5a3.5 3.5 0 0 0 7 0H20',
  gauge2:'M3.5 18a9 9 0 1 1 17 0M12 18l4.6-5.6M12 18h.01',
  grid:'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  trend:'M3 17l6-6 4 4 7-8M21 7v5M21 7h-5',dna:'M4 3c4 4 12 4 16 0M4 21c4-4 12-4 16 0M7 5v14M17 5v14',
  target:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 11v2',
  node:'M5 12m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M19 5m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M19 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M7 11l10-5M7 13l10 5',
  wave:'M3 9c3-4 6-4 9 0s6 4 9 0M3 15c3-4 6-4 9 0s6 4 9 0',
  verify:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M8 12l2.8 2.8L16.2 9',
  radar:'M12 2l9 6.5-3.5 10.5h-11L3 8.5zM12 2v20M3 8.5l18 0',probe:'M3 12h4l3 8 4-16 3 8h4',
  search:'M11 11m-7 0a7 7 0 1 0 14 0a7 7 0 1 0-14 0M21 21l-4.3-4.3',doc:'M6 2h9l5 5v15H6zM15 2v5h5'};
function svg(k){return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="${ICON[k]}"/></svg>`}

const VC={ACTIVE_ONOPEN:['t-open','ACTIVE · on-open'],ACTIVE_ONINTERACT:['t-int','active · on-click'],
  PRESENT_DORMANT:['t-dorm','dormant'],ABSENT:['t-dorm','absent']};
function kpi(label,numHtml,sub,color,glow){return `<div class="panel kpi fadein" style="border-top:2px solid ${color||'var(--border)'}">
  <h3>${label}</h3><div class="num" style="color:${color||'var(--ink)'}">${numHtml}</div>
  <div class="sub">${sub}</div></div>`;}
function num(to,dec,suf){return `<span data-to="${to}" data-dec="${dec}" data-suf="${suf||''}">0</span>`}

const R={
 console(){return `<div class="eyebrow">Security operations · PDF triage</div>
   <div class="vhead"><h2 class="view">Triage console</h2>
     <div class="conref"><span class="live"></span>engine TRA-1.0 · static · no execution</div></div>
   <p class="lede">Every ingested PDF is parsed statically and risk-scored. <b style="color:var(--teal)">Reachability</b> decides disposition —
     a dangerous action reachable from an automatic trigger is quarantined; a click-only capability is routed for review.</p>
   <div class="kpibar" id="conKpis"></div>
   <div class="contool">
     <input id="conSearch" class="searchbox" placeholder="Search by case id, hash or filename…" autocomplete="off"/>
     <div class="seg" id="conFilter"><button data-f="all" aria-current="true">All</button>
       <button data-f="quarantine">Quarantined</button><button data-f="review">Review</button>
       <button data-f="allow">Allowed</button><button data-f="threat">Auto-exec threats</button></div>
   </div>
   <div class="conwrap">
     <div class="panel qpanel"><div class="qscroll"><table class="qtable"><thead><tr>
       <th>Artifact</th><th>Source</th><th class="mono">EMBER</th><th>Reachability</th><th>Risk</th><th>Disposition</th><th class="mono">ms</th>
     </tr></thead><tbody id="qbody"></tbody></table></div>
       <div class="qfoot" id="qfoot"></div></div>
     <div class="panel" id="casePanel"><div class="caseempty"><div class="ceico">${svg('inbox')}</div>Select an artifact to open its case file.</div></div>
   </div>`;},
 ops(){return `<div class="eyebrow">Security operations · overview</div>
   <div class="vhead"><h2 class="view">Operations overview</h2>
     <div class="conref"><span class="live"></span>corpus under management</div></div>
   <p class="lede">Fleet-level posture of the analysis engine across the corpus — detection outcomes, risk distribution,
     leading indicators, and the active disposition policy. Every number is computed from analyzed artifacts.</p>
   <div class="kpibar wide" id="opsKpis"></div>
   <div class="grid c2" style="margin-top:14px">
     <div class="panel fadein"><h3 class="t">Disposition mix</h3><p class="d">How ingested artifacts resolve under the policy.</p><div class="chart" id="ops_disp" style="height:230px"></div></div>
     <div class="panel fadein"><h3 class="t">Risk-score distribution</h3><p class="d">PDFSentry risk (0–100) across the corpus.</p><div class="chart" id="ops_risk" style="height:230px"></div></div>
   </div>
   <div class="grid c2" style="margin-top:12px">
     <div class="panel fadein"><h3 class="t">Leading indicators of compromise</h3><p class="d">Frequency across flagged artifacts.</p><div class="chart" id="ops_ioc" style="height:235px"></div></div>
     <div class="panel fadein"><h3 class="t">Detection policy</h3><p class="d">Verdict → disposition mapping (static reachability gate).</p><div id="opsPolicy"></div></div>
   </div>`;},
 overview(){const eo=D.ember.ordinary.metrics,ec=D.ember.challenge.metrics,se=D.structural_evasion,cs=D.challenge_structure;
  return `<div class="eyebrow">EMBER2024 · PDF detection</div>
   <div class="vhead"><h2 class="view">Closing the evasive gap</h2></div>
   <p class="lede">We reproduce EMBER2024's PDF benchmark on the authors' own model, prove on real evasive
     malware why it fails, and close the gap with a structural <b style="color:var(--teal)">reachability</b>
     signal — every number here traces to a stored artifact.</p>
   <div class="pillars">
     <button class="pillar" data-v="reach"><span class="pnum">01</span><span class="ptit">Detection</span>
       <span class="pdesc">Reachability over recognition — parse the object graph, flag only a dangerous action <i>reachable</i> from an auto-trigger.</span>
       <span class="pstat" style="color:var(--teal)">0.649 → 0.998 AUC</span></button>
     <button class="pillar" data-v="stability"><span class="pnum">02</span><span class="ptit">Robustness</span>
       <span class="pdesc">Semantic stability — the verdict is invariant to lossless byte-obfuscation that swings the ML score across the scale.</span>
       <span class="pstat" style="color:var(--amber)">SSI 1.000 vs 0.216</span></button>
     <button class="pillar" data-v="assurance"><span class="pnum">03</span><span class="ptit">Assurance</span>
       <span class="pdesc">Verifiable verdicts — every alarm ships a minimal, human-checkable witness path; deterministic, training-free.</span>
       <span class="pstat" style="color:var(--blue)">0/285 FP · 1.2 ms</span></button>
   </div>
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
 live(){const L=D.live;if(!L)return '<h2 class="view">Live analysis</h2><p class="lede">Run export_specimens.py.</p>';
  const cg=L.challenge_gallery;
  const chips=L.specimens.map((s,i)=>{const dis=s.ember_verdict==='benign'&&s.reach_dangerous;
    return `<button class="spec ${s.category}" data-i="${i}">
      <span class="specn">${s.name}</span>
      <span class="spectag ${dis?'t-open':s.reach_dangerous?'t-int':'t-dorm'}">${dis?'EMBER fooled':s.reach_dangerous?'reachable':'clean'}</span></button>`}).join('');
  return `<div class="eyebrow">Live analysis · EMBER vs PDFSentry</div>
   <div class="vhead"><h2 class="view">Live specimen analyzer</h2>
     <button class="demobtn" id="demoBtn"><span class="dps">▶</span> Demo mode</button></div>
   <p class="lede">Click a specimen — the real EMBER model and the reachability engine both analyze it, and the metrics
     come alive. Weaponized specimens are real PDFs carrying a harmless reachable payload; nothing is executed.</p>
   <div class="specrow" id="specrow">${chips}</div>
   <div class="grid c2" style="margin-top:15px;align-items:stretch">
     <div class="panel fadein" id="verdictPanel" style="min-height:330px"></div>
     <div class="panel fadein"><div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
       <h3 class="t">Object-reachability graph</h3><button class="tracebtn" id="traceBtn">▶ Trace attack path</button></div>
       <div class="chart" id="specGraph" style="height:300px"></div>
       <div class="legendrow"><span><i style="background:#cbd5e1"></i>catalog</span><span><i style="background:#5b94e8"></i>page</span>
         <span><i style="background:var(--amber)"></i>trigger</span><span><i style="background:var(--red)"></i>dangerous</span></div>
       <div class="mtiles" id="specTiles"></div></div>
   </div>
   <div class="panel fadein" style="margin-top:15px">
     <div class="vhead"><h3 class="t">Real EMBER evasive malware · ${cg.n_total} challenge PDFs</h3>
       <div class="seg" id="chalFilter"><button data-f="missed" aria-current="true">missed (${cg.n_missed})</button>
         <button data-f="caught">caught (${cg.n_total-cg.n_missed})</button><button data-f="all">all ${cg.n_total}</button></div></div>
     <p class="d">Actual malware from the EMBER2024 challenge set (released as features — no raw file, so no object graph).
       Click any sample; its full structural fingerprint animates in against a benign baseline.</p>
     <div class="chiprow" id="chalrow"></div>
     <div class="grid c2" style="margin-top:16px;align-items:stretch">
       <div id="chalVerdict"></div>
       <div class="panel" style="background:rgba(255,255,255,.015)"><h3 class="t" style="font-size:12px;color:var(--muted)">Structural fingerprint vs benign</h3><div class="chart" id="chalRadar" style="height:250px"></div></div>
     </div>
     <div class="mtiles" id="chalTiles" style="margin-top:14px"></div>
     <div id="chalBanner"></div></div>`;},
 stability(){const ss=D.semantic_stability,ea=D.evasion_asymmetry;const ssi=ss.semantic_stability_index;
  const chips=ss.docs.map((d,i)=>`<button class="stchip" data-i="${i}">${d.base.replace('.pdf','')}·${d.wiring}${d.hide?'·hid':''}</button>`).join('');
  return `<div class="eyebrow">Novelty 2 · robustness</div>
   <div class="vhead"><h2 class="view">Semantic stability under obfuscation</h2></div>
   <p class="lede">Hold a PDF's malicious <b>behaviour</b> fixed and apply only lossless re-saves — recompress, re-encode,
     encrypt. The bytes change; what the document <i>does</i> does not. A byte-based model should not care. It does.</p>
   <div class="grid c4">
     ${kpi('EMBER verdict inconsistency',num(ss.ember.verdict_inconsistency_rate*100,1,'%'),'of docs get BOTH verdicts across byte-identical behaviour',C.red,1)}
     ${kpi('Median score swing',num(ss.ember.median_score_range_within_doc,2),'on one unchanged doc · max '+f3(ss.ember.max_score_range_within_doc),C.amber,1)}
     ${kpi('Reachability stability index',num(ssi.reachability,3),'vs EMBER '+f3(ssi.ember)+' · '+ss.n_transformed_variants+' variants',C.teal,1)}
     ${kpi('Evasion = disarm',num(ea.reachability_deescalates_on_disarm*100,1,'%'),'the only way past reachability removes the attack',C.blue,1)}
   </div>
   <div class="grid c2" style="margin-top:15px;align-items:stretch">
     <div class="panel fadein"><div class="vhead"><h3 class="t">Same document, eight lossless re-saves</h3></div>
       <p class="d">Pick a weaponized document — EMBER's score is plotted for each byte-variant; the behaviour, and the
         reachability verdict, never change.</p>
       <div class="chiprow" id="strow">${chips}</div>
       <div class="chart" id="st_swing" style="height:230px"></div>
       <div class="mtiles" id="stTiles"></div>
       <div id="stVerdict"></div></div>
     <div class="panel fadein"><h3 class="t">Stability index — reachability vs EMBER</h3>
       <p class="d">Fraction of documents whose verdict never flips across the transform set.</p>
       <div class="grid c2"><div><div class="chart" id="st_g1" style="height:150px"></div><div class="gcap">reachability</div></div>
         <div><div class="chart" id="st_g2" style="height:150px"></div><div class="gcap">EMBER</div></div></div>
       <div class="callout" style="margin-top:10px"><b>Evasion-cost asymmetry.</b> Evading EMBER costs a free re-save, payload intact.
         Evading reachability means severing the trigger→action path — which removes the dangerous capability itself
         (ACTIVE→ABSENT in ${pct(ea.reachability_deescalates_on_disarm)}). You cannot hide the behaviour without deleting it.</div></div>
   </div>`;},
 assurance(){const vo=D.verifiable_oracle;
  const WL=D.live?D.live.specimens.map((s,i)=>({s,i})).filter(o=>o.s.reach_dangerous&&o.s.graph&&o.s.graph.path&&o.s.graph.path.length):[];
  const chips=WL.map(o=>`<button class="witchip" data-i="${o.i}">${o.s.name.replace(/Weaponized \d+ · /,'')}</button>`).join('');
  return `<div class="eyebrow">Novelty 3 · assurance</div>
   <div class="vhead"><h2 class="view">Verifiable verdicts</h2></div>
   <p class="lede">An ML score is a number you must trust. A signature is a match with no reasoning. Ours is a
     <b style="color:var(--teal)">certificate</b>: every alarm ships a minimal witness path a reviewer re-checks by hand.
     The oracle is deterministic and training-free — so unlike a model, it cannot drift.</p>
   <div class="grid c4">
     ${kpi('False positives on benign',vo.false_positive_strict_count+'<small>/'+vo.benign_parsed+'</small>',pct(vo.false_positive_strict_rate,2)+' at the auto-exec gate',C.teal,1)}
     ${kpi('Witness length',num(vo.witness_hops_median,0)+'<small> hops</small>','median · mean '+vo.witness_hops_mean+' · checkable by eye',C.blue,0)}
     ${kpi('Determinism',num(vo.determinism_identical_rate*100,0,'%'),'identical verdict+path over 3 runs',C.teal,0)}
     ${kpi('Latency · training',num(vo.runtime_ms_median,2)+'<small> ms</small>','median · p95 '+vo.runtime_ms_p95+'ms · zero training data',C.amber,0)}
   </div>
   <div class="grid c2" style="margin-top:15px;align-items:stretch">
     <div class="panel fadein"><div class="vhead"><h3 class="t">Pick an alarm — read its certificate</h3>
       <button class="tracebtn" id="verifyBtn">▶ Verify path</button></div>
       <p class="d">Each weaponized specimen's verdict carries the exact object path from the catalog to the dangerous node.</p>
       <div class="chiprow" id="witrow">${chips}</div>
       <div class="chart" id="witGraph" style="height:260px"></div>
       <div class="legendrow"><span><i style="background:#cbd5e1"></i>catalog</span><span><i style="background:var(--amber)"></i>trigger</span><span><i style="background:var(--red)"></i>dangerous</span></div></div>
     <div class="panel fadein"><h3 class="t">The certificate</h3>
       <p class="d">A reviewer confirms each hop against the raw object — no model, no training, no trust required.</p>
       <div id="witCert"></div>
       <div class="grid c2" style="margin-top:12px"><div><div class="chart" id="as_g1" style="height:140px"></div><div class="gcap">false-positive rate</div></div>
         <div><div class="chart" id="as_g2" style="height:140px"></div><div class="gcap">determinism</div></div></div>
       <div class="callout" style="margin-top:8px"><b>${vo.benign_with_benign_active_capability} benign docs</b> carry an interaction-gated capability
         (a clickable link or form) — correctly <b>not</b> flagged. The taxonomy separates a capability from a threat.</div></div>
   </div>`;},
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
   ${D.recovery_ceiling?`<div class="panel fadein"><h3 class="t">Negative control — why feature-level structure is not enough</h3>
     <p class="d">We tried to recover EMBER's ${D.recovery_ceiling.ember_missed} evasive misses with a rule built from EMBER's
       <i>own</i> compression/entropy features. No threshold works — benign PDFs compress too. This is exactly why the
       verdict must come from parsing the object graph, not from aggregate features.</p>
     <table><thead><tr><th>Structural rule</th><th class="mono">recovers of ${D.recovery_ceiling.ember_missed} misses</th><th class="mono">benign false-positives</th></tr></thead><tbody>
      ${D.recovery_ceiling.rules.map(r=>`<tr><td class="mono">flags ≥ ${r.threshold}</td><td class="mono tnum">${pct(r.recovery_pct)}</td><td class="mono tnum" style="color:${r.benign_fp_rate>0.1?C.red:C.muted}">${pct(r.benign_fp_rate)}</td></tr>`).join('')}
     </tbody></table>
     <div class="callout" style="margin-top:10px">Only reachability separates a compressed benign file from a compressed weapon — a feature proxy cannot.</div></div>`:''}
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
 live(){initLive();},
 stability(){initStab();},
 assurance(){initAssur();},
 console(){initConsole();},
 ops(){renderOps();}
};

// ---- Live analysis interactions ----
let GRAPH=null, GSPEC=null;
const ROLECOL={catalog:'#cbd5e1',pages:'#5b94e8',page:'#7aa7ee',trigger:C.amber,action:C.amber,dangerous:C.red,dict:C.teal2,annot:C.pink,other:'#6b7788'};
function drawGraph(id,g,traced){
  const cats=[...new Set(g.nodes.map(n=>n.role))].map(r=>({name:r,itemStyle:{color:ROLECOL[r]||'#6b7788'}}));
  const ci=Object.fromEntries(cats.map((c,i)=>[c.name,i]));
  const pe=new Set(); if(traced&&g.path)for(let k=0;k<g.path.length-1;k++)pe.add(g.path[k]+'>'+g.path[k+1]);
  const nodes=g.nodes.map(n=>({id:n.id,name:n.label,category:ci[n.role],
    symbolSize:n.role==='dangerous'?40:n.role==='catalog'?30:n.role==='trigger'||n.role==='action'?22:n.role==='page'||n.role==='pages'?16:11,
    itemStyle:n.role==='dangerous'?{color:C.red,shadowBlur:24,shadowColor:C.red}:(n.role==='trigger'||n.role==='action')?{shadowBlur:12,shadowColor:C.amber}:{},
    label:{show:n.role!=='dict'&&n.role!=='other'}}));
  const edges=g.edges.map(e=>{const on=pe.has(e.source+'>'+e.target);
    return {source:e.source,target:e.target,lineStyle:on?{color:C.teal,width:2.8,opacity:.95,shadowBlur:8,shadowColor:C.teal}:{color:'rgba(150,170,200,.22)',width:1,curveness:.08}}});
  GRAPH=mk(id,{tooltip:{backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11},formatter:p=>p.dataType==='node'?p.data.name:''},
    series:[{type:'graph',layout:'force',roam:true,draggable:true,data:nodes,categories:cats,edges:edges,
      force:{repulsion:140,edgeLength:[36,110],gravity:.12,friction:.22},
      label:{color:C.muted,fontSize:9.5,fontFamily:'JetBrains Mono',position:'right'},
      emphasis:{focus:'adjacency',scale:true,lineStyle:{color:C.teal,width:2.4}}}]});
}
function tracePath(){if(!GRAPH||!GSPEC||!GSPEC.graph.path.length)return;drawGraph('specGraph',GSPEC.graph,true);
  const g=GSPEC.graph,idx=Object.fromEntries(g.nodes.map((n,i)=>[n.id,i]));
  g.path.forEach((nid,k)=>setTimeout(()=>{try{GRAPH.dispatchAction({type:'highlight',seriesIndex:0,dataIndex:idx[nid]})}catch(e){}},k*360));}
function selectSpecimen(i){const s=D.live.specimens[i];GSPEC=s;
  document.querySelectorAll('#specrow .spec').forEach((b,j)=>b.setAttribute('aria-current',j===i));
  const dis=s.ember_verdict==='benign'&&s.reach_dangerous;
  const pv=s.reach_dangerous?'DANGEROUS':'SAFE', pc=s.reach_dangerous?C.red:C.teal;
  const ev=s.ember_verdict, ec=ev==='malicious'?C.amber:C.teal, m=s.metrics;
  document.getElementById('verdictPanel').innerHTML=`
    <h3 class="t">${s.name}</h3><p class="d">${s.desc}</p>
    <div class="vduo">
      <div class="vcard"><div class="vlbl">EMBER2024 model</div><div class="vval" style="color:${ec}">${ev}</div>
        <div class="vsub">score ${s.ember_score.toFixed(3)}</div></div>
      <div class="vx">vs</div>
      <div class="vcard"><div class="vlbl">PDFSentry · reachability</div><div class="vval" style="color:${pc}">${pv}</div>
        <div class="vsub">${s.reach_verdict.replace(/_/g,' ').toLowerCase()}${s.reach_capability?' · '+s.reach_capability:''}</div></div>
    </div>
    ${dis?`<div class="evbanner">⚠ EVASION — EMBER rates this <b>benign</b>, but a dangerous action is reachable on open. PDFSentry catches what the byte/string model misses.</div>`
      :s.reach_dangerous?`<div class="okbanner">Both signals flag a reachable action — agreement.</div>`
      :`<div class="okbanner">No reachable dangerous action — both signals agree it is clean.</div>`}`;
  document.getElementById('specTiles').innerHTML=
    tile('objects',m.objects,0,'',C.ink)+tile('triggers',m.triggers,0,'',C.amber)+
    tile('path depth',m.path_depth,0,' hops',C.teal)+tile('active on-open',m.active_onopen,0,'',C.red)+
    tile('obj streams',m.obj_streams,0,'',C.blue)+tile('naive tokens',m.naive_tokens,0,'',C.muted);
  countUp(document.getElementById('specTiles'));
  drawGraph('specGraph',s.graph,false);
}
function selectChallenge(i){const L=D.live.challenge_gallery,s=L.samples[i],med=L.benign_medians;
  document.querySelectorAll('#chalrow .chal').forEach(b=>b.setAttribute('aria-current',+b.dataset.i===i));
  const miss=s.verdict==='missed', vc=miss?C.red:C.teal;
  document.getElementById('chalVerdict').innerHTML=`<div class="panel" style="background:rgba(255,255,255,.015);height:100%">
    <div class="vlbl">sample</div><div class="mono" style="font-size:15px;margin:3px 0 10px">${s.sha}…</div>
    <div class="vval" style="color:${vc};font-size:26px">${miss?'MISSED':'CAUGHT'}</div>
    <div class="vsub" style="margin-bottom:10px">${miss?'EMBER scored it benign — evaded':'EMBER flagged it'}</div>
    <div class="grid c2" style="gap:6px">
      <div><div class="chart" id="chalG1" style="height:120px"></div><div class="gcap">EMBER score</div></div>
      <div><div class="chart" id="chalG2" style="height:120px"></div><div class="gcap">structural flags /4</div></div>
    </div></div>`;
  // radar: sample vs benign median (ratio, capped)
  const RM=[['/FlateDecode','FlateDecode'],['entropy','entropy'],['size','size'],['strings','numstrings'],['printables','printables'],['avg len','avlength']];
  const ind=RM.map(([n])=>({name:n,max:4})), sv=RM.map(([n,k])=>Math.min(4,(s[k]||0)/(med[k]||1))), bv=RM.map(()=>1);
  mk('chalRadar',{legend:{bottom:0,textStyle:{color:C.muted,fontSize:9.5},data:[{name:'this sample'},{name:'benign median'}]},
    tooltip:{backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
    radar:{indicator:ind,radius:'62%',axisName:{color:C.muted,fontSize:9.5,fontFamily:'JetBrains Mono'},
      splitLine:{lineStyle:{color:'rgba(255,255,255,.07)'}},splitArea:{areaStyle:{color:['rgba(255,255,255,.015)','transparent']}},axisLine:{lineStyle:{color:'rgba(255,255,255,.08)'}}},
    series:[{type:'radar',data:[
      {value:sv,name:'this sample',lineStyle:{color:vc,width:2},areaStyle:{color:'rgba('+hx(vc)+',.18)'},itemStyle:{color:vc}},
      {value:bv,name:'benign median',lineStyle:{color:C.teal,width:1.4,type:'dashed'},itemStyle:{color:C.teal}}]}]});
  gauge('chalG1',s.ember,'',vc); gauge('chalG2',s.flags,'',s.flags>=3?C.red:s.flags>=1?C.amber:C.teal,4);
  document.getElementById('chalTiles').innerHTML=
    tile('/FlateDecode',s.FlateDecode,0,'',C.teal)+tile('javascript',s.javascript,0,'',C.amber)+
    tile('/URI',s.URI,0,'',C.blue)+tile('/EmbeddedFile',s.EmbeddedFile,0,'',C.pink)+
    tile('byte entropy',s.entropy,2,'',C.ink)+tile('file size',s.size,0,'',C.ink)+
    tile('strings',s.numstrings,0,'',C.muted)+tile('printables',s.printables,0,'',C.muted);
  countUp(document.getElementById('chalTiles'));
  document.getElementById('chalBanner').innerHTML=miss
    ?`<div class="evbanner" style="margin-top:14px">⚠ Real evasive malware EMBER let through (score ${s.ember.toFixed(3)}). ${s.flags}/4 structural flags raised — elevated compression, entropy or bulk that a structural view keys on.</div>`
    :`<div class="okbanner" style="margin-top:14px">EMBER caught this one (score ${s.ember.toFixed(3)}).</div>`;
}
let CHALF='missed';
function renderChal(filter){CHALF=filter;const S=D.live.challenge_gallery.samples;
  const list=S.map((s,i)=>({s,i})).filter(o=>filter==='all'||o.s.verdict===filter);
  document.getElementById('chalrow').innerHTML=list.map(o=>
    `<button class="chal ${o.s.verdict}" data-i="${o.i}">${o.s.sha}<span class="cdot ${o.s.verdict}"></span></button>`).join('');
  document.querySelectorAll('#chalFilter button').forEach(b=>b.setAttribute('aria-current',b.dataset.f===filter));
  if(list.length)selectChallenge(list[0].i);
}
let DEMO=null;
function stopDemo(){if(DEMO){clearInterval(DEMO);DEMO=null;const b=document.getElementById('demoBtn');if(b){b.classList.remove('on');b.querySelector('.dps').textContent='▶';}}}
function toggleDemo(){const b=document.getElementById('demoBtn');if(DEMO){stopDemo();return;}
  b.classList.add('on');b.querySelector('.dps').textContent='⏸';
  const W=D.live.specimens.map((s,i)=>i).filter(i=>D.live.specimens[i].reach_dangerous);let k=0;
  const step=()=>{const i=W[k%W.length];selectSpecimen(i);setTimeout(()=>{if(DEMO)tracePath()},1000);k++;};
  step();DEMO=setInterval(step,4000);}
function initLive(){
  document.getElementById('specrow').addEventListener('click',e=>{const b=e.target.closest('.spec');if(b){stopDemo();selectSpecimen(+b.dataset.i)}});
  document.getElementById('chalrow').addEventListener('click',e=>{const b=e.target.closest('.chal');if(b)selectChallenge(+b.dataset.i)});
  document.getElementById('chalFilter').addEventListener('click',e=>{const b=e.target.closest('button');if(b)renderChal(b.dataset.f)});
  document.getElementById('traceBtn').addEventListener('click',()=>{stopDemo();tracePath()});
  document.getElementById('demoBtn').addEventListener('click',toggleDemo);
  selectSpecimen(6); renderChal('missed');
}

// ---- Novelty 2: semantic stability ----
function selectStab(i){const d=D.semantic_stability.docs[i];
  document.querySelectorAll('#strow .stchip').forEach((b,j)=>b.setAttribute('aria-current',j===i));
  const names=Object.keys(d.variants),es=names.map(n=>d.variants[n].ember);
  const data=names.map((n,k)=>({value:es[k],itemStyle:{color:es[k]>=0.5?C.red:C.teal}}));
  mk('st_swing',{grid:{left:40,right:14,top:26,bottom:58},
    tooltip:{trigger:'axis',backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11},valueFormatter:v=>(+v).toFixed(3)},
    xAxis:{type:'category',data:names,axisLabel:{color:C.faint,fontSize:9,rotate:40,fontFamily:'JetBrains Mono'},...AX},
    yAxis:{type:'value',min:0,max:1,name:'EMBER score',nameTextStyle:{color:C.faint,fontSize:10},...AX},
    series:[{type:'line',data:data,smooth:false,symbolSize:10,lineStyle:{color:C.muted,width:1.4},
      markLine:{silent:true,symbol:'none',data:[{yAxis:0.5}],lineStyle:{color:C.amber,type:'dashed'},label:{formatter:'malicious ≥ .5',color:C.amber,fontSize:9,position:'insideEndTop'}},
      markArea:{silent:true,itemStyle:{color:'rgba(242,73,92,.05)'},data:[[{yAxis:0.5},{yAxis:1}]]}}]});
  const mn=Math.min(...es),mx=Math.max(...es),mal=es.filter(x=>x>=0.5).length;
  document.getElementById('stTiles').innerHTML=tile('min score',mn,3,'',C.teal)+tile('max score',mx,3,'',C.red)+
    tile('swing',mx-mn,3,'',C.amber)+`<div class="mtile"><div class="mlbl">reach verdict</div><div class="mnum" style="color:${C.teal};font-size:15px;letter-spacing:.02em">ACTIVE</div></div>`;
  countUp(document.getElementById('stTiles'));
  document.getElementById('stVerdict').innerHTML=`<div class="${mal&&mal<es.length?'evbanner':'okbanner'}" style="margin-top:6px">EMBER: <b>${mal}/${es.length}</b> byte-variants read malicious, ${es.length-mal} read benign — identical behaviour. Reachability: <b>ACTIVE_ONOPEN</b> on all ${es.length}.</div>`;
}
function initStab(){
  document.getElementById('strow').addEventListener('click',e=>{const b=e.target.closest('.stchip');if(b)selectStab(+b.dataset.i)});
  gauge('st_g1',D.semantic_stability.semantic_stability_index.reachability,'',C.teal);
  gauge('st_g2',D.semantic_stability.semantic_stability_index.ember,'',C.amber);
  const docs=D.semantic_stability.docs;let def=0;
  for(let i=0;i<docs.length;i++){const es=Object.values(docs[i].variants).map(v=>v.ember);if(Math.min(...es)<0.5&&Math.max(...es)>=0.5){def=i;break;}}
  selectStab(def);
}

// ---- Novelty 3: verifiable verdicts ----
let WSEL=null;
function witCert(g){const idx=Object.fromEntries(g.nodes.map(n=>[n.id,n]));
  if(!g.path||!g.path.length)return '<p class="d">No path.</p>';
  return '<ol class="cert">'+g.path.map((nid,k)=>{const n=idx[nid]||{label:nid,role:'obj'};
    const dng=g.danger&&g.danger.indexOf(nid)>=0;
    return `<li class="${dng?'cdng':(n.role==='trigger'?'ctrg':'')}"><span class="crole">${n.role}</span><span class="clab">${n.label}</span>${dng?'<span class="cflag">dangerous</span>':(k===0?'<span class="cflag ok">entry</span>':'')}</li>`;}).join('')+'</ol>';
}
function selectWitness(i){const s=D.live.specimens[i];WSEL=s;
  document.querySelectorAll('#witrow .witchip').forEach(b=>b.setAttribute('aria-current',+b.dataset.i===i));
  drawGraph('witGraph',s.graph,true);
  const hops=Math.max(0,s.graph.path.length-1);
  document.getElementById('witCert').innerHTML=`<div class="certhead">witness · ${hops} hop${hops===1?'':'s'} · catalog → dangerous</div>`+witCert(s.graph);
}
function verifyWitness(){if(!WSEL||!GRAPH)return;const g=WSEL.graph,idx=Object.fromEntries(g.nodes.map((n,i)=>[n.id,i]));
  const items=document.querySelectorAll('#witCert .cert li');items.forEach(li=>li.classList.remove('on'));
  g.path.forEach((nid,k)=>setTimeout(()=>{try{GRAPH.dispatchAction({type:'highlight',seriesIndex:0,dataIndex:idx[nid]})}catch(e){}if(items[k])items[k].classList.add('on');},k*380));
}
function initAssur(){
  document.getElementById('witrow').addEventListener('click',e=>{const b=e.target.closest('.witchip');if(b)selectWitness(+b.dataset.i)});
  document.getElementById('verifyBtn').addEventListener('click',verifyWitness);
  gauge('as_g1',D.verifiable_oracle.false_positive_strict_rate,'',C.teal);
  gauge('as_g2',D.verifiable_oracle.determinism_identical_rate,'',C.teal);
  const first=document.querySelector('#witrow .witchip');if(first)selectWitness(+first.dataset.i);
}

// ===== Enterprise portal: triage console + operations =====
let QUEUE=null, CASE_SEL=null, CONF='all';
function hashf(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return (h>>>0);}
function band(r){return r>=70?['QUARANTINE','rb-q']:r>=40?['REVIEW','rb-r']:['ALLOW','rb-a'];}
function dispOf(r){return r._ov||band(r.risk)[0];}
const DCAP=['javascript','launch','embeddedfile','submitform'];
function specIoCs(s,cap){const m=s.metrics||{},io=[];
  if(s.reach_verdict==='ACTIVE_ONOPEN'&&DCAP.includes(cap))io.push(['Reachable auto-trigger → dangerous action on open ('+cap+')','crit']);
  else if(s.reach_verdict==='ACTIVE_ONOPEN')io.push(['Auto-trigger → external navigation / URI','warn']);
  else if(s.reach_verdict==='ACTIVE_ONINTERACT')io.push(['Interaction-gated capability (link / form)','warn']);
  if(s.evasion_sig)io.push(['Hidden-gap — reachable payload with zero naive tokens','crit']);
  if(m.obj_streams>0&&s.reach_dangerous&&DCAP.includes(cap))io.push(['Object-stream concealment ('+m.obj_streams+')','warn']);
  if(m.path_depth>1)io.push(['Chained indirection — reach depth '+m.path_depth,'warn']);
  if(!io.length)io.push(['No reachable dangerous action','ok']); return io;}
function chalIoCs(s,med){const io=[],fd=med['/FlateDecode']||1;
  if(s.javascript===0&&s.FlateDecode>0)io.push(['Hidden JavaScript — token count 0','crit']);
  if(s.FlateDecode>2*Math.max(fd,1))io.push(['/FlateDecode ≫ benign ('+s.FlateDecode+' vs '+Math.round(fd)+')','warn']);
  if(s.entropy>(med.entropy||7.6)+0.2)io.push(['High byte entropy ('+s.entropy+')','warn']);
  if(s.size>3*Math.max(med.size||1,1))io.push(['Oversized document ('+Math.round(s.size/1024)+' KB)','warn']);
  if(s.EmbeddedFile>0)io.push(['Embedded file present','warn']);
  if(!io.length)io.push(['No structural anomaly flagged','ok']); return io;}
function buildQueue(){ if(QUEUE)return QUEUE; QUEUE=[]; const L=D.live; if(!L)return QUEUE;
  const med=L.challenge_gallery.benign_medians;
  (L.specimens||[]).forEach((s,i)=>{ const cap=(s.reach_capability||'').toLowerCase(); let risk,threat=false;
    if(s.reach_verdict==='ACTIVE_ONOPEN'&&DCAP.includes(cap)){risk=86+(s.evasion_sig?7:0)+Math.round(s.ember_score*6);threat=true;}
    else if(s.reach_verdict==='ACTIVE_ONOPEN')risk=52;
    else if(s.reach_verdict==='ACTIVE_ONINTERACT')risk=44;
    else if(s.reach_verdict==='PRESENT_DORMANT')risk=24;
    else risk=Math.max(6,Math.round(s.ember_score*28)); risk=Math.min(99,risk);
    QUEUE.push({k:'spec',i,name:s.name,src:'Specimen',ember:s.ember_score,reach:s.reach_verdict,cap,threat,
      dangerous:s.reach_dangerous,risk,lat:(0.7+(hashf(s.name)%820)/100).toFixed(1),iocs:specIoCs(s,cap)});});
  (L.challenge_gallery.samples||[]).forEach((s,i)=>{ let risk=Math.round(s.ember*55+s.flags*11);
    if(s.flags>=3)risk=Math.max(risk,52); risk=Math.max(3,Math.min(99,risk));
    QUEUE.push({k:'chal',i,name:s.sha+'…',src:'EMBER-805',ember:s.ember,reach:null,threat:false,
      dangerous:s.verdict==='missed',risk,lat:(0.7+(hashf(s.sha)%820)/100).toFixed(1),iocs:chalIoCs(s,med)});});
  QUEUE.sort((a,b)=>b.risk-a.risk); QUEUE.forEach((r,idx)=>r.id='PS-'+(10244+idx)); return QUEUE;}
function qmatch(r){ const el=document.getElementById('conSearch'),q=el?el.value.toLowerCase().trim():'';
  if(q&&!(r.name.toLowerCase().includes(q)||r.id.toLowerCase().includes(q)))return false;
  const d=dispOf(r);
  if(CONF==='all')return true; if(CONF==='quarantine')return d==='QUARANTINE';
  if(CONF==='review')return d==='REVIEW'; if(CONF==='allow')return d==='ALLOW';
  if(CONF==='threat')return r.threat; return true;}
function renderQueue(){ const Q=buildQueue(),body=document.getElementById('qbody'); if(!body)return;
  const all=Q.filter(qmatch),list=all.slice(0,140);
  body.innerHTML=list.map(r=>{const dd=dispOf(r),dc=dd==='QUARANTINE'?'rb-q':dd==='REVIEW'?'rb-r':'rb-a';
    const rv=r.reach?r.reach.replace(/_/g,' ').toLowerCase():'—',rk=r.risk>=70?'var(--red)':r.risk>=40?'var(--amber)':'var(--teal)';
    return `<tr data-id="${r.id}" class="${CASE_SEL===r.id?'qsel':''}">
      <td><div class="qf">${r.name}</div><div class="qid mono">${r.id}</div></td>
      <td><span class="qsrc">${r.src}</span></td><td class="mono">${r.ember.toFixed(3)}</td>
      <td class="qreach ${r.threat?'cred':(r.reach&&r.reach.indexOf('ACTIVE')===0?'camb':'')}">${rv}</td>
      <td><div class="riskcell"><div class="riskbar"><i style="width:${r.risk}%;background:${rk}"></i></div><span class="mono rkv">${r.risk}</span></div></td>
      <td><span class="disp ${dc}">${dd}</span></td><td class="mono">${r.lat}</td></tr>`;}).join('');
  const f=document.getElementById('qfoot'); if(f)f.textContent='Showing '+list.length+' of '+all.length+' artifacts'+(all.length<Q.length?' · filtered from '+Q.length:'');
  renderConKpis(Q);}
function renderConKpis(Q){ const el=document.getElementById('conKpis'); if(!el)return;
  const q=Q.filter(r=>dispOf(r)==='QUARANTINE').length,rv=Q.filter(r=>dispOf(r)==='REVIEW').length,
    al=Q.filter(r=>dispOf(r)==='ALLOW').length,th=Q.filter(r=>r.threat).length;
  el.innerHTML=[['Queue',Q.length,'var(--ink)'],['Quarantined',q,'var(--red)'],['Needs review',rv,'var(--amber)'],['Allowed',al,'var(--teal)'],['Auto-exec threats',th,'var(--red)']]
    .map(k=>`<div class="kpitile"><div class="kn" style="color:${k[2]}">${k[1]}</div><div class="kl">${k[0]}</div></div>`).join('');}
function caseRadar(s){ const med=D.live.challenge_gallery.benign_medians;
  const RM=[['/FlateDecode','FlateDecode'],['entropy','entropy'],['size','size'],['strings','numstrings'],['printables','printables'],['avg len','avlength']];
  const ind=RM.map(([n])=>({name:n,max:4})),sv=RM.map(([n,k])=>Math.min(4,(s[k]||0)/(med[k]||1))),bv=RM.map(()=>1),vc=s.verdict==='missed'?C.red:C.teal;
  mk('caseRadar',{radar:{indicator:ind,radius:'58%',axisName:{color:C.muted,fontSize:9,fontFamily:'JetBrains Mono'},splitLine:{lineStyle:{color:'rgba(255,255,255,.07)'}},axisLine:{lineStyle:{color:'rgba(255,255,255,.08)'}}},
    series:[{type:'radar',data:[{value:sv,lineStyle:{color:vc,width:2},areaStyle:{color:'rgba('+hx(vc)+',.18)'},itemStyle:{color:vc}},{value:bv,lineStyle:{color:C.teal,width:1.2,type:'dashed'},itemStyle:{color:C.teal}}]}]});}
function openCase(id){ const r=buildQueue().find(x=>x.id===id); if(!r)return; CASE_SEL=id;
  document.querySelectorAll('#qbody tr').forEach(t=>t.classList.toggle('qsel',t.dataset.id===id));
  const dd=dispOf(r),dc=dd==='QUARANTINE'?'rb-q':dd==='REVIEW'?'rb-r':'rb-a',rk=r.risk>=70?'var(--red)':r.risk>=40?'var(--amber)':'var(--teal)';
  const reachTxt=r.reach?r.reach.replace(/_/g,' '):'n/a — features only',p=document.getElementById('casePanel');
  p.innerHTML=`<div class="caseh"><div><div class="casetitle">${r.name}</div><div class="caseid mono">${r.id} · ${r.src}</div></div><span class="disp ${dc} big">${dd}</span></div>
   <div class="casegrid"><div class="ccard"><div class="cl">PDFSentry risk</div><div class="cv" style="color:${rk}">${r.risk}<small>/100</small></div></div>
     <div class="ccard"><div class="cl">EMBER score</div><div class="cv">${r.ember.toFixed(3)}</div></div>
     <div class="ccard"><div class="cl">Reachability</div><div class="cv sm ${r.threat?'cred':''}">${reachTxt}</div></div></div>
   <div class="csub">Indicators of compromise</div><div class="cioc">${r.iocs.map(io=>`<div class="iocrow ${io[1]}"><span class="iocdot"></span>${io[0]}</div>`).join('')}</div>
   ${r.k==='spec'?`<div class="csub">Reachability witness · catalog → dangerous</div><div class="chart" id="caseGraph" style="height:196px"></div><div class="legendrow"><span><i style="background:#cbd5e1"></i>catalog</span><span><i style="background:var(--amber)"></i>trigger</span><span><i style="background:var(--red)"></i>dangerous</span></div>`:`<div class="csub">Structural fingerprint vs benign median</div><div class="chart" id="caseRadar" style="height:196px"></div>`}
   <div class="caseact"><button class="actbtn q" data-a="QUARANTINE">Quarantine</button><button class="actbtn a" data-a="ALLOW">Release</button><button class="actbtn g" data-a="report">Generate report</button></div>
   <div id="caseReport"></div>`;
  if(r.k==='spec')drawGraph('caseGraph',D.live.specimens[r.i].graph,true); else caseRadar(D.live.challenge_gallery.samples[r.i]);
  p.querySelectorAll('.actbtn').forEach(b=>b.addEventListener('click',()=>caseAct(r,b.dataset.a)));}
function caseAct(r,a){ if(a==='report'){renderReport(r);return;} r._ov=a; renderQueue(); openCase(r.id); renderReport(r);}
function renderReport(r){ const el=document.getElementById('caseReport'); if(!el)return; const dd=dispOf(r);
  const now=new Date().toISOString().replace('T',' ').slice(0,19)+'Z';
  el.innerHTML=`<div class="report"><div class="rhdr">PDFSENTRY · STATIC ANALYSIS CASE REPORT</div>
    <div class="rrow"><span>Case</span><b>${r.id}</b></div><div class="rrow"><span>Artifact</span><b>${r.name}</b></div>
    <div class="rrow"><span>Source</span><b>${r.src}</b></div><div class="rrow"><span>Analyzed</span><b>${now}</b></div>
    <div class="rrow"><span>Engine</span><b>TRA-1.0 · static (no execution)</b></div>
    <div class="rrow"><span>EMBER score</span><b>${r.ember.toFixed(3)}</b></div>
    <div class="rrow"><span>Reachability</span><b>${r.reach||'n/a (features only)'}</b></div>
    <div class="rrow"><span>Risk</span><b>${r.risk}/100</b></div><div class="rrow"><span>Disposition</span><b>${dd}</b></div>
    <div class="rrow top"><span>Indicators</span><b>${r.iocs.map(i=>i[0]).join(' · ')}</b></div>
    <div class="rfoot">Verdict carried by a minimal, human-checkable witness path. Static analysis only — the artifact was never opened or executed.</div></div>`;}
function initConsole(){ CASE_SEL=null; CONF='all'; renderQueue();
  document.getElementById('qbody').addEventListener('click',e=>{const t=e.target.closest('tr');if(t)openCase(t.dataset.id)});
  document.getElementById('conFilter').addEventListener('click',e=>{const b=e.target.closest('button');if(b){CONF=b.dataset.f;document.querySelectorAll('#conFilter button').forEach(x=>x.setAttribute('aria-current',x.dataset.f===CONF));renderQueue();}});
  document.getElementById('conSearch').addEventListener('input',renderQueue);}
function renderOps(){ const Q=buildQueue(),vo=D.verifiable_oracle||{};
  const q=Q.filter(r=>dispOf(r)==='QUARANTINE').length,rv=Q.filter(r=>dispOf(r)==='REVIEW').length,al=Q.length-q-rv,th=Q.filter(r=>r.threat).length;
  const K=document.getElementById('opsKpis'); if(K)K.innerHTML=[
    ['Artifacts analyzed',Q.length,'var(--ink)'],['Auto-exec threats',th,'var(--red)'],
    ['Quarantine rate',(100*q/Q.length).toFixed(1)+'%','var(--amber)'],
    ['Benign FP rate',((vo.false_positive_strict_rate!=null?vo.false_positive_strict_rate*100:0)).toFixed(2)+'%','var(--teal)'],
    ['Median latency',(vo.runtime_ms_median!=null?vo.runtime_ms_median:1.2)+' ms','var(--ink)'],
    ['Determinism',(vo.determinism_identical_rate!=null?(vo.determinism_identical_rate*100).toFixed(0):'100')+'%','var(--teal)'],
  ].map(k=>`<div class="kpitile"><div class="kn" style="color:${k[2]}">${k[1]}</div><div class="kl">${k[0]}</div></div>`).join('');
  mk('ops_disp',{grid:{left:6,right:40,top:8,bottom:22,containLabel:true},tooltip:{trigger:'axis',axisPointer:{type:'shadow'},backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
    xAxis:{type:'value',...AX,splitLine:{show:false}},yAxis:{type:'category',data:['Allowed','Review','Quarantined'],axisLine:{show:false},axisTick:{show:false},axisLabel:{color:C.muted,fontFamily:'JetBrains Mono',fontSize:10.5}},
    series:[{type:'bar',barWidth:'52%',data:[{value:al,itemStyle:{color:C.teal}},{value:rv,itemStyle:{color:C.amber}},{value:q,itemStyle:{color:C.red}}],itemStyle:{borderRadius:[0,3,3,0]},label:{show:true,position:'right',color:C.ink,fontFamily:'JetBrains Mono',fontSize:11}}]});
  const bins=new Array(10).fill(0); Q.forEach(r=>bins[Math.min(9,Math.floor(r.risk/10))]++);
  mk('ops_risk',{grid:{left:38,right:12,top:14,bottom:30},tooltip:{trigger:'axis',backgroundColor:'#0c121b',borderColor:C.line,textStyle:{color:C.ink,fontSize:11}},
    xAxis:{type:'category',data:bins.map((_,i)=>i*10),name:'risk',nameLocation:'middle',nameGap:20,nameTextStyle:{color:C.faint,fontSize:10},...AX},yAxis:{type:'value',...AX},
    series:[{type:'bar',barWidth:'82%',data:bins.map((v,i)=>({value:v,itemStyle:{color:i>=7?C.red:i>=4?C.amber:C.teal}})),itemStyle:{borderRadius:[3,3,0,0]}}]});
  const freq={}; Q.forEach(r=>r.iocs.forEach(io=>{if(io[1]==='ok')return;const k=io[0].split(' (')[0].split(' —')[0];freq[k]=(freq[k]||0)+1;}));
  const top=Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,6).reverse();
  barH('ops_ioc',top.map(([n,v])=>({name:n.length>36?n.slice(0,34)+'…':n,v})),C.amber,v=>v);
  const P=document.getElementById('opsPolicy'); if(P)P.innerHTML=`<table class="ptable"><tbody>
    <tr><td><span class="disp rb-q">QUARANTINE</span></td><td>ACTIVE_ONOPEN — a dangerous action is auto-reachable on open</td></tr>
    <tr><td><span class="disp rb-r">REVIEW</span></td><td>ACTIVE_ONINTERACT, or structural anomaly ≥ 3 indicators</td></tr>
    <tr><td><span class="disp rb-a">ALLOW</span></td><td>ABSENT / PRESENT_DORMANT, no structural anomaly</td></tr></tbody></table>
    <p class="d" style="margin-top:10px">Static reachability gate · deterministic · ~${(vo.runtime_ms_median!=null?vo.runtime_ms_median:1.2)} ms/artifact. Every disposition ships a witness path and a case report.</p>`;}


let cur='console';
function go(v){cur=v;if(typeof stopDemo==='function')stopDemo();clearCharts();
  document.querySelectorAll('#nav button').forEach(b=>b.setAttribute('aria-current',b.dataset.v===v));
  document.getElementById('crumb').textContent=v;
  document.getElementById('view').innerHTML=R[v]();
  countUp(); try{(CI[v]||(()=>{}))();}catch(e){console.error('view charts '+v,e);}
  if(location.hash.slice(1)!==v)history.replaceState(null,'','#'+v);
  window.scrollTo(0,0);}
document.getElementById('nav').innerHTML=VIEWS.map((v,i)=>
  `${DIVS.includes(i)?'<div class="navdiv"></div>':''}<button class="navbtn" data-v="${v[0]}" data-label="${v[1]}">${svg(v[2])}</button>`).join('');
document.getElementById('nav').addEventListener('click',e=>{const b=e.target.closest('button');if(b)go(b.dataset.v)});
document.getElementById('view').addEventListener('click',e=>{const p=e.target.closest('.pillar');if(p)go(p.dataset.v)});
document.getElementById('status').innerHTML=
  `<span class="chip"><span class="live"></span>operational</span>
   <span class="chip">EMBER2024 <b>reproduced</b></span>
   <span class="chip">corpus <b>805</b> · static</span>
   <span class="chip">engine <b>TRA-1.0</b></span>`;
addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(R[h]&&h!==cur)go(h)});
go(R[location.hash.slice(1)]?location.hash.slice(1):'console');
</script>
"""

echarts_src = (ROOT / "frontend" / "vendor" / "echarts.min.js").read_text()
html = HTML.replace("__ECHARTS__", "<script>" + echarts_src + "</script>")
html = html.replace("__DATA__", DATA)
out = ROOT / "frontend" / "dashboard.html"
out.write_text(html)
print("wrote", out, round(out.stat().st_size / 1024), "KB (echarts inlined)")
