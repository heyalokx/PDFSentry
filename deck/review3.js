const T=require('./theme.js'); const A=T.A, C=T.C;
const p=T.mk(); const CT=p.ChartType;
const R='REVIEW 3 · FINAL';

T.cover(p,{eyebrow:'REVIEW 3 — FINAL DEFENCE', title:'PDFSentry',
  subtitle:'Explainable, Drift-Resilient Static Detection of Malicious PDF Files',
  team:['Alok Singh  23BCI0158','Mrinali Charhate  23BCI0073','Aarya Ashish Nagvekar  23BCI0061'],
  guide:'BCSE321L — Malware Analysis · Vellore Institute of Technology'});

T.bullets(p,{title:'The problem, in one slide',right:R,bullets:[
  ['The gap','EMBER2024, a state-of-the-art PDF detector, drops from PR-AUC 0.9933 (ordinary) to 0.7864 (evasive) on its own challenge set.'],
  ['Why','It reads byte and string statistics — it is blind to structure and auto-execution.'],
  ['Cost','355 of 805 real evasive PDFs slip through — exactly the malware that already beat antivirus.'],
  ['Our idea','Recognition asks “does this look like malware?”  Reachability asks “can an auto-trigger reach a dangerous action?”'],
],lede:'Great benchmark numbers hide a blind spot on the malware that matters most.',
  img:A+'dash_overview.jpg',imgW:5.0,imgY:3.3,caption:'Reproduced in the live dashboard'});

T.imageSlide(p,{title:'Final methodology',right:R,img:A+'arch.png',ratio:0.317,
  caption:'The PDFSentry pipeline — static throughout; the fusion node combines structural reachability with the EMBER score.'});

T.numbered(p,{title:'Three pillars of the result',right:R,items:[
  ['01 · Detection','Reachability over recognition — fusion lifts controlled ROC-AUC 0.649 → 0.998.'],
  ['02 · Robustness','Semantic stability — verdict invariant to lossless obfuscation (SSI 1.000 vs 0.216).'],
  ['03 · Assurance','Verifiable verdicts — 0/285 false positives, 1-hop witnesses, deterministic, training-free.'],
],card:{head:'THE ARC',body:'Not one metric, but a complete argument: it works, it holds under attack, and you can verify it by hand.',h:3.2},fs:15});

T.chartSlide(p,{title:'Pillar 01 · Detection',right:R,
  lede:'On controlled structural evasions, EMBER alone is near-blind; adding reachability makes it near-perfect.',
  type:CT.bar,legend:false,
  data:[{name:'ROC-AUC',labels:['EMBER score alone','EMBER + reachability'],values:[0.649,0.998]}],
  opts:{barDir:'col',chartColors:[C.AMBER,C.TEAL],valAxisMinVal:0,valAxisMaxVal:1,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:12,dataLabelFormatCode:'0.000'},
  stats:[['+0.349','ROC-AUC from the structural signal',C.TEAL],['100%','reachability recall on reachable threats',C.INK],['0','false positives on 285 benign',C.INK]]});

T.chartSlide(p,{title:'Pillar 02 · Robustness',right:R,
  lede:'Same malicious behaviour, eight lossless re-saves. EMBER’s score swings across the scale; reachability never moves.',
  type:CT.bar,legend:false,
  data:[{name:'EMBER score',labels:['baseline','recompress','decompress','objstm+','objstm−','normalize','linearize','encrypt'],
    values:[0.80,0.57,0.02,0.00,0.80,0.07,0.73,0.98]}],
  opts:{barDir:'col',chartColors:['c08a2e','c08a2e','2f8f82','2f8f82','c08a2e','2f8f82','c08a2e','c08a2e'],
    valAxisMinVal:0,valAxisMaxVal:1,showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:9,dataLabelFormatCode:'0.00'},
  stats:[['78.4%','of docs get BOTH EMBER verdicts',C.RED],['1.000','reachability stability index',C.TEAL],['0.216','EMBER stability index',C.AMBER]]});

T.imageSlide(p,{title:'Pillar 03 · Assurance',right:R,img:A+'dash_assurance.jpg',ratio:0.573,notes:[
  ['Certificate','Every alarm ships a minimal witness: catalog → trigger → dangerous node.'],
  ['0 / 285','false positives on the benign corpus (auto-exec gate).'],
  ['Deterministic','identical verdict + path over repeated runs; no training data.'],
  ['Fast','~1.2 ms median per document — gateway-deployable.'],
]});

T.bullets(p,{title:'Malware characteristics',right:R,bullets:[
  ['Auto-execution','A dangerous action (JavaScript, Launch, EmbeddedFile) wired to fire on open via /OpenAction, /AA or /Names.'],
  ['Concealment','The payload hidden inside a compressed object stream — present in behaviour, invisible to a token count.'],
  ['Byte camouflage','Elevated /FlateDecode and entropy make the file read as “just compressed” to a statistical model.'],
  ['Indirection','Action chains (GoTo → Next) reach the payload at depth, defeating shallow pattern checks.'],
],lede:'What evasive PDFs do to survive: automate, conceal, and camouflage as ordinary compression.'});

T.bullets(p,{title:'Indicators of Compromise (IoCs)',right:R,bullets:[
  ['Reachable auto-trigger','/OpenAction | /AA | /Names/JavaScript with a path to /JS, /Launch or /EmbeddedFile → ACTIVE_ONOPEN.'],
  ['Hidden-gap signature','An ACTIVE capability whose naive token count is 0 — a contradiction only concealment produces.'],
  ['Object-stream hiding','JavaScript wrapped in an ObjStm; /FlateDecode count far above the benign median (≈ 12 vs 7).'],
  ['Statistical tells','Byte entropy > 7.9 and file size well above benign, with a JS token count of 0.'],
  ['Deep action chains','GoTo → Next sequences terminating at a dangerous node.'],
],lede:'Structural, checkable indicators — each maps to a reachability feature, not a fragile byte signature.'});

T.tableSlide(p,{title:'Comparison / results',right:R,
  headers:['Property','EMBER2024','Hidost','PDFSentry'],highlightCol:3,
  rows:[
   ['Reads what the file DOES','No (bytes/strings)','Partial (static paths)','Yes (reachability)'],
   ['Explainable verdict','Post-hoc SHAP','No','Witness path'],
   ['Obfuscation-invariant','No — SSI 0.22','Not reported','Yes — SSI 1.00'],
   ['Cost to evade','Free re-save','Low–medium','Must disarm payload'],
   ['Training data needed','Yes','Yes','No (deterministic)'],
  ],note:'Honest scope: the 0.78 EMBER benchmark is NOT improved (no raw evasive files to retrain). The 0.998 is a controlled result that isolates the mechanism.'});

T.bullets(p,{title:'Honest scope & limitations',right:R,bullets:[
  ['Benchmark not beaten','We did NOT raise EMBER’s 0.78 evasive score — retraining needs raw evasive PDFs we could not obtain.'],
  ['Controlled mechanism','The 0.998 fusion is on controlled weaponized twins; it isolates the signal, it is not a benchmark claim.'],
  ['Capability ≠ intent','Reachability flags a reachable dangerous capability; a benign PDF that genuinely auto-runs JS would be flagged too.'],
  ['Static only','No dynamic cross-validation — by design, for safety and reproducibility.'],
],lede:'Stated plainly so the contribution is credible: what is proven, and what is projected.'});

T.bullets(p,{title:'Conclusion & future work',right:R,bullets:[
  ['New idea, built','Reachability over recognition — a static detector that reads what a PDF will do, not just what it contains.'],
  ['Three results','Detection (0.649→0.998 controlled), Robustness (SSI 1.000 vs 0.216), Assurance (0/285 FP, verifiable).'],
  ['Next · raw evasive','Retrain a reachability-augmented model on raw evasive PDFs to test the 0.78 directly.'],
  ['Next · deploy','~1.2 ms/file makes an email / browser gateway pre-filter realistic; extend to Office OOXML.'],
]});

T.closing(p,{eyebrow:'PROJECT DEMONSTRATION',title:'Detection. Robustness. Assurance.',
  lines:['Live dashboard — 11 interactive views, every number traceable.','GitHub — full code, scripts, tests and stored artifacts.','Static throughout — nothing is ever executed.'],
  repo:'github.com/heyalokx/PDFSentry', dash:'published interactive dashboard (link in repo README)', right:R});

p.writeFile({fileName:'PDFSentry_Review3.pptx'}).then(f=>console.log('wrote',f));
