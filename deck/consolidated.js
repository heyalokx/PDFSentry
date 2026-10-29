const T=require('./theme.js'); const A=T.A, C=T.C;
const p=T.mk(); const CT=p.ChartType;
const R1='REVIEW 1 · PROPOSAL', R2='REVIEW 2 · IMPLEMENTATION', R3='REVIEW 3 · FINAL';

// 1 COVER
T.cover(p,{eyebrow:'CONSOLIDATED REVIEW · R1 · R2 · R3', title:'PDFSentry',
  subtitle:'Explainable, Drift-Resilient Static Detection of Malicious PDF Files',
  tagline:'Reachability over recognition — reading what a PDF will do, not just what it contains.',
  team:['Alok Singh  23BCI0158','Mrinali Charhate  23BCI0073','Aarya Ashish Nagvekar  23BCI0061'],
  guide:'BCSE321L — Malware Analysis · Vellore Institute of Technology'});

// 2 AGENDA
T.numbered(p,{title:'What this deck covers',right:'AGENDA',eb:'ROADMAP',items:[
  ['Review 1 — Proposal','The problem, objectives, existing vs proposed system, samples, tools, datasets, methodology and expected outcome.'],
  ['Review 2 — Implementation','Finalised architecture, tools installed, datasets collected, static-analysis results, SHAP diagnosis, findings and blockers.'],
  ['Review 3 — Final','Final results across three pillars — Detection, Robustness, Assurance — malware characteristics, IoCs, comparison and demo.'],
  ['The thesis','A byte/string model sees what a file contains; PDFSentry parses the object graph and asks whether an automatic trigger can reach a dangerous action.'],
],card:{head:'ONE LINE',body:'We reproduce a state-of-the-art PDF detector, prove why it fails on evasive malware, and add a structural reachability signal that is explainable and obfuscation-invariant — without ever executing a file.',h:4.7},fs:15});

/* ============ REVIEW 1 — PROPOSAL ============ */
T.divider(p,{num:'R1',title:'PROPOSAL',right:R1,orn:'star',desc:'The problem we target, our proposed system, and the plan to build and evaluate it.',
  covers:'Title · Domain · Problem · Motivation · Objectives · Existing vs Proposed · Samples · Tools · Datasets · Methodology · Expected outcome'});

T.bullets(p,{title:'Project title & domain',right:R1,eb:'TITLE · DOMAIN',bullets:[
  ['Title','PDFSentry — Explainable, Drift-Resilient Static Detection of Malicious PDF Files.'],
  ['Domain','Static malware analysis · machine-learning security · document-borne threat detection.'],
  ['Why PDF','One of the most common malware delivery vectors — portable, trusted by users, and rich in active-content features (JavaScript, launch actions, embedded files).'],
  ['Positioning','A built and defended research project with a genuinely novel structural idea — not a survey, and not just a benchmark score.'],
],lede:'A static, explainable detector for malicious PDFs, built around a structural idea rather than metrics alone.',
  metrics:[['PDF','a top malware delivery vector',C.INK],['Static','zero execution, zero detonation',C.TEAL],['Novel','reachability over recognition',C.AMBER]]});

T.bullets(p,{title:'Problem statement',right:R1,eb:'PROBLEM',bullets:[
  ['Looks solved','State-of-the-art detectors report near-perfect scores on ordinary PDF malware.'],
  ['Breaks on evasion','On evasive malware — files that already slipped past antivirus — EMBER2024 drops from PR-AUC 0.9933 to 0.7841 on its own challenge set.'],
  ['Root cause','These detectors read byte and string statistics; they are structurally blind to a document’s object graph and its auto-execution behaviour.'],
  ['Consequence','355 of 805 real evasive PDFs pass straight through — precisely the malware that reaches an inbox after a gateway.'],
],lede:'Strong benchmark numbers hide a dangerous blind spot on exactly the malware that matters most.',
  metrics:[['0.9933 → 0.7841','PR-AUC: ordinary → evasive',C.AMBER],['355 / 805','real evasive PDFs missed',C.RED],['44%','of evasive malware slips through',C.RED]]});

T.bullets(p,{title:'Motivation',right:R1,eb:'MOTIVATION',bullets:[
  ['Highest-value target','Evasive PDFs are what remain after an AV gateway — detecting them has outsized security value.'],
  ['Explainability','Security analysts need a reason, not just a probability — a verdict they can verify and act on.'],
  ['Drift resilience','Byte statistics shift as attackers re-encode and re-compress; a structural signal should be stable by construction.'],
  ['Behaviour over appearance','The real question is not “does it look malicious?” but “can it act maliciously when opened?”'],
  ['Academic brief','The course rewards a genuinely new idea and real engineering over another high score on a known benchmark.'],
]});

T.numbered(p,{title:'Objectives',right:R1,eb:'OBJECTIVES',items:[
  ['O1 · Reproduce','Re-establish the EMBER2024 PDF benchmark on the authors’ released model, as a verified baseline.'],
  ['O2 · Diagnose','Use SHAP to explain why evasive malware is systematically missed.'],
  ['O3 · Build','A trigger-reachability analyzer over the PDF object graph (engine TRA-1.0).'],
  ['O4 · Fuse','Show that reachability + EMBER recovers structural evasions a byte model cannot.'],
  ['O5 · Harden','Prove obfuscation-invariance — a verdict stable under lossless re-encoding (semantic stability).'],
  ['O6 · Assure','Deliver verifiable, explainable verdicts and an interactive dashboard.'],
],card:{head:'DESIGN PRINCIPLE',body:'Every objective is falsifiable and traced to a stored artifact. We separate what is proven on real data from what is demonstrated in a controlled setting.',h:4.7},fs:14});

T.bullets(p,{title:'Threat model & assumptions',right:R1,eb:'THREAT MODEL',bullets:[
  ['Attacker goal','Deliver a PDF that auto-executes a dangerous action (JavaScript, Launch, EmbeddedFile) on open, while reading as benign to an ML detector.'],
  ['Attacker capability','Full control of file structure — can compress, encrypt, reorder objects and hide payloads in object streams.'],
  ['Defender constraint','Static analysis only — no execution, no sandbox detonation (safety + reproducibility).'],
  ['In scope','Structural auto-execution threats reachable from a trigger; byte-level obfuscation of those threats.'],
  ['Out of scope','Pure social-engineering PDFs with no active content, and exploits in the viewer binary itself.'],
],lede:'A clear boundary for what PDFSentry defends against — and, honestly, what it does not.'});

T.tableSlide(p,{title:'Existing system vs proposed system',right:R1,eb:'EXISTING vs PROPOSED',
  headers:['Property','AV signatures','EMBER2024 (byte ML)','PDFSentry (ours)'],highlightCol:3,
  rows:[
   ['Reads what the file DOES','No','No (bytes/strings)','Yes — reachability'],
   ['Explainable verdict','Match only','Post-hoc SHAP','Minimal witness path'],
   ['Robust to re-encoding','No','No (SSI 0.22)','Yes (SSI 1.00)'],
   ['Needs training data','Signatures','Yes','No (deterministic rule)'],
   ['New / evasive malware','Weak','Weak on evasive','Targets the evasion mechanism'],
  ],lede:'Where current approaches fall short, and what PDFSentry adds on top of them.',
  note:'PDFSentry does not replace EMBER — it supplies the structural evidence a byte/string model structurally lacks.'});

T.bullets(p,{title:'Malware / samples to be analyzed',right:R1,eb:'SAMPLES',bullets:[
  ['EMBER2024 challenge','805 real evasive PDFs that first evaded antivirus — the authors release these as feature vectors.'],
  ['CIC-Evasive-PDFMal2022','10,025 labelled PDFs (UNB) — used for evasion-cost mapping on a count-based feature set.'],
  ['Controlled twins','Benign PDFs carrying a harmless reachable payload (app.alert) across 4 trigger wirings — for mechanism and robustness studies.'],
  ['Safety boundary','Everything is static. No PDF is opened; no JavaScript, launch action or embedded file is ever executed.'],
],lede:'Real evasive malware for evidence; controlled, harmless twins for mechanism — never live execution.',
  metrics:[['805','real evasive PDFs',C.INK],['10,025','CIC labelled PDFs',C.INK],['0','files ever executed',C.TEAL]]});

T.bullets(p,{title:'Tools required & dataset sources',right:R1,eb:'TOOLS · DATASETS',bullets:[
  ['Parsing','pikepdf — static object-graph recovery; the file is parsed, never executed.'],
  ['Detector','LightGBM + thrember (EMBER v3 feature extractor, 2568 dimensions).'],
  ['Explainability','SHAP (TreeExplainer) for per-feature-family attribution of the model’s decisions.'],
  ['Engineering','Python 3.11 · FastAPI service · pytest · a self-contained ECharts dashboard.'],
  ['Datasets','EMBER2024 (FutureComputing4AI, KDD 2025) · CIC-Evasive-PDFMal2022 (University of New Brunswick).'],
]});

T.numbered(p,{title:'Proposed methodology',right:R1,eb:'METHODOLOGY',items:[
  ['Static parse','Open with pikepdf — never executed — and recover the object-reference graph.'],
  ['Trigger surface','Enumerate auto / interaction triggers: /OpenAction, /AA, /Names/JavaScript, action chains.'],
  ['Reachability BFS','Shortest-path search from each trigger to a dangerous capability.'],
  ['Verdict taxonomy','ABSENT · PRESENT_DORMANT · ACTIVE_ONINTERACT · ACTIVE_ONOPEN, each with a minimal witness.'],
  ['Fusion','Combine the 65-D reachability vector with the EMBER score for the final decision.'],
],card:{head:'KEY IDEA',body:'Recognition asks “does this look like malware?”  Reachability asks “can an automatic trigger reach a dangerous action?” — the question that actually defines the threat.',h:4.7},fs:14});

T.stats(p,{title:'Expected outcome',right:R1,eb:'EXPECTED OUTCOME',lede:'What the project set out to deliver, stated as measurable goals.',stats:[
  ['Structural','a detector that reads behaviour, supplying the signal byte-ML lacks',C.TEAL],
  ['Explainable','a verifiable witness path accompanying every verdict',C.INK],
  ['Drift-resilient','stability under obfuscation, measured and not merely asserted',C.AMBER],
  ['Reproducible','every reported number traced to a stored JSON artifact',C.INK],
  ['Honest','a clear line between what is proven and what is projected',C.GRAPH],
  ['Usable','an interactive dashboard for the defence and live demonstration',C.INK],
],big:30});

/* ============ REVIEW 2 — IMPLEMENTATION ============ */
T.divider(p,{num:'R2',title:'IMPLEMENTATION',right:R2,orn:'arcs',ornX:10.2,ornY:1.2,ornW:2.1,
  desc:'What we built, the tools and data in place, and the first measured results.',
  covers:'Finalised methodology · Architecture · Tools installed · Datasets collected · Static & behavioural results · SHAP · Findings · Problems · Status'});

T.imageSlide(p,{title:'Finalized methodology & system architecture',right:R2,eb:'ARCHITECTURE',img:A+'arch.png',ratio:0.317,
  caption:'The PDFSentry pipeline — static throughout; the fusion node combines structural reachability with the EMBER score to produce a typed, witnessed verdict.'});

T.bullets(p,{title:'Tools installed & working',right:R2,eb:'TOOLS INSTALLED',bullets:[
  ['Static parser','pikepdf operational — object-graph recovery + reachability engine (TRA-1.0).'],
  ['Detector','EMBER2024 released PDF model loaded via LightGBM; thrember built from source (not on PyPI).'],
  ['Explainability','SHAP TreeExplainer over the full 2568-D EMBER vector, grouped by feature family.'],
  ['Backend & tests','FastAPI service; 23 pytest cases passing across parsing, reachability and fusion.'],
  ['Dashboard','Self-contained ECharts dashboard (library inlined) — 11 interactive views.'],
],lede:'The full stack is built, tested and reproducible — not slideware.',
  metrics:[['23','pytest cases passing',C.TEAL],['2568-D','EMBER feature vector',C.INK],['11','interactive dashboard views',C.INK]]});

T.bullets(p,{title:'Datasets & malware samples collected',right:R2,eb:'DATA COLLECTED',bullets:[
  ['EMBER2024','Authors’ PDF model + ordinary test set + the 805 evasive challenge PDFs (released as features).'],
  ['Benign corpus','35 real PDF fixtures + 250 generated benign documents (links, forms, bookmarks) for false-positive testing.'],
  ['Weaponized twins','Benign bases × 4 trigger wirings × 8 lossless transforms, each carrying a harmless payload.'],
  ['Provenance','Every sample set is scripted and regenerable; all results fold into stored JSON artifacts.'],
],metrics:[['285','benign documents',C.INK],['4 × 8','wirings × transforms',C.INK],['100%','results traced to artifacts',C.TEAL]]});

T.chartSlide(p,{title:'Static analysis results — reproducing the gap',right:R2,eb:'STATIC RESULTS · O1',
  lede:'Same EMBER model, two regimes. Ordinary malware looks solved; evasive malware collapses precision.',
  type:CT.bar,legend:true,
  data:[{name:'Ordinary',labels:['PR-AUC','ROC-AUC','Recall'],values:[0.9933,0.9913,0.973]},
        {name:'Evasive',labels:['PR-AUC','ROC-AUC','Recall'],values:[0.7864,0.9075,0.559]}],
  opts:{barDir:'col',chartColors:[C.TEAL,C.AMBER],valAxisMinVal:0,valAxisMaxVal:1,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:9,dataLabelFormatCode:'0.00'},
  stats:[['0.7864','evasive PR-AUC (reproduced)',C.AMBER],['355/805','real evasive PDFs missed',C.RED],['0.9933','ordinary PR-AUC',C.TEAL]]});

T.chartSlide(p,{title:'SHAP diagnosis — the structural void',right:R2,eb:'SHAP · O2',
  lede:'Where the EMBER model spends its attention on the evasive malware it misses (mean |SHAP| by feature family).',
  type:CT.bar,legend:false,
  data:[{name:'attention',labels:['strings','byte histogram','byte entropy','structure'],values:[60,29,9,0.4]}],
  opts:{barDir:'col',chartColors:['6b7178','6b7178','6b7178','b4473f'],valAxisMinVal:0,valAxisMaxVal:70,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:11,dataLabelFormatCode:'0"%"'},
  stats:[['~0%','attention on structure',C.RED],['~60%','on string statistics',C.GRAPH],['≈','missed looks like caught',C.AMBER]],big:38});

T.bullets(p,{title:'Behavioural reasoning — without execution',right:R2,eb:'BEHAVIOUR (STATIC)',bullets:[
  ['By design, static','No sandbox, no detonation — PDFs are never opened. This removes all execution risk and keeps results reproducible.'],
  ['Reachability as proxy','Instead of dynamic tracing, we statically prove whether an auto-trigger can reach a dangerous action.'],
  ['The void confirmed','SHAP shows the model acts on string/byte statistics and essentially nothing structural — so it cannot separate evasive malware from benign files.'],
  ['Our fill','Reachability supplies exactly that missing structural evidence, as a 65-D feature vector fused with the EMBER score.'],
],lede:'The template’s “dynamic analysis” is answered by static behavioural reachability — safer, and reproducible.',
  img:A+'shot_overview.jpg',imgW:5.0,imgY:3.5,caption:'Reproduction + SHAP in the dashboard'});

T.imageSlide(p,{title:'Screenshots — interactive dashboard',right:R2,eb:'SCREENSHOTS',img:A+'shot_overview.jpg',ratio:0.625,notes:[
  ['Traceable','Every KPI links to a stored JSON artifact — nothing is hand-typed.'],
  ['Three pillars','Detection, Robustness and Assurance, each a clickable view.'],
  ['Live PR curves','Ordinary vs evasive, rendered from the real EMBER model.'],
  ['Self-contained','ECharts inlined — opens offline, shareable as a single file.'],
]});

T.bullets(p,{title:'Important findings',right:R2,eb:'FINDINGS',bullets:[
  ['The collapse is real','EMBER PR-AUC 0.9933 → 0.7864 on evasive malware; 355/805 missed.'],
  ['Misses are structural','Missed malware is measurably more compressed than caught malware — median /FlateDecode 12 vs 7 (p < 10⁻¹⁵), higher entropy, larger size.'],
  ['Reachability recovers it','On controlled structural evasions, EMBER + reachability fusion lifts ROC-AUC from 0.649 to 0.998.'],
  ['Confound-free','The real-malware evidence uses EMBER’s own released features — no new tooling, no execution, no circular labels.'],
],metrics:[['p < 10⁻¹⁵','compression gap on real misses',C.TEAL],['12 vs 7','/FlateDecode: missed vs caught',C.INK],['0.649 → 0.998','fusion ROC-AUC (controlled)',C.AMBER]]});

T.bullets(p,{title:'Problems encountered',right:R2,eb:'PROBLEMS',bullets:[
  ['Raw malware unobtainable','EMBER releases the 805 challenge as features only; CIC raw PDFs triggered AV quarantine and download limits.'],
  ['Our workaround','Used EMBER’s released features for confound-free real-malware evidence, and controlled twins for the mechanism.'],
  ['Tooling friction','thrember is not on PyPI (built from source); a signify import bug was stubbed around.'],
  ['Safety boundary','No safe way to execute live malware — so the whole pipeline stays static, which became a design strength.'],
]});

T.numbered(p,{title:'Work completed vs remaining (at Review 2)',right:R2,eb:'STATUS',items:[
  ['Completed','EMBER reproduction, SHAP diagnosis, reachability engine + 65-D features, fusion study, dashboard v1.'],
  ['Remaining · robustness','Quantify obfuscation-invariance (semantic stability).'],
  ['Remaining · assurance','Verifiable verdicts: witnesses, false-positive and determinism measurement.'],
  ['Remaining · rigour','Negative controls and honest-scope framing.'],
  ['Remaining · delivery','Final packaging, dashboard polish and write-up.'],
],card:{head:'STATUS → R3',body:'Every “remaining” item was completed for Review 3. The two new pillars — Robustness and Assurance — and the negative controls are the headline additions.',h:4.7},fs:14});

/* ============ REVIEW 3 — FINAL ============ */
T.divider(p,{num:'R3',title:'FINAL',right:R3,orn:'globe',ornX:9.9,ornY:1.0,ornW:2.6,
  desc:'The complete system and its results across three pillars — Detection, Robustness, Assurance.',
  covers:'Final methodology · Taxonomy · Implementation · Three pillars · Characteristics · IoCs · Detection results · Comparison · Limits · Conclusion · Demo'});

T.numbered(p,{title:'Final methodology',right:R3,eb:'FINAL METHODOLOGY',items:[
  ['Static parse','pikepdf recovers the object-reference graph; the file is never executed.'],
  ['Trigger surface','Enumerate every auto / interaction trigger across the known PDF execution vectors.'],
  ['Reachability BFS','Shortest-path search from trigger to dangerous capability; record the minimal witness.'],
  ['65-D reach vector','Encode verdicts, hop counts, concealment signatures and trigger classes as features.'],
  ['Fusion + verdict','Combine with the EMBER score; emit a typed verdict with a human-checkable path.'],
],card:{head:'UNCHANGED, PROVEN',body:'The methodology promised at Review 1 is the one that shipped — now measured for accuracy, robustness and assurance.',h:4.7},fs:14});

T.numbered(p,{title:'Reachability verdict taxonomy',right:R3,eb:'TAXONOMY',items:[
  ['ABSENT','No dangerous capability present in the document at all.'],
  ['PRESENT_DORMANT','A dangerous capability exists but no trigger can reach it — inert.'],
  ['ACTIVE_ONINTERACT','Reachable only on user interaction (e.g. a clickable link) — a capability, not an auto-threat.'],
  ['ACTIVE_ONOPEN','A dangerous action auto-fires on open — the threat class PDFSentry is built to catch.'],
],card:{head:'CAPABILITY ≠ INTENT',body:'The four-state taxonomy is what lets PDFSentry separate a benign clickable link from a weaponised auto-run payload — and report exactly which it found.',h:4.7},fs:15});

T.stats(p,{title:'Complete implementation',right:R3,eb:'IMPLEMENTATION',lede:'A built system, end to end — reproducible, tested and deployable.',stats:[
  ['TRA-1.0','trigger-reachability engine (static, deterministic)',C.TEAL],
  ['65-D','reachability feature vector fused with EMBER',C.INK],
  ['23','pytest cases passing (parse · reach · fusion)',C.INK],
  ['11 views','interactive ECharts dashboard, self-contained',C.AMBER],
  ['285','benign documents for false-positive testing',C.INK],
  ['704','obfuscation variants in the stability study',C.INK],
],big:34});

T.numbered(p,{title:'Three pillars of the final result',right:R3,eb:'RESULTS OVERVIEW',items:[
  ['01 · Detection','Reachability over recognition — fusion lifts controlled ROC-AUC 0.649 → 0.998.'],
  ['02 · Robustness','Semantic stability — verdict invariant to lossless obfuscation (SSI 1.000 vs 0.216).'],
  ['03 · Assurance','Verifiable verdicts — 0/285 false positives, 1-hop witnesses, deterministic, training-free.'],
],card:{head:'THE ARC',body:'Not one metric, but a complete argument: it works, it holds under attack, and you can verify it by hand.',h:3.3},fs:15});

T.chartSlide(p,{title:'Pillar 01 · Detection results',right:R3,eb:'DETECTION',
  lede:'On controlled structural evasions, EMBER alone is near-blind; adding the reachability signal makes it near-perfect.',
  type:CT.bar,legend:false,
  data:[{name:'ROC-AUC',labels:['EMBER score alone','EMBER + reachability'],values:[0.649,0.998]}],
  opts:{barDir:'col',chartColors:[C.AMBER,C.TEAL],valAxisMinVal:0,valAxisMaxVal:1,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:12,dataLabelFormatCode:'0.000'},
  stats:[['+0.349','ROC-AUC from the structural signal',C.TEAL],['100%','reachability recall on reachable threats',C.INK],['0','false positives on 285 benign',C.INK]]});

T.chartSlide(p,{title:'Pillar 02 · Robustness — semantic stability',right:R3,eb:'ROBUSTNESS',
  lede:'Same malicious behaviour, eight lossless re-saves. EMBER’s score swings across the scale; reachability never moves.',
  type:CT.bar,legend:false,
  data:[{name:'EMBER score',labels:['baseline','recompress','decompress','objstm+','objstm−','normalize','linearize','encrypt'],
    values:[0.80,0.57,0.02,0.00,0.80,0.07,0.73,0.98]}],
  opts:{barDir:'col',chartColors:['c08a2e','c08a2e','2f8f82','2f8f82','c08a2e','2f8f82','c08a2e','c08a2e'],
    valAxisMinVal:0,valAxisMaxVal:1,showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:9,dataLabelFormatCode:'0.00'},
  stats:[['78.4%','of docs get BOTH EMBER verdicts',C.RED],['1.000','reachability stability index',C.TEAL],['0.216','EMBER stability index',C.AMBER]]});

T.imageSlide(p,{title:'Pillar 03 · Assurance — verifiable verdicts',right:R3,eb:'ASSURANCE',img:A+'shot_assurance.jpg',ratio:0.625,notes:[
  ['Certificate','Each alarm ships a minimal witness: catalog → trigger → dangerous node.'],
  ['0 / 285','false positives on the benign corpus (auto-exec gate).'],
  ['Deterministic','identical verdict + path over repeated runs; no training data.'],
  ['Fast','~1.2 ms median per document — gateway-deployable.'],
]});

T.bullets(p,{title:'Malware characteristics',right:R3,eb:'CHARACTERISTICS',bullets:[
  ['Auto-execution','A dangerous action (JavaScript, Launch, EmbeddedFile) wired to fire on open via /OpenAction, /AA or /Names.'],
  ['Concealment','The payload hidden inside a compressed object stream — present in behaviour, invisible to a token count.'],
  ['Byte camouflage','Elevated /FlateDecode and entropy make the file read as “just compressed” to a statistical model.'],
  ['Indirection','Action chains (GoTo → Next) reach the payload at depth, defeating shallow pattern checks.'],
],lede:'What evasive PDFs do to survive: automate, conceal, and camouflage as ordinary compression.',
  metrics:[['entropy > 7.9','byte camouflage',C.INK],['naive = 0','hidden auto-run payload',C.RED],['depth','chained indirection',C.INK]]});

T.bullets(p,{title:'Indicators of Compromise (IoCs)',right:R3,eb:'IOCs',bullets:[
  ['Reachable auto-trigger','/OpenAction | /AA | /Names/JavaScript with a path to /JS, /Launch or /EmbeddedFile → ACTIVE_ONOPEN.'],
  ['Hidden-gap signature','An ACTIVE capability whose naive token count is 0 — a contradiction only concealment produces.'],
  ['Object-stream hiding','JavaScript wrapped in an ObjStm; /FlateDecode count far above the benign median (≈ 12 vs 7).'],
  ['Statistical tells','Byte entropy > 7.9 and file size well above benign, with a JS token count of 0.'],
  ['Deep action chains','GoTo → Next sequences terminating at a dangerous node.'],
],lede:'Structural, checkable indicators — each maps to a reachability feature, not a fragile byte signature.'});

T.tableSlide(p,{title:'Comparison / results',right:R3,eb:'COMPARISON',
  headers:['Property','EMBER2024','Hidost','PDFSentry'],highlightCol:3,
  rows:[
   ['Reads what the file DOES','No (bytes/strings)','Partial (static paths)','Yes (reachability)'],
   ['Explainable verdict','Post-hoc SHAP','No','Witness path'],
   ['Obfuscation-invariant','No — SSI 0.22','Not reported','Yes — SSI 1.00'],
   ['Cost to evade','Free re-save','Low–medium','Must disarm payload'],
   ['Training data needed','Yes','Yes','No (deterministic)'],
  ],lede:'PDFSentry against the byte-ML baseline and a classic structural-path detector.',
  note:'Honest scope: the 0.78 EMBER benchmark is NOT improved (no raw evasive files to retrain). The 0.998 is a controlled result that isolates the mechanism.'});

/* ============ THE PORTAL — enterprise showcase (dark) ============ */
T.darkDivider(p,{eb:'ENTERPRISE · SECURITY OPERATIONS',title:'The Command Center',right:'LIVE PORTAL',
  desc:'The research shipped as a working PDF-security portal — ingest, risk-score, triage, and prove every verdict.'});

T.heroShot(p,{eb:'TRIAGE CONSOLE',title:'Every PDF, parsed and risk-scored',right:'LIVE PORTAL',img:A+'shot_console.jpg',
  caption:'826 artifacts triaged — an auto-exec threat open, with its indicators and the reachability witness that justifies quarantine.'});

T.gallery2(p,{eb:'OPERATIONS',title:'Fleet posture at a glance',right:'LIVE PORTAL',shots:[
  {img:A+'shot_ops.jpg',cap:'Operations — 0.00% false positives · 1.17 ms · 100% deterministic'},
  {img:A+'shot_evasion.jpg',cap:'Structural evasion — fusion lifts 0.649 → 0.998'}]});

T.heroShot(p,{eb:'LIVE ANALYSIS',title:'The attack path, traced live',right:'LIVE PORTAL',img:A+'shot_live.jpg',
  caption:'EMBER says benign; PDFSentry says dangerous — and the object graph lights the catalog → trigger → JavaScript path.'});

T.gallery2(p,{eb:'EVIDENCE',title:'The science behind the verdict',right:'LIVE PORTAL',shots:[
  {img:A+'shot_realmal.jpg',cap:'Real evasive malware — the compression signature (p < 10⁻¹⁵)'},
  {img:A+'shot_stability.jpg',cap:'Semantic stability — SSI 1.000 vs EMBER 0.216'}]});

T.bullets(p,{title:'Honest scope & limitations',right:R3,eb:'LIMITATIONS',bullets:[
  ['Benchmark not beaten','We did NOT raise EMBER’s 0.78 evasive score — retraining needs raw evasive PDFs we could not obtain.'],
  ['Controlled mechanism','The 0.998 fusion is on controlled weaponized twins; it isolates the signal, it is not a benchmark claim.'],
  ['Capability ≠ intent','Reachability flags a reachable dangerous capability; a benign PDF that genuinely auto-runs JS would be flagged too.'],
  ['Static only','No dynamic cross-validation — by design, for safety and reproducibility.'],
],lede:'Stated plainly so the contribution is credible: what is proven, and what is projected.'});

T.bullets(p,{title:'Conclusion',right:R3,eb:'CONCLUSION',bullets:[
  ['New idea, built','Reachability over recognition — a structural, static detector that reads what a PDF will do.'],
  ['Three results','Detection (0.649→0.998 controlled), Robustness (SSI 1.000 vs 0.216), Assurance (0/285 FP, verifiable).'],
  ['Explains the gap','Byte-ML spends ~0% on structure; evasive misses are measurably more compressed (p < 10⁻¹⁵).'],
  ['Honest & reproducible','Every number traces to an artifact; scope is stated without overclaim.'],
],metrics:[['0.998','detection (controlled ROC-AUC)',C.TEAL],['1.000','robustness (stability index)',C.TEAL],['0 / 285','assurance (false positives)',C.TEAL]]});

T.bullets(p,{title:'Future enhancement',right:R3,eb:'FUTURE WORK',bullets:[
  ['Train on raw evasive','Obtain raw evasive PDFs to retrain a reachability-augmented model and test the 0.78 benchmark directly.'],
  ['Dynamic cross-check','Sandbox a sample to validate reachability verdicts against observed behaviour.'],
  ['Gateway deployment','~1.2 ms/file makes an email / browser gateway pre-filter realistic.'],
  ['Beyond PDF','Extend the reachability abstraction to Office OOXML and other active-content formats.'],
]});

T.closingDark(p,{eyebrow:'THANK YOU',title:'Detection. Robustness.\nAssurance.',
  lines:['Reachability over recognition — reading what a PDF will do, not what it looks like.','A working portal, 23 tests, and every number traced to an artifact.','Honest by design — static throughout, nothing ever executed.'],
  repo:'github.com/heyalokx/PDFSentry', dash:'self-contained interactive dashboard (link in repo README)', right:'PDFSENTRY · R3'});

p.writeFile({fileName:'PDFSentry_Consolidated_R1-R2-R3.pptx'}).then(f=>console.log('wrote',f));
