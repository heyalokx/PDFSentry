const T=require('./theme.js'); const A=T.A, C=T.C;
const p=T.mk();
const CT=p.ChartType;
const RIGHT={r1:'REVIEW 1 · PROPOSAL', r2:'REVIEW 2 · IMPLEMENTATION', r3:'REVIEW 3 · FINAL'};

// 1 COVER
T.cover(p,{eyebrow:'CONSOLIDATED REVIEW · R1 · R2 · R3', title:'PDFSentry',
  subtitle:'Explainable, Drift-Resilient Static Detection of Malicious PDF Files',
  team:['Alok Singh  23BCI0158','Mrinali Charhate  23BCI0073','Aarya Ashish Nagvekar  23BCI0061'],
  guide:'BCSE321L — Malware Analysis · Vellore Institute of Technology'});

// 2 AGENDA
T.numbered(p,{title:'What this deck covers',right:'AGENDA',items:[
  ['Review 1 — Proposal','Problem, objectives, proposed system, methodology, datasets and expected outcome.'],
  ['Review 2 — Implementation','Architecture, tools, datasets collected, static analysis results, findings and blockers.'],
  ['Review 3 — Final','Final results across three pillars — Detection, Robustness, Assurance — IoCs, comparison and demo.'],
  ['The thesis','A byte/string model sees what a file contains; PDFSentry sees what it will do when opened.'],
],card:{head:'ONE LINE',body:'We reproduce a state-of-the-art PDF detector, prove why it fails on evasive malware, and add a structural reachability signal that is explainable and obfuscation-invariant.',h:4.5,orn:'arcs'},fs:15});

/* ============ REVIEW 1 — PROPOSAL ============ */
T.divider(p,{num:'R1',title:'PROPOSAL',right:RIGHT.r1,orn:'star',desc:'Problem, objectives, proposed system, datasets, methodology and expected outcome.'});

T.bullets(p,{title:'Project title & domain',right:RIGHT.r1,bullets:[
  ['Title','PDFSentry — Explainable, Drift-Resilient Static Detection of Malicious PDF Files.'],
  ['Domain','Static malware analysis · machine-learning security · document-borne threats.'],
  ['Course','BCSE321L Malware Analysis — a built, defended research project, not a survey.'],
  ['Focus','PDF: one of the most common malware delivery vectors in phishing and targeted attacks.'],
],lede:'A static, explainable detector for malicious PDFs — built around a structural idea, not just metrics.',
  img:A+'orn_globe.png',imgW:3.4,imgY:3.1});

T.bullets(p,{title:'Problem statement',right:RIGHT.r1,bullets:[
  ['The gap','Modern ML detectors look solved on ordinary malware but collapse on evasive malware — files that already slipped past antivirus.'],
  ['Measured','EMBER2024, a state-of-the-art PDF detector, drops from PR-AUC 0.9933 (ordinary) to 0.7841 (evasive) on its own challenge set.'],
  ['Why','These detectors read byte and string statistics; they are blind to a document’s structure and auto-execution behaviour.'],
  ['Consequence','355 of 805 real evasive PDFs slip straight through — the ones that matter most.'],
],lede:'Good benchmark numbers hide a dangerous blind spot on exactly the malware that evades defences.'});

T.bullets(p,{title:'Motivation',right:RIGHT.r1,bullets:[
  ['Real risk','Evasive PDFs are what reach inboxes after passing an AV gateway — detecting them has outsized value.'],
  ['Explainability','Analysts need a reason, not just a score — a verdict they can verify and act on.'],
  ['Drift','Byte-statistics drift as attackers re-encode; a structural signal should be stable by construction.'],
  ['Novelty over metrics','The brief rewards a genuinely new idea and real engineering, not another high score on a known benchmark.'],
]});

T.numbered(p,{title:'Objectives',right:RIGHT.r1,items:[
  ['O1 · Reproduce','Re-establish the EMBER2024 PDF benchmark on the authors’ released model.'],
  ['O2 · Diagnose','Use SHAP to show why evasive malware is missed.'],
  ['O3 · Build','A trigger-reachability analyzer over the PDF object graph.'],
  ['O4 · Fuse','Show reachability + EMBER recovers structural evasions.'],
  ['O5 · Harden','Prove obfuscation-invariance (semantic stability).'],
  ['O6 · Assure','Deliver verifiable, explainable verdicts + an interactive dashboard.'],
],fs:14});

T.tableSlide(p,{title:'Existing system vs proposed system',right:RIGHT.r1,
  headers:['Property','AV signatures','EMBER2024 (byte ML)','PDFSentry (ours)'],highlightCol:3,
  rows:[
   ['Reads what the file DOES','No','No (bytes/strings)','Yes — reachability'],
   ['Explainable verdict','Match only','Post-hoc SHAP','Witness path'],
   ['Robust to re-encoding','No','No','Yes (by design)'],
   ['Needs training data','Signatures','Yes','No (deterministic rule)'],
  ],note:'PDFSentry does not replace EMBER — it supplies the structural evidence EMBER structurally lacks.'});

T.bullets(p,{title:'Malware / samples to be analyzed',right:RIGHT.r1,bullets:[
  ['EMBER2024 challenge','805 real evasive PDFs that first evaded antivirus (released as features).'],
  ['CIC-Evasive-PDFMal2022','10,025 labelled PDFs — used for evasion-cost mapping.'],
  ['Controlled twins','Benign PDFs carrying a harmless reachable payload (app.alert) — for mechanism studies.'],
  ['Safety','Everything is STATIC. No PDF is ever opened, no JavaScript or action is ever executed.'],
],lede:'Real evasive malware for evidence; controlled, harmless twins for mechanism — never live execution.'});

T.bullets(p,{title:'Tools required & dataset sources',right:RIGHT.r1,bullets:[
  ['Parsing','pikepdf — static object-graph recovery (never executes the file).'],
  ['Detector','LightGBM + thrember (EMBER v3 feature extractor, 2568-D).'],
  ['Explainability','SHAP (TreeExplainer) for feature-family attribution.'],
  ['Engineering','Python 3.11 · FastAPI · pytest · ECharts dashboard.'],
  ['Datasets','EMBER2024 (FutureComputing4AI, KDD 2025) · CIC-Evasive-PDFMal2022 (UNB).'],
]});

T.numbered(p,{title:'Proposed methodology',right:RIGHT.r1,items:[
  ['Static parse','Open with pikepdf — never executed — recover the object-reference graph.'],
  ['Trigger surface','Enumerate auto / interaction triggers: /OpenAction, /AA, /Names/JavaScript, action chains.'],
  ['Reachability BFS','Shortest-path search from each trigger to a dangerous capability.'],
  ['Verdict taxonomy','ABSENT · PRESENT_DORMANT · ACTIVE_ONINTERACT · ACTIVE_ONOPEN, with a minimal witness.'],
  ['Fusion','Combine the 65-D reachability vector with the EMBER score for the final decision.'],
],card:{head:'KEY IDEA',body:'Recognition asks “does this look like malware?”  Reachability asks “can an automatic trigger reach a dangerous action?” — the question that actually defines the threat.',h:4.5,orn:'ring'},fs:14});

T.stats(p,{title:'Expected outcome',right:RIGHT.r1,lede:'What the project set out to deliver.',stats:[
  ['Structural','a detector that reads behaviour, supplying the signal byte-ML lacks',C.TEAL],
  ['Explainable','a verifiable witness path with every verdict',C.INK],
  ['Drift-resilient','stability under obfuscation, measured not asserted',C.AMBER],
  ['Reproducible','every number traced to a stored artifact',C.INK],
  ['Honest','clear separation of what is proven from what is projected',C.GRAPH],
  ['Usable','an interactive dashboard for the defence and demo',C.INK],
],big:30});

/* ============ REVIEW 2 — IMPLEMENTATION ============ */
T.divider(p,{num:'R2',title:'IMPLEMENTATION',right:RIGHT.r2,orn:'arcs',ornX:10.2,ornY:1.2,ornW:2.1,
  desc:'Architecture, tooling, datasets collected, static analysis results, findings and blockers.'});

T.imageSlide(p,{title:'Finalized methodology & system architecture',right:RIGHT.r2,img:A+'arch.png',ratio:0.317,
  caption:'The PDFSentry pipeline — static throughout; the fusion node combines structural reachability with the EMBER score.'});

T.bullets(p,{title:'Tools installed & working',right:RIGHT.r2,bullets:[
  ['Static parser','pikepdf operational — object graph + reachability engine (TRA-1.0).'],
  ['Detector','EMBER2024 released PDF model loaded via LightGBM; thrember built from source.'],
  ['Explainability','SHAP TreeExplainer over the full 2568-D EMBER vector.'],
  ['Backend & tests','FastAPI service; 23 pytest cases passing across parsing, reachability and fusion.'],
  ['Dashboard','Self-contained ECharts dashboard (ECharts inlined) — 11 interactive views.'],
],lede:'The full stack is built and reproducible — not slideware.'});

T.bullets(p,{title:'Datasets & malware samples collected',right:RIGHT.r2,bullets:[
  ['EMBER2024','Authors’ PDF model + ordinary test set + 805 evasive challenge PDFs (released as features).'],
  ['Benign corpus','35 real PDF fixtures + 250 generated benign documents for false-positive testing.'],
  ['Weaponized twins','Benign bases × 4 trigger wirings × 8 lossless transforms, each with a harmless payload.'],
  ['Provenance','Every sample set is scripted and regenerable; results fold into stored JSON artifacts.'],
]});

T.chartSlide(p,{title:'Static analysis results — reproducing the gap',right:RIGHT.r2,
  lede:'Same EMBER model, two regimes. Ordinary malware looks solved; evasive malware collapses precision.',
  type:CT.bar,legend:true,
  data:[{name:'Ordinary',labels:['PR-AUC','ROC-AUC','Recall'],values:[0.9933,0.9913,0.973]},
        {name:'Evasive',labels:['PR-AUC','ROC-AUC','Recall'],values:[0.7864,0.9075,0.559]}],
  opts:{barDir:'col',chartColors:[C.TEAL,C.AMBER],valAxisMinVal:0,valAxisMaxVal:1,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:9,dataLabelFormatCode:'0.00'},
  stats:[['0.7864','evasive PR-AUC (reproduced)',C.AMBER],['355/805','real evasive PDFs missed',C.RED],['0.9933','ordinary PR-AUC',C.TEAL]]});

T.bullets(p,{title:'Behavioural reasoning — without execution',right:RIGHT.r2,bullets:[
  ['By design, static','No sandbox, no detonation — PDFs are never opened. This removes all execution risk and is reproducible.'],
  ['Reachability as proxy','Instead of dynamic tracing, we statically prove whether an auto-trigger can reach a dangerous action.'],
  ['SHAP diagnosis','On the EMBER model, attribution is ~60% string features, ~29% byte histogram, and essentially 0% structure.'],
  ['Implication','The detector has no structural signal to separate evasive malware from benign files — the void we fill.'],
],lede:'The template’s “dynamic analysis” is answered by static behavioural reachability — safer and reproducible.',
  img:A+'dash_overview.jpg',imgW:5.0,imgY:3.5,caption:'SHAP + reproduction in the dashboard'});

T.imageSlide(p,{title:'Screenshots — interactive dashboard',right:RIGHT.r2,img:A+'dash_overview.jpg',ratio:0.573,notes:[
  ['Traceable','Every KPI links to a stored JSON artifact — nothing is hand-typed.'],
  ['Three pillars','Detection, Robustness and Assurance, each a clickable view.'],
  ['Live PR curves','Ordinary vs evasive rendered from the real EMBER model.'],
  ['Self-contained','ECharts inlined — opens offline, shareable as one file.'],
]});

T.bullets(p,{title:'Important findings (Review 2)',right:RIGHT.r2,bullets:[
  ['Collapse is real','EMBER PR-AUC 0.9933 → 0.7864 on evasive malware; 355/805 missed.'],
  ['Misses are structural','Missed malware is measurably more compressed than caught malware — /FlateDecode 12 vs 7 (p < 10⁻¹⁵), higher entropy, larger size.'],
  ['Reachability recovers it','On controlled structural evasions, EMBER+reachability fusion lifts ROC-AUC from 0.649 to 0.998.'],
  ['Confound-free','The real-malware evidence uses EMBER’s own released features — no new tooling, no execution.'],
]});

T.bullets(p,{title:'Problems encountered',right:RIGHT.r2,bullets:[
  ['Raw malware unobtainable','EMBER releases the 805 challenge as features only; CIC raw PDFs triggered AV quarantine and download limits.'],
  ['Our workaround','Used EMBER’s released features for confound-free real-malware evidence, and controlled twins for the mechanism.'],
  ['Tooling friction','thrember is not on PyPI (built from source); a signify import bug was stubbed around.'],
  ['Safety boundary','No safe way to execute live malware — so the whole pipeline stays static, which became a design strength.'],
]});

T.numbered(p,{title:'Work completed vs remaining (at Review 2)',right:RIGHT.r2,items:[
  ['Completed','EMBER reproduction, SHAP diagnosis, reachability engine + 65-D features, fusion study, dashboard v1.'],
  ['Remaining · robustness','Quantify obfuscation-invariance (semantic stability).'],
  ['Remaining · assurance','Verifiable verdicts: witnesses, false-positive and determinism measurement.'],
  ['Remaining · rigour','Negative controls and honest-scope framing.'],
  ['Remaining · delivery','Final packaging, dashboard polish and write-up.'],
],card:{head:'STATUS → R3',body:'Every “remaining” item below was completed for Review 3 — the two new pillars (Robustness, Assurance) and the negative controls are the headline additions.',h:4.5,orn:'star'},fs:14});

/* ============ REVIEW 3 — FINAL ============ */
T.divider(p,{num:'R3',title:'FINAL',right:RIGHT.r3,orn:'globe',ornX:9.9,ornY:1.0,ornW:2.6,
  desc:'Final methodology, complete implementation, results across three pillars, IoCs, comparison and demo.'});

T.numbered(p,{title:'Final methodology',right:RIGHT.r3,items:[
  ['Static parse','pikepdf recovers the object-reference graph; the file is never executed.'],
  ['Trigger surface','Enumerate every auto / interaction trigger across the known PDF execution vectors.'],
  ['Reachability BFS','Shortest-path search from trigger to dangerous capability; record the minimal witness.'],
  ['65-D reach vector','Encode verdicts, hops, concealment signatures and trigger classes as features.'],
  ['Fusion + verdict','Combine with the EMBER score; emit a typed verdict with a human-checkable path.'],
],card:{head:'UNCHANGED, PROVEN',body:'The methodology promised at Review 1 is the one that shipped — now measured for accuracy, robustness and assurance.',h:4.5,orn:'arcs'},fs:14});

T.stats(p,{title:'Complete implementation',right:RIGHT.r3,lede:'A built system, end to end — reproducible and tested.',stats:[
  ['TRA-1.0','trigger-reachability engine (static, deterministic)',C.TEAL],
  ['65-D','reachability feature vector fused with EMBER',C.INK],
  ['23','pytest cases passing (parse · reach · fusion)',C.INK],
  ['11 views','interactive ECharts dashboard, self-contained',C.AMBER],
  ['285','benign documents for false-positive testing',C.INK],
  ['704','obfuscation variants in the stability study',C.INK],
],big:34});

T.numbered(p,{title:'Three pillars of the final result',right:RIGHT.r3,items:[
  ['01 · Detection','Reachability over recognition — fusion lifts controlled ROC-AUC 0.649 → 0.998.'],
  ['02 · Robustness','Semantic stability — verdict invariant to lossless obfuscation (SSI 1.000 vs 0.216).'],
  ['03 · Assurance','Verifiable verdicts — 0/285 false positives, 1-hop witnesses, deterministic, training-free.'],
],card:{head:'THE ARC',body:'Detection → Robustness → Assurance. Not one metric, but a complete argument: it works, it holds under attack, and you can verify it.',h:3.2,orn:'ring'},fs:15});

T.chartSlide(p,{title:'Pillar 01 · Detection results',right:RIGHT.r3,
  lede:'On controlled structural evasions, EMBER alone is near-blind; adding the reachability signal makes it near-perfect.',
  type:CT.bar,legend:false,
  data:[{name:'ROC-AUC',labels:['EMBER score alone','EMBER + reachability'],values:[0.649,0.998]}],
  opts:{barDir:'col',chartColors:[C.AMBER,C.TEAL],valAxisMinVal:0,valAxisMaxVal:1,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:12,dataLabelFormatCode:'0.000'},
  stats:[['+0.349','ROC-AUC from the structural signal',C.TEAL],['100%','reachability recall on reachable threats',C.INK],['0','false positives on 285 benign',C.INK]]});

T.chartSlide(p,{title:'Pillar 02 · Robustness — semantic stability',right:RIGHT.r3,
  lede:'Same malicious behaviour, eight lossless re-saves. EMBER’s score swings across the scale; reachability never moves.',
  type:CT.bar,legend:false,
  data:[{name:'EMBER score',labels:['baseline','recompress','decompress','objstm+','objstm−','normalize','linearize','encrypt'],
    values:[0.80,0.57,0.02,0.00,0.80,0.07,0.73,0.98]}],
  opts:{barDir:'col',chartColors:['c08a2e','c08a2e','2f8f82','2f8f82','c08a2e','2f8f82','c08a2e','c08a2e'],
    valAxisMinVal:0,valAxisMaxVal:1,showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:9,dataLabelFormatCode:'0.00'},
  stats:[['78.4%','of docs get BOTH EMBER verdicts',C.RED],['1.000','reachability stability index',C.TEAL],['0.216','EMBER stability index',C.AMBER]]});

T.imageSlide(p,{title:'Pillar 03 · Assurance — verifiable verdicts',right:RIGHT.r3,img:A+'dash_assurance.jpg',ratio:0.573,notes:[
  ['Certificate','Each alarm ships a minimal witness: catalog → trigger → dangerous node.'],
  ['0 / 285','false positives on the benign corpus (auto-exec gate).'],
  ['Deterministic','identical verdict + path over repeated runs; no training data.'],
  ['Fast','~1.2 ms median per document — gateway-deployable.'],
]});

T.bullets(p,{title:'Malware characteristics',right:RIGHT.r3,bullets:[
  ['Auto-execution','A dangerous action (JavaScript, Launch, EmbeddedFile) wired to fire on open via /OpenAction, /AA or /Names.'],
  ['Concealment','The payload hidden inside a compressed object stream — present in behaviour, invisible to a token count.'],
  ['Byte camouflage','Elevated /FlateDecode and entropy make the file read as “just compressed” to a statistical model.'],
  ['Indirection','Action chains (GoTo → Next) reach the payload at depth, defeating shallow pattern checks.'],
],lede:'What evasive PDFs do to survive: automate, conceal, and camouflage as ordinary compression.'});

T.bullets(p,{title:'Indicators of Compromise (IoCs)',right:RIGHT.r3,bullets:[
  ['Reachable auto-trigger','/OpenAction | /AA | /Names/JavaScript with a path to /JS, /Launch or /EmbeddedFile → ACTIVE_ONOPEN.'],
  ['Hidden-gap signature','An ACTIVE capability whose naive token count is 0 — a contradiction only concealment produces.'],
  ['Object-stream hiding','JavaScript wrapped in an ObjStm; /FlateDecode count far above the benign median (≈ 12 vs 7).'],
  ['Statistical tells','Byte entropy > 7.9 and file size well above benign, with a JS token count of 0.'],
  ['Deep action chains','GoTo → Next sequences terminating at a dangerous node.'],
],lede:'Structural, checkable indicators — each maps to a reachability feature, not a fragile byte signature.'});

T.tableSlide(p,{title:'Comparison / results',right:RIGHT.r3,
  headers:['Property','EMBER2024','Hidost','PDFSentry'],highlightCol:3,
  rows:[
   ['Reads what the file DOES','No (bytes/strings)','Partial (static paths)','Yes (reachability)'],
   ['Explainable verdict','Post-hoc SHAP','No','Witness path'],
   ['Obfuscation-invariant','No — SSI 0.22','Not reported','Yes — SSI 1.00'],
   ['Cost to evade','Free re-save','Low–medium','Must disarm payload'],
   ['Training data needed','Yes','Yes','No (deterministic)'],
  ],note:'Honest scope: the 0.78 EMBER benchmark is NOT improved (no raw evasive files to retrain). The 0.998 is a controlled result that isolates the mechanism.'});

T.imageSlide(p,{title:'Screenshots — reachability & robustness',right:RIGHT.r3,img:A+'dash_stability.jpg',ratio:0.573,notes:[
  ['Interactive','Pick any weaponized twin; its EMBER score-swing plots live.'],
  ['Invariance','Reachability verdict held constant across all re-saves.'],
  ['Object graph','A force-directed view traces the catalog→danger path.'],
  ['Negative control','A feature-only recovery rule fails — motivating true reachability.'],
]});

T.bullets(p,{title:'Honest scope & limitations',right:RIGHT.r3,bullets:[
  ['Benchmark not beaten','We did NOT raise EMBER’s 0.78 evasive score — retraining needs raw evasive PDFs we could not obtain.'],
  ['Controlled mechanism','The 0.998 fusion is on controlled weaponized twins; it isolates the signal, it is not a benchmark claim.'],
  ['Capability ≠ intent','Reachability flags a reachable dangerous capability; a benign PDF that genuinely auto-runs JS would be flagged too.'],
  ['Static only','No dynamic cross-validation — by design, for safety and reproducibility.'],
],lede:'Stated plainly so the contribution is credible: what is proven, and what is projected.'});

T.bullets(p,{title:'Conclusion',right:RIGHT.r3,bullets:[
  ['New idea, built','Reachability over recognition — a structural, static detector that reads what a PDF will do.'],
  ['Three results','Detection (0.649→0.998 controlled), Robustness (SSI 1.000 vs 0.216), Assurance (0/285 FP, verifiable).'],
  ['Explains the gap','Byte-ML spends ~0% on structure; evasive misses are measurably more compressed (p < 10⁻¹⁵).'],
  ['Honest & reproducible','Every number traces to an artifact; scope is stated without overclaim.'],
]});

T.bullets(p,{title:'Future enhancement',right:RIGHT.r3,bullets:[
  ['Train on raw evasive','Obtain raw evasive PDFs to retrain a reachability-augmented model and test the 0.78 directly.'],
  ['Dynamic cross-check','Sandbox a sample to validate reachability verdicts against observed behaviour.'],
  ['Gateway deployment','~1.2 ms/file makes an email / browser gateway pre-filter realistic.'],
  ['Beyond PDF','Extend the reachability abstraction to Office OOXML and other active-content formats.'],
]});

T.closing(p,{eyebrow:'PROJECT DEMONSTRATION',title:'Detection. Robustness. Assurance.',
  lines:['Live dashboard — 11 interactive views, every number traceable.','GitHub — full code, scripts, tests and stored artifacts.','Static throughout — nothing is ever executed.'],
  repo:'github.com/heyalokx/PDFSentry', dash:'published interactive dashboard (link in repo README)', right:'REVIEW 3 · FINAL'});

p.writeFile({fileName:'PDFSentry_Consolidated_R1-R2-R3.pptx'}).then(f=>console.log('wrote',f));
