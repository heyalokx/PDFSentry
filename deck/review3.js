const T=require('./theme.js'); const A=T.A, C=T.C;
const p=T.mk(); const CT=p.ChartType;
const R='REVIEW 3 · FINAL';
function N(s,t){ if(s&&s.addNotes) s.addNotes(t); }

/* ===== COVER ===== */
T.cover(p,{eyebrow:'REVIEW 3 — FINAL DEFENCE', title:'PDFSentry',
  subtitle:'Explainable, Drift-Resilient Static Detection of Malicious PDF Files',
  tagline:'Reachability over recognition — reading what a PDF will do, not just what it contains.',
  team:['Alok Singh  23BCI0158','Mrinali Charhate  23BCI0073','Aarya Ashish Nagvekar  23BCI0061'],
  guide:'BCSE321L — Malware Analysis · Vellore Institute of Technology'});

/* ===== 01 · PROBLEM ===== */
N(T.bullets(p,{title:'The problem — the evasive gap',right:R,eb:'01 · PROBLEM',bullets:[
  ['State of the art','EMBER2024 is a leading ML detector for PDFs — near-perfect on ordinary malware (PR-AUC 0.9933).'],
  ['It breaks on evasion','On its own 805-sample challenge set of malware that already beat antivirus, PR-AUC collapses to 0.7841.'],
  ['Why it breaks','It classifies byte and string statistics; it has no view of the document’s object graph or its auto-execution behaviour.'],
  ['The stakes','355 of 805 real evasive PDFs pass straight through — the exact samples that reach a user after a gateway.'],
  ['Our target','Close that structural blind spot with an explainable signal that does not drift as attackers re-encode.'],
],lede:'The malware that matters most — evasive, post-antivirus PDFs — is exactly where today’s detectors fail.',
  metrics:[['0.9933 → 0.7841','PR-AUC: ordinary → evasive',C.AMBER],['355 / 805','real evasive PDFs missed',C.RED],['44%','slip-through rate',C.RED]]}),
  'Open with the paradox: the benchmark looks solved, yet nearly half of real evasive malware is missed. Stress that these 805 are not synthetic — they are samples that already evaded AV, so they are the realistic threat. This motivates everything that follows.');

/* ===== 02 · RELATED WORK ===== */
N(T.tableSlide(p,{title:'Background & related work',right:R,eb:'02 · RELATED WORK',highlightRow:4,
  headers:['Approach','What it uses','Why it misses evasive malware'],
  rows:[
   ['AV signatures','Known byte patterns','Zero-day and re-encoded variants evade by construction'],
   ['PDFRate / Slayer','Keyword & count features','Mimicry attacks flip counts with cheap edits'],
   ['Hidost','Structural path features','A path being present ≠ reachable; no auto-trigger logic'],
   ['EMBER2024','Byte/string statistics (2568-D)','~0% of its attention is on structure (shown via SHAP)'],
   ['PDFSentry (ours)','Trigger → action reachability','Directly models the auto-execution mechanism'],
  ],lede:'Prior PDF detectors read appearance or static structure — none test whether a dangerous action is reachable from a trigger.',
  note:'Structure-aware work (Hidost) is closest, but it lists structural paths without asking whether a trigger actually reaches a dangerous node.'}),
  'Place PDFSentry in the literature. Signatures and count-based models (PDFRate, Slayer) are defeated by cheap edits; Hidost is structure-aware but static-path only. Our novelty is reachability — connecting an automatic trigger to a dangerous capability — which none of these model.');

/* ===== 03 · CORE IDEA ===== */
N(T.bullets(p,{title:'Core idea — reachability over recognition',right:R,eb:'03 · THE IDEA',bullets:[
  ['Recognition (old)','“Does this file look like malware?” — a statistical judgement on bytes and strings, easily camouflaged.'],
  ['Reachability (ours)','“Can an automatic trigger reach a dangerous action?” — a structural fact about what the document will do on open.'],
  ['Why it is stronger','Appearance can be re-encoded freely; the trigger→action path cannot be hidden without removing the attack itself.'],
  ['Explainable by nature','The answer is a concrete path, not a probability — a reviewer can confirm it by hand.'],
],lede:'We reframe detection from a pattern-matching question into a reachability question on the PDF object graph.',
  metrics:[['Recognition','what it looks like',C.AMBER],['Reachability','what it will do',C.TEAL],['Witness','why we say so',C.INK]]}),
  'This is the thesis slide — spend time here. Contrast the two questions explicitly. The key line: an attacker can change how a file looks for free, but to defeat reachability they must sever the trigger-to-action path, which disarms their own payload.');

/* ===== 04 · ARCHITECTURE ===== */
N(T.imageSlide(p,{title:'System architecture',right:R,eb:'04 · ARCHITECTURE',img:A+'arch.png',ratio:0.317,
  caption:'Static throughout — pikepdf parses the file (never executes it); reachability and the EMBER score are fused into a typed, witnessed verdict.'}),
  'Walk the pipeline left to right. Emphasise “never executed” — this is pure static analysis, which is both safer and reproducible. The fusion node is where our structural signal meets the byte-ML score; the output is not just a label but a verdict plus a witness path.');

/* ===== 05 · ENGINE ===== */
N(T.numbered(p,{title:'Inside the reachability engine (TRA-1.0)',right:R,eb:'05 · ENGINE',items:[
  ['Build the graph','Parse the PDF with pikepdf into an object-reference graph (catalog, pages, actions, streams).'],
  ['Enumerate triggers','Find every auto/interaction entry point: /OpenAction, document & page /AA, /Names/JavaScript, action chains.'],
  ['Bounded BFS','Shortest-path search from each trigger to a dangerous capability (JavaScript, Launch, EmbeddedFile, SubmitForm), capped at 12 hops.'],
  ['Classify','Assign a verdict by the strongest trigger class reaching a danger; record min-hops and the concealment state.'],
  ['Emit witness','Return the minimal catalog→danger path as a checkable certificate.'],
],card:{head:'DETERMINISTIC',body:'No training, no randomness. The same file always yields the same verdict and the same witness path — ~1.2 ms per document.',h:4.6},fs:14}),
  'This is your “depth” slide — show the machinery. Name the trigger vectors explicitly; examiners like to see you know the PDF spec. The BFS is bounded for safety against pathological files. Stress determinism: unlike an ML model, this cannot drift.');

/* ===== 06 · TAXONOMY ===== */
N(T.numbered(p,{title:'Reachability verdict taxonomy',right:R,eb:'06 · TAXONOMY',items:[
  ['ABSENT','No dangerous capability present in the document at all.'],
  ['PRESENT_DORMANT','A dangerous capability exists but no trigger can reach it — inert.'],
  ['ACTIVE_ONINTERACT','Reachable only on user interaction (e.g. a clickable link) — a capability, not an auto-threat.'],
  ['ACTIVE_ONOPEN','A dangerous action auto-fires on open — the threat class we are built to catch.'],
],card:{head:'CAPABILITY ≠ INTENT',body:'The four states let us separate a benign clickable link from a weaponised auto-run payload — and say precisely which one we found.',h:4.6},fs:15}),
  'Explain why a scalar score is not enough. A clickable URL and an auto-run JavaScript are both “active” but very different threats. The taxonomy encodes that distinction, and it is why we get zero false positives on benign links in testing.');

/* ===== 07 · FEATURE VECTOR ===== */
N(T.bullets(p,{title:'The 65-D reachability feature vector',right:R,eb:'07 · FEATURES',bullets:[
  ['Verdict encoding','One-hot of the worst verdict per capability, plus counts of active-on-open vs dormant nodes.'],
  ['Reach geometry','Minimum hops to each danger, number of auto triggers, number of distinct reachable capabilities.'],
  ['Concealment','Object-stream counts and the hidden-gap signature — a reachable capability whose naive token count is zero.'],
  ['Naive baseline','Raw token counts (/JS, /Launch, /URI...) so the model can contrast appearance with reachability.'],
  ['Fusion','These 65 features are concatenated with the EMBER score and read by the final classifier.'],
],lede:'Reachability is distilled into 65 interpretable features — each one a structural fact, not a byte statistic.',
  metrics:[['65-D','interpretable reachability features',C.TEAL],['hidden-gap','headline concealment flag',C.RED,24],['⊕ EMBER','fused final decision',C.INK]]}),
  'Show that reachability is not a single rule but a rich, interpretable feature space. The star feature is the hidden-gap signature: a payload that is reachable yet has a zero naive token count can only exist through deliberate concealment. Every feature is human-readable, unlike the 2568-D byte vector.');

/* ===== 08 · SETUP ===== */
N(T.bullets(p,{title:'Experimental setup & datasets',right:R,eb:'08 · SETUP',bullets:[
  ['Baseline','EMBER2024 authors’ released PDF model, reproduced on the ordinary test set and the 805-sample evasive challenge set.'],
  ['Protocol','Challenge reproduction uses the authors’ 6,000-benign sampling (seed 1337); fusion is scored with 5-fold cross-validation.'],
  ['Controlled twins','300 benign PDFs weaponised across 4 trigger wirings × 8 lossless transforms, each with a harmless app.alert payload.'],
  ['Benign corpus','35 real fixtures + 250 generated documents (links, forms, bookmarks) for false-positive measurement.'],
  ['Reproducibility','Every figure folds into a stored JSON artifact and renders in the dashboard — no hand-typed numbers.'],
],lede:'A rigorous, reproducible protocol — real malware for evidence, controlled twins for mechanism, never live execution.',
  metrics:[['805','real evasive PDFs',C.INK],['300 × 32','weaponised variants',C.INK],['285','benign test documents',C.INK]]}),
  'Establish rigour before the results. Note we follow the EMBER authors’ own evaluation protocol so our baseline is honest. Distinguish the two experiment types: real-malware evidence (features only) and controlled mechanism studies (our twins). Reiterate: nothing is ever executed.');

/* ===== 09 · SHAP ===== */
N(T.chartSlide(p,{title:'SHAP diagnosis — the structural void',right:R,eb:'09 · DIAGNOSIS',
  lede:'Where the EMBER model spends attention on the evasive malware it misses (mean |SHAP| by feature family).',
  type:CT.bar,legend:false,
  data:[{name:'attention',labels:['strings','byte histogram','byte entropy','structure'],values:[60,29,9,0.4]}],
  opts:{barDir:'col',chartColors:['6b7178','6b7178','6b7178','b4473f'],valAxisMinVal:0,valAxisMaxVal:70,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:11,dataLabelFormatCode:'0"%"'},
  stats:[['~0%','attention on structure',C.RED],['~60%','on string statistics',C.GRAPH],['≈','missed looks like caught',C.AMBER]],big:38}),
  'This is the “why” evidence. SHAP on the real model shows it reasons almost entirely from string and byte statistics and essentially ignores structure. Critically, the feature profile of what it misses is nearly identical to what it catches — so once a file’s byte profile looks benign, the model has nothing left. That void is what reachability fills.');

/* ===== 10 · REAL-MALWARE SIGNATURE ===== */
N(T.bullets(p,{title:'Real evasive malware — the compression signature',right:R,eb:'10 · REAL-MALWARE EVIDENCE',bullets:[
  ['Confound-free','Measured directly on the 805 real challenge PDFs using EMBER’s own released features — no new tooling, no execution.'],
  ['Misses are compressed','Missed malware has a median /FlateDecode count of 12 vs 7 for caught malware (Mann-Whitney p < 10⁻¹⁵).'],
  ['Higher entropy, larger','Byte entropy 7.93 vs 7.87 (p < 10⁻⁶) and file size 143.6 KB vs 75.8 KB (p < 10⁻¹⁹).'],
  ['The mechanism','EMBER’s blind spot aligns exactly with structural concealment — the thing reachability is built to see.'],
],lede:'On real malware, the samples EMBER misses carry a measurable structural-concealment fingerprint.',
  metrics:[['12 vs 7','/FlateDecode: missed vs caught',C.TEAL],['p < 10⁻¹⁵','statistical significance',C.INK],['1.9×','file-size ratio',C.AMBER]]}),
  'This is the strongest real-data result — it is on actual malware, not twins, and it is confound-free because it uses EMBER’s own features. The misses are systematically more compressed, higher-entropy and larger: the hallmark of hiding active content in object streams. State the p-values to show it is not noise.');

/* ===== 11 · DETECTION ===== */
N(T.chartSlide(p,{title:'Pillar 01 · Detection — fusion result',right:R,eb:'11 · DETECTION',
  lede:'On controlled structural evasions, EMBER alone is near-blind; adding the reachability signal makes it near-perfect.',
  type:CT.bar,legend:false,
  data:[{name:'ROC-AUC',labels:['EMBER score alone','EMBER + reachability'],values:[0.649,0.998]}],
  opts:{barDir:'col',chartColors:[C.AMBER,C.TEAL],valAxisMinVal:0,valAxisMaxVal:1,
    showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:12,dataLabelFormatCode:'0.000'},
  stats:[['+0.349','ROC-AUC from the structural signal',C.TEAL],['100%','reachability recall on reachable threats',C.INK],['0','false positives on 285 benign',C.INK]]}),
  'Pillar one. On the controlled twins, EMBER alone scores 0.649 ROC-AUC — barely better than chance for this evasion class. Fusing reachability lifts it to 0.998. Be scrupulous: say clearly this is the controlled study, not the 0.78 benchmark (which we address under limitations).');

/* ===== 12 · ROBUSTNESS ===== */
N(T.chartSlide(p,{title:'Pillar 02 · Robustness — semantic stability',right:R,eb:'12 · ROBUSTNESS',
  lede:'Same malicious behaviour, eight lossless re-saves. EMBER’s score swings across the scale; reachability never moves.',
  type:CT.bar,legend:false,
  data:[{name:'EMBER score',labels:['baseline','recompress','decompress','objstm+','objstm−','normalize','linearize','encrypt'],
    values:[0.80,0.57,0.02,0.00,0.80,0.07,0.73,0.98]}],
  opts:{barDir:'col',chartColors:['c08a2e','c08a2e','2f8f82','2f8f82','c08a2e','2f8f82','c08a2e','c08a2e'],
    valAxisMinVal:0,valAxisMaxVal:1,showValue:true,dataLabelPosition:'outEnd',dataLabelColor:C.GRAPH,dataLabelFontFace:'Calibri',dataLabelFontSize:9,dataLabelFormatCode:'0.00'},
  stats:[['78.4%','of docs get BOTH EMBER verdicts',C.RED],['1.000','reachability stability index',C.TEAL],['0.216','EMBER stability index',C.AMBER]]}),
  'Pillar two — our novel robustness result. Take one malicious document, re-save it losslessly eight ways: the behaviour is byte-for-byte identical, yet EMBER’s score ranges from 0.00 to 0.98. Across 704 variants it flips verdict on 78.4% of documents. Reachability is invariant — stability index 1.000 — because it reads behaviour, not encoding.');

/* ===== 13 · ASSURANCE ===== */
N(T.imageSlide(p,{title:'Pillar 03 · Assurance — verifiable verdicts',right:R,eb:'13 · ASSURANCE',img:A+'dash_assurance.jpg',ratio:0.573,notes:[
  ['Certificate','Every alarm ships a minimal witness: catalog → trigger → dangerous node.'],
  ['0 / 285','false positives on the benign corpus (auto-exec gate).'],
  ['Deterministic','identical verdict + path over repeated runs; no training data.'],
  ['Fast','~1.2 ms median per document — gateway-deployable.'],
]}),
  'Pillar three — trust. An ML score is a number you must trust; our verdict comes with a path a human can re-check in seconds. Zero false positives on 285 benign documents at the auto-execution gate, fully deterministic, and fast enough to sit in an email gateway. This is what turns a research result into something deployable.');

/* ===== 14 · CHARACTERISTICS & IoCs ===== */
N(T.bullets(p,{title:'Malware characteristics & Indicators of Compromise',right:R,eb:'14 · CHARACTERISTICS · IoCs',bullets:[
  ['Auto-execution','A dangerous action (JavaScript, Launch, EmbeddedFile) wired to fire on open via /OpenAction, /AA or /Names.'],
  ['Concealment','The payload hidden in a compressed object stream — present in behaviour, invisible to a token count.'],
  ['IoC · reachable trigger','An auto-trigger with a path to /JS, /Launch or /EmbeddedFile → ACTIVE_ONOPEN.'],
  ['IoC · hidden-gap','An ACTIVE capability whose naive token count is 0 — a contradiction only concealment produces.'],
  ['IoC · byte tells','/FlateDecode far above the benign median (≈ 12 vs 7), entropy > 7.9, JS token count 0, oversized file.'],
  ['IoC · deep chains','GoTo → Next action sequences terminating at a dangerous node.'],
],lede:'What evasive PDFs do to survive, and the structural indicators PDFSentry extracts — each a reachability feature, not a fragile byte signature.'}),
  'Make this concrete and operational. First two bullets are behaviours; the rest are checkable IoCs a SOC analyst could use. The hidden-gap IoC is the memorable one: a payload that is reachable but “invisible” to a token count is, by definition, deliberately concealed.');

/* ===== 15 · COMPARISON & SCOPE ===== */
N(T.tableSlide(p,{title:'Comparison & honest scope',right:R,eb:'15 · COMPARISON',highlightRow:null,highlightCol:3,
  headers:['Property','EMBER2024','Hidost','PDFSentry'],
  rows:[
   ['Reads what the file DOES','No (bytes/strings)','Partial (static paths)','Yes (reachability)'],
   ['Explainable verdict','Post-hoc SHAP','No','Witness path'],
   ['Obfuscation-invariant','No — SSI 0.22','Not reported','Yes — SSI 1.00'],
   ['Cost to evade','Free re-save','Low–medium','Must disarm payload'],
   ['Training data needed','Yes','Yes','No (deterministic)'],
  ],lede:'PDFSentry against the byte-ML baseline and a classic structural-path detector — with the scope stated plainly.',
  note:'Honest scope: the 0.78 EMBER benchmark is NOT improved (no raw evasive files to retrain). The 0.998 is a controlled result that isolates the mechanism; a benign PDF that genuinely auto-runs JS would also be flagged.'}),
  'Close the argument, then pre-empt the hard question. PDFSentry wins on every structural property. Then be the first to say what we did NOT do: we did not beat the 0.78 benchmark, because that needs raw evasive files to retrain, which we could not obtain. The 0.998 is controlled. Owning this is what makes the rest credible.');

/* ===== CLOSING ===== */
T.closing(p,{eyebrow:'PROJECT DEMONSTRATION',title:'Detection. Robustness. Assurance.',
  lines:['Live dashboard — 11 interactive views, every number traceable.','GitHub — full code, scripts, tests and stored artifacts.','Static throughout — nothing is ever executed.'],
  repo:'github.com/heyalokx/PDFSentry', dash:'published interactive dashboard (link in repo README)', right:R});

p.writeFile({fileName:'PDFSentry_Review3.pptx'}).then(f=>console.log('wrote',f));
