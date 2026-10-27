# Results — every number traces to an artifact

Two tracks: the **EMBER2024** track (Review-2 primary: O1/O2 + the structural
augmentation result O4) and the **CIC** track (the O6 mimicry probe + the
reachability engine validation). All figures are produced by `scripts/` and
stored under `artifacts/`.

## 1. EMBER2024 benchmark — reproduced (O1)
`artifacts/metrics/ember_reproduction.json` — authors' released PDF model, their protocol.

| Evaluation | ROC-AUC | PR-AUC | Published | Samples |
|---|---|---|---|---|
| Ordinary test | 0.9913 | **0.9933** | 0.9912 / 0.9933 | 24,000 PDFs |
| Evasive challenge | 0.9075 | **0.7864** | 0.9066 / 0.7841 | 805 evasive + 6,000 benign |

Matches the published benchmark within bootstrap noise → baseline verified, not
assumed. The model **misses 355 of 805 evasive PDFs** (44%) at threshold 0.5.

## 2. Why they evade — SHAP diagnosis (O2)
`artifacts/explanations/ember_shap.json` — SHAP on the real EMBER model, 3 groups.

Feature-family attention (mean |SHAP| mass):

| Group | strings | histogram | byte-entropy | structure |
|---|---|---|---|---|
| Caught ordinary malware | 57.6% | 33.4% | 8.0% | ~0% |
| Caught evasive malware | 62.3% | 28.1% | 8.1% | ~0% |
| **Missed evasive malware** | 60.1% | 29.3% | 9.4% | ~0% |

Missed and caught evasive malware are **nearly indistinguishable** to the model —
both are byte/string statistics with no structural signal. Once an evasive file's
byte/string profile looks benign, the baseline has nothing left to catch it with.

## 3. Structural evasion + reachability fusion (O3/O4) — the headline
`artifacts/metrics/structural_evasion_study.json` — run against the real EMBER model.

300 confident-benign real PDFs, each weaponized with a reachable auto-run
JavaScript action (harmless `app.alert`) hidden in a compressed object stream.

| Metric | Value |
|---|---|
| Weaponized docs that **evade EMBER** (score < 0.5) | **99.3%** (298/300) |
| Mean EMBER score, original → weaponized | 0.0004 → 0.0106 (barely moves) |
| Weaponized docs **caught by reachability** | **100%** |
| Separating safe vs weaponized — **EMBER score alone** | AUC 0.649 |
| Separating safe vs weaponized — **EMBER + reachability (fusion, 5-fold CV)** | **AUC 0.998** |
| Top fusion features (gain) | `rc_javascript_onopen` (7688), `rc_javascript_hidden_gap` (797) |

Compression-mechanism isolation (same action, real EMBER model):

| Crafted PDF | EMBER score | EMBER verdict | reachability |
|---|---|---|---|
| auto-run, visible tokens | 0.995 | flagged | ACTIVE_ONOPEN |
| auto-run, hidden in compressed stream | **0.242** | **missed** | ACTIVE_ONOPEN (evasion_sig=1) |
| dormant (never runs) | 0.996 | flagged | PRESENT_DORMANT |
| runs only on click | 0.995 | flagged | ACTIVE_ONINTERACT |

Hiding the identical action in a compressed stream drops EMBER below threshold;
reachability tracks it regardless.

## 4. Mimicry probe (O6)
`artifacts/metrics/evasion_baseline.json`, `model_comparison.json` — CIC feature set.

- A count-based detector (PR-AUC 0.9995 on CIC) is evaded on **67%** of caught
  malware at a **median of 3** feature edits.
- Dropping the keyword counts (structure-first model) leaves resilience almost
  unchanged (0.330 → 0.345; paired ΔPR-AUC not significant) → you cannot
  feature-select your way out of the count paradigm; a different *kind* of signal
  (reachability) is required.

## 5. Reachability engine validation
`artifacts/metrics/reachability_corpus.json` — 39 real + crafted PDFs; the
count-view and reachability-view disagree in **7 cases** (4 over-alarm,
3 under-alarm), e.g. real `GeoTopo.pdf`: a URI reachable on open with byte-count 0.

## Separation of evidence
- **Published reference (EMBER2024):** cited as such; our reproduction matches it.
- **Our results:** tables 1–5 above.
- **Weaponized samples:** controlled, clearly labelled (benign PDF + harmless
  reachable payload); never presented as wild malware or as detection performance.
