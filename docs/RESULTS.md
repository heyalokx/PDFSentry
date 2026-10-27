# Results — every number traces to an artifact

All figures are produced by the scripts and stored under `artifacts/`. Reproduce
with the commands in `README.md`.

## Dataset (artifacts/manifests/dataset_manifest.json)
| Item | Value |
|---|---|
| Source | CIC-Evasive-PDFMal2022 (UNB) |
| Samples after cleaning | 10,025 (1 unlabeled row dropped) |
| Malicious / Benign | 5,557 / 4,468 |
| Features after engineering | 39 |
| Rows with parser-failure sentinel (`-1`) | 1,317 |
| Malformed `%PDF-` headers | 907 |
| Split | stratified 70/30, seed 1337 → train 7,017 / test 3,008 |

> CIC has no timestamp field; temporal drift (as in EMBER2024) is **not
> available** and is not reported.

## Baseline detector — test split (artifacts/metrics/baseline_eval.json)
| Metric | Value | 95% bootstrap CI |
|---|---|---|
| PR-AUC (average precision) | **0.9995** | 0.9990 – 0.9999 |
| ROC-AUC | 0.9994 | 0.9988 – 0.9998 |
| F1 | 0.9913 | — |
| Precision | 0.9904 | — |
| Recall | 0.9922 | — |
| Accuracy | 0.9904 | — |
| Confusion (tn, fp, fn, tp) | 1325, 16, 13, 1654 | — |

Bootstrap: 2,000 stratified replicates, seed 1337.

## Evasion-Cost Map (artifacts/metrics/evasion_baseline.json)
| Item | Value |
|---|---|
| Caught malware probed | 800 |
| Successfully evaded | 536 (**67.0%**) |
| **Evasion-Resilience Score** | **0.330** |
| Median edits to evade | 3 (of 13 editable features) |
| Cost distribution (edits→count) | 1→25, 2→160, 3→252, 4→85, 5→11, 6→3 |
| Most fragile features | Javascript, metadata size, JS, OpenAction, XFA |

## Model comparison (artifacts/metrics/model_comparison.json)
| Detector | Clean PR-AUC | ERS | Median cost |
|---|---|---|---|
| Baseline (all features) | 0.9995 | 0.330 | 3 |
| Structure-first (keyword counts dropped) | 0.9994 | 0.345 | 3 |

Paired bootstrap ΔPR-AUC = −0.00013 (95% CI −0.00037 to +0.00004), **not
significant** → dropping fragile features costs no accuracy and barely changes
resilience.

## Explainability (artifacts/explanations/shap_analysis.json)
- SHAP global top: `keyword_concentration`, `metadata size`, `Javascript`, `pdfsize`, `js_total`.
- Permutation top: `metadata size`, `keyword_concentration`, `pdfsize`, `Colors`, `n_parse_failures`.
- The two methods converge on the fragile keyword/size features; 13 malicious
  test files are missed outright (false negatives).

## Reachability corpus (artifacts/metrics/reachability_corpus.json)
| Item | Value |
|---|---|
| Files analyzed | 39 (4 crafted + 35 real) |
| Count vs reachability disagreements | 7 (4 over-alarm, 3 under-alarm) |
| Headline under-alarm | `GeoTopo.pdf`: URI ACTIVE_ONOPEN, byte-count 0 |
| Crafted fixtures | dormant / active-on-open / interaction-only / token-buried, all byte-count 2 except buried (0) |

## Separation of evidence
- **Published reference values (EMBER2024):** not reproduced — BLOCKED (data unreachable). Not used anywhere as our result.
- **Our experimental results:** all tables above, on CIC-PDFMal2022.
- **Fixtures:** the 4 crafted PDFs are clearly labelled demonstrations, never counted as detection performance.
