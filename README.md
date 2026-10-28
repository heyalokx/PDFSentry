# PDFSentry

**Explainable, Drift-Resilient Static Detection of Malicious PDF Files**

BCSE321L — Malware Analysis · Vellore Institute of Technology
Alok Singh (23BCI0158) · Mrinali Charhate (23BCI0073) · Aarya Ashish Nagvekar (23BCI0061)

---

## What this is

A state-of-the-art PDF malware detector (EMBER2024) looks solved on ordinary malware
but **collapses on evasive malware** — files that have already slipped past antivirus
(PR-AUC **0.9933 → 0.7841** on its own challenge set; **355 of 805** real evasive PDFs
missed). It reads byte and string statistics, so it is blind to a document's *structure*
and its *auto-execution behaviour*.

PDFSentry adds the missing signal: **reachability over recognition.** Instead of asking
*"does this look like malware?"*, it parses the PDF's object graph and asks *"can an
automatic trigger reach a dangerous action?"* — the question that actually defines the threat.

> **Everything is static.** No PDF is ever opened, no JavaScript or action is ever
> executed. The only payload used anywhere in this project is a harmless `app.alert()`
> injected into *benign* files to build controlled test twins.

## Three contributions

| Pillar | Idea | Headline result |
|---|---|---|
| **01 · Detection** | Parse → object graph → BFS from an auto-trigger to a dangerous capability | Controlled fusion ROC-AUC **0.649 → 0.998** |
| **02 · Robustness** | *Semantic stability* — the verdict is invariant to lossless byte-obfuscation | Stability index **1.000** vs EMBER's **0.216** (704 variants); EMBER flips on **78.4%** of docs |
| **03 · Assurance** | *Verifiable verdicts* — every alarm ships a minimal, human-checkable witness path | **0 / 285** false positives, **1-hop** median witness, **100%** deterministic, **~1.2 ms**/file, training-free |

## Honest scope

- We did **not** raise EMBER's 0.78 evasive benchmark score — retraining a reachability-augmented
  model needs raw evasive PDFs we could not obtain (EMBER releases the challenge set as features
  only; CIC raw PDFs triggered AV quarantine).
- The **0.998** fusion result is a **controlled** experiment (benign PDFs vs their weaponized twins)
  that *isolates the mechanism* — it is not a benchmark claim.
- Reachability flags a reachable dangerous **capability**, not intent: a benign PDF that genuinely
  auto-runs JavaScript would also be flagged.
- Static only; no dynamic sandbox cross-validation (by design, for safety and reproducibility).

Every number in the dashboard traces to a stored JSON artifact under `artifacts/metrics/`.

## Repository layout

```
backend/      core, parsing, reachability engine (TRA-1.0), features, fusion, evaluation
scripts/      reproduction + all studies (ember, shap, structural evasion, stability, oracle, ...)
config/       dataset semantics + model/feature/evasion parameters
tests/        pytest suite (parse · reachability · fusion) + fixtures
frontend/     dashboard.html — self-contained interactive dashboard (ECharts inlined)
docs/         NOVELTY, FACULTY_QA, RESULTS, LIMITATIONS, ARCHITECTURE, ...
deck/         Review-3 and consolidated presentation decks (.pptx) + sources
artifacts/    stored result metrics (JSON)
```

## Reproduce

```bash
pip install -r requirements.txt
# Datasets are not committed — see docs/COLAB.md / config/default.yaml for sources:
#   EMBER2024 (FutureComputing4AI, KDD'25) · CIC-Evasive-PDFMal2022 (UNB)
python -m pytest -q                       # 23 tests
python scripts/reproduce_ember.py         # O1 — the evasive gap
python scripts/ember_shap.py              # O2 — why evasive malware is missed
python scripts/structural_evasion_study.py# detection — fusion recovers evasions
python scripts/semantic_stability_study.py# robustness — obfuscation invariance
python scripts/verifiable_oracle_study.py # assurance — verifiable verdicts
python scripts/bundle_dashboard_data.py && python scripts/build_dashboard.py
```

## Dashboard

Open `frontend/dashboard.html` in any browser — it is fully self-contained (ECharts inlined,
data embedded), with 11 interactive views across the three pillars.

## Safety

This repository is for **defensive, static** malware analysis and research. It never executes
PDFs or embedded content, and contains no real malware — only released *features* of public
benchmark samples and controlled benign twins carrying a harmless alert payload.
