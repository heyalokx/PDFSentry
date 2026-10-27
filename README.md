# PDFSentry — Reachability-aware PDF malware intelligence

> A near-perfect static PDF-malware detector, the evasion gap its benchmark
> accuracy hides, and a structural **reachability** signal that survives that
> gap. Built on the real CIC-Evasive-PDFMal2022 dataset.

**Live dashboard:** published as a Claude artifact (see the chat).
**Research contribution:** `docs/NOVELTY.md`. **Defense prep:** `docs/FACULTY_QA.md`.

## The idea in one paragraph
Standard PDF detectors count dangerous tokens (`/JavaScript`, `/OpenAction`, …).
PDFSentry measures that this representation is evasion-fragile — a 0.9995 PR-AUC
model is evaded on 67% of caught malware by editing a median of 3 fields — and
replaces *counting* with *reachability*: a static object-graph engine that
decides whether a dangerous action can actually fire on open. The same edit that
fools a counter does not fool reachability.

## Architecture
```
backend/
  data/        ingest.py (CIC loader + provenance), splits.py
  models/      baseline.py (LightGBM + provenance)
  evaluation/  metrics.py (point metrics, bootstrap + paired CIs, curves)
  explainability/ shap_engine.py (SHAP + permutation + group analysis)
  robustness/  evasion.py  ← NOVEL: Evasion-Cost Map + ERS
  structural/  reachability.py ← NOVEL: Trigger-Reachability Analyzer
  features/    extract.py (CIC-compatible features from a raw PDF)
  reporting/   report.py (safe HTML/JSON risk report)
  core/        analyze.py (reconciles count-model + reachability), config.py
  main.py      FastAPI app
scripts/       train_baseline, compare_models, shap, make_fixtures,
               run_reachability_corpus, bundle_dashboard_data, build_dashboard
tests/         unit / integration / security  (23 tests)
artifacts/     manifests, models, metrics, explanations  (all real outputs)
docs/          NOVELTY, FACULTY_QA, RESULTS, LIMITATIONS, DEMO_SCRIPT, ...
```

## Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt           # lightgbm, shap, fastapi, pikepdf, pandas, ...
export PYTHONPATH=.
```

## Reproduce every result
```bash
python scripts/train_baseline.py            # baseline + bootstrap CIs
python backend/explainability/shap_engine.py
python scripts/compare_models.py            # structure-first + evasion (both models)
python scripts/make_fixtures.py             # harmless crafted PDFs
python scripts/run_reachability_corpus.py   # reachability over 39 PDFs
python scripts/bundle_dashboard_data.py
python scripts/build_dashboard.py           # rebuild frontend/dashboard.html
```

## Run the live product
```bash
uvicorn backend.main:app --reload
# POST a PDF:
curl -F file=@tests/fixtures/crafted/fixture_active_buried.pdf http://127.0.0.1:8000/api/analyze
curl -F file=@tests/fixtures/crafted/fixture_dormant.pdf      http://127.0.0.1:8000/api/report.html
```

## Tests
```bash
pytest -q        # 23 passed
```

## Data acquisition
The CIC-Evasive-PDFMal2022 feature CSV is included under `data/raw/`. The full
EMBER2024 dataset (for an optional cross-dataset check) is hosted on HuggingFace;
it was **unreachable** from the build environment, so that comparison is marked
BLOCKED in `docs/LIMITATIONS.md`. To add it later:
`pip install thrember && python -c "import thrember; thrember.download_dataset('<dir>')"`.

## Safety
Uploaded PDFs are treated as hostile: parsed statically, never executed,
rendered, or have attachments/URLs opened. Size/object/time guards enforced; HTML
reports escape all untrusted strings (security tests cover this).
