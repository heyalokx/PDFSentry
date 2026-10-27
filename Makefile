export PYTHONPATH=.
.PHONY: all pipeline test backend dashboard gate
pipeline:
	python scripts/train_baseline.py
	python backend/explainability/shap_engine.py
	python scripts/compare_models.py
	python scripts/make_fixtures.py
	python scripts/run_reachability_corpus.py
	python scripts/bundle_dashboard_data.py
	python scripts/build_dashboard.py

# EMBER track — needs data/ember/ (PDF_test.zip, challenge.zip extracted;
# EMBER2024_PDF.model) obtained from the EMBER2024 HuggingFace release.
ember:
	python scripts/reproduce_ember.py
	python scripts/ember_shap.py
	python scripts/structural_evasion_study.py
	python scripts/bundle_dashboard_data.py
	python scripts/build_dashboard.py
test:
	python3 -m pytest -q
backend:
	uvicorn backend.main:app --reload
gate:
	python scripts/acceptance_gate.py
