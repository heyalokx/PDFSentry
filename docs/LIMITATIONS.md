# Limitations and honest scope

1. **EMBER2024 reproduction — BLOCKED.** The EMBER2024 features/models are hosted
   on HuggingFace, which is unreachable from the build environment (proxy denies
   `huggingface.co`). We therefore do **not** reproduce the published
   PDF-only benchmark (0.9912/0.9933 ordinary, 0.9066/0.7841 challenge). Those
   numbers are reference values only and appear nowhere as our results. The
   official `thrember` code is vendored and the loader interface is implemented,
   so the comparison can be run later verbatim.

2. **Reachability is not yet a trained feature on the full dataset.** CIC-PDFMal2022
   ships *feature counts*, not raw PDFs, so we cannot compute reachability for its
   10k rows. Reachability is demonstrated on 39 real + crafted PDFs and in the
   live analyzer. The quantitative robustness argument on the tabular side is the
   evasion-cost map (which proves the count paradigm is fragile); the reachability
   robustness claim is demonstrated structurally, not yet trained-and-scored at
   scale. Closing this needs a raw-PDF corpus with labels.

3. **Temporal drift — not available.** CIC has no timestamps, so the EMBER-style
   temporal challenge/drift analysis cannot be done here. We do not fabricate a
   time series.

4. **The evasion search is a lower bound.** It is a constrained, realistic
   feature-space counterfactual, not a complete adversarial evaluation. A real
   attacker has moves we don't model (and some we model may be impractical). ERS
   should be read as "at least this evadable," not an exact security guarantee.

5. **CIC-compatible live extraction is approximate.** The original CIC features
   came from a specific pdfid-style tool; `backend/features/extract.py`
   reconstructs them and may differ in edge cases. The live model score carries
   this caveat; the reachability verdict does not depend on it.

6. **SHAP attributes model behaviour, not causation or intent.** Correlated
   features share credit; permutation importance is reported as an independent
   cross-check.

7. **Static only.** No dynamic/sandbox analysis. A clean result never proves a
   file is safe; a flagged result is evidence, not proof.
