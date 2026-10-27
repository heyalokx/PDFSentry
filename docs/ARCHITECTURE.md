# Architecture
Three products on one codebase (see README for the tree):
- **Research pipeline** (scripts/ + backend/{data,models,evaluation,explainability,robustness}):
  deterministic, provenance-tracked experiments writing JSON artifacts.
- **Live workbench** (backend/{features,structural,core,reporting} + main.py):
  upload → static reachability + count-model → reconciled risk + safe report.
- **Dashboard** (frontend/dashboard.html): self-contained, embeds the real result JSON.
Modules are independently testable; the structural analyzer and the model are decoupled
so either runs without the other. Safety guards live in backend/structural/reachability.py.
