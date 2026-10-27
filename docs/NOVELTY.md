# What is genuinely new in PDFSentry

**Thesis — "Reachability over Recognition."**
Mainstream static PDF-malware detectors — the CIC-Evasive-PDFMal2022 feature
set, the EMBER v3 string-regex features, pdfid-style tools — represent a
document as a **bag of keyword counts**: how many `/JavaScript`, `/OpenAction`,
`/Launch`, `/EmbeddedFile` tokens appear. PDFSentry's contribution is to show,
with measurements on real data, that this representation is **evasion-fragile by
construction**, and to build a signal that is not.

The project has two original components and one original evaluation metric.

## 1. The Evasion-Cost Map (diagnostic)
For every malicious file the detector *catches*, a constrained, feature-space
counterfactual search finds the cheapest set of realistic author-side edits
(removing capability tokens, trimming metadata) that flips the verdict to
benign. Derived features recompute after every edit, so nothing can be gamed in
isolation. Aggregated, this yields:

- an **Evasion-Resilience Score (ERS)** — the fraction of caught malware that
  *cannot* be evaded within a bounded edit budget; and
- a **per-feature fragility ranking** — how often, and how cheaply, each feature
  participates in a successful evasion.

Why it's novel: PDF-malware papers report accuracy/AUC on a fixed split. They do
not quantify *how much of the caught malware a motivated author could trivially
reclaim*, nor rank features by evasion cost. The Review-2 plan's optional O6
("mimicry robustness probe") is a single bullet; this is a full, reproducible
diagnostic with a headline number.

**Measured result:** a LightGBM detector with **PR-AUC 0.9995 / ROC-AUC 0.9994 /
F1 0.991** is evaded on **67% of the malware it catches (ERS = 0.33)** at a
**median of 3 edits**, and the fragile features are exactly the keyword counts
(`Javascript`, `metadata size`, `JS`, `OpenAction`). A control detector that
drops the raw keyword counts keeps the same clean accuracy (paired ΔPR-AUC not
significant) and barely improves resilience (0.33 → 0.345) — proving you cannot
*feature-select* your way out of the count paradigm.

## 2. The Trigger-Reachability Analyzer (the robust signal)
A static object-graph engine that answers what a count cannot: **is a dangerous
action reachable from an automatic trigger point, and in how many hops?** It
walks the reference graph from `/OpenAction`, document and page `/AA`,
`/Names/JavaScript`, `/AcroForm`, and annotation actions, tags each trigger
**auto** (fires on open) or **interaction** (needs a click), and classifies each
capability as `ACTIVE_ONOPEN`, `ACTIVE_ONINTERACT`, `PRESENT_DORMANT`, or
`ABSENT`. It also records the naive byte-count a counter would report, for
direct contrast.

Why it's novel and why it's *robust*: reachability tracks **functional
necessity**. An author can bury or split tokens to fool a counter, but cannot
make an attack work without leaving a reachable auto-trigger path. The same edit
that defeats a count-based detector does **not** defeat reachability.

**Measured result:** across 39 real + crafted PDFs the two views disagree in
**7 cases** — 4 where a counter over-alarms (many tokens, nothing auto-runs) and
3 where it under-alarms (auto-runs, tokens hidden in compressed object streams,
e.g. `GeoTopo.pdf`: a URI action reachable on open with **byte-count 0**). Four
harmless crafted fixtures are byte-identical to a counter yet separate cleanly
under reachability.

## 3. The reconciled product
The live analyzer runs the fragile count-model and the robust reachability
engine on an upload and raises its loudest alarm precisely when they
**disagree** (count says calm, an action auto-runs) — the operational signature
of token-evasion. That reconciliation, driven by two independently-justified
signals, is the deliverable a reviewer can see working.

## One-line defense
> "Our 99.9%-AUC detector can be evaded on two-thirds of the malware it catches
> by changing three fields, and no feature subset fixes it — so we built a
> reachability signal that measures whether an attack can actually fire, and
> showed it catches exactly the cases counting misses."
