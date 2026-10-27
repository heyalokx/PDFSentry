# Faculty Q&A — evidence-based answers

**Q. What is genuinely novel here? Isn't this just the EMBER/CIC baseline again?**
No. The baseline is a control, not the contribution. The contribution is (1) the
Evasion-Cost Map with an Evasion-Resilience Score, which quantifies how much
caught malware an author could trivially reclaim, and (2) the Trigger-
Reachability Analyzer, which replaces token *counting* with structural
*reachability*. See `NOVELTY.md`. Every count-based PDF detector in the
literature stops at an AUC on a fixed split; we measure the fragility behind
that AUC and build a signal that survives it.

**Q. Your baseline is 99.9% PR-AUC. Why isn't that the result?**
Because it's the setup, not the finding. The finding is that the same detector
is evaded on 67% of caught malware at a median of 3 feature edits. High
benchmark accuracy and evasion resilience are different axes; the standard
evaluation only ever reports the first.

**Q. Is the evasion search just adversarial examples?**
It is a *constrained, interpretable* counterfactual search in feature space,
designed to be realistic rather than minimal-Lp. Edits are limited to moves an
author actually controls (remove capability tokens, adjust cosmetic fields),
counts stay non-negative, and derived features recompute after each edit so an
attacker can't desynchronise a derived feature from its parents. It is a *lower
bound* on a real attacker's options — we say so in `LIMITATIONS.md`. It never
generates a PDF or a payload; it operates on integer feature vectors.

**Q. Why did the structure-first model barely help (0.33 → 0.345)?**
That negative result *is* evidence. Every count-based feature — raw or derived —
responds to the same author edit (removing tokens), so dropping some doesn't
change the attack surface. It shows robustness needs a different *kind* of
signal, not a different feature subset. Paired bootstrap ΔPR-AUC is not
significant, so we also lose no accuracy by dropping fragile features.

**Q. What does "reachability" actually compute, and why is it robust?**
It parses the object graph and does a BFS from automatic trigger points
(`/OpenAction`, `/AA`, `/Names/JavaScript`, etc.) to each dangerous action,
recording hop distance and whether the trigger is auto or interaction. It is
robust because it tracks functional necessity: an attack that must auto-run
cannot remove its reachable trigger path without ceasing to be an attack.
Burying tokens defeats a counter; it does not defeat reachability.

**Q. Show me a case where counting and reachability disagree.**
`GeoTopo.pdf` (real, benign): a URI action is reachable on open, but the raw
byte count of `/URI` is **0** because the tokens live inside compressed object
streams. A byte counter sees nothing; reachability sees it. Conversely
`cropped-rotated-scaled.pdf` has 128 `/URI` tokens but they're only reachable by
clicking a link — reachability correctly downgrades it to interaction-required.
Across the corpus, 7 such disagreements.

**Q. Why PR-AUC as the primary metric?**
The class split is roughly balanced here (55% malicious), but PR-AUC is the
honest primary for detection because it reflects performance on the positive
(malicious) class and degrades visibly under false positives at low prevalence —
the regime a deployed scanner faces. We report ROC-AUC, F1, precision, recall,
accuracy and confusion matrices alongside. PR-AUC is computed as **average
precision** (documented, not trapezoidal) to avoid the known AP-vs-AUC ambiguity.

**Q. How do you prevent data leakage / tuning on the evaluation set?**
Single stratified split (seed 1337, 70/30), split hashes recorded. The evasion
search and SHAP run on the held-out test split; thresholds are fixed at 0.5 and
never tuned on test. No challenge samples are used to fit anything.

**Q. Why static analysis and not a sandbox?**
Scope and safety. Dynamic detonation is explicitly out of scope; everything here
is static. The reachability engine never executes JavaScript, never opens
attachments or URLs, never renders the file. Resource guards bound size, object
count and time; malformed/encrypted inputs are handled without crashing (tested).

**Q. Is SHAP enough on its own?**
No — SHAP explains model behaviour, not attacker intent, and splits credit
across correlated features. We cross-check with permutation importance (computed
independently); the two rankings converge on the same fragile features, which is
why the evasion map and the explanation agree.

**Q. What couldn't you do, honestly?**
Reproduce EMBER2024 (its data is unreachable from the build environment —
BLOCKED, not skipped); add reachability as a trained feature on the full set
(CIC ships counts, not raw PDFs, so reachability is demonstrated on parsed files
and the live analyzer); and temporal drift (CIC has no timestamps). All stated
in `LIMITATIONS.md` and on the dashboard's "Method & limits" view.

**Q. Can I see it work live?**
Yes — `make backend`, then `POST /api/analyze` a PDF, or use the crafted
fixtures. The dashboard's Investigate tab shows four precomputed real analyses.
See `DEMO_SCRIPT.md`.
