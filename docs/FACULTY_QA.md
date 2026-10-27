# Faculty Q&A — evidence-based answers

**Q. Did you reproduce the EMBER2024 baseline you cited in Review 2?**
Yes, on the authors' released PDF model and their protocol: ordinary ROC/PR
0.9913/0.9933 (published 0.9912/0.9933), evasive challenge 0.9075/0.7864
(published 0.9066/0.7841). The baseline is verified, not assumed. See
`scripts/reproduce_ember.py` and `artifacts/metrics/ember_reproduction.json`.

**Q. What is genuinely new, versus just reproducing the benchmark?**
The reachability feature family (O3) and the result that it closes the evasive gap
(O4). Reproduction is the control. See `NOVELTY.md`.

**Q. Why does the detector miss evasive malware? (O2)**
SHAP on the real EMBER model shows it spends ~60% of its attention on string
features, ~29% on the byte histogram, ~9% on byte-entropy, and ~0% on structure.
Crucially the malware it *misses* and the malware it *catches* have nearly
identical family profiles — so once an evasive file looks byte/string-normal, the
model has no structural evidence left. The gap is a structural blind spot.

**Q. What is "reachability" and why is it robust?**
We parse the object graph and decide whether a dangerous action (JavaScript,
Launch, SubmitForm, EmbeddedFile…) is reachable from an automatic trigger
(`/OpenAction`, `/AA`, `/Names/JavaScript`), in how many hops, and whether it is
hidden from the byte scan. It is robust because it tracks functional necessity: an
attack that must auto-run cannot remove its reachable trigger path. Burying or
compressing tokens defeats a byte/string detector; it does not defeat reachability.

**Q. Show me the headline result. (O4)**
We took 300 real benign PDFs EMBER is confident about and weaponized each with a
reachable auto-run action hidden in a compressed stream. 99.3% still scored benign
on the real EMBER model; reachability caught 100%. Fusing reachability with the
EMBER score lifts separation of safe-vs-weaponized from AUC 0.649 to 0.998
(5-fold CV). `scripts/structural_evasion_study.py`.

**Q. Isn't injecting your own payload cheating? It's not real malware.**
The weaponized file is genuinely dangerous — it auto-runs code on open; that is a
real attack vector. We use a harmless payload for safety, but the evasion
*mechanism* (hiding the action in a compressed object stream) is payload-agnostic:
it removes the giveaway strings for *any* JavaScript, which is exactly why real
evasive malware uses it. This is the EvadeML-style controlled evasion methodology
Review 2 cites. We state the scope plainly in `LIMITATIONS.md`.

**Q. Could you not just retrain EMBER with structural features on the challenge set?**
Not directly: EMBER releases the 805 challenge PDFs as feature vectors, not raw
files, and reachability needs the object graph. That is why we demonstrate the
augmentation on real PDFs we control, against the real model. Obtaining the raw
challenge PDFs (VirusTotal-gated) is the natural next step.

**Q. Why PR-AUC primary?**
It reflects positive-class (malicious) performance and degrades under false
positives at low prevalence — the deployed-scanner regime. We report ROC-AUC, F1,
precision, recall and confusion matrices too. PR-AUC is average precision
(documented), not trapezoidal, to avoid the AP-vs-AUC ambiguity.

**Q. What about the mimicry probe you promised as O6?**
Done, on the CIC feature set: a 0.9995-PR-AUC count-based detector is evaded on
67% of caught malware at a median of 3 feature edits, and dropping the keyword
counts barely changes resilience (0.33 → 0.345, ΔPR-AUC not significant) — so
counting is structurally fragile and feature selection doesn't fix it.

**Q. How is the uploaded PDF kept safe?**
Parsed statically with pikepdf; JavaScript is never executed, launch/embedded
payloads never opened, URLs never contacted, the file never rendered. Size, object
and time guards; malformed/encrypted files handled without crashing (tested). HTML
reports escape all untrusted strings (security tests).

**Q. Which objectives are complete, and what's left?**
O1 reproduced; O2 done; O3 reachability family built; O4 augmentation shown on the
real model; O6 mimicry probe done; O7 risk report + live workbench done. Left:
validate reachability on raw wild evasive PDFs (needs a raw, labelled corpus).
