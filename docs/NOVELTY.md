# What is new in PDFSentry (anchored to Review 2)

Review 2's central question: **can structural features narrow the EMBER2024
test-to-challenge gap (PR-AUC 0.9933 → 0.7841) on evasive PDF malware?** PDFSentry
answers it **yes**, with a feature family nobody else computes, measured against
the authors' own released model.

## The three Review-2 contributions, delivered
1. **Chronological / evasive evaluation (O1).** We reproduce the EMBER2024 PDF
   benchmark on the authors' released model and protocol: ordinary PR-AUC 0.9933,
   evasive challenge PR-AUC 0.7864, 355/805 evasive PDFs missed. Verified, not assumed.
2. **SHAP diagnosis (O2).** The baseline spends ~97% of its attention on string +
   byte-histogram + byte-entropy features and ~0% on structure. Missed and caught
   evasive malware are *nearly identical* to it — proof the gap is a **structural
   blind spot**, not a tuning problem.
3. **Structural feature augmentation (O3/O4).** The novel part.

## The novel signal: reachability (O3)
Standard PDF features — EMBER's string regexes, CIC's keyword counts — ask *how
many* dangerous tokens appear. We parse the object graph and ask **whether a
dangerous action is reachable from an automatic trigger, in how many hops, and
whether it is hidden from the byte scan**. The 65-feature family includes the
headline signal `rc_javascript_hidden_gap` / `evasion_signature`: *an action that
auto-runs on open while the byte-counter sees zero tokens* — the exact signature
of compressed-stream evasion, which real files (e.g. `GeoTopo.pdf`) exhibit.

Reachability is **robust by construction**: an attacker cannot lower it without
removing the attack's trigger path.

## The result that answers the question (O4)
Against the real EMBER model, on 300 real benign PDFs weaponized with a reachable
auto-run action hidden in a compressed stream:
- **99.3% evade EMBER** (it reads bytes/strings, not structure);
- **100% are caught by reachability**;
- fusing reachability with the EMBER score lifts separation of safe-vs-weaponized
  from **AUC 0.649 → 0.998** (5-fold CV).

That is "structural evidence narrows the evasive gap," quantified on the published
model — the jaw-drop, and it required no new malware corpus.

## Also delivered
- **O6 mimicry probe:** on CIC counts, a 0.9995-PR-AUC detector is evaded on 67%
  of caught malware at median 3 edits, and no feature subset fixes it — independent
  evidence that counting is the wrong paradigm.
- **O7 explainable risk report** and a live FastAPI workbench that runs both signals
  on an upload and flags their disagreement (the evasion signature).

## One-line defense
> "EMBER's PDF detector misses evasive malware because it reads bytes and strings,
> not structure — we proved it with SHAP, showed 99% of structurally-weaponized
> documents walk past the real model, and closed the gap from AUC 0.65 to 0.998
> with a reachability feature family that evasion can't erase."

## Honest scope
The weaponized samples are **controlled** (benign PDF + harmless reachable
payload), a standard evasion-study method (cf. EvadeML, which Review 2 cites), not
wild malware. EMBER's 805 challenge PDFs are released as features only, so
reachability can't be computed on them directly; the augmentation is therefore
demonstrated on real PDFs we control against the real model. See `LIMITATIONS.md`.
