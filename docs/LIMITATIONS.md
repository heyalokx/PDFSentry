# Limitations and honest scope

1. **Weaponized samples are controlled, not wild malware.** The structural-evasion
   study injects a *harmless* reachable payload (`app.alert`) into real benign
   PDFs and hides it in a compressed stream. This is a standard evasion-study
   methodology (cf. EvadeML, cited in Review 2), and the evasion *mechanism*
   (compression-based token hiding) is real and payload-agnostic — it hides any
   JavaScript content from a byte/string scanner. But we do not claim to have
   tested against a corpus of wild evasive malware. Nothing is ever executed.

2. **EMBER's 805 challenge PDFs are released as features, not raw files.** So
   reachability (which needs the object graph) cannot be computed on them
   directly. The augmentation result is therefore demonstrated on real PDFs we
   control, scored by the real EMBER model — not on the 805 challenge files
   themselves. Closing this would require the raw challenge PDFs (VirusTotal-gated,
   not publicly released).

3. **The fusion result separates safe vs weaponized, not wild-malicious vs benign.**
   AUC 0.998 is for the controlled task. It demonstrates that reachability supplies
   the discriminative signal EMBER lacks; it is not a drop-in replacement
   benchmark number for a production detector.

4. **The mimicry probe (CIC) is feature-space and a lower bound.** Edits are
   realistic author-side moves on integer counts; a real attacker has options we
   don't model.

5. **Reachability resolves most but not all object structures.** Encrypted PDFs
   (no key), heavily malformed files and deeply nested name trees can defeat the
   parser; these are reported as parse failures, not silently scored.

6. **SHAP attributes model behaviour, not causation or intent.** Cross-checked
   with permutation importance on the CIC model; on EMBER it is used as a
   comparative family-level diagnostic.

7. **Static only.** No dynamic/sandbox analysis. A clean result never proves a file
   is safe; a flagged result is evidence, not proof.
