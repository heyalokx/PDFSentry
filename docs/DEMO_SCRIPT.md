# Demo script

## 3-minute version (dashboard only)
1. **Overview.** "This detector scores PR-AUC 0.9995 — effectively perfect. Watch
   the fourth tile." Point to **ERS 33%**. "Two out of three malware it catches
   can be evaded. Benchmark accuracy hid that."
2. **Evasion collapse.** "For every caught sample we search for the cheapest
   author-side edit that flips it. 536 of 800 evade, median **3 edits**, and the
   fragile features are exactly the keyword counts the model trusts."
3. **Reachability.** Point to the crafted-fixtures table: "A byte counter sees the
   same `/JavaScript` count on all four — reachability tells auto-run from
   dormant from buried." Then `GeoTopo.pdf`: "Real file, URI runs on open, byte
   count **zero** — hidden in a compressed stream. Counting is blind; reachability
   isn't."
4. **One-liner close:** read the bold line at the bottom of `NOVELTY.md`.

## 8–10-minute version (adds the live product)
5. **Investigate tab** — walk the four precomputed analyses; stop on *Dormant*:
   "the count-model cries malicious 1.000; reachability says dormant — a false
   positive reachability would cut."
6. **Live backend:**
   ```bash
   uvicorn backend.main:app --reload
   curl -F file=@tests/fixtures/crafted/fixture_active_buried.pdf \
        http://127.0.0.1:8000/api/analyze | python -m json.tool
   ```
   Show `risk_band: HIGH`, `javascript ACTIVE_ONOPEN`, `naive_count 0`.
7. **Explainability tab** — "SHAP and permutation importance independently agree
   on the fragile features — the explanation and the attack map point to the same
   place."
8. **Method & limits tab** — be upfront: EMBER blocked, reachability demonstrated
   not yet trained at scale, evasion is a lower bound.
9. **Reset / reproduce:** `pytest -q` (23 pass); any `scripts/*.py` re-runs its
   artifact.

## Likely questions → see FACULTY_QA.md
