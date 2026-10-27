"""
Evasion-Cost Map + Evasion-Resilience Score  (the core novel contribution).

For every malicious PDF the detector CATCHES, we run a constrained,
feature-space counterfactual search for the cheapest set of author-side edits
that flips the verdict to benign. This is done ENTIRELY in feature space on
harmless integer counts — no PDF is generated, no payload is produced, no
exploit is described. It answers a question raw benchmark accuracy cannot:

    "How many of the malware we catch could a motivated author evade,
     and how expensive is each evasion?"

Edits respect realistic author-side constraints:
  * capability token counts (JS, /OpenAction, /Launch, ...) may only be REDUCED
    toward 0 (an author can remove/bury a feature, not conjure negative tokens);
  * cosmetic fields (metadata size, title characters) may move to the benign
    median;
  * derived features (js_total, autoexec_tokens, keyword_concentration, deltas,
    content_density) are RECOMPUTED after every edit, so an attacker cannot
    cheat by editing a derived feature independently of its parents;
  * structural-integrity fields (obj/endobj/stream counts) are NOT freely
    editable — desynchronising them is itself a detectable malformation.

Cost = number of distinct features the author must modify to evade.
Evasion-Resilience Score (ERS) = fraction of caught malware that CANNOT be
evaded within the search budget.
"""
from __future__ import annotations
import json
import numpy as np
import pandas as pd
from backend.core.config import load_config, art


def recompute_derived(v: dict, keyword_cols) -> dict:
    """Keep derived features consistent after raw edits (mirrors ingest.py)."""
    def g(k): return float(v.get(k, 0.0))
    v["obj_endobj_delta"] = abs(g("obj") - g("endobj"))
    v["stream_endstream_delta"] = abs(g("stream") - g("endstream"))
    v["js_total"] = max(g("JS"), 0) + max(g("Javascript"), 0)
    v["autoexec_tokens"] = max(g("OpenAction"), 0) + max(g("AA"), 0) + max(g("launch"), 0)
    v["content_density"] = g("pdfsize") / (abs(g("obj")) + 1.0)
    kw_sum = sum(max(g(c), 0) for c in keyword_cols)
    v["keyword_concentration"] = kw_sum / (abs(g("obj")) + 1.0)
    return v


class EvasionProbe:
    """The attacker edits the FULL author-side feature space (raw tokens +
    cosmetic fields); each model is scored only on the features it actually
    uses. This keeps the fight fair across models with different feature sets:
    removing JS tokens lowers derived features (e.g. keyword_concentration)
    even for a model that never sees the raw JS count."""

    def __init__(self, booster, model_cols, all_cols, cfg, benign_median: dict):
        self.booster = booster
        self.model_cols = model_cols      # features the model scores on
        self.all_cols = all_cols          # full author-editable feature space
        self.thr = cfg["model"]["decision_threshold"]
        self.budget = cfg["evasion"]["budget_steps"]
        self.keyword_cols = cfg["feature_groups"]["keyword_capability"]
        self.controllable = [c for c in cfg["evasion"]["attacker_controllable"] if c in all_cols]
        self.cosmetic = {"metadata size", "title characters"}
        self.benign_median = benign_median

    def _score(self, v: dict) -> float:
        x = np.array([[v[c] for c in self.model_cols]], dtype=np.float32)
        return float(self.booster.predict(x)[0])

    def _target(self, feat, cur):
        if feat in self.cosmetic:
            return float(self.benign_median.get(feat, 0.0))
        return 0.0  # capability tokens -> removed

    def probe(self, row: dict):
        v = dict(row)
        v = recompute_derived(v, self.keyword_cols)
        s0 = self._score(v)
        if s0 < self.thr:
            return {"caught": False}  # not caught to begin with; skip
        edited, changed = set(), []
        score = s0
        for _ in range(self.budget):
            best = None
            for feat in self.controllable:
                if feat in edited:
                    continue
                tgt = self._target(feat, v[feat])
                if abs(v[feat] - tgt) < 1e-9:
                    continue
                trial = dict(v); trial[feat] = tgt
                trial = recompute_derived(trial, self.keyword_cols)
                sc = self._score(trial)
                if best is None or sc < best[1]:
                    best = (feat, sc, tgt)
            if best is None:
                break
            feat, sc, tgt = best
            v[feat] = tgt
            v = recompute_derived(v, self.keyword_cols)
            edited.add(feat); changed.append({"feature": feat, "to": tgt, "score_after": sc})
            score = sc
            if score < self.thr:
                return {"caught": True, "evaded": True, "cost": len(edited),
                        "start_score": s0, "end_score": score, "edits": changed}
        return {"caught": True, "evaded": False, "cost": None,
                "start_score": s0, "end_score": score, "edits": changed}


def run(model_name: str, config: dict | None = None) -> dict:
    cfg = config or load_config()
    from backend.data.ingest import load_dataset
    from backend.models.baseline import load_model
    from backend.data.splits import make_split
    X, y, _ = load_dataset(cfg)
    booster, prov = load_model(model_name)
    cols = prov["features"]
    tr, te, _ = make_split(X, y, cfg)
    yv = y.values

    all_cols = list(X.columns)
    benign_median = X.iloc[tr][yv[tr] == 0].median().to_dict()
    probe = EvasionProbe(booster, cols, all_cols, cfg, benign_median)

    # caught malware in the TEST split
    scores_all = booster.predict(X.iloc[te][cols].values)
    thr = cfg["model"]["decision_threshold"]
    caught_mask = (yv[te] == 1) & (scores_all >= thr)
    caught_rows = np.array(te)[caught_mask]
    rng = np.random.default_rng(cfg["project"]["seed"])
    n = min(cfg["evasion"]["samples_analyzed"], len(caught_rows))
    sample_rows = rng.choice(caught_rows, n, replace=False)

    results, costs, feat_use = [], [], {}
    evaded = 0
    for r in sample_rows:
        row = X.iloc[int(r)][all_cols].to_dict()
        res = probe.probe(row)
        if not res.get("caught"):
            continue
        results.append(res)
        if res["evaded"]:
            evaded += 1
            costs.append(res["cost"])
            for e in res["edits"]:
                feat_use[e["feature"]] = feat_use.get(e["feature"], 0) + 1
    n_eval = len(results)
    ers = 1.0 - evaded / n_eval if n_eval else float("nan")
    costs = np.array(costs) if costs else np.array([])

    # fragility ranking: how often a feature appears in a successful evasion
    fragility = sorted(
        [{"feature": f, "used_in_evasions": c, "share": c / max(evaded, 1)}
         for f, c in feat_use.items()], key=lambda d: -d["used_in_evasions"])

    out = {
        "model": model_name, "model_hash": prov["model_hash"],
        "n_caught_evaluated": n_eval,
        "n_evaded": int(evaded),
        "evasion_resilience_score": float(ers),
        "evasion_cost": {
            "mean": float(costs.mean()) if costs.size else None,
            "median": float(np.median(costs)) if costs.size else None,
            "min": int(costs.min()) if costs.size else None,
            "max": int(costs.max()) if costs.size else None,
            "hist": {str(int(k)): int(v) for k, v in
                     zip(*np.unique(costs, return_counts=True))} if costs.size else {},
        },
        "feature_fragility": fragility,
        "budget_steps": cfg["evasion"]["budget_steps"],
        "controllable_features": probe.controllable,
    }
    with open(art("metrics", f"evasion_{model_name}.json"), "w") as f:
        json.dump(out, f, indent=2)
    return out


if __name__ == "__main__":
    o = run("baseline")
    print(f"ERS={o['evasion_resilience_score']:.3f}  caught={o['n_caught_evaluated']} "
          f"evaded={o['n_evaded']}  median_cost={o['evasion_cost']['median']}")
    print("most fragile:", [f["feature"] for f in o["feature_fragility"][:6]])
