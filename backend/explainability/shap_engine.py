"""
SHAP explanations + permutation-importance cross-check + grouped failure analysis.

SHAP explains MODEL BEHAVIOUR, not attacker intent — this caveat is attached to
every artifact. Permutation importance is computed independently as a sanity check.
"""
from __future__ import annotations
import json
import numpy as np
import pandas as pd
import shap
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score
from backend.core.config import load_config, art
from backend.models.baseline import load_model


CAVEAT = ("SHAP attributions describe how the trained model responds to feature "
          "values. They do not establish that a feature caused maliciousness or "
          "that an attacker intended it. Correlated features share credit.")


def _groups(y_true, y_pred, scores, thr):
    y_true = np.asarray(y_true); y_pred = np.asarray(y_pred); scores = np.asarray(scores)
    return {
        "true_positive": np.where((y_true == 1) & (y_pred == 1))[0],
        "false_negative": np.where((y_true == 1) & (y_pred == 0))[0],  # MISSED malware
        "false_positive": np.where((y_true == 0) & (y_pred == 1))[0],
        "true_negative": np.where((y_true == 0) & (y_pred == 0))[0],
        "borderline": np.where(np.abs(scores - thr) < 0.10)[0],
    }


def run(config: dict | None = None) -> dict:
    cfg = config or load_config()
    from backend.data.ingest import load_dataset
    X, y, _ = load_dataset(cfg)
    booster, prov = load_model("baseline")
    cols = prov["features"]
    pred = np.load(art("metrics", "baseline_predictions.npz"))
    te, y_te, scores = pred["test_idx"], pred["y_test"], pred["scores"]
    thr = cfg["model"]["decision_threshold"]
    y_pred = (scores >= thr).astype(int)
    Xte = X.iloc[te][cols].reset_index(drop=True)

    explainer = shap.TreeExplainer(booster)
    sv = explainer.shap_values(Xte.values)
    if isinstance(sv, list):          # binary -> take positive class
        sv = sv[1]
    sv = np.asarray(sv)

    # global mean |SHAP|
    glob = np.abs(sv).mean(axis=0)
    global_rank = sorted(
        [{"feature": c, "mean_abs_shap": float(v)} for c, v in zip(cols, glob)],
        key=lambda d: -d["mean_abs_shap"])

    # group-level mean |SHAP|
    grp_idx = _groups(y_te, y_pred, scores, thr)
    group_importance = {}
    for gname, idx in grp_idx.items():
        if len(idx) == 0:
            group_importance[gname] = {"n": 0, "top": []}
            continue
        gi = np.abs(sv[idx]).mean(axis=0)
        top = sorted([{"feature": c, "mean_abs_shap": float(v)} for c, v in zip(cols, gi)],
                     key=lambda d: -d["mean_abs_shap"])[:10]
        group_importance[gname] = {"n": int(len(idx)), "top": top}

    # rank-shift: caught vs missed malware
    def rankmap(idx):
        gi = np.abs(sv[idx]).mean(axis=0)
        order = np.argsort(-gi)
        return {cols[j]: r for r, j in enumerate(order)}
    rank_shift = []
    if len(grp_idx["true_positive"]) and len(grp_idx["false_negative"]):
        rc, rm = rankmap(grp_idx["true_positive"]), rankmap(grp_idx["false_negative"])
        for c in cols:
            rank_shift.append({"feature": c, "rank_caught": rc[c], "rank_missed": rm[c],
                               "shift": rc[c] - rm[c]})
        rank_shift.sort(key=lambda d: d["shift"])  # features that drop most when missed

    # permutation importance cross-check (ROC-AUC drop)
    def _score(_est, Xv, yv):
        return roc_auc_score(yv, booster.predict(Xv))
    class _Wrap:  # sklearn estimator shim
        def fit(self, *a, **k): return self
        def predict(self, Xv): return booster.predict(Xv)
    perm = permutation_importance(
        _Wrap(), Xte.values, y_te, scoring=_score, n_repeats=10,
        random_state=cfg["project"]["seed"], n_jobs=1)
    perm_rank = sorted(
        [{"feature": c, "importance": float(m), "std": float(s)}
         for c, m, s in zip(cols, perm.importances_mean, perm.importances_std)],
        key=lambda d: -d["importance"])

    # a few representative per-sample explanations (one per group)
    samples = []
    base_val = float(np.ravel(explainer.expected_value)[-1])
    for gname in ["true_positive", "false_negative", "false_positive"]:
        idx = grp_idx[gname]
        if len(idx) == 0:
            continue
        i = int(idx[len(idx) // 2])
        contribs = sorted([{"feature": c, "shap": float(sv[i, j]),
                            "value": float(Xte.values[i, j])}
                           for j, c in enumerate(cols)],
                          key=lambda d: -abs(d["shap"]))[:8]
        samples.append({"group": gname, "row": i, "score": float(scores[i]),
                        "base_value": base_val, "top_contributions": contribs})

    out = {
        "caveat": CAVEAT, "model_hash": prov["model_hash"],
        "global_importance": global_rank,
        "group_importance": group_importance,
        "rank_shift_caught_vs_missed": rank_shift,
        "permutation_importance": perm_rank,
        "sample_explanations": samples,
        "base_value": base_val,
    }
    with open(art("explanations", "shap_analysis.json"), "w") as f:
        json.dump(out, f, indent=2)
    return out


if __name__ == "__main__":
    o = run()
    print("top global:", [d["feature"] for d in o["global_importance"][:8]])
    print("perm top:", [d["feature"] for d in o["permutation_importance"][:8]])
    print("missed-malware FN count:", o["group_importance"]["false_negative"]["n"])
