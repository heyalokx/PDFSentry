"""
The 10/10 result: train and ablate on REAL labelled PDFs (features.csv from
extract_corpus_features.py). Shows whether reachability lifts detection of real
(evasive) malware over the EMBER byte/string score, with cross-validation and
bootstrap confidence intervals.

Ablation:
  A  EMBER score alone
  B  reachability features alone
  C  EMBER + reachability (fusion)
Reports 5-fold CV ROC-AUC and PR-AUC with 95% bootstrap CIs, and a paired
bootstrap test that C > A.

Usage: python scripts/train_augmented_real.py --csv features.csv
"""
from __future__ import annotations
import argparse, json
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from backend.evaluation.metrics import bootstrap_ci, paired_bootstrap
from backend.features.reach_features import FEATURE_NAMES
from backend.core.config import art


def cv_scores(X, y, cols, seed=1337):
    skf = StratifiedKFold(5, shuffle=True, random_state=seed)
    oof = np.zeros(len(y))
    params = dict(objective="binary", num_leaves=31, learning_rate=0.05,
                  num_iterations=300, min_data_in_leaf=20, verbosity=-1, seed=seed,
                  is_unbalance=True)
    for tr, te in skf.split(X, y):
        b = lgb.train(params, lgb.Dataset(X[tr][:, cols], y[tr]))
        oof[te] = b.predict(X[te][:, cols])
    return oof


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--csv", required=True)
    args = ap.parse_args()
    df = pd.read_csv(args.csv)
    y = df["label"].values.astype(int)
    feat = ["ember_score"] + FEATURE_NAMES
    X = df[feat].apply(pd.to_numeric, errors="coerce").fillna(0.0).values.astype(np.float32)
    idx = {f: i for i, f in enumerate(feat)}
    ember_c = [idx["ember_score"]]
    reach_c = [idx[f] for f in FEATURE_NAMES]
    all_c = list(range(len(feat)))

    # EMBER score alone is just the score (no model needed)
    s_ember = X[:, idx["ember_score"]]
    s_reach = cv_scores(X, y, reach_c)
    s_fusion = cv_scores(X, y, all_c)

    def block(name, s):
        return {"model": name,
                "roc_auc": bootstrap_ci(y, s, "roc_auc", 2000),
                "pr_auc": bootstrap_ci(y, s, "pr_auc", 2000)}

    out = {
        "n_malicious": int((y == 1).sum()), "n_benign": int((y == 0).sum()),
        "A_ember_only": block("EMBER score alone", s_ember),
        "B_reachability_only": block("reachability only", s_reach),
        "C_fusion": block("EMBER + reachability", s_fusion),
        "paired_fusion_vs_ember_pr": paired_bootstrap(y, s_ember, s_fusion, "pr_auc", 2000),
        "paired_fusion_vs_ember_roc": paired_bootstrap(y, s_ember, s_fusion, "roc_auc", 2000),
    }
    with open(art("metrics", "augmented_real.json"), "w") as f:
        json.dump(out, f, indent=2)
    for k in ["A_ember_only", "B_reachability_only", "C_fusion"]:
        b = out[k]
        print(f"{b['model']:24s} ROC {b['roc_auc']['estimate']:.4f} "
              f"[{b['roc_auc']['ci_low']:.4f},{b['roc_auc']['ci_high']:.4f}]   "
              f"PR {b['pr_auc']['estimate']:.4f} "
              f"[{b['pr_auc']['ci_low']:.4f},{b['pr_auc']['ci_high']:.4f}]")
    p = out["paired_fusion_vs_ember_pr"]
    print(f"fusion - ember  ΔPR {p['delta']:+.4f}  CI [{p['ci_low']:+.4f},{p['ci_high']:+.4f}]  "
          f"significant={p['significant']}")


if __name__ == "__main__":
    main()
