"""
Real-malware recovery analysis (the confound-free 10/10 result).

Needs only REAL malicious PDFs (a benign set is optional). Of the real evasive
malware the published EMBER model MISSES (scores < 0.5), how many does
reachability flag as carrying a dangerous action reachable on open? That is
recovery of evasive malware EMBER lets through — pure recall on real malware, no
benign-vs-malicious confound.

A "reachability alarm" = a dangerous action reachable on open (rc_n_active_onopen>0)
OR the hidden-in-compressed-stream signature (rc_evasion_signature==1).

If a benign set is present in the CSV, also reports the alarm's benign
false-positive rate and the EMBER+reachability fusion (CV AUC + bootstrap CIs).
Usage: python scripts/recovery_analysis.py --csv features.csv
"""
from __future__ import annotations
import argparse, json
import numpy as np
import pandas as pd
from backend.core.config import art


def alarm(df):
    a = np.zeros(len(df), bool)
    if "rc_n_active_onopen" in df:
        a |= df["rc_n_active_onopen"].fillna(0).values > 0
    if "rc_evasion_signature" in df:
        a |= df["rc_evasion_signature"].fillna(0).values >= 1
    return a


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--csv", required=True)
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()
    df = pd.read_csv(args.csv)
    df["ember_score"] = pd.to_numeric(df["ember_score"], errors="coerce")
    thr = args.threshold

    mal = df[df["label"] == 1].copy()
    es = mal["ember_score"].values
    ra = alarm(mal)
    caught = es >= thr
    missed = ~caught
    recovered = missed & ra

    out = {
        "n_malicious": int(len(mal)),
        "ember_recall": float(caught.mean()),
        "ember_missed": int(missed.sum()),
        "reachability_alarm_rate_overall": float(ra.mean()),
        "recovered_of_missed": int(recovered.sum()),
        "recovery_rate_of_missed": float(recovered.sum() / max(missed.sum(), 1)),
        "combined_recall_ember_or_reach": float((caught | ra).mean()),
    }

    ben = df[df["label"] == 0]
    if len(ben) > 0:
        out["benign"] = {
            "n_benign": int(len(ben)),
            "reachability_false_positive_rate": float(alarm(ben).mean()),
        }
        # optional fusion
        try:
            import lightgbm as lgb
            from sklearn.model_selection import StratifiedKFold
            from backend.evaluation.metrics import bootstrap_ci, paired_bootstrap
            from backend.features.reach_features import FEATURE_NAMES
            feat = ["ember_score"] + [c for c in FEATURE_NAMES if c in df]
            X = df[feat].apply(pd.to_numeric, errors="coerce").fillna(0).values.astype(np.float32)
            y = df["label"].values.astype(int)
            idx = {f: i for i, f in enumerate(feat)}
            skf = StratifiedKFold(5, shuffle=True, random_state=1337)
            oof = np.zeros(len(y))
            P = dict(objective="binary", num_leaves=31, learning_rate=0.05,
                     num_iterations=300, min_data_in_leaf=20, verbosity=-1,
                     seed=1337, is_unbalance=True)
            for tr, te in skf.split(X, y):
                b = lgb.train(P, lgb.Dataset(X[tr], y[tr]))
                oof[te] = b.predict(X[te])
            s_e = X[:, idx["ember_score"]]
            out["fusion"] = {
                "ember_only": bootstrap_ci(y, s_e, "pr_auc", 2000),
                "ember_plus_reach": bootstrap_ci(y, oof, "pr_auc", 2000),
                "paired_pr": paired_bootstrap(y, s_e, oof, "pr_auc", 2000),
                "ember_only_roc": bootstrap_ci(y, s_e, "roc_auc", 2000),
                "ember_plus_reach_roc": bootstrap_ci(y, oof, "roc_auc", 2000),
            }
        except Exception as e:
            out["fusion_error"] = str(e)[:160]

    with open(art("metrics", "recovery_analysis.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps({k: v for k, v in out.items() if k != "fusion"}, indent=2))
    if "fusion" in out:
        fu = out["fusion"]
        print(f"FUSION PR-AUC  ember {fu['ember_only']['estimate']:.4f} -> "
              f"ember+reach {fu['ember_plus_reach']['estimate']:.4f}  "
              f"Δ {fu['paired_pr']['delta']:+.4f} sig={fu['paired_pr']['significant']}")


if __name__ == "__main__":
    main()
