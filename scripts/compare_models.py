"""
Train the 'structure-first' detector and compare it head-to-head with the
keyword-reliant baseline on BOTH clean accuracy and evasion resilience.

Thesis test: dropping the fragile raw keyword-count features costs little or
nothing in clean benchmark accuracy, but makes the detector substantially
harder to evade.
"""
from __future__ import annotations
import json
import numpy as np
from backend.core.config import load_config, art
from backend.data.ingest import load_dataset
from backend.data.splits import make_split
from backend.models.baseline import train_lgbm, save_model, load_model
from backend.evaluation.metrics import point_metrics, bootstrap_ci, paired_bootstrap, curves
from backend.robustness import evasion

# raw keyword counts + their raw aggregates the author can trivially edit
FRAGILE = {"JS", "Javascript", "AA", "OpenAction", "Acroform", "JBIG2Decode",
           "RichMedia", "launch", "EmbeddedFile", "XFA", "js_total", "autoexec_tokens"}


def main():
    cfg = load_config()
    X, y, rep = load_dataset(cfg)
    tr, te, split = make_split(X, y, cfg)
    yv = y.values
    thr = cfg["model"]["decision_threshold"]

    # structure-first feature set
    sf_cols = [c for c in X.columns if c not in FRAGILE]

    # baseline (reuse if present)
    try:
        b_boost, b_prov = load_model("baseline")
    except Exception:
        b_boost, bc, bs = train_lgbm(X.iloc[tr], yv[tr], cfg)
        b_prov = save_model(b_boost, bc, {"train_seconds": round(bs, 2),
                            "feature_set": "all"}, "baseline")

    # structure-first
    s_boost, s_cols, s_sec = train_lgbm(X.iloc[tr], yv[tr], cfg, feature_subset=sf_cols)
    s_prov = save_model(s_boost, s_cols, {"train_seconds": round(s_sec, 2),
                        "feature_set": "structure_first",
                        "dropped_features": sorted(FRAGILE)}, "structure_first")

    # clean metrics
    b_scores = b_boost.predict(X.iloc[te][b_prov["features"]].values)
    s_scores = s_boost.predict(X.iloc[te][s_cols].values)
    b_pm = point_metrics(yv[te], b_scores, thr)
    s_pm = point_metrics(yv[te], s_scores, thr)
    b_pr = bootstrap_ci(yv[te], b_scores, "pr_auc", cfg["evaluation"]["bootstrap_replicates"])
    s_pr = bootstrap_ci(yv[te], s_scores, "pr_auc", cfg["evaluation"]["bootstrap_replicates"])
    paired = paired_bootstrap(yv[te], b_scores, s_scores, "pr_auc",
                              cfg["evaluation"]["bootstrap_replicates"])
    s_curves = curves(yv[te], s_scores)

    # evasion resilience for both
    b_ev = evasion.run("baseline", cfg)
    s_ev = evasion.run("structure_first", cfg)

    comp = {
        "clean": {
            "baseline": {"pr_auc": b_pm["pr_auc"], "roc_auc": b_pm["roc_auc"],
                         "f1": b_pm["f1"], "recall": b_pm["recall"],
                         "precision": b_pm["precision"], "pr_auc_ci": [b_pr["ci_low"], b_pr["ci_high"]]},
            "structure_first": {"pr_auc": s_pm["pr_auc"], "roc_auc": s_pm["roc_auc"],
                                "f1": s_pm["f1"], "recall": s_pm["recall"],
                                "precision": s_pm["precision"], "pr_auc_ci": [s_pr["ci_low"], s_pr["ci_high"]]},
            "paired_pr_auc_delta": paired,
        },
        "evasion": {
            "baseline": {"ers": b_ev["evasion_resilience_score"],
                         "median_cost": b_ev["evasion_cost"]["median"],
                         "n_caught": b_ev["n_caught_evaluated"], "n_evaded": b_ev["n_evaded"]},
            "structure_first": {"ers": s_ev["evasion_resilience_score"],
                                "median_cost": s_ev["evasion_cost"]["median"],
                                "n_caught": s_ev["n_caught_evaluated"], "n_evaded": s_ev["n_evaded"]},
        },
        "structure_first_curves": s_curves,
        "dropped_features": sorted(FRAGILE),
        "structure_first_features": s_cols,
    }
    with open(art("metrics", "model_comparison.json"), "w") as f:
        json.dump(comp, f, indent=2)

    print(f"CLEAN PR-AUC   baseline={b_pm['pr_auc']:.4f}  structure_first={s_pm['pr_auc']:.4f}  "
          f"delta={paired['delta']:+.4f} (CI {paired['ci_low']:+.4f},{paired['ci_high']:+.4f})")
    print(f"EVASION ERS    baseline={b_ev['evasion_resilience_score']:.3f}  "
          f"structure_first={s_ev['evasion_resilience_score']:.3f}")
    print(f"MEDIAN COST    baseline={b_ev['evasion_cost']['median']}  "
          f"structure_first={s_ev['evasion_cost']['median']}")


if __name__ == "__main__":
    main()
