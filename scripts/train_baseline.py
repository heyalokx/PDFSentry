"""Train the baseline detector and run full evaluation with bootstrap CIs."""
from __future__ import annotations
import json
import numpy as np
from backend.core.config import load_config, art
from backend.data.ingest import load_dataset, write_manifest
from backend.data.splits import make_split
from backend.models.baseline import train_lgbm, save_model
from backend.evaluation.metrics import point_metrics, bootstrap_ci, curves


def main():
    cfg = load_config()
    X, y, rep = load_dataset(cfg)
    write_manifest(rep)
    tr, te, split = make_split(X, y, cfg)
    yv = y.values

    booster, cols, train_s = train_lgbm(X.iloc[tr], yv[tr], cfg)
    prov = save_model(booster, cols, {
        "train_seconds": round(train_s, 2),
        "split_test_hash": split["test_hash"],
        "dataset_sha256": rep.raw_sha256,
        "feature_set": "all",
    }, "baseline")

    thr = cfg["model"]["decision_threshold"]
    scores = booster.predict(X.iloc[te][cols].values)
    pm = point_metrics(yv[te], scores, thr)
    boot_pr = bootstrap_ci(yv[te], scores, "pr_auc",
                           cfg["evaluation"]["bootstrap_replicates"],
                           cfg["evaluation"]["bootstrap_ci"], cfg["project"]["seed"])
    boot_roc = bootstrap_ci(yv[te], scores, "roc_auc",
                            cfg["evaluation"]["bootstrap_replicates"],
                            cfg["evaluation"]["bootstrap_ci"], cfg["project"]["seed"])
    cv = curves(yv[te], scores)

    out = {
        "model": "baseline", "model_hash": prov["model_hash"],
        "split": split, "point_metrics": pm,
        "bootstrap": {"pr_auc": boot_pr, "roc_auc": boot_roc},
        "curves": cv, "train_seconds": prov["train_seconds"],
    }
    with open(art("metrics", "baseline_eval.json"), "w") as f:
        json.dump(out, f, indent=2)

    # persist predictions for downstream (SHAP, evasion, drift)
    np.savez(art("metrics", "baseline_predictions.npz"),
             test_idx=te, y_test=yv[te], scores=scores)
    print(json.dumps({"point_metrics": pm,
                      "pr_auc_ci": [boot_pr["ci_low"], boot_pr["ci_high"]],
                      "roc_auc_ci": [boot_roc["ci_low"], boot_roc["ci_high"]],
                      "train_seconds": prov["train_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
