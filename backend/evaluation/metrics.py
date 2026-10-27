"""
Evaluation metrics with bootstrap confidence intervals.

PR-AUC is computed as average precision (sklearn.average_precision_score) —
documented explicitly to avoid the trapezoidal-vs-AP ambiguity. ROC-AUC,
precision, recall, accuracy, F1 and confusion matrices are all reported at a
documented operating threshold.
"""
from __future__ import annotations
import numpy as np
from sklearn.metrics import (
    roc_auc_score, average_precision_score, precision_score, recall_score,
    accuracy_score, f1_score, confusion_matrix, roc_curve, precision_recall_curve,
)


def point_metrics(y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.5) -> dict:
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    if not np.all(np.isfinite(y_score)):
        raise ValueError("Non-finite scores encountered.")
    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "pr_auc": float(average_precision_score(y_true, y_score)),  # = average precision
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n": int(len(y_true)),
        "prevalence": float(y_true.mean()),
    }


_METRIC_FNS = {
    "roc_auc": lambda yt, ys: roc_auc_score(yt, ys),
    "pr_auc": lambda yt, ys: average_precision_score(yt, ys),
}


def bootstrap_ci(y_true, y_score, metric="pr_auc", n_boot=2000, ci=0.95,
                 seed=1337, stratified=True) -> dict:
    """Stratified bootstrap CI for a threshold-free metric."""
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    fn = _METRIC_FNS[metric]
    rng = np.random.default_rng(seed)
    pos = np.where(y_true == 1)[0]
    neg = np.where(y_true == 0)[0]
    n = len(y_true)
    stats = []
    for _ in range(n_boot):
        if stratified:
            samp = np.concatenate([rng.choice(pos, len(pos), replace=True),
                                   rng.choice(neg, len(neg), replace=True)])
        else:
            samp = rng.integers(0, n, n)
        yt, ys = y_true[samp], y_score[samp]
        if yt.min() == yt.max():
            continue
        stats.append(fn(yt, ys))
    stats = np.array(stats)
    lo = float(np.quantile(stats, (1 - ci) / 2))
    hi = float(np.quantile(stats, 1 - (1 - ci) / 2))
    return {
        "metric": metric, "estimate": float(fn(y_true, y_score)),
        "ci_low": lo, "ci_high": hi, "ci_level": ci,
        "n_boot": int(len(stats)), "seed": seed, "stratified": stratified,
    }


def paired_bootstrap(y_true, score_a, score_b, metric="pr_auc", n_boot=2000,
                     ci=0.95, seed=1337) -> dict:
    """Paired bootstrap of metric(B) - metric(A) on identical samples."""
    y_true = np.asarray(y_true).astype(int)
    a = np.asarray(score_a, float); b = np.asarray(score_b, float)
    fn = _METRIC_FNS[metric]
    rng = np.random.default_rng(seed)
    n = len(y_true)
    diffs = []
    for _ in range(n_boot):
        s = rng.integers(0, n, n)
        yt = y_true[s]
        if yt.min() == yt.max():
            continue
        diffs.append(fn(yt, b[s]) - fn(yt, a[s]))
    diffs = np.array(diffs)
    lo = float(np.quantile(diffs, (1 - ci) / 2))
    hi = float(np.quantile(diffs, 1 - (1 - ci) / 2))
    return {
        "metric": metric, "delta": float(fn(y_true, b) - fn(y_true, a)),
        "ci_low": lo, "ci_high": hi, "ci_level": ci,
        "significant": bool(lo > 0 or hi < 0), "n_boot": int(len(diffs)),
    }


def curves(y_true, y_score) -> dict:
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, float)
    fpr, tpr, _ = roc_curve(y_true, y_score)
    prec, rec, _ = precision_recall_curve(y_true, y_score)
    # subsample to keep artifacts small but faithful
    def thin(a, k=300):
        if len(a) <= k:
            return a
        idx = np.linspace(0, len(a) - 1, k).astype(int)
        return a[idx]
    return {
        "roc": {"fpr": thin(fpr).tolist(), "tpr": thin(tpr).tolist()},
        "pr": {"recall": thin(rec).tolist(), "precision": thin(prec).tolist()},
    }
