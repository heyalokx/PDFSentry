import numpy as np
from backend.evaluation.metrics import point_metrics, bootstrap_ci, paired_bootstrap


def test_point_metrics_hand_checked():
    # 4 samples, perfectly separable at 0.5
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.8, 0.9])
    m = point_metrics(y, s, 0.5)
    assert m["accuracy"] == 1.0
    assert m["roc_auc"] == 1.0
    assert m["confusion"] == {"tn": 2, "fp": 0, "fn": 0, "tp": 2}


def test_point_metrics_known_confusion():
    y = np.array([1, 1, 0, 0])
    s = np.array([0.9, 0.4, 0.6, 0.1])  # one FN, one FP
    m = point_metrics(y, s, 0.5)
    assert m["confusion"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert abs(m["precision"] - 0.5) < 1e-9
    assert abs(m["recall"] - 0.5) < 1e-9


def test_bootstrap_deterministic_and_ordered():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 400)
    s = rng.random(400)
    a = bootstrap_ci(y, s, "roc_auc", n_boot=300, seed=7)
    b = bootstrap_ci(y, s, "roc_auc", n_boot=300, seed=7)
    assert a == b                       # reproducible
    assert a["ci_low"] <= a["estimate"] <= a["ci_high"]


def test_non_finite_rejected():
    import pytest
    with pytest.raises(ValueError):
        point_metrics([0, 1], [0.5, np.inf])


def test_paired_bootstrap_detects_improvement():
    rng = np.random.default_rng(1)
    y = rng.integers(0, 2, 500)
    # score_b is strictly more informative than score_a
    a = rng.random(500)
    b = np.where(y == 1, 0.5 + 0.5 * rng.random(500), 0.5 * rng.random(500))
    res = paired_bootstrap(y, a, b, "roc_auc", n_boot=300)
    assert res["delta"] > 0
