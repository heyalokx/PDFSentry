"""
HEADLINE EXPERIMENT — Structural evasion of the EMBER2024 PDF detector, and its
repair by reachability augmentation. Run against the authors' REAL PDF model.

Protocol:
  1. Take confident-benign real PDFs (EMBER P(mal) < 0.05).
  2. Weaponize each: inject a reachable /OpenAction -> JavaScript action
     (harmless alert), hidden inside a compressed object stream. The file now
     auto-runs code on open — a genuine structural threat — while its bytes stay
     document-like.
  3. Measure, on the real EMBER model:
       - EMBER evasion rate: how many weaponized files still score < 0.5.
       - Reachability detection rate: how many the reachability engine flags.
       - Fusion: EMBER-score-alone vs EMBER+reachability at telling an original
         from its weaponized twin (5-fold CV ROC-AUC). This is the augmentation
         result Review-2 O4 asks for, on a controlled but real-model test.

Harmless payload only; nothing is executed; no malware is downloaded or created.
"""
from __future__ import annotations
import sys, types, glob, json
import numpy as np

_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
import thrember, lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score
from backend.core.config import art, ROOT
from backend.features.reach_features import reach_feature_vector, FEATURE_NAMES
from backend.robustness.structural_evasion import inject_autorun

EXTRACTOR = thrember.PEFeatureExtractor()
MODEL = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))
THR = 0.5
MAX_N = 300


def ember_score(data: bytes) -> float:
    v = np.array(EXTRACTOR.feature_vector(data), dtype=np.float32).reshape(1, -1)
    return float(MODEL.predict(v)[0])


def main():
    pdfs = sorted(glob.glob(str(ROOT / "data/benign_corpus/**/*.pdf"), recursive=True))
    rng = np.random.default_rng(1337)
    rng.shuffle(pdfs)

    orig_rows, evad_rows = [], []
    ember_orig, ember_evad = [], []
    reach_caught = 0
    n = 0
    for p in pdfs:
        try:
            d = open(p, "rb").read()
        except Exception:
            continue
        if not d or len(d) > 3_000_000:
            continue
        try:
            s0 = ember_score(d)
        except Exception:
            continue
        if s0 >= 0.05:            # start from confident-benign only
            continue
        ev = inject_autorun(d, hide=True)
        if ev is None:
            continue
        try:
            s1 = ember_score(ev)
            rf0 = reach_feature_vector(d)
            rf1 = reach_feature_vector(ev)
        except Exception:
            continue
        orig_rows.append([s0] + [rf0[k] for k in FEATURE_NAMES])
        evad_rows.append([s1] + [rf1[k] for k in FEATURE_NAMES])
        ember_orig.append(s0); ember_evad.append(s1)
        reach_caught += int(rf1["rc_evasion_signature"] == 1 or rf1["rc_javascript_onopen"] == 1)
        n += 1
        if n >= MAX_N:
            break

    ember_evad = np.array(ember_evad); ember_orig = np.array(ember_orig)
    X = np.array(orig_rows + evad_rows, dtype=np.float32)
    y = np.array([0] * len(orig_rows) + [1] * len(evad_rows))
    feat_cols = ["ember_score"] + FEATURE_NAMES

    # EMBER-score-alone detector (the baseline) on the same task
    ember_only_scores = X[:, 0]
    auc_ember = roc_auc_score(y, ember_only_scores)

    # Fusion detector: EMBER score + reachability features, 5-fold CV
    skf = StratifiedKFold(5, shuffle=True, random_state=1337)
    oof = np.zeros(len(y))
    params = dict(objective="binary", num_leaves=31, learning_rate=0.05,
                  num_iterations=200, min_data_in_leaf=20, verbosity=-1, seed=1337)
    for tr, te in skf.split(X, y):
        booster = lgb.train(params, lgb.Dataset(X[tr], y[tr], feature_name=feat_cols))
        oof[te] = booster.predict(X[te])
    auc_fusion = roc_auc_score(y, oof)

    # fusion feature importance (which signal does the work)
    full = lgb.train(params, lgb.Dataset(X, y, feature_name=feat_cols))
    imp = sorted(zip(feat_cols, full.feature_importance(importance_type="gain")),
                 key=lambda t: -t[1])[:10]

    out = {
        "n_benign_originals": len(orig_rows),
        "ember_evasion_rate": float((ember_evad < THR).mean()),
        "ember_mean_score_original": float(ember_orig.mean()),
        "ember_mean_score_weaponized": float(ember_evad.mean()),
        "reachability_detection_rate": float(reach_caught / n) if n else 0.0,
        "detector_auc": {
            "ember_score_alone": float(auc_ember),
            "ember_plus_reachability_fusion": float(auc_fusion),
        },
        "fusion_top_features": [{"feature": f, "gain": float(g)} for f, g in imp],
        "note": ("Weaponized = benign PDF + reachable auto-run JS hidden in a "
                 "compressed object stream (harmless alert payload). AUC is for "
                 "separating originals from their weaponized twins."),
    }
    with open(art("metrics", "structural_evasion_study.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
