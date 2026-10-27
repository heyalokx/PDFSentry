"""
O1/O2 — reproduce the EMBER2024 PDF-only benchmark with the authors' released
model, then run the SHAP failure diagnosis (O2).

Ordinary test  : 12,000 PDF test files.
Challenge eval : 805 evasive PDF challenge malicious + 6,000 benign PDF test
                 files (the dataset authors' protocol).
Published targets: ordinary ROC 0.9912 / PR 0.9933 ; challenge ROC 0.9066 / PR 0.7841.
"""
from __future__ import annotations
import sys, types, glob, json
import numpy as np

# stub signify (only needed to parse raw PE bytes; we use precomputed features)
_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)

import thrember
import lightgbm as lgb
from backend.core.config import art, ROOT
from backend.evaluation.metrics import point_metrics, bootstrap_ci, curves

EMBER = ROOT / "data" / "ember"
EXTRACTOR = thrember.PEFeatureExtractor()
PUBLISHED = {"ordinary": {"roc": 0.9912, "pr": 0.9933},
             "challenge": {"roc": 0.9066, "pr": 0.7841}}


def load_jsonl(pattern, pdf_only=False, limit=None):
    X, y, meta = [], [], []
    for fp in sorted(glob.glob(pattern, recursive=True)):
        with open(fp) as f:
            for line in f:
                d = json.loads(line)
                if pdf_only and d.get("file_type") != "PDF":
                    continue
                lbl = d.get("label")
                if lbl is None or lbl == -1:
                    continue
                X.append(EXTRACTOR.process_raw_features(d))
                y.append(int(lbl))
                meta.append({"sha256": d.get("sha256"), "label": int(lbl)})
                if limit and len(y) >= limit:
                    break
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32), meta


def main():
    model = lgb.Booster(model_file=str(EMBER / "EMBER2024_PDF.model"))

    print("Vectorizing PDF test set ...")
    X_test, y_test, meta_test = load_jsonl(str(EMBER / "PDF_test/**/*.jsonl"), pdf_only=True)
    print(f"  test: {X_test.shape[0]} files ({int((y_test==1).sum())} mal / {int((y_test==0).sum())} ben)")

    print("Vectorizing PDF challenge (evasive) ...")
    X_ch, y_ch, meta_ch = load_jsonl(str(EMBER / "challenge/**/*.jsonl"), pdf_only=True)
    print(f"  challenge: {X_ch.shape[0]} evasive PDFs")

    # ordinary test
    s_test = model.predict(X_test)
    m_ord = point_metrics(y_test, s_test, 0.5)
    ci_ord = bootstrap_ci(y_test, s_test, "pr_auc", 2000)

    # challenge protocol (authors'): 805 evasive malicious + 6000 benign test PDFs
    Xb_all = X_test[y_test == 0]
    rng = np.random.default_rng(1337)
    bidx = rng.choice(len(Xb_all), 6000, replace=False)
    Xb = Xb_all[bidx]
    X_cheval = np.concatenate([Xb, X_ch]); y_cheval = np.concatenate([np.zeros(6000, int), np.ones(len(X_ch), int)])
    s_ch = model.predict(X_cheval)
    m_ch = point_metrics(y_cheval, s_ch, 0.5)
    ci_ch = bootstrap_ci(y_cheval, s_ch, "pr_auc", 2000)

    out = {
        "model": "EMBER2024_PDF (authors' released benchmark)",
        "ordinary": {"metrics": m_ord, "pr_auc_ci": [ci_ord["ci_low"], ci_ord["ci_high"]],
                     "published": PUBLISHED["ordinary"], "curves": curves(y_test, s_test)},
        "challenge": {"metrics": m_ch, "pr_auc_ci": [ci_ch["ci_low"], ci_ch["ci_high"]],
                      "published": PUBLISHED["challenge"], "curves": curves(y_cheval, s_ch),
                      "n_evasive": int(len(X_ch)), "n_benign": int(len(Xb))},
    }
    with open(art("metrics", "ember_reproduction.json"), "w") as f:
        json.dump(out, f, indent=2)

    # persist arrays for SHAP (O2) and later fusion
    np.savez(art("metrics", "ember_arrays.npz"),
             X_test=X_test, y_test=y_test, s_test=s_test,
             X_ch=X_ch, y_ch=y_ch, s_ch_eval=s_ch, y_cheval=y_cheval)

    def row(tag, m, pub):
        print(f"  {tag:10s} ROC {m['roc_auc']:.4f} (pub {pub['roc']})   "
              f"PR {m['pr_auc']:.4f} (pub {pub['pr']})")
    print("\n=== EMBER2024 PDF reproduction ===")
    row("ordinary", m_ord, PUBLISHED["ordinary"])
    row("challenge", m_ch, PUBLISHED["challenge"])
    print(f"  challenge FN (missed evasive): {m_ch['confusion']['fn']} / {len(X_ch)}")


if __name__ == "__main__":
    main()
