"""
O2 — SHAP diagnosis of the test->challenge drop on EMBER2024.

Compares mean|SHAP| across three groups (Review-2 protocol):
  A: correctly classified ordinary test PDFs
  B: correctly caught evasive challenge PDFs
  C: MISSED evasive challenge PDFs (the failures)
Cross-checked against which EMBER feature family each top feature belongs to,
to show evasive misses look byte/string-normal.
"""
from __future__ import annotations
import sys, types, json
import numpy as np

_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
import thrember, shap, lightgbm as lgb
from backend.core.config import art, ROOT

# feature-family index ranges, in PEFeatureExtractor order
FAMILIES = [("general", 7), ("histogram", 256), ("byteentropy", 256), ("strings", 177),
            ("header", 74), ("section", 224), ("imports", 1282), ("exports", 129),
            ("datadirectories", 34), ("richheader", 33), ("authenticode", 8),
            ("pefilewarnings", 88)]


def family_of(idx):
    c = 0
    for name, n in FAMILIES:
        if idx < c + n:
            return name
        c += n
    return "?"


def main():
    model = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))
    d = np.load(art("metrics", "ember_arrays.npz"))
    X_test, y_test, s_test = d["X_test"], d["y_test"], d["s_test"]
    X_ch, y_ch = d["X_ch"], d["y_ch"]
    s_ch = model.predict(X_ch)
    rng = np.random.default_rng(1337)

    def sample(X, n):
        if len(X) <= n:
            return X
        return X[rng.choice(len(X), n, replace=False)]

    # groups
    A = sample(X_test[(y_test == 1) & (s_test >= 0.5)], 1500)   # caught ordinary malware
    B = sample(X_ch[s_ch >= 0.5], 1500)                          # caught evasive
    C = X_ch[s_ch < 0.5]                                         # MISSED evasive (355)

    expl = shap.TreeExplainer(model)

    def top(X, k=12):
        sv = expl.shap_values(X)
        if isinstance(sv, list):
            sv = sv[1]
        mabs = np.abs(np.asarray(sv)).mean(axis=0)
        order = np.argsort(-mabs)[:k]
        return [{"feature_index": int(i), "family": family_of(int(i)),
                 "mean_abs_shap": float(mabs[i])} for i in order], mabs

    tA, mA = top(A); tB, mB = top(B); tC, mC = top(C)

    # family-level mass per group
    def fam_mass(mabs):
        out = {}
        for i, v in enumerate(mabs):
            out[family_of(i)] = out.get(family_of(i), 0.0) + float(v)
        s = sum(out.values()) or 1.0
        return {k: round(v / s, 4) for k, v in sorted(out.items(), key=lambda x: -x[1])}

    out = {
        "groups": {"caught_ordinary": int(len(A)), "caught_evasive": int(len(B)),
                   "missed_evasive": int(len(C))},
        "top_features": {"caught_ordinary": tA, "caught_evasive": tB, "missed_evasive": tC},
        "family_mass": {"caught_ordinary": fam_mass(mA), "caught_evasive": fam_mass(mB),
                        "missed_evasive": fam_mass(mC)},
        "note": ("Feature indices are EMBER v3 positions; PDFs carry only general, "
                 "byte histogram, byte-entropy and string families (PE families are ~0)."),
    }
    with open(art("explanations", "ember_shap.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("missed-evasive top families:", list(out["family_mass"]["missed_evasive"].items())[:5])
    print("caught-evasive top families:", list(out["family_mass"]["caught_evasive"].items())[:5])


if __name__ == "__main__":
    main()
