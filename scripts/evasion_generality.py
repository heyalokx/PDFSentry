"""
Generality + ablation study — answers the "you designed the test to win" critique.

(1) GENERALITY: weaponize benign PDFs four structurally DISTINCT ways (direct
    OpenAction, a GoTo->Next action chain, the document-level Names/JavaScript
    name tree, and a page-open /AA action), each hidden in a compressed stream.
    Reachability must catch ALL of them, via different parts of the graph walk —
    so detection is not an artefact of one tailored feature.

(2) ABLATION: show reachability still catches the evasion even with the
    purpose-built 'hidden-gap / evasion-signature' features REMOVED (i.e. using
    only generic "is a dangerous action reachable on open" signals).

Harmless payload; nothing executed.
"""
from __future__ import annotations
import sys, types, glob, json
import numpy as np

_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
import thrember, lightgbm as lgb
from backend.core.config import art, ROOT
from backend.features.reach_features import reach_feature_vector
from backend.robustness.structural_evasion import inject_autorun, WIRINGS

EXT = thrember.PEFeatureExtractor()
MDL = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))
MAX_N = 150


def ember(data):
    return float(MDL.predict(np.array(EXT.feature_vector(data), dtype=np.float32).reshape(1, -1))[0])


def caught_full(rf):
    return rf["rc_javascript_onopen"] == 1 or rf["rc_javascript_oninteract"] == 1 \
        or rf["rc_evasion_signature"] == 1


def caught_ablated(rf):
    # WITHOUT the hidden-gap / evasion-signature features: only "is JS reachable?"
    return rf["rc_javascript_onopen"] == 1 or rf["rc_javascript_oninteract"] == 1


def main():
    pdfs = sorted(glob.glob(str(ROOT / "data/benign_corpus/**/*.pdf"), recursive=True))
    rng = np.random.default_rng(7); rng.shuffle(pdfs)
    per = {w: {"n": 0, "ember_evaded": 0, "reach_full": 0, "reach_ablated": 0,
               "hops": []} for w in WIRINGS}
    n = 0
    for p in pdfs:
        try:
            d = open(p, "rb").read()
        except Exception:
            continue
        if not d or len(d) > 2_500_000:
            continue
        try:
            if ember(d) >= 0.05:
                continue
        except Exception:
            continue
        ok_any = False
        for w in WIRINGS:
            ev = inject_autorun(d, hide=True, wiring=w)
            if ev is None:
                continue
            try:
                s = ember(ev); rf = reach_feature_vector(ev)
            except Exception:
                continue
            per[w]["n"] += 1
            per[w]["ember_evaded"] += int(s < 0.5)
            per[w]["reach_full"] += int(caught_full(rf))
            per[w]["reach_ablated"] += int(caught_ablated(rf))
            if rf["rc_javascript_minhops"] >= 0:
                per[w]["hops"].append(rf["rc_javascript_minhops"])
            ok_any = True
        if ok_any:
            n += 1
        if n >= MAX_N:
            break

    out = {"n_base_pdfs": n, "wirings": {}}
    for w in WIRINGS:
        x = per[w]
        if x["n"] == 0:
            continue
        out["wirings"][w] = {
            "n": x["n"],
            "ember_evasion_rate": x["ember_evaded"] / x["n"],
            "reach_detection_full": x["reach_full"] / x["n"],
            "reach_detection_ablated": x["reach_ablated"] / x["n"],
            "mean_min_hops": float(np.mean(x["hops"])) if x["hops"] else None,
        }
    with open(art("metrics", "evasion_generality.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"base PDFs: {n}")
    print(f"{'wiring':14s} {'EMBER evaded':>12s} {'reach(full)':>12s} {'reach(ablated)':>15s} {'hops':>6s}")
    for w, v in out["wirings"].items():
        print(f"{w:14s} {v['ember_evasion_rate']:>11.0%} {v['reach_detection_full']:>12.0%} "
              f"{v['reach_detection_ablated']:>15.0%} {str(v['mean_min_hops']):>6s}")


if __name__ == "__main__":
    main()
