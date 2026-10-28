"""
Real-malware structural diagnosis — on the actual 805 evasive EMBER challenge
PDFs, using only the released features (NO raw files, NO malware handling).

Question: are the evasive PDFs the EMBER model MISSES (scores < 0.5)
structurally different from the ones it CATCHES, in a way that matches the
compression/token-hiding evasion mechanism? If the misses are more compressed
(/FlateDecode), carry fewer VISIBLE javascript strings, and have higher byte
entropy, that is the token-hiding signature operating in real evasive malware —
the real-data evidence behind the controlled evasion study.

This is confound-free (within-malicious: missed vs caught), needs nothing from
the user, and touches no malware file.
"""
from __future__ import annotations
import sys, types, glob, json
import numpy as np
from scipy.stats import mannwhitneyu

_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
import thrember, lightgbm as lgb
from backend.core.config import art, ROOT

EXT = thrember.PEFeatureExtractor()
MDL = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))

TOKENS = ["/FlateDecode", "/EmbeddedFile", "/URI", "javascript", "<script", "base64"]


def collect():
    rows = []
    for fp in sorted(glob.glob(str(ROOT / "data/ember/challenge/*.jsonl"))):
        for line in open(fp):
            d = json.loads(line)
            if d.get("file_type") != "PDF" or d.get("label") != 1:
                continue
            vec = np.array(EXT.process_raw_features(d), dtype=np.float32).reshape(1, -1)
            score = float(MDL.predict(vec)[0])
            sc = d.get("strings", {}).get("string_counts", {}) or {}
            g = d.get("general", {})
            st = d.get("strings", {})
            row = {"score": score, "size": g.get("size", 0), "entropy": g.get("entropy", 0),
                   "numstrings": st.get("numstrings", 0), "str_entropy": st.get("entropy", 0)}
            for t in TOKENS:
                row[t] = sc.get(t, 0)
            rows.append(row)
    return rows


def main():
    rows = collect()
    score = np.array([r["score"] for r in rows])
    caught = score >= 0.5
    missed = ~caught
    n = len(rows)

    metrics = ["/FlateDecode", "javascript", "/EmbeddedFile", "/URI",
               "entropy", "str_entropy", "size", "numstrings"]
    comp = {}
    for mname in metrics:
        v = np.array([r[mname] for r in rows], dtype=float)
        a, b = v[missed], v[caught]
        try:
            u, p = mannwhitneyu(a, b, alternative="two-sided")
        except Exception:
            p = float("nan")
        comp[mname] = {
            "missed_median": float(np.median(a)), "caught_median": float(np.median(b)),
            "missed_mean": float(a.mean()), "caught_mean": float(b.mean()),
            "mannwhitney_p": float(p),
        }

    # the token-hiding signature: compressed (FlateDecode>0) but no visible JS strings
    fd = np.array([r["/FlateDecode"] for r in rows]) > 0
    nojs = np.array([r["javascript"] for r in rows]) == 0
    hidden_sig = fd & nojs
    out = {
        "n_evasive_pdf": n,
        "ember_caught": int(caught.sum()), "ember_missed": int(missed.sum()),
        "ember_recall_on_challenge": float(caught.mean()),
        "metric_comparison_missed_vs_caught": comp,
        "token_hiding_signature": {
            "definition": "/FlateDecode present AND zero visible 'javascript' strings",
            "rate_in_missed": float(hidden_sig[missed].mean()),
            "rate_in_caught": float(hidden_sig[caught].mean()),
        },
    }
    with open(art("metrics", "challenge_structure.json"), "w") as f:
        json.dump(out, f, indent=2)

    print(f"evasive PDFs={n}  caught={int(caught.sum())}  missed={int(missed.sum())}")
    print(f"{'metric':14s} {'missed_med':>11s} {'caught_med':>11s} {'p':>10s}")
    for mname in metrics:
        c = comp[mname]
        print(f"{mname:14s} {c['missed_median']:>11.3g} {c['caught_median']:>11.3g} {c['mannwhitney_p']:>10.2e}")
    hs = out["token_hiding_signature"]
    print(f"token-hiding signature (compressed, no visible JS): "
          f"missed {hs['rate_in_missed']:.1%} vs caught {hs['rate_in_caught']:.1%}")


if __name__ == "__main__":
    main()
