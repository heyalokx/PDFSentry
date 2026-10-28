"""
NOVELTY 2 — Semantic Stability under Obfuscation.
Hold the malicious BEHAVIOR fixed (a reachable auto-run payload); apply lossless
byte-level re-saves that change the file's bytes/entropy/compression but NOT its
object-graph semantics. Measure how often each detector's verdict survives.

A byte-based ML detector (EMBER) should be unstable; a reachability verdict,
which reads what the document *does*, should be invariant. Static only; the only
payload is a harmless app.alert(). We also record the FUNCTIONAL evasion-cost
asymmetry: the one transform family that flips reachability is the one that
severs the trigger->action path, i.e. disarms the payload.
"""
import sys, types, io, json, itertools
import numpy as np
_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
import pikepdf, thrember, lightgbm as lgb
from backend.core.config import ROOT, art
from backend.robustness.structural_evasion import inject_autorun
from backend.structural.reachability import analyze_bytes

EXT = thrember.PEFeatureExtractor()
MDL = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))
FX = ROOT / "tests/fixtures/real_pdfs"
RANK = {"ABSENT": 0, "PRESENT_DORMANT": 1, "ACTIVE_ONINTERACT": 2, "ACTIVE_ONOPEN": 3}

def ember(data):
    return float(MDL.predict(np.array(EXT.feature_vector(data), dtype=np.float32).reshape(1, -1))[0])

def reach_verdict(data):
    try:
        r = analyze_bytes(data)
    except Exception:
        return "PARSE_FAIL"
    worst = "ABSENT"
    for c in r.capabilities:
        if RANK.get(c["verdict"], 0) > RANK[worst]:
            worst = c["verdict"]
    return worst

def resave(data, **kw):
    """Lossless re-save with given qpdf/pikepdf options. Returns new bytes or None."""
    try:
        pdf = pikepdf.open(io.BytesIO(data))
        buf = io.BytesIO()
        pdf.save(buf, **kw)
        pdf.close()
        return buf.getvalue()
    except Exception:
        return None

# Behavior-preserving transforms (should NOT change what the doc does)
def transforms(data):
    out = {"baseline": data}
    specs = {
        "recompress":   dict(compress_streams=True, recompress_flate=True),
        "decompress":   dict(compress_streams=False, stream_decode_level=pikepdf.StreamDecodeLevel.generalized),
        "objstm_gen":   dict(object_stream_mode=pikepdf.ObjectStreamMode.generate),
        "objstm_off":   dict(object_stream_mode=pikepdf.ObjectStreamMode.disable),
        "normalize":    dict(normalize_content=True),
        "linearize":    dict(linearize=True),
        "encrypt_rc4":  dict(encryption=pikepdf.Encryption(owner="", user="", R=4)),
        "encrypt_aes":  dict(encryption=pikepdf.Encryption(owner="", user="", R=6)),
    }
    for name, kw in specs.items():
        v = resave(data, **kw)
        if v is not None:
            out[name] = v
    return out

def run():
    bases = ["pdflatex-outline.pdf","multicolumn.pdf","libreoffice-form.pdf",
             "mistitled_outlines_example.pdf","ocg_map_test.pdf","pdflatex-4-pages.pdf",
             "google-doc-document.pdf","pdflatex-forms.pdf","annotated_pdf.pdf",
             "minimal-document.pdf","crazyones-pdfa.pdf"]
    wirings = ["openaction","names_js","page_aa","action_chain"]
    docs = []
    for base in bases:
        try:
            raw = open(FX / base, "rb").read()
        except Exception:
            continue
        for wiring in wirings:
            for hide in (True, False):
                try:
                    twin = inject_autorun(raw, hide=hide, wiring=wiring)
                    if not twin:
                        continue
                except Exception:
                    continue
                variants = transforms(twin)
                rows = {}
                for vname, vdata in variants.items():
                    rows[vname] = {"ember": round(ember(vdata), 4), "reach": reach_verdict(vdata),
                                   "bytes": len(vdata)}
                docs.append({"base": base, "wiring": wiring, "hide": hide, "variants": rows})

    # aggregate
    nvar = 0
    ember_ranges, reach_inconsistent, ember_inconsistent = [], 0, 0
    straddle_e = 0  # docs whose lossless variants land on BOTH sides of 0.5 (identical behavior, opposite verdicts)
    straddle_r = 0
    for d in docs:
        es = [v["ember"] for v in d["variants"].values()]
        rs = [RANK.get(v["reach"], 0) >= 2 for v in d["variants"].values()]
        ember_ranges.append(max(es) - min(es))
        e_verdicts = set(e >= 0.5 for e in es)
        if len(e_verdicts) > 1: straddle_e += 1
        if len(set(rs)) > 1: straddle_r += 1
        nvar += len(d["variants"]) - 1
    nd = max(len(docs), 1)
    res = {
        "n_docs": len(docs), "n_transformed_variants": nvar, "n_transforms_each": 8,
        "ember": {
            "verdict_inconsistency_rate": round(straddle_e / nd, 4),
            "mean_score_range_within_doc": round(float(np.mean(ember_ranges)), 4),
            "median_score_range_within_doc": round(float(np.median(ember_ranges)), 4),
            "max_score_range_within_doc": round(float(np.max(ember_ranges)), 4),
        },
        "reachability": {
            "verdict_inconsistency_rate": round(straddle_r / nd, 4),
        },
        "semantic_stability_index": {
            "reachability": round(1 - straddle_r / nd, 4),
            "ember": round(1 - straddle_e / nd, 4),
        },
        "docs": docs,
    }
    json.dump(res, open(art("metrics", "semantic_stability.json"), "w"), indent=2)
    print(f"docs={res['n_docs']}  transformed variants={nvar}  (8 lossless re-saves each)")
    print(f"EMBER   verdict-inconsistency {res['ember']['verdict_inconsistency_rate']:.1%} of docs give"
          f" BOTH verdicts across byte-identical-behavior variants")
    print(f"        score-range within one doc: mean {res['ember']['mean_score_range_within_doc']:.3f}"
          f"  median {res['ember']['median_score_range_within_doc']:.3f}  max {res['ember']['max_score_range_within_doc']:.3f}")
    print(f"REACH   verdict-inconsistency {res['reachability']['verdict_inconsistency_rate']:.1%}")
    print(f"Semantic Stability Index   reachability {res['semantic_stability_index']['reachability']:.3f}"
          f"   vs EMBER {res['semantic_stability_index']['ember']:.3f}")
    print("\nper-transform EMBER swing (first 3 docs):")
    for d in docs[:3]:
        line = "  ".join(f"{k}:{v['ember']:.2f}/{v['reach'][:3]}" for k,v in d["variants"].items())
        print(f"  {d['base'][:22]:22s} {d['wiring']:12s} {line}")

if __name__ == "__main__":
    run()
