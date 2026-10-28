"""
Build the Live-Analysis data: interactive specimens (real PDFs with object
graphs + EMBER-vs-reachability verdicts) and a gallery of real EMBER challenge
malware (feature-level, with EMBER's real verdict + structural fingerprint).
Static only; the only injected payload is a harmless alert.
"""
from __future__ import annotations
import sys, types, glob, json
import numpy as np

_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
import thrember, lightgbm as lgb
from backend.core.config import art, ROOT
from backend.structural.graph import build_graph
from backend.structural.reachability import analyze_bytes
from backend.features.reach_features import reach_feature_vector
from backend.robustness.structural_evasion import inject_autorun

EXT = thrember.PEFeatureExtractor()
MDL = lgb.Booster(model_file=str(ROOT / "data/ember/EMBER2024_PDF.model"))
FX = ROOT / "tests/fixtures/real_pdfs"


def ember(data):
    return float(MDL.predict(np.array(EXT.feature_vector(data), dtype=np.float32).reshape(1, -1))[0])


def verdict_reach(data):
    r = analyze_bytes(data)
    rank = {"ABSENT": 0, "PRESENT_DORMANT": 1, "ACTIVE_ONINTERACT": 2, "ACTIVE_ONOPEN": 3}
    worst = "ABSENT"; cap = None
    for c in r.capabilities:
        if rank[c["verdict"]] > rank[worst]:
            worst = c["verdict"]; cap = c
    return worst, cap, r.n_objects


def specimen(name, cat, desc, base, wiring=None, hide=False):
    data = open(FX / base, "rb").read()
    if wiring:
        inj = inject_autorun(data, hide=hide, wiring=wiring)
        if inj: data = inj
    g = build_graph(data)
    es = ember(data)
    vr, cap, nobj = verdict_reach(data)
    rf = reach_feature_vector(data)
    reach_dangerous = vr in ("ACTIVE_ONOPEN", "ACTIVE_ONINTERACT")
    return {
        "name": name, "category": cat, "desc": desc, "base": base,
        "ember_score": es, "ember_verdict": "malicious" if es >= 0.5 else "benign",
        "reach_verdict": vr, "reach_capability": (cap or {}).get("capability"),
        "reach_dangerous": reach_dangerous, "evasion_sig": int(rf["rc_evasion_signature"]),
        "n_objects": g["nodes"].__len__(), "graph": g,
    }


def build_specimens():
    S = []
    S.append(specimen("Clean report", "benign", "A normal LaTeX document — no reachable actions.", "pdflatex-outline.pdf"))
    S.append(specimen("Multi-column paper", "benign", "A benign formatted document.", "multicolumn.pdf"))
    S.append(specimen("GeoTopo.pdf", "benign", "Real benign file — a URI action is reachable on open (link navigation).", "GeoTopo.pdf"))
    S.append(specimen("Weaponized · visible JS", "weaponized", "Auto-run JavaScript wired to /OpenAction, tokens visible.", "pdflatex-outline.pdf", "openaction", False))
    S.append(specimen("Weaponized · hidden JS", "weaponized", "Same auto-run action, hidden inside a compressed object stream.", "pdflatex-outline.pdf", "openaction", True))
    S.append(specimen("Weaponized · document JS", "weaponized", "Document-level /Names/JavaScript — runs on open, compressed.", "libreoffice-form.pdf", "names_js", True))
    S.append(specimen("Weaponized · page action", "weaponized", "Page-open /AA action triggers the payload.", "multicolumn.pdf", "page_aa", False))
    S.append(specimen("Weaponized · chained", "weaponized", "GoTo→Next action chain reaches the payload at depth.", "pdflatex-4-pages.pdf", "action_chain", True))
    return S


def benign_medians():
    toks = ["/FlateDecode", "javascript", "/URI"]
    acc = {k: [] for k in toks + ["entropy", "size", "numstrings"]}
    n = 0
    for fp in sorted(glob.glob(str(ROOT / "data/ember/PDF_test/*.jsonl")))[:4]:
        for line in open(fp):
            d = json.loads(line)
            if d.get("file_type") != "PDF" or d.get("label") != 0:
                continue
            sc = d.get("strings", {}).get("string_counts", {}) or {}
            for t in toks: acc[t].append(sc.get(t, 0))
            acc["entropy"].append(d.get("general", {}).get("entropy", 0))
            acc["size"].append(d.get("general", {}).get("size", 0))
            acc["numstrings"].append(d.get("strings", {}).get("numstrings", 0))
            n += 1
            if n >= 4000: break
        if n >= 4000: break
    return {k: float(np.median(v)) for k, v in acc.items()}


def challenge_gallery():
    rows = []
    for fp in sorted(glob.glob(str(ROOT / "data/ember/challenge/*.jsonl"))):
        for line in open(fp):
            d = json.loads(line)
            if d.get("file_type") != "PDF" or d.get("label") != 1:
                continue
            vec = np.array(EXT.process_raw_features(d), dtype=np.float32).reshape(1, -1)
            s = float(MDL.predict(vec)[0])
            sc = d.get("strings", {}).get("string_counts", {}) or {}
            g = d.get("general", {}); st = d.get("strings", {})
            rows.append({"sha": (d.get("sha256") or "")[:10], "ember": s,
                         "verdict": "caught" if s >= 0.5 else "missed",
                         "FlateDecode": sc.get("/FlateDecode", 0), "javascript": sc.get("javascript", 0),
                         "URI": sc.get("/URI", 0), "entropy": round(g.get("entropy", 0), 2),
                         "size": g.get("size", 0), "numstrings": st.get("numstrings", 0)})
    rows.sort(key=lambda r: r["ember"])
    missed = [r for r in rows if r["verdict"] == "missed"]
    caught = [r for r in rows if r["verdict"] == "caught"]
    # spread: most-confident misses + a few caught, ~36 samples
    pick = missed[:24] + caught[-12:]
    return {"benign_medians": benign_medians(), "samples": pick, "n_total": len(rows)}


def main():
    out = {"specimens": build_specimens(), "challenge_gallery": challenge_gallery()}
    with open(art("metrics", "live_analysis.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("specimens:", len(out["specimens"]), "| challenge samples:", len(out["challenge_gallery"]["samples"]))
    for s in out["specimens"]:
        print(f"  {s['name']:28s} EMBER {s['ember_score']:.3f} ({s['ember_verdict']:9s}) | reach {s['reach_verdict']:18s} | nodes {s['n_objects']}")


if __name__ == "__main__":
    main()
