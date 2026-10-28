"""
Live-Analysis data: many interactive specimens (real PDFs with object graphs +
EMBER-vs-reachability verdicts + rich reachability metrics) and the full gallery
of real EMBER challenge malware (feature-level, with EMBER's verdict + a broad
structural fingerprint). Static only; the only injected payload is a harmless alert.
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


def reach_detail(data):
    r = analyze_bytes(data)
    rank = {"ABSENT": 0, "PRESENT_DORMANT": 1, "ACTIVE_ONINTERACT": 2, "ACTIVE_ONOPEN": 3}
    worst, cap = "ABSENT", None
    for c in r.capabilities:
        if rank[c["verdict"]] > rank[worst]:
            worst, cap = c["verdict"], c
    return worst, cap, len(r.trigger_points), r.parsed


def specimen(name, cat, desc, base, wiring=None, hide=False):
    data = open(FX / base, "rb").read()
    if wiring:
        inj = inject_autorun(data, hide=hide, wiring=wiring)
        if inj: data = inj
    g = build_graph(data)
    es = ember(data)
    vr, cap, ntrig, parsed = reach_detail(data)
    rf = reach_feature_vector(data)
    return {
        "name": name, "category": cat, "desc": desc,
        "ember_score": es, "ember_verdict": "malicious" if es >= 0.5 else "benign",
        "reach_verdict": vr, "reach_capability": (cap or {}).get("capability"),
        "reach_dangerous": vr in ("ACTIVE_ONOPEN", "ACTIVE_ONINTERACT"),
        "evasion_sig": int(rf["rc_evasion_signature"]),
        "metrics": {
            "objects": len(g["nodes"]), "triggers": ntrig,
            "path_depth": max(0, len(g["path"]) - 1),
            "active_onopen": int(rf["rc_n_active_onopen"]),
            "dormant": int(rf["rc_n_dormant"]),
            "obj_streams": int(rf["rc_objstm_count"]),
            "naive_tokens": int(rf["rc_total_naive_tokens"]),
            "auto_triggers": int(rf["rc_n_auto_triggers"]),
        },
        "graph": g,
    }


def build_specimens():
    ben = [("Clean report", "pdflatex-outline.pdf", "A normal LaTeX document."),
           ("Multi-column paper", "multicolumn.pdf", "A benign formatted document."),
           ("Form document", "libreoffice-form.pdf", "A benign interactive form."),
           ("Outlined report", "mistitled_outlines_example.pdf", "A benign report with bookmarks."),
           ("Map document", "ocg_map_test.pdf", "A benign layered map PDF."),
           ("GeoTopo.pdf", "GeoTopo.pdf", "Real benign file — a URI action is reachable on open.")]
    weap = []
    combos = [("pdflatex-outline.pdf", "openaction", False, "auto-run JS wired to /OpenAction, tokens visible"),
              ("pdflatex-outline.pdf", "openaction", True, "auto-run JS hidden in a compressed object stream"),
              ("multicolumn.pdf", "openaction", True, "compressed auto-run JS injected into a clean document"),
              ("libreoffice-form.pdf", "names_js", True, "document-level /Names/JavaScript, compressed"),
              ("mistitled_outlines_example.pdf", "names_js", True, "document-level JS hidden in a bookmarked report"),
              ("multicolumn.pdf", "page_aa", False, "page-open /AA action triggers the payload"),
              ("ocg_map_test.pdf", "page_aa", True, "compressed page-open action in a layered map"),
              ("pdflatex-4-pages.pdf", "action_chain", True, "GoTo→Next action chain reaches the payload at depth"),
              ("pdflatex-outline.pdf", "action_chain", True, "chained action, compressed, deeper reach"),
              ("libreoffice-form.pdf", "openaction", False, "visible auto-run JS added to a form"),
              ("ocg_map_test.pdf", "openaction", True, "compressed auto-run JS in a layered map"),
              ("mistitled_outlines_example.pdf", "page_aa", True, "compressed page action in a report"),
              ("google-doc-document.pdf", "openaction", True, "compressed auto-run JS in an exported doc"),
              ("pdflatex-forms.pdf", "names_js", True, "document-level JS in an interactive form"),
              ("multicolumn.pdf", "action_chain", False, "visible chained action in a document")]
    out = [specimen(n, "benign", d, b) for (n, b, d) in ben]
    i = 1
    for base, wiring, hide, d in combos:
        tag = {"openaction": "/OpenAction", "names_js": "document JS", "page_aa": "page action",
               "action_chain": "chained"}[wiring]
        nm = f"Weaponized {i:02d} · {tag}{' (hidden)' if hide else ''}"
        try:
            out.append(specimen(nm, "weaponized", d, base, wiring, hide)); i += 1
        except Exception:
            continue
    return out


def benign_medians():
    toks = ["/FlateDecode", "javascript", "/URI", "/EmbeddedFile"]
    acc = {k: [] for k in toks + ["entropy", "size", "numstrings", "printables", "avlength"]}
    n = 0
    for fp in sorted(glob.glob(str(ROOT / "data/ember/PDF_test/*.jsonl")))[:5]:
        for line in open(fp):
            d = json.loads(line)
            if d.get("file_type") != "PDF" or d.get("label") != 0:
                continue
            sc = d.get("strings", {}).get("string_counts", {}) or {}
            st = d.get("strings", {}); g = d.get("general", {})
            for t in toks: acc[t].append(sc.get(t, 0))
            acc["entropy"].append(g.get("entropy", 0)); acc["size"].append(g.get("size", 0))
            acc["numstrings"].append(st.get("numstrings", 0)); acc["printables"].append(st.get("printables", 0))
            acc["avlength"].append(st.get("avlength", 0))
            n += 1
            if n >= 5000: break
        if n >= 5000: break
    return {k: float(np.median(v)) for k, v in acc.items()}


def challenge_gallery():
    med = benign_medians()
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
            fd, js = sc.get("/FlateDecode", 0), sc.get("javascript", 0)
            ent, sz = g.get("entropy", 0), g.get("size", 0)
            flags = int(fd > 2 * max(med["/FlateDecode"], 1)) + int(ent > max(med["entropy"], 7.6) + 0.2) \
                + int(sz > 3 * max(med["size"], 1)) + int(js == 0 and fd > 0)
            rows.append({"sha": (d.get("sha256") or "")[:10], "ember": round(s, 4),
                         "verdict": "caught" if s >= 0.5 else "missed", "flags": flags,
                         "FlateDecode": fd, "javascript": js, "URI": sc.get("/URI", 0),
                         "EmbeddedFile": sc.get("/EmbeddedFile", 0), "entropy": round(ent, 2),
                         "size": sz, "numstrings": st.get("numstrings", 0),
                         "printables": st.get("printables", 0), "avlength": round(st.get("avlength", 0), 1)})
    rows.sort(key=lambda r: r["ember"])
    return {"benign_medians": med, "samples": rows, "n_total": len(rows),
            "n_missed": sum(1 for r in rows if r["verdict"] == "missed")}


def main():
    out = {"specimens": build_specimens(), "challenge_gallery": challenge_gallery()}
    with open(art("metrics", "live_analysis.json"), "w") as f:
        json.dump(out, f, separators=(",", ":"))
    cg = out["challenge_gallery"]
    print(f"specimens: {len(out['specimens'])} | challenge samples: {len(cg['samples'])} "
          f"({cg['n_missed']} missed)")
    fooled = sum(1 for s in out["specimens"] if s["ember_verdict"] == "benign" and s["reach_dangerous"])
    print(f"specimens where EMBER fooled but reachability catches: {fooled}")


if __name__ == "__main__":
    main()
