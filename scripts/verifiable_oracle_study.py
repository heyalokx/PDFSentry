"""
NOVELTY 3 — Certificate-carrying detection (verifiable verdicts).
Unlike an ML score (opaque) or a signature (a match with no reasoning), every
ACTIVE verdict ships a MINIMAL WITNESS PATH: catalog -> trigger -> ... -> dangerous
node, which a human can re-check by hand in O(path length) WITHOUT trusting any
model. The oracle is deterministic and training-free -> it cannot drift.
We measure: (a) witness length / auditability, (b) coverage (every positive has a
witness), (c) false-ACTIVE rate on a large benign corpus, (d) determinism, (e) runtime.
Static only; harmless payload for the weaponized set.
"""
import sys, types, io, time, json, glob, random
import numpy as np
_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)
from backend.core.config import ROOT, art
from backend.structural.reachability import analyze_bytes
from backend.structural.graph import build_graph
from backend.robustness.structural_evasion import inject_autorun
FX = ROOT / "tests/fixtures/real_pdfs"
RANK = {"ABSENT":0,"PRESENT_DORMANT":1,"ACTIVE_ONINTERACT":2,"ACTIVE_ONOPEN":3}

HIGH = {"javascript","launch","embeddedfile","submitform"}  # code/file execution, not navigation

def worst(data):
    r = analyze_bytes(data); w="ABSENT"
    for c in r.capabilities:
        if RANK.get(c["verdict"],0)>RANK[w]: w=c["verdict"]
    return w

def is_malicious(data):
    """Detection gate: an auto-executing (ACTIVE_ONOPEN) code/file capability.
    A clickable URI (ACTIVE_ONINTERACT) is a benign-common capability, not a threat."""
    r = analyze_bytes(data)
    return any(c.get("trigger_class")=="auto" and c.get("capability") in HIGH for c in r.capabilities)

def any_active_capability(data):
    r = analyze_bytes(data)
    return any(RANK.get(c["verdict"],0)>=2 for c in r.capabilities)

# ---- generate a varied benign corpus (reportlab) ----
def gen_benign(n, outdir):
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import cm
    import os
    random.seed(7); paths=[]
    words=("security analysis document report invoice summary chapter figure table "
           "appendix reference abstract method result conclusion dataset model").split()
    for i in range(n):
        p=os.path.join(outdir,f"benign_{i:04d}.pdf")
        c=canvas.Canvas(p, pagesize=(A4 if i%2 else letter))
        for pg in range(random.randint(1,4)):
            c.setFont("Helvetica", random.choice([9,10,11,12]))
            y=27*cm
            for _ in range(random.randint(10,30)):
                c.drawString(2*cm, y, " ".join(random.choice(words) for _ in range(random.randint(5,12))))
                y-=0.7*cm
            if i%5==0:  # benign external link (URI - NOT a dangerous capability)
                c.linkURL("https://example.org", (2*cm,2*cm,8*cm,3*cm), relative=0)
                c.drawString(2*cm, 2.2*cm, "see https://example.org")
            if i%7==0:  # benign interactive form field
                try: c.acroForm.textfield(name=f"f{pg}", x=2*cm, y=5*cm, width=6*cm, height=0.8*cm)
                except Exception: pass
            if i%3==0:  # benign outline/bookmark
                c.bookmarkPage(f"pg{pg}"); c.addOutlineEntry(f"Section {pg}", f"pg{pg}")
            c.showPage()
        c.save(); paths.append(p)
    return paths

def main():
    outdir="/tmp/claude-0/benign_corpus"
    benign = gen_benign(250, outdir) + [str(p) for p in sorted(FX.glob("*.pdf"))]
    # ---- (c) false-positive on benign (two gates) + (e) runtime ----
    fp_strict=[]; fp_capability=0; parsed=0; times=[]
    for p in benign:
        data=open(p,"rb").read()
        t=time.perf_counter()
        try:
            mal=is_malicious(data); cap=any_active_capability(data); parsed+=1
        except Exception:
            continue
        times.append((time.perf_counter()-t)*1000)
        if mal: fp_strict.append(p.split("/")[-1])
        if cap: fp_capability+=1
    nben=len(benign)
    # ---- (a,b) witnesses on weaponized ----
    bases=["pdflatex-outline.pdf","multicolumn.pdf","libreoffice-form.pdf",
           "mistitled_outlines_example.pdf","ocg_map_test.pdf","pdflatex-4-pages.pdf",
           "google-doc-document.pdf","pdflatex-forms.pdf","annotated_pdf.pdf","minimal-document.pdf"]
    wirings=["openaction","names_js","page_aa","action_chain"]
    hops=[]; with_witness=0; total_pos=0; valid_witness=0
    for b in bases:
        try: raw=open(FX/b,"rb").read()
        except Exception: continue
        for w in wirings:
            twin=inject_autorun(raw,hide=True,wiring=w)
            if not twin: continue
            if not is_malicious(twin): continue
            total_pos+=1
            g=build_graph(twin)
            if g["path"]:
                with_witness+=1; hops.append(len(g["path"])-1)
                # validate: path starts at catalog, ends at a dangerous node
                nd={n["id"]:n for n in g["nodes"]}
                start_ok = nd.get(g["path"][0],{}).get("role")=="catalog"
                end_ok = g["path"][-1] in g["danger"]
                if start_ok and end_ok: valid_witness+=1
    # ---- (d) determinism: same file -> identical verdict+path, 3 runs ----
    sample=random.sample(benign,20)+[str(FX/bases[0])]
    det_ok=0; det_n=0
    for p in sample:
        data=open(p,"rb").read(); sigs=set()
        for _ in range(3):
            try:
                v=worst(data); g=build_graph(data); sigs.add((v,tuple(g["path"])))
            except Exception: sigs.add(("ERR",()))
        det_n+=1; det_ok+=int(len(sigs)==1)
    res={
      "benign_corpus_size": nben, "benign_parsed": parsed,
      "false_positive_strict_count": len(fp_strict),
      "false_positive_strict_rate": round(len(fp_strict)/max(parsed,1),4),
      "false_positive_strict_examples": fp_strict[:8],
      "benign_with_benign_active_capability": fp_capability,
      "benign_capability_note": "interaction-gated URI/form capabilities in benign docs; correctly NOT flagged as threats by the auto-trigger gate",
      "weaponized_positives": total_pos, "witness_coverage": round(with_witness/max(total_pos,1),4),
      "valid_witness_rate": round(valid_witness/max(total_pos,1),4),
      "witness_hops_mean": round(float(np.mean(hops)),2) if hops else None,
      "witness_hops_median": float(np.median(hops)) if hops else None,
      "witness_hops_max": int(np.max(hops)) if hops else None,
      "determinism_files": det_n, "determinism_identical_rate": round(det_ok/max(det_n,1),4),
      "runtime_ms_median": round(float(np.median(times)),2), "runtime_ms_p95": round(float(np.percentile(times,95)),2),
      "training_free": True,
    }
    json.dump(res,open(art("metrics","verifiable_oracle.json"),"w"),indent=2)
    print(f"benign corpus: {nben} ({parsed} parsed)")
    print(f"FALSE-POSITIVE (auto-exec code/file threat on benign): {res['false_positive_strict_count']}/{parsed} = {res['false_positive_strict_rate']:.2%}")
    if fp_strict: print("  examples:", fp_strict[:6])
    print(f"  (benign docs with an interaction-gated capability, correctly NOT flagged: {fp_capability})")
    print(f"weaponized positives: {total_pos} | witness coverage {res['witness_coverage']:.1%} | valid (catalog->dangerous) {res['valid_witness_rate']:.1%}")
    print(f"witness length (hops): median {res['witness_hops_median']}  mean {res['witness_hops_mean']}  max {res['witness_hops_max']}")
    print(f"determinism: {det_ok}/{det_n} files identical over 3 runs = {res['determinism_identical_rate']:.1%}")
    print(f"runtime/file: median {res['runtime_ms_median']} ms  p95 {res['runtime_ms_p95']} ms | training-free: yes")

if __name__=="__main__":
    main()
