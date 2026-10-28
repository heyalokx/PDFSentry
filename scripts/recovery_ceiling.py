"""Measured recovery headroom on EMBER's real evasive misses, using a single
interpretable STRUCTURAL rule derived from EMBER's own released features (no raw
files). Shows how much structural awareness EMBER leaves on the table."""
import sys,types,glob,json
import numpy as np
_m=types.ModuleType("signify");_a=types.ModuleType("signify.authenticode");_a.SignedPEFile=object;_m.authenticode=_a
sys.modules.setdefault("signify",_m);sys.modules.setdefault("signify.authenticode",_a)
import thrember,lightgbm as lgb
from backend.core.config import ROOT,art
EXT=thrember.PEFeatureExtractor();MDL=lgb.Booster(model_file=str(ROOT/"data/ember/EMBER2024_PDF.model"))

def feats(d):
    sc=d.get("strings",{}).get("string_counts",{}) or {}; g=d.get("general",{})
    return dict(fd=sc.get("/FlateDecode",0), js=sc.get("javascript",0), ent=g.get("entropy",0), sz=g.get("size",0))

# benign medians from PDF_test benign
bm={"fd":[],"ent":[],"sz":[]};n=0
for fp in sorted(glob.glob(str(ROOT/"data/ember/PDF_test/*.jsonl"))):
    for line in open(fp):
        d=json.loads(line)
        if d.get("file_type")!="PDF" or d.get("label")!=0: continue
        f=feats(d); bm["fd"].append(f["fd"]);bm["ent"].append(f["ent"]);bm["sz"].append(f["sz"]);n+=1
        if n>=6000:break
    if n>=6000:break
med={k:float(np.median(v)) for k,v in bm.items()}

def flags(f):
    return (int(f["fd"]>2*max(med["fd"],1))+int(f["ent"]>max(med["ent"],7.6)+0.2)
            +int(f["sz"]>3*max(med["sz"],1))+int(f["js"]==0 and f["fd"]>0))

# challenge PDFs: ember score + flags
ch=[]
for fp in sorted(glob.glob(str(ROOT/"data/ember/challenge/*.jsonl"))):
    for line in open(fp):
        d=json.loads(line)
        if d.get("file_type")!="PDF" or d.get("label")!=1: continue
        s=float(MDL.predict(np.array(EXT.process_raw_features(d),dtype=np.float32).reshape(1,-1))[0])
        ch.append((s,flags(feats(d))))
ch=np.array(ch); scores=ch[:,0]; chflags=ch[:,1]
caught=scores>=0.5; missed=~caught
# benign test flags for FP
bflags=[]
n=0
for fp in sorted(glob.glob(str(ROOT/"data/ember/PDF_test/*.jsonl"))):
    for line in open(fp):
        d=json.loads(line)
        if d.get("file_type")!="PDF" or d.get("label")!=0: continue
        bflags.append(flags(feats(d))); n+=1
        if n>=6000:break
    if n>=6000:break
bflags=np.array(bflags)

print(f"challenge evasive PDFs: {len(ch)}  | EMBER caught {caught.sum()} missed {missed.sum()}  base recall {caught.mean():.3f}")
print(f"benign test PDFs for FP: {len(bflags)}")
out={"n_evasive":int(len(ch)),"ember_caught":int(caught.sum()),"ember_missed":int(missed.sum()),
     "base_recall":float(caught.mean()),"n_benign":int(len(bflags)),"rules":[]}
for k in (1,2,3):
    rule_m=chflags>=k
    recovered=int((missed & rule_m).sum())
    combined_recall=float(((caught)|(rule_m)).mean())
    fp=float((bflags>=k).mean())
    out["rules"].append({"threshold":k,"recovered_of_missed":recovered,
        "recovery_pct":recovered/int(missed.sum()),"combined_recall":combined_recall,"benign_fp_rate":fp})
    print(f"  rule flags>={k}:  recover {recovered}/{int(missed.sum())} misses ({recovered/int(missed.sum()):.1%})"
          f"  -> combined recall {caught.mean():.3f} -> {combined_recall:.3f}   benign FP {fp:.2%}")
json.dump(out,open(art("metrics","recovery_ceiling.json"),"w"),indent=2)
