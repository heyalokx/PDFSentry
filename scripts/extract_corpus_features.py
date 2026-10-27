"""
Extract a training table from a folder of raw PDFs: EMBER byte/string features
(+ the real EMBER model score) and the reachability feature family, labelled by
folder. Output is a small CSV safe to move between machines.

Runs in this sandbox OR in Google Colab (see docs/COLAB.md). Static only:
nothing is executed; PDFs are parsed, never run.

Usage:
  python scripts/extract_corpus_features.py \
      --malicious /path/to/malicious --benign /path/to/benign \
      --ember-model data/ember/EMBER2024_PDF.model --out features.csv
"""
from __future__ import annotations
import sys, types, argparse, glob, csv, hashlib
import numpy as np

# stub signify (unused for PDFs; avoids an oscrypto import error)
_m = types.ModuleType("signify"); _a = types.ModuleType("signify.authenticode")
_a.SignedPEFile = object; _m.authenticode = _a
sys.modules.setdefault("signify", _m); sys.modules.setdefault("signify.authenticode", _a)

from backend.features.reach_features import reach_feature_vector, FEATURE_NAMES


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--ember-model", default=None)
    ap.add_argument("--out", default="features.csv")
    ap.add_argument("--max-bytes", type=int, default=6_000_000)
    args = ap.parse_args()

    ember = None
    if args.ember_model:
        import thrember, lightgbm as lgb
        ext = thrember.PEFeatureExtractor()
        mdl = lgb.Booster(model_file=args.ember_model)
        def ember(data):
            v = np.array(ext.feature_vector(data), dtype=np.float32).reshape(1, -1)
            return float(mdl.predict(v)[0])

    cols = ["sha256", "label", "ember_score"] + FEATURE_NAMES
    n = {"malicious": 0, "benign": 0}; fail = 0
    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(cols)
        for label, folder in [(1, args.malicious), (0, args.benign)]:
            for p in glob.glob(f"{folder}/**/*", recursive=True):
                if not p.lower().endswith(".pdf"):
                    continue
                try:
                    data = open(p, "rb").read()
                    if not data or len(data) > args.max_bytes:
                        continue
                    es = ember(data) if ember else ""
                    rf = reach_feature_vector(data)
                    sha = hashlib.sha256(data).hexdigest()
                    w.writerow([sha, label, es] + [rf[k] for k in FEATURE_NAMES])
                    n["malicious" if label else "benign"] += 1
                except Exception:
                    fail += 1
    print(f"wrote {args.out}: {n['malicious']} malicious, {n['benign']} benign, {fail} skipped")


if __name__ == "__main__":
    main()
