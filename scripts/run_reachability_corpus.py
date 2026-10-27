"""
Run the Trigger-Reachability Analyzer across the crafted fixtures and the real
benign PDF corpus, and quantify how often a count-based view disagrees with the
reachability view (the robust-invariant evidence on the PDF side).
"""
from __future__ import annotations
import glob
import json
from backend.core.config import load_config, art
from backend.structural.reachability import analyze_path

VERDICT_RANK = {"ABSENT": 0, "PRESENT_DORMANT": 1, "ACTIVE_ONINTERACT": 2, "ACTIVE_ONOPEN": 3}


def summarize(path):
    r = analyze_path(path)
    naive = sum(c["naive_count"] for c in r.capabilities)
    worst = "ABSENT"
    for c in r.capabilities:
        if VERDICT_RANK[c["verdict"]] > VERDICT_RANK[worst]:
            worst = c["verdict"]
    return {
        "file": path.split("/")[-1],
        "parsed": r.parsed,
        "n_objects": r.n_objects,
        "naive_token_count": naive,
        "reachability_verdict": worst,
        "capabilities": r.capabilities,
        "n_triggers": len(r.trigger_points),
        "warnings": r.parse_warnings[:4],
        "error": r.error,
    }


def main():
    cfg = load_config()
    crafted = sorted(glob.glob("tests/fixtures/crafted/*.pdf"))
    real = sorted(glob.glob("tests/fixtures/real_pdfs/*.pdf"))
    rows = {"crafted": [summarize(p) for p in crafted],
            "real": [summarize(p) for p in real]}

    # disagreement accounting at the CAPABILITY level (a per-file aggregate
    # masks cases like GeoTopo, where a dormant token hides a hidden live one).
    over_alarm = under_alarm = 0
    files_with_disagreement = set()
    examples = []
    for grp in rows.values():
        for s in grp:
            if not s["parsed"]:
                continue
            for c in s["capabilities"]:
                nc, v = c["naive_count"], c["verdict"]
                # UNDER-alarm: auto-runs on open but invisible to a byte scan
                if v == "ACTIVE_ONOPEN" and nc == 0:
                    under_alarm += 1
                    files_with_disagreement.add(s["file"])
                    examples.append({"file": s["file"], "capability": c["capability"],
                                     "type": "naive_under_alarm", "naive": nc, "verdict": v})
                # OVER-alarm: many tokens, but it never auto-runs
                elif nc >= 2 and v in ("PRESENT_DORMANT", "ACTIVE_ONINTERACT"):
                    over_alarm += 1
                    files_with_disagreement.add(s["file"])
                    examples.append({"file": s["file"], "capability": c["capability"],
                                     "type": "naive_over_alarm", "naive": nc, "verdict": v})
    agree = sum(1 for grp in rows.values() for s in grp if s["parsed"]) - len(files_with_disagreement)

    out = {
        "engine": "TRA-1.0",
        "n_crafted": len(crafted), "n_real": len(real),
        "disagreement": {"naive_over_alarm": over_alarm,
                         "naive_under_alarm": under_alarm,
                         "agree": agree,
                         "examples": examples},
        "rows": rows,
    }
    with open(art("metrics", "reachability_corpus.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"crafted={len(crafted)} real={len(real)} "
          f"over_alarm={over_alarm} under_alarm={under_alarm} agree={agree}")
    for e in examples[:12]:
        print(" ", e)


if __name__ == "__main__":
    main()
