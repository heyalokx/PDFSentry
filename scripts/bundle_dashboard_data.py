"""Consolidate every real artifact into one JSON the dashboard embeds."""
import json
from backend.core.config import art


def L(name):
    p = art("metrics", name)
    if not p.exists():
        p = art("explanations", name)
    if not p.exists():
        p = art("manifests", name)
    return json.load(open(p)) if p.exists() else None


bundle = {
    "dataset": L("dataset_manifest.json"),
    "split": json.load(open(art("manifests", "split_manifest.json"))),
    "baseline": L("baseline_eval.json"),
    "comparison": L("model_comparison.json"),
    "evasion_baseline": L("evasion_baseline.json"),
    "evasion_structure_first": L("evasion_structure_first.json"),
    "shap": L("shap_analysis.json"),
    "reachability": L("reachability_corpus.json"),
    # EMBER2024 track (Review-2 primary)
    "ember": L("ember_reproduction.json"),
    "ember_shap": L("ember_shap.json"),
    "structural_evasion": L("structural_evasion_study.json"),
}
out = art("metrics", "dashboard_data.json")
json.dump(bundle, open(out, "w"))
print("bundled ->", out, out.stat().st_size, "bytes")
# headline numbers for narrative
b = bundle["baseline"]["point_metrics"]
cmp = bundle["comparison"]
print("baseline PR-AUC", round(b["pr_auc"], 4), "ROC-AUC", round(b["roc_auc"], 4), "F1", round(b["f1"], 4))
print("baseline ERS", cmp["evasion"]["baseline"]["ers"], "median cost", cmp["evasion"]["baseline"]["median_cost"])
print("structure_first ERS", cmp["evasion"]["structure_first"]["ers"])
print("reach disagreements", bundle["reachability"]["disagreement"]["naive_over_alarm"],
      "over /", bundle["reachability"]["disagreement"]["naive_under_alarm"], "under")
