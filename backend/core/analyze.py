"""
Unified per-file analysis service: the live product's brain.

Combines three independent sources of evidence and keeps them separate:
  1. count-based model verdict  (the tabular detector, fragile by our thesis)
  2. trigger-reachability verdict (our robust structural signal)
  3. a reconciled PDFSentry risk band that fires loudest when the two DISAGREE
     (count says calm, reachability says an action auto-runs = classic evasion).
"""
from __future__ import annotations
import datetime as dt
import numpy as np

from backend.core.config import load_config
from backend.features.extract import extract_features
from backend.structural.reachability import analyze_bytes
from backend.models.baseline import load_model

_PLAIN = {
    "javascript": "Embedded JavaScript. Legitimate forms use it too; the risk is whether it runs automatically.",
    "launch": "A /Launch action can ask the viewer to run an external program.",
    "uri": "A link/URI action points outside the document.",
    "submit_form": "A form-submit action can send data to a remote endpoint.",
    "import_data": "An import-data action pulls external form data.",
    "remote_goto": "A remote go-to action references another document.",
    "embedded_file": "The document carries an embedded file attachment.",
    "rich_media_execute": "A RichMedia action can execute embedded multimedia.",
}
_VERDICT_WEIGHT = {"ACTIVE_ONOPEN": 3, "ACTIVE_ONINTERACT": 2, "PRESENT_DORMANT": 1, "ABSENT": 0}


def _risk_band(model_score, reach_caps, parsed):
    auto = [c for c in reach_caps if c["verdict"] == "ACTIVE_ONOPEN"]
    interact = [c for c in reach_caps if c["verdict"] == "ACTIVE_ONINTERACT"]
    disagreement = None
    if auto and model_score is not None and model_score < 0.5:
        disagreement = ("Count-based model rates this low, but a dangerous action "
                        "is reachable on open — a classic token-evasion pattern.")
    # banding
    if auto:
        band = "HIGH" if (model_score is None or model_score >= 0.5 or disagreement) else "ELEVATED"
    elif interact:
        band = "ELEVATED"
    elif model_score is not None and model_score >= 0.5:
        band = "ELEVATED"
    elif not parsed:
        band = "UNKNOWN"
    else:
        band = "LOW"
    return band, disagreement


def analyze(data: bytes, config: dict | None = None, with_model: bool = True) -> dict:
    cfg = config or load_config()
    s = cfg["structural"]
    reach = analyze_bytes(data, s["max_file_bytes"], s["max_objects"],
                          s["reachability_max_hops"], s["parse_timeout_s"])
    feat = extract_features(data)

    model_block = None
    if with_model:
        try:
            booster, prov = load_model("baseline")
            cols = prov["features"]
            x = np.array([[feat["features"][c] for c in cols]], dtype=np.float32)
            score = float(booster.predict(x)[0])
            top = sorted(
                [{"feature": c, "value": float(feat["features"][c])} for c in cols],
                key=lambda d: -abs(d["value"]))[:5]
            model_block = {
                "score": score,
                "verdict": "malicious" if score >= cfg["model"]["decision_threshold"] else "benign",
                "threshold": cfg["model"]["decision_threshold"],
                "model_hash": prov["model_hash"],
                "top_features": top,
                "caveat": feat["caveat"],
            }
        except Exception as e:
            model_block = {"unavailable": True, "reason": str(e)[:160]}

    mscore = model_block["score"] if model_block and "score" in model_block else None
    band, disagreement = _risk_band(mscore, reach.capabilities, reach.parsed)

    findings = []
    for c in reach.capabilities:
        findings.append({
            **c,
            "explanation": _PLAIN.get(c["capability"], "Security-relevant structure."),
        })

    return {
        "sha256": reach.sha256,
        "size_bytes": reach.size_bytes,
        "parsed": reach.parsed,
        "n_objects": reach.n_objects,
        "risk_band": band,
        "disagreement": disagreement,
        "reachability": {
            "engine": reach.engine_version,
            "trigger_points": reach.trigger_points,
            "capabilities": findings,
            "warnings": reach.parse_warnings,
            "error": reach.error,
            "analysis_ms": reach.analysis_ms,
        },
        "model": model_block,
        "structural_features": feat["features"],
        "disclaimer": ("Static analysis only. A clean result cannot guarantee a "
                       "file is safe; a flagged result is evidence, not proof."),
        "analyzed_utc": dt.datetime.utcnow().isoformat() + "Z",
    }
