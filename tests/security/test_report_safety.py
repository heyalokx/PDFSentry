from backend.reporting.report import to_html


def _base(**over):
    a = {
        "sha256": "a" * 64, "size_bytes": 10, "parsed": True, "n_objects": 3,
        "risk_band": "LOW", "disagreement": None,
        "reachability": {"engine": "TRA-1.0", "trigger_points": [],
                         "capabilities": [], "warnings": [], "error": None,
                         "analysis_ms": 1},
        "model": {"score": 0.1, "verdict": "benign", "threshold": 0.5,
                  "model_hash": "x", "top_features": [], "caveat": "c"},
        "structural_features": {}, "disclaimer": "d", "analyzed_utc": "t",
    }
    a.update(over)
    return a


def test_html_escapes_hostile_capability_path():
    hostile = "<script>alert(1)</script>"
    a = _base(reachability={
        "engine": "TRA-1.0", "trigger_points": [],
        "capabilities": [{"capability": hostile, "verdict": "ACTIVE_ONOPEN",
                          "min_hops": 0, "naive_count": 1,
                          "trigger_path": [hostile], "reachable_from_trigger": True}],
        "warnings": [hostile], "error": None, "analysis_ms": 1})
    html = to_html(a)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_disagreement():
    a = _base(disagreement="<img src=x onerror=alert(1)>")
    html = to_html(a)
    assert "<img src=x" not in html
