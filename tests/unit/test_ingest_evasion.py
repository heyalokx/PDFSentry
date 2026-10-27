import numpy as np
from backend.core.config import load_config
from backend.data.ingest import load_dataset
from backend.robustness.evasion import recompute_derived


def test_ingest_shapes_and_labels():
    X, y, rep = load_dataset()
    assert X.shape[0] == y.shape[0] == rep.final_rows
    assert set(np.unique(y)) <= {0, 1}
    assert np.isfinite(X.values).all()         # no NaN/inf leaks through
    assert rep.parse_failure_rows > 0          # -1 sentinel really exists


def test_header_parsing_flags_malformed():
    X, y, rep = load_dataset()
    assert rep.malformed_header_rows > 0
    assert "header_version" in X.columns and "header_malformed" in X.columns


def test_recompute_derived_consistency():
    cfg = load_config()
    kw = cfg["feature_groups"]["keyword_capability"]
    v = {c: 0.0 for c in kw}
    v.update({"JS": 3, "Javascript": 2, "OpenAction": 1, "AA": 0, "launch": 0,
              "obj": 9, "endobj": 9, "stream": 1, "endstream": 1, "pdfsize": 10})
    out = recompute_derived(dict(v), kw)
    assert out["js_total"] == 5
    assert out["autoexec_tokens"] == 1
    # removing JS tokens must lower the derived concentration
    v2 = dict(v); v2["JS"] = 0; v2["Javascript"] = 0
    out2 = recompute_derived(v2, kw)
    assert out2["keyword_concentration"] < out["keyword_concentration"]
