"""Explainable risk report: JSON + safe self-contained HTML."""
from __future__ import annotations
import html
import json
import datetime as dt

_BAND_COLOR = {"HIGH": "#ff5c5c", "ELEVATED": "#ffb020", "LOW": "#36d399",
               "UNKNOWN": "#8a8f98"}


def to_json(analysis: dict) -> str:
    return json.dumps(analysis, indent=2)


def _esc(x) -> str:
    return html.escape(str(x), quote=True)


def to_html(analysis: dict) -> str:
    a = analysis
    band = a["risk_band"]
    color = _BAND_COLOR.get(band, "#8a8f98")
    rows = []
    for c in a["reachability"]["capabilities"]:
        path = " → ".join(_esc(p) for p in c.get("trigger_path", [])) or "—"
        rows.append(
            f"<tr><td>{_esc(c['capability'])}</td><td><b>{_esc(c['verdict'])}</b></td>"
            f"<td>{_esc(c.get('min_hops'))}</td><td>{_esc(c['naive_count'])}</td>"
            f"<td style='max-width:360px'>{path}</td></tr>")
    cap_table = "".join(rows) or "<tr><td colspan=5>No dangerous capabilities detected.</td></tr>"

    model = a.get("model") or {}
    if "score" in model:
        model_html = (f"<p>Count-based model: <b>{_esc(model['verdict'])}</b> "
                      f"(score {model['score']:.3f}, threshold {model['threshold']}). "
                      f"<span class=caveat>{_esc(model['caveat'])}</span></p>")
    else:
        model_html = "<p>Count-based model: <i>unavailable</i>.</p>"

    disagree = (f"<div class='disagree'>&#9888; {_esc(a['disagreement'])}</div>"
                if a.get("disagreement") else "")
    warn = a["reachability"].get("warnings") or []
    warn_html = ("<ul>" + "".join(f"<li>{_esc(w)}</li>" for w in warn) + "</ul>") if warn else "<p>None.</p>"

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>PDFSentry Report {_esc(a['sha256'][:12])}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:32px;}}
.card{{max-width:860px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px;}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#8a8f98;font-size:13px;word-break:break-all}}
.band{{display:inline-block;padding:6px 16px;border-radius:999px;font-weight:700;color:#0d1117;background:{color};margin:16px 0}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #21262d}} th{{color:#8a8f98;font-weight:600}}
.caveat{{color:#8a8f98;font-size:12px}}
.disagree{{background:#3d2a00;border:1px solid #ffb020;color:#ffb020;padding:12px 14px;border-radius:8px;margin:12px 0;font-size:13px}}
.foot{{color:#6e7681;font-size:11px;margin-top:20px;border-top:1px solid #21262d;padding-top:12px}}
</style></head><body><div class="card">
<h1>PDFSentry — Explainable Risk Report</h1>
<div class="sub">SHA-256 {_esc(a['sha256'])}</div>
<div class="sub">{_esc(a['size_bytes'])} bytes · {_esc(a['n_objects'])} objects · parsed: {_esc(a['parsed'])}</div>
<div class="band">RISK: {_esc(band)}</div>
{disagree}
{model_html}
<h3>Reachability findings</h3>
<table><tr><th>Capability</th><th>Verdict</th><th>Hops</th><th>Naive byte count</th><th>Trigger path</th></tr>
{cap_table}</table>
<h3>Parser warnings</h3>{warn_html}
<div class="foot">{_esc(a['disclaimer'])}<br>Analyzed {_esc(a['analyzed_utc'])} · engine {_esc(a['reachability']['engine'])}</div>
</div></body></html>"""
