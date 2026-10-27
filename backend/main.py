"""PDFSentry FastAPI backend — the live analyst workbench API."""
from __future__ import annotations
import json
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from backend.core.config import load_config, art, ROOT
from backend.core.analyze import analyze
from backend.reporting.report import to_html, to_json

cfg = load_config()
app = FastAPI(title="PDFSentry API", version="1.0",
              description="Reachability-aware PDF malware intelligence")

MAX_BYTES = cfg["structural"]["max_file_bytes"]


def _load_metric(name: str):
    p = art("metrics", name)
    return json.load(open(p)) if p.exists() else None


@app.get("/api/health")
def health():
    model_ok = (ROOT / "artifacts" / "models" / "baseline.txt").exists()
    return {"status": "ok", "model_available": model_ok,
            "max_upload_bytes": MAX_BYTES, "engine": "TRA-1.0"}


@app.get("/api/status")
def status():
    man = art("manifests", "dataset_manifest.json")
    return {
        "dataset": json.load(open(man)) if man.exists() else None,
        "baseline": _load_metric("baseline_eval.json"),
        "comparison": _load_metric("model_comparison.json"),
    }


@app.get("/api/metrics/{name}")
def metrics(name: str):
    safe = Path(name).name  # prevent traversal
    data = _load_metric(f"{safe}.json")
    if data is None:
        raise HTTPException(404, f"no metric '{safe}'")
    return data


async def _read_upload(file: UploadFile) -> bytes:
    if not (file.filename or "").lower().endswith(".pdf"):
        raise HTTPException(415, "only .pdf files are accepted")
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"file exceeds {MAX_BYTES} byte cap")
    if len(data) == 0:
        raise HTTPException(400, "empty file")
    return data


@app.post("/api/analyze")
async def analyze_pdf(file: UploadFile = File(...)):
    data = await _read_upload(file)
    return JSONResponse(analyze(data, cfg))


@app.post("/api/report.html", response_class=HTMLResponse)
async def report_html(file: UploadFile = File(...)):
    data = await _read_upload(file)
    return HTMLResponse(to_html(analyze(data, cfg)))


@app.post("/api/report.json")
async def report_json(file: UploadFile = File(...)):
    data = await _read_upload(file)
    return JSONResponse(json.loads(to_json(analyze(data, cfg))))
