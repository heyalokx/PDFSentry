import io
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_analyze_active_fixture():
    data = open("tests/fixtures/crafted/fixture_active_onopen.pdf", "rb").read()
    r = client.post("/api/analyze", files={"file": ("a.pdf", data, "application/pdf")})
    assert r.status_code == 200
    j = r.json()
    caps = {c["capability"]: c["verdict"] for c in j["reachability"]["capabilities"]}
    assert caps.get("javascript") == "ACTIVE_ONOPEN"
    assert j["risk_band"] in ("HIGH", "ELEVATED")


def test_reject_non_pdf():
    r = client.post("/api/analyze", files={"file": ("x.txt", b"hi", "text/plain")})
    assert r.status_code == 415


def test_reject_empty():
    r = client.post("/api/analyze", files={"file": ("x.pdf", b"", "application/pdf")})
    assert r.status_code == 400


def test_report_html_is_escaped_and_served():
    data = open("tests/fixtures/crafted/fixture_dormant.pdf", "rb").read()
    r = client.post("/api/report.html", files={"file": ("d.pdf", data, "application/pdf")})
    assert r.status_code == 200 and "PDFSentry" in r.text


def test_metrics_endpoint_traversal_safe():
    r = client.get("/api/metrics/..%2f..%2fconfig%2fdefault")
    assert r.status_code in (404, 400)
