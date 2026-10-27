"""
CIC-compatible static feature extraction from raw PDF bytes.

The original CIC-Evasive-PDFMal2022 features were produced with a pdfid-style
keyword counter. This module reconstructs a compatible feature vector so the
tabular detector can score a live upload. It is an APPROXIMATION of the
original tool and may differ in edge cases; that caveat travels with every
live model score. It also returns the raw token counts the reachability
engine contrasts against.

Static only: counts keywords and parses structure; never executes anything.
"""
from __future__ import annotations
import re
import io
import hashlib
import pikepdf

KEYWORDS = ["obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref"]
SLASH = {"ObjStm": "/ObjStm", "JS": "/JS", "Javascript": "/JavaScript", "AA": "/AA",
         "OpenAction": "/OpenAction", "Acroform": "/AcroForm", "JBIG2Decode": "/JBIG2Decode",
         "RichMedia": "/RichMedia", "launch": "/Launch", "EmbeddedFile": "/EmbeddedFile",
         "XFA": "/XFA", "Colors": "/Colors"}
MODEL_FEATURES = [
    "pdfsize", "metadata size", "pages", "xref Length", "title characters",
    "isEncrypted", "embedded files", "images", "obj", "endobj", "stream",
    "endstream", "xref", "trailer", "startxref", "pageno", "encrypt", "ObjStm",
    "JS", "Javascript", "AA", "OpenAction", "Acroform", "JBIG2Decode",
    "RichMedia", "launch", "EmbeddedFile", "XFA", "Colors", "header_version",
    "header_malformed", "text_code", "obj_endobj_delta", "stream_endstream_delta",
    "js_total", "autoexec_tokens", "n_parse_failures", "content_density",
    "keyword_concentration",
]
KEYWORD_CAPABILITY = ["JS", "Javascript", "AA", "OpenAction", "Acroform",
                      "JBIG2Decode", "RichMedia", "launch", "EmbeddedFile", "XFA"]


def _count(data: bytes, token: str) -> int:
    return len(re.findall(re.escape(token.encode()), data))


def extract_features(data: bytes) -> dict:
    f = {k: 0.0 for k in MODEL_FEATURES}
    f["pdfsize"] = round(len(data) / 1024.0, 2)

    m = re.search(rb"%PDF-(\d+)\.(\d+)", data[:1024])
    if m:
        f["header_version"] = float(f"{int(m.group(1))}.{int(m.group(2))}")
        f["header_malformed"] = 0.0
    else:
        f["header_version"] = 0.0
        f["header_malformed"] = 1.0

    for k in KEYWORDS:
        f[k] = float(_count(data, k))
    for col, tok in SLASH.items():
        f[col] = float(_count(data, tok))

    pages = 0
    title_chars = 0
    meta_size = 0
    encrypted = 0
    text_present = 0
    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            encrypted = 1 if pdf.is_encrypted else 0
            try:
                pages = len(pdf.pages)
            except Exception:
                pages = 0
            try:
                di = pdf.docinfo
                if di is not None and "/Title" in di.keys():
                    title_chars = len(str(di["/Title"]))
                meta_size = len(bytes(str(di), "utf-8")) if di is not None else 0
            except Exception:
                pass
            try:
                txt = pdf.pages[0].obj.get("/Contents")
                text_present = 2 if txt is not None else 0
            except Exception:
                text_present = 0
    except Exception:
        f["n_parse_failures"] = 1.0

    f["pages"] = float(pages)
    f["pageno"] = float(pages)
    f["title characters"] = float(title_chars)
    f["metadata size"] = float(meta_size)
    f["isEncrypted"] = float(encrypted)
    f["encrypt"] = float(encrypted)
    f["xref Length"] = float(_count(data, "xref") * 10)  # rough proxy
    f["text_code"] = float(text_present)

    # derived (identical formulas to ingest.py)
    f["obj_endobj_delta"] = abs(f["obj"] - f["endobj"])
    f["stream_endstream_delta"] = abs(f["stream"] - f["endstream"])
    f["js_total"] = max(f["JS"], 0) + max(f["Javascript"], 0)
    f["autoexec_tokens"] = max(f["OpenAction"], 0) + max(f["AA"], 0) + max(f["launch"], 0)
    kw_sum = sum(max(f[c], 0) for c in KEYWORD_CAPABILITY)
    f["content_density"] = f["pdfsize"] / (abs(f["obj"]) + 1.0)
    f["keyword_concentration"] = kw_sum / (abs(f["obj"]) + 1.0)

    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "features": f,
        "feature_order": MODEL_FEATURES,
        "extractor": "cic-compatible-approx-1.0",
        "caveat": ("Features reconstructed with a pdfid-style counter; an "
                   "approximation of the original CIC extraction tool."),
    }
