"""
Generate HARMLESS PDF fixtures that isolate the reachability contrast.

NO malware, NO exploits: the only JavaScript used is a benign `app.alert`.
These exist so the demo can show, on files whose bytes a count-based detector
scores identically, that reachability separates 'auto-runs on open' from
'inert / needs a click / buried in a compressed stream'.
"""
from __future__ import annotations
import pikepdf
from pikepdf import Name, String, Dictionary, Array
from pathlib import Path

OUT = Path("tests/fixtures/crafted"); OUT.mkdir(parents=True, exist_ok=True)
HARMLESS_JS = "app.alert('PDFSentry reachability demo \\u2014 harmless');"


def _skeleton():
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    return pdf


def make_dormant():
    """A /JavaScript action object exists and is reachable from Root via a
    NON-trigger key, so a byte counter sees '/JavaScript' but it can never run."""
    pdf = _skeleton()
    act = pdf.make_indirect(Dictionary(
        Type=Name("/Action"), S=Name("/JavaScript"), JS=String(HARMLESS_JS)))
    # reference it from a non-trigger custom key so pikepdf keeps it on save
    pdf.Root["/PDFSentryDormant"] = act
    pdf.save(OUT / "fixture_dormant.pdf")


def make_active_onopen():
    """Same JS action, but wired to /OpenAction -> runs automatically on open."""
    pdf = _skeleton()
    act = pdf.make_indirect(Dictionary(
        Type=Name("/Action"), S=Name("/JavaScript"), JS=String(HARMLESS_JS)))
    pdf.Root.OpenAction = act
    pdf.save(OUT / "fixture_active_onopen.pdf")


def make_active_buried():
    """Auto-run JS wired to /OpenAction, but saved with object streams so the
    literal '/JavaScript' and '/JS' tokens are compressed out of the raw bytes:
    a byte counter sees ~0, reachability still finds it ACTIVE_ONOPEN."""
    pdf = _skeleton()
    act = pdf.make_indirect(Dictionary(
        Type=Name("/Action"), S=Name("/JavaScript"), JS=String(HARMLESS_JS)))
    pdf.Root.OpenAction = act
    pdf.save(OUT / "fixture_active_buried.pdf",
             object_stream_mode=pikepdf.ObjectStreamMode.generate,
             compress_streams=True)


def make_interaction_only():
    """JS reachable only through a link annotation's /A -> needs a click."""
    pdf = _skeleton()
    act = pdf.make_indirect(Dictionary(
        Type=Name("/Action"), S=Name("/JavaScript"), JS=String(HARMLESS_JS)))
    page = pdf.pages[0]
    annot = pdf.make_indirect(Dictionary(
        Type=Name("/Annot"), Subtype=Name("/Link"),
        Rect=Array([10, 10, 100, 40]), A=act))
    page.obj["/Annots"] = Array([annot])
    pdf.save(OUT / "fixture_interaction_only.pdf")


if __name__ == "__main__":
    make_dormant(); make_active_onopen(); make_active_buried(); make_interaction_only()
    for p in sorted(OUT.glob("*.pdf")):
        print("wrote", p, p.stat().st_size, "bytes")
