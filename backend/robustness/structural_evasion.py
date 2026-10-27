"""
Controlled structural-evasion study (Review-2 O3/O4/O6, done against the REAL
EMBER2024 PDF model).

Premise proven by SHAP (O2): the EMBER baseline decides on byte/string
statistics and has no structural signal. So an attacker who adds a dangerous,
auto-running action to a document but keeps its *bytes* looking normal should
slip past it. The standard way to do that in the wild is to place the action
inside a compressed object stream (/ObjStm), which removes the giveaway tokens
(`/JavaScript`, `/OpenAction`) from the raw byte scan — exactly what the real
benign file GeoTopo.pdf does by accident.

This module performs that transformation with a HARMLESS payload (an
`app.alert`), never real malware, and measures:
  * how often the compression-hidden injection EVADES the EMBER model, and
  * whether the reachability engine still catches it (it should: it decompresses
    and traces the object graph).

No malicious samples are downloaded or created; the only JavaScript used is a
benign alert, and nothing is ever executed.
"""
from __future__ import annotations
import io
import pikepdf
from pikepdf import Name, String, Dictionary

HARMLESS_JS = "app.alert('structural-evasion study \\u2014 harmless');"


from pikepdf import Array

# structurally DISTINCT ways to wire the same auto-run action. Reachability must
# catch all of them; each exercises a different part of the graph traversal, so
# the result cannot be an artefact of one tailored feature.
WIRINGS = ["openaction", "action_chain", "names_js", "page_aa"]


def _js_action(pdf):
    return pdf.make_indirect(Dictionary(
        Type=Name("/Action"), S=Name("/JavaScript"), JS=String(HARMLESS_JS)))


def inject_autorun(data: bytes, hide: bool = True, wiring: str = "openaction") -> bytes | None:
    """Inject a reachable auto-run JavaScript action (harmless alert) into an
    existing PDF via `wiring`, then optionally hide its tokens in a compressed
    object stream. Returns None if the file can't be parsed/edited.

    wirings:
      openaction   - /Root /OpenAction -> JS                  (hops 0)
      action_chain - /Root /OpenAction -> GoTo, /Next -> JS   (deeper chain)
      names_js      - /Root /Names /JavaScript name tree -> JS (document-level)
      page_aa       - first /Page /AA /O (page-open) -> JS
    """
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except Exception:
        return None
    try:
        act = _js_action(pdf)
        if wiring == "openaction":
            pdf.Root.OpenAction = act
        elif wiring == "action_chain":
            lead = pdf.make_indirect(Dictionary(
                Type=Name("/Action"), S=Name("/GoTo"), Next=act))
            pdf.Root.OpenAction = lead
        elif wiring == "names_js":
            name_entry = pdf.make_indirect(Dictionary(
                Names=Array([String("PDFSentryJS"), act])))
            names = pdf.Root.get("/Names")
            if names is None:
                pdf.Root.Names = pdf.make_indirect(Dictionary())
                names = pdf.Root["/Names"]
            names["/JavaScript"] = name_entry
        elif wiring == "page_aa":
            page = pdf.pages[0].obj
            page["/AA"] = pdf.make_indirect(Dictionary(O=act))
        else:
            return None
        out = io.BytesIO()
        if hide:
            pdf.save(out, object_stream_mode=pikepdf.ObjectStreamMode.generate,
                     compress_streams=True)
        else:
            pdf.save(out, object_stream_mode=pikepdf.ObjectStreamMode.disable)
        return out.getvalue()
    except Exception:
        return None
    finally:
        pdf.close()
