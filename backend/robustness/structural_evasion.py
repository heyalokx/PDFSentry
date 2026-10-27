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


def inject_autorun(data: bytes, hide: bool = True) -> bytes | None:
    """Add a reachable /OpenAction -> JavaScript action to an existing PDF.
    hide=True re-saves with object streams so the action's tokens are
    compressed out of the raw byte scan (the evasion); hide=False leaves them
    visible (the control). Returns None if the file can't be parsed."""
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except Exception:
        return None
    try:
        act = pdf.make_indirect(Dictionary(
            Type=Name("/Action"), S=Name("/JavaScript"), JS=String(HARMLESS_JS)))
        pdf.Root.OpenAction = act
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
