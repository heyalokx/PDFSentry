"""
Trigger-Reachability Analyzer  (novel structural engine).

Standard PDF-malware features (CIC-PDFMal2022, EMBER string regexes) COUNT
dangerous tokens in the file's bytes: how many '/JavaScript', '/OpenAction',
'/Launch' appear. A count cannot tell whether that JavaScript is wired to run
automatically when the document opens, or is inert bytes an author can bury to
fool the counter.

This module parses the PDF object graph STATICALLY and answers the question a
count cannot:  is each dangerous capability REACHABLE from an automatic trigger
point, and in how many hops?

Entry (auto-trigger) points:
  * /Root /OpenAction                      (runs on open)
  * /Root /AA  (document additional-actions: /WC /WS /DS /WP /DP)
  * /Root /Names /JavaScript  name tree    (document-level JS, runs on open)
  * each /Page /AA                          (page open/close actions)
  * /AcroForm field  /AA and /A
  * annotation  /AA and /A                  (e.g. widget / link actions)

Dangerous targets:  /JavaScript or /JS, /Launch, /SubmitForm, /ImportData,
/URI, /GoToR, /RichMediaExecute, and /EmbeddedFile references.

SAFETY: parsing only. No JavaScript is executed, no launch/embedded payload is
opened, no URL is contacted, no stream is rendered. Resource guards bound file
size, object count and wall-clock time.
"""
from __future__ import annotations
import re
import time
import hashlib
from dataclasses import dataclass, field, asdict

import pikepdf

TRIGGER_AA_KEYS = {"/WC", "/WS", "/DS", "/WP", "/DP", "/O", "/C", "/K", "/F", "/V",
                   "/U", "/Fo", "/Bl", "/E", "/X", "/D", "/PO", "/PC", "/PV", "/PI"}
DANGEROUS = {
    "/JavaScript": "javascript",
    "/JS": "javascript",
    "/Launch": "launch",
    "/SubmitForm": "submit_form",
    "/ImportData": "import_data",
    "/URI": "uri",
    "/GoToR": "remote_goto",
    "/RichMediaExecute": "rich_media_execute",
    "/EmbeddedFile": "embedded_file",
}
# bytes-level tokens a naive count-based detector keys on (mirrors CIC/EMBER)
NAIVE_TOKENS = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch",
                "/EmbeddedFile", "/URI", "/AcroForm", "/XFA", "/RichMedia"]


@dataclass
class CapabilityFinding:
    capability: str
    naive_count: int            # how many tokens a byte-counter would see
    present_in_graph: bool      # parsed as a real object/key anywhere
    reachable_from_trigger: bool
    min_hops: int | None        # shortest path from an auto-trigger
    verdict: str                # ACTIVE_ONOPEN | ACTIVE_ONINTERACT | PRESENT_DORMANT | ABSENT
    trigger_class: str | None = None   # auto | interaction
    trigger_path: list = field(default_factory=list)


@dataclass
class ReachabilityReport:
    sha256: str
    size_bytes: int
    parsed: bool
    n_objects: int
    trigger_points: list
    capabilities: list
    parse_warnings: list
    analysis_ms: int
    engine_version: str = "TRA-1.0"
    error: str | None = None


def _ref_id(obj):
    try:
        if obj.is_indirect:
            g = obj.objgen
            return f"{g[0]}R{g[1]}"
    except Exception:
        pass
    return None


class _Graph:
    """Lazily-built object-reference graph from a pikepdf document."""

    def __init__(self, pdf, max_objects, max_hops):
        self.pdf = pdf
        self.max_objects = max_objects
        self.max_hops = max_hops
        self.n_visited = 0

    def children(self, obj):
        """Yield (edge_label, child_obj) for references out of obj."""
        try:
            if isinstance(obj, pikepdf.Dictionary) or isinstance(obj, pikepdf.Stream):
                for k in obj.keys():
                    try:
                        yield str(k), obj[k]
                    except Exception:
                        continue
            elif isinstance(obj, pikepdf.Array):
                for i, it in enumerate(obj):
                    yield f"[{i}]", it
        except Exception:
            return


def _dangerous_here(label, obj):
    """Return set of dangerous capability names signalled at this node."""
    hits = set()
    if label in DANGEROUS:
        hits.add(DANGEROUS[label])
    try:
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            # /S /JavaScript  (action subtype), /Type /Action etc.
            s = obj.get("/S")
            if s is not None and str(s) in DANGEROUS:
                hits.add(DANGEROUS[str(s)])
            if "/JS" in obj.keys():
                hits.add("javascript")
            if "/JavaScript" in obj.keys():
                hits.add("javascript")
            t = obj.get("/Type")
            if t is not None and str(t) == "/EmbeddedFile":
                hits.add("embedded_file")
    except Exception:
        pass
    return hits


def analyze_bytes(data: bytes, max_file_bytes=15_000_000, max_objects=50_000,
                  max_hops=12, timeout_s=20) -> ReachabilityReport:
    t0 = time.time()
    sha = hashlib.sha256(data).hexdigest()
    size = len(data)
    warnings: list[str] = []

    if size == 0:
        return ReachabilityReport(sha, 0, False, 0, [], [], ["empty file"], 0,
                                  error="empty file")
    if size > max_file_bytes:
        return ReachabilityReport(sha, size, False, 0, [], [],
                                  ["file exceeds size cap"], 0, error="too large")
    if not data[:1024].lstrip().startswith(b"%PDF-"):
        warnings.append("missing %PDF- header in first 1KB (possibly polyglot/malformed)")

    # --- naive byte-level token counts (what a count-based detector sees) ---
    naive = {}
    for tok in NAIVE_TOKENS:
        naive[tok] = len(re.findall(re.escape(tok.encode()), data))

    # --- parse object graph (in-memory, never touches disk) ---
    import io
    try:
        pdf = pikepdf.open(io.BytesIO(data), suppress_warnings=False)
    except Exception as e:  # malformed, encrypted-without-key, polyglot...
        caps = _caps_from_naive_only(naive)
        return ReachabilityReport(sha, size, False, 0, [], caps,
                                  warnings + [f"parse failed: {type(e).__name__}"],
                                  int((time.time() - t0) * 1000), error=str(e)[:200])

    with pdf:
        try:
            n_objects = len(pdf.objects)
        except Exception:
            n_objects = 0
        graph = _Graph(pdf, max_objects, max_hops)
        root = pdf.Root

        # collect trigger entry objects, each tagged auto (fires on open) or
        # interaction (needs a click/focus).
        triggers = []  # (name, class, obj)
        try:
            if "/OpenAction" in root.keys():
                triggers.append(("Root/OpenAction", "auto", root["/OpenAction"]))
        except Exception:
            pass
        try:
            if "/AA" in root.keys():
                aa = root["/AA"]
                for k in aa.keys():
                    triggers.append((f"Root/AA{k}", "auto", aa[k]))
        except Exception:
            pass
        try:
            names = root.get("/Names")
            if names is not None and "/JavaScript" in names.keys():
                triggers.append(("Root/Names/JavaScript", "auto", names["/JavaScript"]))
        except Exception:
            pass
        try:
            for page in pdf.pages:
                po = page.obj
                if "/AA" in po.keys():
                    aa = po["/AA"]
                    for k in aa.keys():
                        triggers.append(("Page/AA" + str(k), "auto", aa[k]))
                if "/Annots" in po.keys():
                    for annot in po["/Annots"]:
                        for ak, cls in (("/A", "interaction"), ("/AA", "interaction")):
                            try:
                                if ak in annot.keys():
                                    triggers.append(("Annot" + ak, cls, annot[ak]))
                            except Exception:
                                continue
        except Exception as e:
            warnings.append(f"page/annot walk partial: {type(e).__name__}")
        try:
            af = root.get("/AcroForm")
            if af is not None:
                triggers.append(("Root/AcroForm", "interaction", af))
        except Exception:
            pass

        # BFS from triggers over the reference graph. For each capability record
        # the best (auto beats interaction; then fewest hops) reaching path.
        RANK = {"auto": 0, "interaction": 1}
        cap_best: dict[str, dict] = {}  # cap -> {hops, class, path}

        def _offer(cap, hops, cls, path):
            cur = cap_best.get(cap)
            if cur is None or (RANK[cls], hops) < (RANK[cur["class"]], cur["hops"]):
                cap_best[cap] = {"hops": hops, "class": cls, "path": path}

        visited = set()
        frontier = [(tobj, 0, cls, [tname]) for tname, cls, tobj in triggers]
        guard = 0
        while frontier:
            guard += 1
            if guard > max_objects or (time.time() - t0) > timeout_s:
                warnings.append("traversal truncated by resource guard")
                break
            obj, hops, cls, path = frontier.pop(0)
            rid = _ref_id(obj)
            key = (rid or id(obj))
            if (key, cls) in visited or hops > max_hops:
                continue
            visited.add((key, cls))
            lbl = path[-1]
            lbl = lbl if lbl.startswith("/") else "/" + lbl.split("/")[-1]
            for cap in _dangerous_here(lbl, obj):
                _offer(cap, hops, cls, path)
            for elabel, child in graph.children(obj):
                for cap in _dangerous_here(elabel, child):
                    _offer(cap, hops + 1, cls, path + [elabel])
                frontier.append((child, hops + 1, cls, path + [elabel]))

        # full-graph presence scan from Root (reachable at all, even if not from a trigger)
        present = set()
        vis2 = set()
        stack = [root, pdf.trailer]
        g2 = 0
        while stack:
            g2 += 1
            if g2 > max_objects or (time.time() - t0) > timeout_s:
                break
            obj = stack.pop()
            rid = _ref_id(obj); key = rid or id(obj)
            if key in vis2:
                continue
            vis2.add(key)
            for elabel, child in graph.children(obj):
                present |= _dangerous_here(elabel, child)
                stack.append(child)

        caps = _assemble(naive, present, cap_best)

    trig_summary = [{"point": t[0], "class": t[1]} for t in triggers[:40]]
    return ReachabilityReport(
        sha, size, True, n_objects,
        trig_summary, caps, warnings,
        int((time.time() - t0) * 1000))


def _cap_naive_count(cap: str, naive: dict) -> int:
    if cap == "javascript":
        return naive.get("/JavaScript", 0) + naive.get("/JS", 0)
    tokmap = {"launch": "/Launch", "uri": "/URI", "embedded_file": "/EmbeddedFile"}
    return naive.get(tokmap.get(cap, ""), 0)


_NAIVE_CAP = {"/JavaScript": "javascript", "/JS": "javascript", "/Launch": "launch",
              "/URI": "uri", "/EmbeddedFile": "embedded_file"}


def _assemble(naive, present, cap_best):
    caps = []
    # include capabilities a byte counter would see, even if the graph walk did
    # not reach them (reported as PRESENT_DORMANT) — completeness + determinism
    naive_present = {cap for tok, cap in _NAIVE_CAP.items() if naive.get(tok, 0) > 0}
    cap_names = set(present) | set(cap_best) | naive_present
    for cap in sorted(cap_names):
        best = cap_best.get(cap)
        reachable = best is not None
        in_graph = (cap in present) or reachable
        nc = _cap_naive_count(cap, naive)
        if reachable:
            verdict = "ACTIVE_ONOPEN" if best["class"] == "auto" else "ACTIVE_ONINTERACT"
        elif in_graph or nc > 0:
            verdict = "PRESENT_DORMANT"
        else:
            continue
        caps.append(asdict(CapabilityFinding(
            capability=cap, naive_count=nc, present_in_graph=in_graph,
            reachable_from_trigger=reachable,
            min_hops=best["hops"] if best else None, verdict=verdict,
            trigger_class=best["class"] if best else None,
            trigger_path=best["path"] if best else [])))
    return caps


def _caps_from_naive_only(naive):
    caps = []
    for cap in sorted(set(DANGEROUS.values())):
        nc = _cap_naive_count(cap, naive)
        if nc > 0:
            caps.append(asdict(CapabilityFinding(
                capability=cap, naive_count=nc, present_in_graph=False,
                reachable_from_trigger=False, min_hops=None,
                verdict="PRESENT_DORMANT", trigger_path=[])))
    return caps


class BytesIOGuard:
    """Minimal read-only file-like wrapper so pikepdf never touches disk."""
    def __init__(self, data: bytes):
        import io
        self._b = io.BytesIO(data)
    def read(self, *a): return self._b.read(*a)
    def seek(self, *a): return self._b.seek(*a)
    def tell(self): return self._b.tell()
    def readable(self): return True
    def seekable(self): return True


def analyze_path(path: str, **kw) -> ReachabilityReport:
    with open(path, "rb") as f:
        return analyze_bytes(f.read(), **kw)
