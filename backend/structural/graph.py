"""Object-reference graph + reachable-path extraction for visualization."""
from __future__ import annotations
import io
import pikepdf

ROLE_BY_KEY = {"/OpenAction": "trigger", "/AA": "trigger", "/Names": "trigger"}


def _rid(o):
    try:
        if o.is_indirect:
            g = o.objgen
            return f"{g[0]}_{g[1]}"
    except Exception:
        pass
    return None


def _label(key, obj):
    try:
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            s = obj.get("/S")
            if s is not None and str(s) in ("/JavaScript", "/Launch", "/SubmitForm"):
                return str(s).strip("/"), "dangerous"
            if "/JS" in obj.keys() or "/JavaScript" in obj.keys():
                return "JavaScript", "dangerous"
            t = obj.get("/Type")
            if t is not None:
                tt = str(t).strip("/")
                if tt == "EmbeddedFile":
                    return "EmbeddedFile", "dangerous"
                role = {"Catalog": "catalog", "Pages": "pages", "Page": "page",
                        "Action": "action", "Annot": "annot"}.get(tt, "dict")
                return tt, role
            return (key.strip("/") if key else "dict"), "dict"
    except Exception:
        pass
    return (key.strip("/") if key else "obj"), "other"


def build_graph(data: bytes, max_nodes=48):
    """Return {nodes, edges, danger, path} for a PDF's object graph.
    path = node-id list from the catalog to a reachable dangerous node (or [])."""
    pdf = pikepdf.open(io.BytesIO(data))
    nodes, edges, parent = {}, [], {}
    root = pdf.Root
    rroot = _rid(root) or "root"
    nodes[rroot] = {"id": rroot, "label": "Catalog", "role": "catalog"}
    frontier = [(rroot, root)]
    while frontier and len(nodes) < max_nodes:
        pid, obj = frontier.pop(0)
        try:
            if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
                items = list(obj.items())
            elif isinstance(obj, pikepdf.Array):
                items = [(f"[{i}]", v) for i, v in enumerate(obj)]
            else:
                items = []
        except Exception:
            items = []
        for k, child in items:
            k = str(k)
            if not isinstance(child, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
                continue
            cid = _rid(child) or f"{pid}:{k}"
            if cid not in nodes:
                if len(nodes) >= max_nodes:
                    continue
                lab, role = _label(k, child)
                if k in ROLE_BY_KEY and role not in ("dangerous",):
                    role = "trigger"
                nodes[cid] = {"id": cid, "label": lab, "role": role}
                parent[cid] = pid
                frontier.append((cid, child))
            edges.append({"source": pid, "target": cid})
    pdf.close()
    danger = [n["id"] for n in nodes.values() if n["role"] == "dangerous"]
    # reconstruct catalog -> dangerous path
    path = []
    if danger:
        cur = danger[0]; chain = [cur]
        while cur in parent:
            cur = parent[cur]; chain.append(cur)
        path = list(reversed(chain))
    return {"nodes": list(nodes.values()), "edges": edges, "danger": danger, "path": path}
