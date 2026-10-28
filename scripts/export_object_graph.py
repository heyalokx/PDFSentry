"""
Export a real PDF object-reference graph (nodes + edges + roles + the reachable
trigger path) for the dashboard's signature visualization. Real structure from a
real parsed PDF; the auto-run action is a harmless injected one so the graph
shows a live reachability path. Nothing executed.
"""
from __future__ import annotations
import sys, types, io, json
import pikepdf
sys.path.insert(0, ".")
from backend.robustness.structural_evasion import inject_autorun
from backend.core.config import art, ROOT

DANGER_KEYS = {"/JavaScript", "/JS", "/Launch", "/OpenAction", "/AA", "/Names"}


def rid(o):
    try:
        if o.is_indirect:
            g = o.objgen; return f"{g[0]}_{g[1]}"
    except Exception:
        pass
    return None


def label_of(key, obj):
    try:
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            t = obj.get("/Type"); s = obj.get("/S")
            if s is not None and str(s) in ("/JavaScript", "/Launch"):
                return str(s).strip("/"), "dangerous"
            if t is not None:
                tt = str(t).strip("/")
                role = {"Catalog": "catalog", "Pages": "pages", "Page": "page",
                        "Action": "action", "Annot": "annot"}.get(tt, "dict")
                return tt, role
            if "/JS" in obj.keys() or "/JavaScript" in obj.keys():
                return "JavaScript", "dangerous"
            return (key.strip("/") if key else "dict"), "dict"
    except Exception:
        pass
    return (key.strip("/") if key else "obj"), "other"


def build(data: bytes, max_nodes=46):
    pdf = pikepdf.open(io.BytesIO(data))
    nodes, edges, seen = {}, [], {}
    root = pdf.Root
    rroot = rid(root) or "root"
    nodes[rroot] = {"id": rroot, "label": "Catalog", "role": "catalog"}
    frontier = [(rroot, root, "/Root")]
    while frontier and len(nodes) < max_nodes:
        pid, obj, key = frontier.pop(0)
        try:
            items = list(obj.items()) if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)) else \
                    [(f"[{i}]", v) for i, v in enumerate(obj)] if isinstance(obj, pikepdf.Array) else []
        except Exception:
            items = []
        for k, child in items:
            k = str(k)
            if not isinstance(child, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
                continue
            cid = rid(child) or f"{pid}:{k}"
            if cid not in nodes:
                lab, role = label_of(k, child)
                # trigger roles by the edge key
                if k in ("/OpenAction", "/AA", "/Names") and role not in ("dangerous",):
                    role = "trigger"
                if len(nodes) < max_nodes:
                    nodes[cid] = {"id": cid, "label": lab, "role": role}
                    frontier.append((cid, child, k))
                else:
                    continue
            edges.append({"source": pid, "target": cid, "label": k.strip("/")})
    pdf.close()
    # mark the reachable dangerous path (catalog -> trigger -> action -> dangerous)
    danger = [n["id"] for n in nodes.values() if n["role"] == "dangerous"]
    return {"nodes": list(nodes.values()), "edges": edges, "danger": danger}


def main():
    base = ROOT / "tests/fixtures/real_pdfs/pdflatex-outline.pdf"
    data = open(base, "rb").read()
    inj = inject_autorun(data, hide=False, wiring="openaction") or data
    g = build(inj)
    roles = {}
    for n in g["nodes"]:
        roles[n["role"]] = roles.get(n["role"], 0) + 1
    out = {"source": "pdflatex-outline.pdf + injected reachable /OpenAction→JavaScript",
           "nodes": g["nodes"], "edges": g["edges"], "danger": g["danger"],
           "role_counts": roles}
    with open(art("metrics", "object_graph.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("nodes", len(g["nodes"]), "edges", len(g["edges"]), "roles", roles, "danger", g["danger"])


if __name__ == "__main__":
    main()
