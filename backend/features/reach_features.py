"""
Reachability feature family — the novel structural evidence (Review-2 O3).

Turns one PDF into a fixed numeric vector that encodes not *how many* dangerous
tokens a byte-counter sees, but whether dangerous actions are structurally
REACHABLE from automatic triggers, how deep the action chains run, and — the
headline signal — whether a live action is HIDDEN from the byte scan
(reachable on open yet naive token count ~0, the signature of compressed-stream
token evasion).

These features are designed to catch the evasive samples that EMBER's
byte/string features miss, and to be hard to game: an author cannot lower them
without actually removing the attack's trigger path.
"""
from __future__ import annotations
import re
import numpy as np
from backend.structural.reachability import analyze_bytes

CAPS = ["javascript", "launch", "uri", "submit_form", "import_data",
        "remote_goto", "rich_media_execute", "embedded_file"]
# per-capability sub-features
_PC = ["onopen", "oninteract", "dormant", "minhops", "naive", "hidden_gap"]

FEATURE_NAMES = (
    [f"rc_{c}_{s}" for c in CAPS for s in _PC] +
    ["rc_n_auto_triggers", "rc_n_interact_triggers", "rc_n_triggers",
     "rc_n_active_onopen", "rc_n_active_oninteract", "rc_n_dormant",
     "rc_max_chain_depth", "rc_total_naive_tokens", "rc_n_reachable_caps",
     "rc_hidden_token_ratio", "rc_evasion_signature", "rc_has_objstm",
     "rc_objstm_count", "rc_n_objects", "rc_parsed", "rc_n_warnings",
     "rc_parse_failed"]
)


def reach_feature_vector(data: bytes, **kw) -> dict:
    r = analyze_bytes(data, **kw)
    f = {k: 0.0 for k in FEATURE_NAMES}
    capmap = {c["capability"]: c for c in r.capabilities}

    n_onopen = n_oninteract = n_dormant = 0
    hops_reachable = []
    total_naive = 0
    reachable_caps = 0
    hidden_live = 0

    for c in CAPS:
        cc = capmap.get(c)
        pre = f"rc_{c}_"
        if cc is None:
            f[pre + "minhops"] = -1.0
            continue
        v = cc["verdict"]; nc = cc["naive_count"]; mh = cc["min_hops"]
        onopen = 1.0 if v == "ACTIVE_ONOPEN" else 0.0
        oninteract = 1.0 if v == "ACTIVE_ONINTERACT" else 0.0
        dormant = 1.0 if v == "PRESENT_DORMANT" else 0.0
        reachable = onopen or oninteract
        hidden = 1.0 if (reachable and nc == 0) else 0.0
        f[pre + "onopen"] = onopen
        f[pre + "oninteract"] = oninteract
        f[pre + "dormant"] = dormant
        f[pre + "minhops"] = float(mh) if mh is not None else -1.0
        f[pre + "naive"] = float(nc)
        f[pre + "hidden_gap"] = hidden
        n_onopen += int(onopen); n_oninteract += int(oninteract)
        n_dormant += int(dormant); total_naive += nc
        if reachable:
            reachable_caps += 1
            if mh is not None:
                hops_reachable.append(mh)
        hidden_live += int(hidden)

    trig = r.trigger_points
    n_auto = sum(1 for t in trig if t.get("class") == "auto")
    n_inter = sum(1 for t in trig if t.get("class") == "interaction")
    objstm = len(re.findall(b"/ObjStm", data))

    f["rc_n_auto_triggers"] = float(n_auto)
    f["rc_n_interact_triggers"] = float(n_inter)
    f["rc_n_triggers"] = float(len(trig))
    f["rc_n_active_onopen"] = float(n_onopen)
    f["rc_n_active_oninteract"] = float(n_oninteract)
    f["rc_n_dormant"] = float(n_dormant)
    f["rc_max_chain_depth"] = float(max(hops_reachable)) if hops_reachable else 0.0
    f["rc_total_naive_tokens"] = float(total_naive)
    f["rc_n_reachable_caps"] = float(reachable_caps)
    f["rc_hidden_token_ratio"] = float(hidden_live / reachable_caps) if reachable_caps else 0.0
    f["rc_evasion_signature"] = 1.0 if hidden_live > 0 else 0.0
    f["rc_has_objstm"] = 1.0 if objstm > 0 else 0.0
    f["rc_objstm_count"] = float(objstm)
    f["rc_n_objects"] = float(r.n_objects)
    f["rc_parsed"] = 1.0 if r.parsed else 0.0
    f["rc_n_warnings"] = float(len(r.parse_warnings))
    f["rc_parse_failed"] = 0.0 if r.parsed else 1.0
    return f


def vectorize(data: bytes, **kw) -> np.ndarray:
    f = reach_feature_vector(data, **kw)
    return np.array([f[k] for k in FEATURE_NAMES], dtype=np.float32)


if __name__ == "__main__":
    import glob
    print(f"{len(FEATURE_NAMES)} reachability features")
    for p in (sorted(glob.glob("tests/fixtures/crafted/*.pdf")) +
              ["tests/fixtures/real_pdfs/GeoTopo.pdf"]):
        f = reach_feature_vector(open(p, "rb").read())
        print(p.split("/")[-1].ljust(30),
              "evasion_sig", f["rc_evasion_signature"],
              "hidden_ratio", round(f["rc_hidden_token_ratio"], 2),
              "js_onopen", f["rc_javascript_onopen"],
              "uri_onopen", f["rc_uri_onopen"])
