"""Deterministic stratified split with provenance hashing."""
from __future__ import annotations
import hashlib
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from backend.core.config import load_config, art


def _hash_idx(idx: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(np.sort(idx)).tobytes()).hexdigest()[:16]


def make_split(X: pd.DataFrame, y: pd.Series, config: dict | None = None):
    cfg = config or load_config()
    seed = cfg["project"]["seed"]
    frac = cfg["split"]["test_fraction"]
    idx = np.arange(len(X))
    tr, te = train_test_split(
        idx, test_size=frac, stratify=y.values if cfg["split"]["stratify"] else None,
        random_state=seed,
    )
    manifest = {
        "seed": seed,
        "test_fraction": frac,
        "stratified": cfg["split"]["stratify"],
        "n_train": int(len(tr)),
        "n_test": int(len(te)),
        "train_hash": _hash_idx(tr),
        "test_hash": _hash_idx(te),
        "train_label_counts": {"benign": int((y.values[tr] == 0).sum()),
                               "malicious": int((y.values[tr] == 1).sum())},
        "test_label_counts": {"benign": int((y.values[te] == 0).sum()),
                              "malicious": int((y.values[te] == 1).sum())},
        "note": "No temporal axis in CIC-PDFMal2022; stratified random holdout, "
                "NOT a temporal challenge split.",
    }
    with open(art("manifests", "split_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return tr, te, manifest
