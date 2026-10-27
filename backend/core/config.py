"""Centralised config + path handling for PDFSentry."""
from __future__ import annotations
import os
from pathlib import Path
from functools import lru_cache
import yaml

ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=4)
def load_config(path: str | None = None) -> dict:
    cfg_path = Path(path) if path else ROOT / "config" / "default.yaml"
    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)
    cfg["_root"] = str(ROOT)
    return cfg


def art(*parts: str) -> Path:
    """Path inside artifacts/ (created on demand)."""
    p = ROOT / "artifacts"
    for part in parts:
        p = p / part
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def data_path(rel: str) -> Path:
    return ROOT / rel
