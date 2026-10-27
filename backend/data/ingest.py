"""
Dataset ingestion + provenance for PDFSentry.

Loads the raw CIC-Evasive-PDFMal2022 CSV, repairs its many type quirks
(string-encoded numerics, -1 parser-failure sentinels, malformed PDF headers,
a categorical `text` column), engineers derived integrity/density features,
validates the schema, and writes a canonical manifest recording every
deviation. Nothing here is fabricated: every transformation is deterministic
and logged.
"""
from __future__ import annotations
import hashlib
import json
import re
import datetime as dt
from dataclasses import dataclass, field, asdict
from pathlib import Path

import numpy as np
import pandas as pd

from backend.core.config import load_config, data_path, art


@dataclass
class IngestReport:
    dataset_name: str
    source: str
    raw_sha256: str
    raw_rows: int
    raw_cols: int
    dropped_unlabeled: int
    final_rows: int
    n_features: int
    label_counts: dict
    coerced_columns: list
    sentinel_columns: list
    parse_failure_rows: int
    malformed_header_rows: int
    feature_names: list
    deviations: list = field(default_factory=list)
    created_utc: str = field(default_factory=lambda: dt.datetime.utcnow().isoformat() + "Z")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_header(val) -> tuple[float, int]:
    """Return (pdf_version, malformed_flag). '\\t%PDF-1.4' -> (1.4, 0);
    garbage like '%PDF-\\x07.3' -> (0.0, 1)."""
    if not isinstance(val, str):
        return 0.0, 1
    m = re.search(r"%PDF-(\d+)\.(\d+)", val)
    if m:
        return float(f"{m.group(1)}.{m.group(2)}"), 0
    return 0.0, 1


def _coerce_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(
        series.astype(str).str.strip().str.replace(r"[^0-9eE.+-]", "", regex=True),
        errors="coerce",
    )


_TEXT_MAP = {"yes": 2, "no": 0, "unclear": 1, "-1": -1, "0": 0}


def load_dataset(config: dict | None = None) -> tuple[pd.DataFrame, pd.Series, IngestReport]:
    """Return (X features frame, y labels, IngestReport)."""
    cfg = config or load_config()
    dcfg = cfg["dataset"]
    raw = data_path(dcfg["raw_csv"])
    raw_sha = _sha256(raw)

    df = pd.read_csv(raw)
    raw_rows, raw_cols = df.shape
    deviations: list[str] = []

    # --- labels ---
    label_col = dcfg["label_column"]
    before = len(df)
    df = df[df[label_col].notna()].copy()
    dropped = before - len(df)
    if dropped:
        deviations.append(f"Dropped {dropped} row(s) with missing {label_col} label.")
    y = df[label_col].map(dcfg["label_map"]).astype(int)

    ident = df[dcfg["id_column"]].astype(str).values
    df = df.drop(columns=[dcfg["id_column"], label_col])

    # --- coerce string-encoded numerics (pandas>=3 uses a 'str' dtype, not object) ---
    def _is_textual(s: pd.Series) -> bool:
        return not pd.api.types.is_numeric_dtype(s)

    coerced = []
    for c in dcfg["stringy_numeric"]:
        if c in df.columns and _is_textual(df[c]):
            df[c] = _coerce_numeric(df[c])
            coerced.append(c)

    # --- header -> version + malformed flag ---
    hv, hm = zip(*df["header"].map(_parse_header))
    df["header_version"] = np.array(hv, dtype=np.float32)
    df["header_malformed"] = np.array(hm, dtype=np.int8)
    malformed_rows = int(df["header_malformed"].sum())
    df = df.drop(columns=["header"])

    # --- categorical text column ---
    df["text_code"] = (
        df[dcfg["text_column"]].astype(str).str.strip().str.lower().map(_TEXT_MAP).fillna(-1)
    ).astype(np.int8)
    df = df.drop(columns=[dcfg["text_column"]])

    # any remaining textual columns -> coerce (defensive)
    for c in list(df.columns):
        if _is_textual(df[c]):
            df[c] = _coerce_numeric(df[c])
            coerced.append(c)

    df = df.fillna(0.0)

    # --- sentinel (-1 = parser failure) -> explicit meta feature ---
    sentinel_cols = [c for c in dcfg["sentinel_neg1"] if c in df.columns]
    n_parse_failures = (df[sentinel_cols] == -1).sum(axis=1).astype(np.int16)
    parse_fail_rows = int((n_parse_failures > 0).sum())

    # --- engineered derived features (our additions / robustness candidates) ---
    df["obj_endobj_delta"] = (df["obj"] - df["endobj"]).abs()
    df["stream_endstream_delta"] = (df["stream"] - df["endstream"]).abs()
    df["js_total"] = df["JS"].clip(lower=0) + df["Javascript"].clip(lower=0)
    df["autoexec_tokens"] = (
        df["OpenAction"].clip(lower=0) + df["AA"].clip(lower=0) + df["launch"].clip(lower=0)
    )
    df["n_parse_failures"] = n_parse_failures
    df["content_density"] = df["pdfsize"] / (df["obj"].abs() + 1.0)
    kw = cfg["feature_groups"]["keyword_capability"]
    kw_sum = df[kw].clip(lower=0).sum(axis=1)
    df["keyword_concentration"] = kw_sum / (df["obj"].abs() + 1.0)

    df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0).astype(np.float32)

    report = IngestReport(
        dataset_name=dcfg["name"],
        source=dcfg["source"],
        raw_sha256=raw_sha,
        raw_rows=raw_rows,
        raw_cols=raw_cols,
        dropped_unlabeled=dropped,
        final_rows=len(df),
        n_features=df.shape[1],
        label_counts={"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        coerced_columns=sorted(set(coerced)),
        sentinel_columns=sentinel_cols,
        parse_failure_rows=parse_fail_rows,
        malformed_header_rows=malformed_rows,
        feature_names=list(df.columns),
        deviations=deviations
        + [
            "CIC-Evasive-PDFMal2022 has no timestamp field; temporal drift analysis "
            "(as in EMBER2024) is NOT available and is reported as such.",
            "-1 values retained as parser-failure signal; count exposed as n_parse_failures.",
        ],
    )
    df.attrs["ident"] = ident
    return df, y, report


def write_manifest(report: IngestReport) -> Path:
    out = art("manifests", "dataset_manifest.json")
    with open(out, "w") as f:
        json.dump(asdict(report), f, indent=2)
    return out


if __name__ == "__main__":
    X, y, rep = load_dataset()
    p = write_manifest(rep)
    print(json.dumps(asdict(rep), indent=2))
    print("manifest ->", p)
