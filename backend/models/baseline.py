"""LightGBM baseline detector with provenance."""
from __future__ import annotations
import hashlib
import json
import time
import datetime as dt
import numpy as np
import pandas as pd
import lightgbm as lgb
from backend.core.config import load_config, art


def train_lgbm(X_train: pd.DataFrame, y_train: np.ndarray, config: dict | None = None,
               feature_subset: list[str] | None = None):
    cfg = config or load_config()
    params = dict(cfg["model"]["params"])
    cols = feature_subset or list(X_train.columns)
    dset = lgb.Dataset(X_train[cols].values, label=np.asarray(y_train),
                       feature_name=cols)
    t0 = time.time()
    booster = lgb.train(params, dset, num_boost_round=params["num_iterations"])
    train_s = time.time() - t0
    return booster, cols, train_s


def model_hash(booster: lgb.Booster) -> str:
    return hashlib.sha256(booster.model_to_string().encode()).hexdigest()[:16]


def save_model(booster: lgb.Booster, cols: list[str], meta: dict, name: str) -> dict:
    path = art("models", f"{name}.txt")
    booster.save_model(str(path))
    prov = {
        "name": name,
        "model_hash": model_hash(booster),
        "n_features": len(cols),
        "features": cols,
        "num_trees": booster.num_trees(),
        "created_utc": dt.datetime.utcnow().isoformat() + "Z",
        **meta,
    }
    with open(art("models", f"{name}.provenance.json"), "w") as f:
        json.dump(prov, f, indent=2)
    return prov


def load_model(name: str):
    path = art("models", f"{name}.txt")
    booster = lgb.Booster(model_file=str(path))
    prov = json.load(open(art("models", f"{name}.provenance.json")))
    return booster, prov
