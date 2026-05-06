import argparse
import json
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd
import xgboost as xgb


CANONICAL_COLUMNS = [
    "time",
    "duration",
    "src_comp",
    "src_port",
    "dest_comp",
    "dest_port",
    "protocol",
    "pkt_cnt",
    "byte_cnt",
]

# Avoid introducing unseen categorical labels at inference time.
CATEGORICAL_DEFAULTS = {
    "src_port": "1",
    "dest_port": "1",
    "protocol": "6",
}

# Supports both LANL-style flow columns and this repo's generated flow CSV columns.
COLUMN_RENAME_MAP = {
    "Time": "time",
    "Duration (s)": "duration",
    "Computer": "src_comp",
    "Source Port": "src_port",
    "Dest Port": "dest_port",
    "Protocol": "protocol",
    "Packet Count": "pkt_cnt",
    "Byte Count": "byte_cnt",
    "Source IP": "source_ip",
    "Dest IP": "dest_ip",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run inference on flow dataset using saved XGBoost flow model."
    )
    parser.add_argument(
        "--input",
        default="data/flows.csv",
        help="Path to input flows CSV (default: data/flows.csv).",
    )
    parser.add_argument(
        "--model",
        default="model/saved/lanl_flow_xgb.json",
        help="Path to saved XGBoost model JSON.",
    )
    parser.add_argument(
        "--metadata",
        default="model/saved/flow_metadata.json",
        help="Path to model metadata JSON containing feature list.",
    )
    parser.add_argument(
        "--output",
        default="data/flows_inference.csv",
        help="Path to write inference results CSV.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Decision threshold for binary prediction (default: 0.5).",
    )
    return parser.parse_args()


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns=COLUMN_RENAME_MAP).copy()

    # If destination computer is missing, use destination IP as a practical proxy.
    if "dest_comp" not in df.columns:
        if "dest_ip" in df.columns:
            df["dest_comp"] = df["dest_ip"]
        else:
            df["dest_comp"] = "?"

    # If source computer is missing, use source IP as a practical proxy.
    if "src_comp" not in df.columns:
        if "source_ip" in df.columns:
            df["src_comp"] = df["source_ip"]
        else:
            df["src_comp"] = "UNKNOWN_SRC"

    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            if col in CATEGORICAL_DEFAULTS:
                df[col] = CATEGORICAL_DEFAULTS[col]
            else:
                df[col] = np.nan

    return df


def to_unix_seconds(time_series: pd.Series) -> pd.Series:
    numeric_time = pd.to_numeric(time_series, errors="coerce")
    numeric_ratio = numeric_time.notna().mean()

    if numeric_ratio >= 0.7:
        return numeric_time.fillna(0).astype(np.int64)

    dt = pd.to_datetime(time_series, errors="coerce", utc=True)
    time_seconds = pd.Series(np.zeros(len(dt), dtype=np.int64), index=time_series.index)
    valid = dt.notna()
    if valid.any():
        time_seconds.loc[valid] = (dt.loc[valid].astype("int64") // 1_000_000_000).astype(
            np.int64
        )
    return time_seconds


def engineer_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["time"] = to_unix_seconds(df["time"])

    for col in ["duration", "pkt_cnt", "byte_cnt"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.float32)

    for col in ["src_port", "dest_port", "protocol"]:
        fallback = CATEGORICAL_DEFAULTS[col]
        df[col] = df[col].fillna(fallback).astype(str)
        df[col] = df[col].replace("", fallback).astype("category")

    df["src_comp"] = df["src_comp"].fillna("UNKNOWN_SRC").astype(str)
    df["dest_comp"] = df["dest_comp"].fillna("?").astype(str)

    df["hour_of_day"] = ((df["time"] % 86400) // 3600).astype(np.int16)
    df["is_off_hours"] = ((df["hour_of_day"] < 8) | (df["hour_of_day"] > 18)).astype(np.int8)

    dest_available = df["dest_comp"].notna() & (df["dest_comp"] != "?")
    df["is_lateral_movement"] = np.where(
        dest_available, (df["src_comp"] != df["dest_comp"]).astype(int), 0
    ).astype(np.int8)

    df["bytes_per_packet"] = np.where(
        df["pkt_cnt"] > 0, df["byte_cnt"] / df["pkt_cnt"], 0
    ).astype(np.float32)
    df["is_short_flow"] = (df["duration"] < 2.0).astype(np.int8)
    df["is_long_flow"] = (df["duration"] > 60.0).astype(np.int8)
    return df


def extract_training_categories(model: xgb.XGBClassifier) -> dict:
    categories_by_feature = {}
    booster = model.get_booster()
    if not hasattr(booster, "get_categories"):
        return categories_by_feature

    raw_categories = booster.get_categories(export_to_arrow=True).to_arrow()
    for feature_name, category_values in raw_categories:
        if category_values is None:
            continue
        if hasattr(category_values, "to_pylist"):
            values = [str(v) for v in category_values.to_pylist() if v is not None]
        else:
            values = [str(v) for v in category_values if v is not None]
        categories_by_feature[feature_name] = set(values)

    return categories_by_feature


def normalize_protocol_values(values: pd.Series) -> pd.Series:
    mapping = {
        "tcp": "6",
        "udp": "17",
        "icmp": "1",
        "ipv6": "41",
    }
    normalized = values.astype(str).str.strip().str.lower().replace(mapping)
    return normalized


def build_feature_matrix(
    df: pd.DataFrame, feature_names: List[str], training_categories: dict
) -> pd.DataFrame:
    df = df.copy()
    for col in feature_names:
        if col not in df.columns:
            if col in {"src_port", "dest_port", "protocol"}:
                df[col] = CATEGORICAL_DEFAULTS[col]
            else:
                df[col] = 0

    x = df[feature_names].copy()
    for col in {"src_port", "dest_port", "protocol"} & set(feature_names):
        fallback = CATEGORICAL_DEFAULTS[col]
        values = x[col].fillna(fallback).astype(str).replace("", fallback)
        if col == "protocol":
            values = normalize_protocol_values(values)

        allowed = training_categories.get(col, set())
        if allowed:
            safe_fallback = fallback if fallback in allowed else sorted(allowed)[0]
            values = values.where(values.isin(allowed), safe_fallback)

        x[col] = values.astype("category")
    return x


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    model_path = Path(args.model)
    metadata_path = Path(args.metadata)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input dataset not found: {input_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"Saved model not found: {model_path}")
    if not metadata_path.exists():
        raise FileNotFoundError(f"Model metadata not found: {metadata_path}")

    print(f"Loading dataset: {input_path}")
    raw_df = pd.read_csv(input_path, dtype=str, low_memory=False)
    print(f"Rows loaded: {len(raw_df):,}")

    normalized_df = normalize_columns(raw_df)
    feature_df = engineer_flow_features(normalized_df)

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    feature_names = metadata.get("features", [])
    if not feature_names:
        raise ValueError("Metadata JSON does not contain a non-empty 'features' list.")

    print(f"Loading model: {model_path}")
    model = xgb.XGBClassifier()
    model.load_model(str(model_path))
    training_categories = extract_training_categories(model)

    x = build_feature_matrix(feature_df, feature_names, training_categories)

    print("Running inference...")
    anomaly_score = model.predict_proba(x)[:, 1]
    predicted_anomaly = (anomaly_score >= args.threshold).astype(np.int8)

    output_df = raw_df.copy()
    output_df["anomaly_score"] = anomaly_score
    output_df["predicted_anomaly"] = predicted_anomaly

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_csv(output_path, index=False)

    flagged = int(predicted_anomaly.sum())
    print(f"Inference complete. Results saved to: {output_path}")
    print(f"Threshold: {args.threshold}")
    print(f"Flagged flows: {flagged:,} / {len(output_df):,}")


if __name__ == "__main__":
    main()
