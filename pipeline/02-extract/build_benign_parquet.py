"""Build combined and feature-group Parquet files for benign JSON reports."""

from __future__ import annotations

import importlib.util
import json
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "benign_dataset"
JSON_DIR = DATA / "json"
OUT = DATA
SOURCE_BUILDER = Path(r"E:\LLM\Malware PFE\Statique\_extract\phase_b_full.py")
CHUNK_SIZE = 1000
WORKERS = 8
META_COLS = [
    "sha256", "raw_label", "category_label", "binary_label",
    "category_label_corrected", "label_type", "normalized_label", "alt_category_labels",
]


def load_builder():
    spec = importlib.util.spec_from_file_location("phase_b_full", SOURCE_BUILDER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load feature builder: {SOURCE_BUILDER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_report(path):
    try:
        obj = json.loads(path.read_bytes())
        if not isinstance(obj, dict):
            return path, None, "malformed"
        return path, obj, None
    except Exception:
        return path, None, "malformed"


def main():
    builder = load_builder()
    group_dir = OUT / "by_feature_group"
    group_dir.mkdir(parents=True, exist_ok=True)
    paths = sorted(JSON_DIR.glob("*.json"))
    if not paths:
        raise ValueError(f"No JSON reports found in {JSON_DIR}")
    print(f"[*] JSON reports: {len(paths)}", flush=True)

    rule_freq = Counter()
    valid_paths = []
    malformed = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for index, (path, obj, error) in enumerate(pool.map(read_report, paths, chunksize=64), 1):
            if error:
                malformed += 1
            else:
                valid_paths.append(path)
                rules = (obj.get("advanced_yara") or {}).get("yara_matched_rules", []) or []
                rule_freq.update(str(rule) for rule in rules)
            if index % 5000 == 0:
                print(f"    pass 1: {index}/{len(paths)}", flush=True)

    vocab = sorted(rule_freq)
    yara_rule_cols = [f"yara_rule::{rule}" for rule in vocab]
    print(f"[*] valid={len(valid_paths)} malformed={malformed} YARA columns={len(vocab)}", flush=True)

    first = json.loads(valid_paths[0].read_bytes())
    groups, _ = builder.build_groups(first)
    group_cols = OrderedDict((name, list(values.keys())) for name, values in groups.items())
    group_cols["advanced_yara"] = builder.YARA_BASE_COLS + yara_rule_cols
    feature_cols = [column for cols in group_cols.values() for column in cols]
    all_cols = feature_cols + META_COLS
    string_cols = set(META_COLS)

    def field_type(column):
        if column in string_cols:
            return pa.string()
        return builder.arrow_type(column)

    schema = pa.schema([pa.field(column, field_type(column)) for column in all_cols])
    schema_set = set(all_cols)
    pandas_types = {
        column: ("float32" if column in builder.FLOAT_COLS else
                 "int64" if column in builder.BIG_INT_COLS else "int32")
        for column in feature_cols
    }

    def featurize(path):
        obj = json.loads(path.read_bytes())
        sha = str(obj.get("sha256") or path.stem).lower()
        raw_label = str(obj.get("label") or "benign")
        groups, _ = builder.build_groups(obj)
        flat = {}
        for group in groups.values():
            flat.update(group)
        flat.update({
            "sha256": sha,
            "raw_label": raw_label,
            "category_label": "benign",
            "binary_label": "benign",
            "category_label_corrected": "benign",
            "label_type": "category",
            "normalized_label": "benign",
            "alt_category_labels": "",
        })
        return {key: value for key, value in flat.items() if key in schema_set}

    combined = OUT / "benign_all_features.parquet"
    rows = 0
    with pq.ParquetWriter(combined, schema, compression="zstd") as writer:
        buffer = []
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for index, row in enumerate(pool.map(featurize, valid_paths, chunksize=64), 1):
                buffer.append(row)
                rows += 1
                if len(buffer) >= CHUNK_SIZE:
                    frame = pd.DataFrame(buffer).reindex(columns=all_cols, fill_value=0)
                    frame[feature_cols] = frame[feature_cols].fillna(0).astype(pandas_types)
                    for column in META_COLS:
                        frame[column] = frame[column].astype(str)
                    writer.write_table(pa.Table.from_pandas(frame, schema=schema, preserve_index=False))
                    buffer = []
                if index % 5000 == 0:
                    print(f"    pass 2: {index}/{len(valid_paths)}", flush=True)
        if buffer:
            frame = pd.DataFrame(buffer).reindex(columns=all_cols, fill_value=0)
            frame[feature_cols] = frame[feature_cols].fillna(0).astype(pandas_types)
            for column in META_COLS:
                frame[column] = frame[column].astype(str)
            writer.write_table(pa.Table.from_pandas(frame, schema=schema, preserve_index=False))

    print(f"[+] {combined.name}: {rows} rows x {len(all_cols)} columns", flush=True)
    for name, cols in group_cols.items():
        target = group_dir / f"{name}.parquet"
        table = pq.read_table(combined, columns=cols + META_COLS)
        pq.write_table(table, target, compression="zstd")
        print(f"[+] by_feature_group/{target.name}: {table.num_rows} rows x {table.num_columns} columns", flush=True)

    report = {
        "source_directory": str(JSON_DIR),
        "source_json_reports": len(paths),
        "valid_reports": len(valid_paths),
        "malformed_reports_excluded": malformed,
        "feature_groups": list(group_cols),
        "yara_rule_columns": len(yara_rule_cols),
        "combined_file": str(combined),
        "duplicate_conflict_directory": str(DATA / "020_raw"),
    }
    (OUT / "feature_build_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] wrote {OUT / 'feature_build_report.json'}", flush=True)


if __name__ == "__main__":
    main()
