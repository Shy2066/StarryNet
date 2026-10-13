#!/usr/bin/env python3
"""Compute auditable WF metrics from per-sample predictions.

Input is JSONL or CSV with at least ``sample_id``, ``y_true`` and ``y_pred``.
Optional ``model``, ``domain``, ``seed`` and ``protocol`` columns produce grouped metrics.
The tool never chooses a checkpoint and never reads training data; it only
summarizes an already produced prediction file.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_rows(path):
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSONL at line {0}: {1}".format(line_number, exc))
            if not isinstance(row, dict):
                raise ValueError("prediction row is not an object at line {0}".format(line_number))
            rows.append(row)
    return rows


def required_fields(rows):
    missing = []
    for index, row in enumerate(rows, 1):
        absent = [field for field in ("sample_id", "y_true", "y_pred") if field not in row]
        if absent:
            missing.append("row {0}: missing {1}".format(index, ",".join(absent)))
    return missing


def metric_rows(rows):
    true_values = [str(row["y_true"]) for row in rows]
    pred_values = [str(row["y_pred"]) for row in rows]
    labels = sorted(set(true_values) | set(pred_values))
    correct = sum(actual == predicted for actual, predicted in zip(true_values, pred_values))
    per_class = {}
    f1_values = []
    for label in labels:
        tp = sum(actual == label and predicted == label
                 for actual, predicted in zip(true_values, pred_values))
        fp = sum(actual != label and predicted == label
                 for actual, predicted in zip(true_values, pred_values))
        fn = sum(actual == label and predicted != label
                 for actual, predicted in zip(true_values, pred_values))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        per_class[label] = {"support": tp + fn, "tp": tp, "fp": fp, "fn": fn,
                            "precision": precision, "recall": recall, "f1": f1}
        f1_values.append(f1)
    return {"sample_count": len(rows), "correct_count": correct,
            "accuracy": correct / len(rows) if rows else None,
            "macro_f1": statistics.fmean(f1_values) if f1_values else None,
            "labels": labels, "per_class": per_class}


def group_key(row, fields):
    values = []
    for field in fields:
        value = row.get(field)
        values.append("unspecified" if value in (None, "") else str(value))
    return tuple(values)


def sample_std(values):
    return statistics.stdev(values) if len(values) >= 2 else None


def evaluate(args):
    rows = load_rows(args.predictions)
    missing = required_fields(rows)
    if missing:
        raise ValueError("; ".join(missing[:10]))
    duplicate_keys = [key for key, count in Counter(
        (str(row.get("model", "unspecified")),
         str(row.get("domain", "unspecified")),
         str(row.get("protocol", "unspecified")),
         str(row.get("seed", "unspecified")), str(row["sample_id"]))
        for row in rows).items() if count > 1]
    groups = defaultdict(list)
    for row in rows:
        groups[group_key(row, ("model", "domain", "protocol", "seed"))].append(row)
    group_metrics = {}
    for key, group in sorted(groups.items()):
        label = "|".join(key)
        group_metrics[label] = {"model": key[0], "domain": key[1],
                                "protocol": key[2], "seed": key[3],
                                **metric_rows(group)}
    seed_groups = defaultdict(list)
    for key, value in group_metrics.items():
        # Seed-level summaries are only meaningful when all rows in that seed
        # belong to the same protocol/domain; otherwise report each group above.
        seed_groups[(value["model"], value["domain"], value["protocol"])].append(value)
    aggregate = {}
    for key, values in sorted(seed_groups.items()):
        accuracies = [value["accuracy"] for value in values if value["accuracy"] is not None]
        macro_f1s = [value["macro_f1"] for value in values if value["macro_f1"] is not None]
        aggregate["|".join(key)] = {
            "model": key[0], "domain": key[1], "protocol": key[2],
            "seed_count": len(values),
            "seed_metrics": [{"seed": value["seed"], "accuracy": value["accuracy"],
                               "macro_f1": value["macro_f1"],
                               "sample_count": value["sample_count"]} for value in values],
            "accuracy_mean": statistics.fmean(accuracies) if accuracies else None,
            "accuracy_sample_std": sample_std(accuracies),
            "macro_f1_mean": statistics.fmean(macro_f1s) if macro_f1s else None,
            "macro_f1_sample_std": sample_std(macro_f1s),
        }
    expected_seeds = {str(seed) for seed in args.expected_seed}
    observed_seeds = {str(row.get("seed")) for row in rows if row.get("seed") not in (None, "")}
    result = {"schema_version": 1, "tool": "evaluate_predictions",
        "prediction_file": str(Path(args.predictions).resolve()),
        "prediction_sha256": file_sha256(args.predictions), "row_count": len(rows),
        "overall": metric_rows(rows), "groups": group_metrics, "seed_aggregates": aggregate,
        "duplicate_sample_keys": [list(key) for key in sorted(duplicate_keys)],
        "observed_seeds": sorted(observed_seeds), "expected_seeds": sorted(expected_seeds),
        "protocol_policy": {
            "target_test_predictions_are_not_used_for_checkpoint_selection": True,
            "accuracy_and_macro_f1_are_reported_from_rows": True,
            "sample_std_is_across_seed_group_metrics": True,
        }}
    if expected_seeds:
        result["missing_expected_seeds"] = sorted(expected_seeds - observed_seeds)
        result["unexpected_seeds"] = sorted(observed_seeds - expected_seeds)
    result["passed"] = not duplicate_keys and not result.get("missing_expected_seeds")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-seed", action="append", default=[],
                        help="Expected seed; repeat for 42, 2024, 2025")
    args = parser.parse_args()
    try:
        result = evaluate(args)
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit(str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
