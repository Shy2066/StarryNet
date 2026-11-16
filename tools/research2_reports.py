"""Streaming, standard-library reports for Research 2 exported traces."""

from __future__ import division

import csv
import hashlib
import json
import math
import re
from pathlib import Path


SAMPLE_ID_RE = re.compile(r"^(?P<class_id>\d+)-(?P<repeat_id>\d+)$")
REQUIRED_SCENARIOS = ("base", "delay25", "jitter25_10", "loss0p1")
COMPARISONS = (
    ("delay25_vs_base", "delay25", "base"),
    ("jitter25_10_vs_delay25", "jitter25_10", "delay25"),
    ("loss0p1_vs_base", "loss0p1", "base"),
)
FEATURE_COLUMNS = (
    "event_count", "positive_events", "negative_events", "duration_seconds",
    "iat_mean_seconds", "iat_std_seconds", "iat_median_seconds",
    "iat_p90_seconds", "burst_count", "mean_burst_events",
)


def _is_finite(value):
    try:
        return math.isfinite(value)
    except (TypeError, ValueError, OverflowError):
        return False


def _sample_id(path):
    stem = Path(path).stem
    match = SAMPLE_ID_RE.fullmatch(stem)
    if not match:
        return None, None
    return stem, int(match.group("class_id"))


def _id_key(sample_id):
    match = SAMPLE_ID_RE.fullmatch(sample_id)
    if match:
        return (int(match.group("class_id")), int(match.group("repeat_id")), sample_id)
    return (float("inf"), float("inf"), sample_id)


def _mean(values):
    if not values:
        return None
    scale = max(abs(value) for value in values)
    if scale == 0:
        return 0.0
    return scale * (sum(value / scale for value in values) / len(values))


def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return ordered[middle - 1] / 2.0 + ordered[middle] / 2.0


def _population_std(values):
    if not values:
        return None
    average = _mean(values)
    scale = max(abs(value) for value in values)
    if scale == 0:
        return 0.0
    scaled_average = average / scale
    variance = sum((value / scale - scaled_average) ** 2 for value in values) / len(values)
    return scale * math.sqrt(variance)


def _nearest_rank_p90(values):
    """Return the empirical nearest-rank 90th percentile (rank ceil(.9*n))."""
    if not values:
        return None
    ordered = sorted(values)
    index = int(math.ceil(0.90 * len(ordered))) - 1
    return ordered[max(0, index)]


def empirical_ks_distance(sample_a, sample_b):
    """Compute the two-sample empirical CDF distance, without a p-value."""
    if not sample_a or not sample_b:
        return None
    all_values = list(sample_a) + list(sample_b)
    if any(not _is_finite(value) for value in all_values):
        raise ValueError("KS samples must contain only finite numeric values")
    first = sorted(sample_a)
    second = sorted(sample_b)
    index_a = 0
    index_b = 0
    maximum = 0.0
    while index_a < len(first) or index_b < len(second):
        if index_a >= len(first):
            value = second[index_b]
        elif index_b >= len(second):
            value = first[index_a]
        else:
            value = min(first[index_a], second[index_b])
        while index_a < len(first) and first[index_a] <= value:
            index_a += 1
        while index_b < len(second) and second[index_b] <= value:
            index_b += 1
        distance = abs(index_a / float(len(first)) - index_b / float(len(second)))
        if distance > maximum:
            maximum = distance
    return maximum


def _read_trace(path, scenario, sample_id, class_id):
    """Read one trace in a single streaming pass while hashing its raw bytes."""
    digest = hashlib.sha256()
    first_timestamp = None
    previous_timestamp = None
    last_timestamp = None
    iats = []
    direction_counts = {1: 0, -1: 0}
    previous_direction = None
    current_burst_length = 0
    burst_lengths = []
    errors = []
    line_count = 0
    hash_complete = True
    try:
        with open(str(path), "rb") as stream:
            for line_count, raw_line in enumerate(stream, 1):
                digest.update(raw_line)
                try:
                    line = raw_line.decode("utf-8").strip()
                except UnicodeDecodeError:
                    errors.append("line {0}: invalid UTF-8".format(line_count))
                    continue
                fields = line.split()
                if len(fields) != 2:
                    errors.append("line {0}: expected timestamp and direction".format(
                        line_count))
                    continue
                try:
                    timestamp = float(fields[0])
                    direction = int(fields[1])
                except ValueError:
                    errors.append("line {0}: non-numeric timestamp or direction".format(
                        line_count))
                    continue
                if not _is_finite(timestamp) or timestamp < 0:
                    errors.append("line {0}: timestamp must be finite and nonnegative".format(
                        line_count))
                    continue
                if direction not in (-1, 1):
                    errors.append("line {0}: direction must be -1 or +1".format(line_count))
                    continue
                if previous_timestamp is not None and timestamp < previous_timestamp:
                    errors.append("line {0}: timestamp moved backwards".format(line_count))
                    continue
                if previous_timestamp is not None:
                    iats.append(timestamp - previous_timestamp)
                if first_timestamp is None:
                    first_timestamp = timestamp
                previous_timestamp = timestamp
                last_timestamp = timestamp
                direction_counts[direction] += 1
                if direction == previous_direction:
                    current_burst_length += 1
                else:
                    if current_burst_length:
                        burst_lengths.append(current_burst_length)
                    previous_direction = direction
                    current_burst_length = 1
    except OSError as exc:
        hash_complete = False
        errors.append("read error: {0}".format(exc))

    if direction_counts[1] == 0 or direction_counts[-1] == 0:
        errors.append("trace must contain both directions")
    if line_count == 0:
        errors.append("trace is empty")
    event_count = direction_counts[1] + direction_counts[-1]
    if event_count != line_count and not errors:
        errors.append("not all trace rows were parsed")
    if current_burst_length:
        burst_lengths.append(current_burst_length)

    record = {
        "scenario": scenario,
        "sample_id": sample_id,
        "source_group_id": sample_id,
        "class_id": class_id,
        "trace_path": str(path),
        "status": "invalid" if errors else "valid",
        "error": "; ".join(errors),
        "sha256": digest.hexdigest() if hash_complete else None,
        "line_count": line_count,
        "event_count": event_count,
        "positive_events": direction_counts[1],
        "negative_events": direction_counts[-1],
    }
    if errors:
        for name in FEATURE_COLUMNS:
            record.setdefault(name, None)
        return record

    record.update({
        "duration_seconds": last_timestamp - first_timestamp,
        "iat_mean_seconds": _mean(iats),
        "iat_std_seconds": _population_std(iats),
        "iat_median_seconds": _median(iats),
        "iat_p90_seconds": _nearest_rank_p90(iats),
        "burst_count": len(burst_lengths),
        "mean_burst_events": _mean(burst_lengths),
    })
    derived_features = [record[name] for name in FEATURE_COLUMNS
                        if isinstance(record.get(name), float)]
    if any(not _is_finite(value) for value in derived_features):
        record["status"] = "invalid"
        record["error"] = "derived feature is non-finite"
        for name in FEATURE_COLUMNS:
            if name not in ("event_count", "positive_events", "negative_events"):
                record[name] = None
    return record


def _csv_value(value):
    if value is None:
        return ""
    if isinstance(value, float):
        return "{0:.17g}".format(value)
    return value


def _valid_index(records_by_scenario):
    return {scenario: {sample_id: row for sample_id, row in rows.items()
                       if row.get("status") == "valid"}
            for scenario, rows in records_by_scenario.items()}


def _comparison(name, scenario_a, scenario_b, valid_by_scenario, expected_set):
    rows_a = valid_by_scenario.get(scenario_a, {})
    rows_b = valid_by_scenario.get(scenario_b, {})
    common_ids = sorted(set(rows_a).intersection(rows_b).intersection(expected_set),
                        key=_id_key)
    features = {}
    for feature in FEATURE_COLUMNS:
        values_a = [rows_a[sample_id][feature] for sample_id in common_ids]
        values_b = [rows_b[sample_id][feature] for sample_id in common_ids]
        values_a = [value for value in values_a if value is not None]
        values_b = [value for value in values_b if value is not None]
        if len(values_a) != len(common_ids) or len(values_b) != len(common_ids):
            features[feature] = {"available": False, "reason": "missing feature values"}
            continue
        paired_differences = [rows_a[sample_id][feature] - rows_b[sample_id][feature]
                              for sample_id in common_ids]
        mean_a = _mean(values_a)
        mean_b = _mean(values_b)
        median_a = _median(values_a)
        median_b = _median(values_b)
        features[feature] = {
            "available": bool(common_ids),
            "scenario_a_mean": mean_a,
            "scenario_b_mean": mean_b,
            "mean_difference_a_minus_b": (mean_a - mean_b) if common_ids else None,
            "scenario_a_median": median_a,
            "scenario_b_median": median_b,
            "median_difference_a_minus_b": (median_a - median_b) if common_ids else None,
            "paired_mean_difference_a_minus_b": _mean(paired_differences),
            "empirical_ks_distance": empirical_ks_distance(values_a, values_b),
        }
    return {
        "name": name,
        "scenario_a": scenario_a,
        "scenario_b": scenario_b,
        "common_source_count": len(common_ids),
        "common_source_ids": common_ids,
        "features": features,
    }


def _validate_expected_ids(expected_ids):
    if expected_ids is None:
        return None
    if not isinstance(expected_ids, (list, tuple, set)):
        raise ValueError("expected_ids must be a list, tuple, set, or None")
    values = list(expected_ids)
    if any(not isinstance(value, str) or not SAMPLE_ID_RE.fullmatch(value)
           for value in values):
        raise ValueError("expected_ids must contain class-repeat IDs")
    if len(values) != len(set(values)):
        raise ValueError("expected_ids contains duplicates")
    return sorted(values, key=_id_key)


def generate_reports(scenario_roots, output_dir, expected_ids=None):
    """Generate trajectory metrics, source grouping, and scenario comparisons.

    Durations use last minus first timestamp. IAT is the difference between
    adjacent event timestamps; standard deviation is population standard
    deviation and p90 uses the empirical nearest-rank definition. A burst is a
    maximal consecutive run of events with the same direction. KS values are
    descriptive empirical distances and have no associated significance claim.
    """
    if not isinstance(scenario_roots, dict) or not scenario_roots:
        raise ValueError("scenario_roots must be a nonempty scenario-to-path mapping")
    expected = _validate_expected_ids(expected_ids)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    trace_rows = []
    invalid_rows = []
    scenario_info = {}
    scenario_rows = {}
    all_seen_ids = set()
    for scenario in sorted(scenario_roots):
        root = Path(scenario_roots[scenario])
        candidates = []
        root_error = None
        if not root.is_dir():
            root_error = "scenario root is missing or not a directory"
            invalid_rows.append({"scenario": scenario, "sample_id": "",
                                 "trace_path": str(root), "error": root_error})
        else:
            for path in sorted(root.iterdir(), key=lambda item: item.name):
                if not path.is_file():
                    continue
                sample_id, class_id = _sample_id(path)
                if sample_id is None:
                    continue
                candidates.append((sample_id, class_id, path))
        rows_by_id = {}
        for sample_id, class_id, path in candidates:
            all_seen_ids.add(sample_id)
            row = _read_trace(path, scenario, sample_id, class_id)
            trace_rows.append(row)
            rows_by_id.setdefault(sample_id, []).append(row)
        for sample_id, rows in rows_by_id.items():
            if len(rows) > 1:
                duplicate_error = "duplicate trajectory ID in scenario directory"
                for row in rows:
                    row["status"] = "invalid"
                    row["error"] = (row["error"] + "; " if row["error"] else "") + duplicate_error
                invalid_rows.append({"scenario": scenario, "sample_id": sample_id,
                                     "trace_path": "; ".join(row["trace_path"] for row in rows),
                                     "error": duplicate_error})
            elif rows[0]["status"] == "invalid":
                invalid_rows.append({"scenario": scenario, "sample_id": sample_id,
                                     "trace_path": rows[0]["trace_path"],
                                     "error": rows[0]["error"]})
        # Keep one representative invalid row for duplicate IDs so coverage and
        # source-group reports distinguish "present but invalid" from missing.
        scenario_rows[scenario] = {sample_id: rows[0]
                                   for sample_id, rows in rows_by_id.items()}

    if expected is None:
        expected = sorted(all_seen_ids, key=_id_key)
    expected_set = set(expected)
    valid_by_scenario = _valid_index(scenario_rows)
    for scenario in sorted(scenario_roots):
        rows = scenario_rows.get(scenario, {})
        valid_ids = set(valid_by_scenario.get(scenario, {}))
        present_ids = set(rows)
        invalid_ids = {sample_id for sample_id, row in rows.items()
                       if row.get("status") != "valid"}
        missing_ids = expected_set - present_ids
        unexpected_ids = present_ids - expected_set
        uncovered_ids = expected_set - valid_ids
        scenario_info[scenario] = {
            "path": str(scenario_roots[scenario]),
            "root_error": ("scenario root is missing or not a directory"
                           if not Path(scenario_roots[scenario]).is_dir() else None),
            "present_ids": sorted(present_ids, key=_id_key),
            "valid_ids": sorted(valid_ids, key=_id_key),
            "invalid_ids": sorted(invalid_ids, key=_id_key),
            "missing_ids": sorted(missing_ids, key=_id_key),
            "unexpected_ids": sorted(unexpected_ids, key=_id_key),
            "uncovered_ids": sorted(uncovered_ids, key=_id_key),
            "expected_count": len(expected),
            "present_count": len(present_ids),
            "valid_count": len(valid_ids),
        }
        scenario_info[scenario]["complete"] = (
            not uncovered_ids and not invalid_ids and not unexpected_ids and
            scenario_info[scenario]["root_error"] is None)

    comparison_results = {}
    for name, scenario_a, scenario_b in COMPARISONS:
        comparison_results[name] = _comparison(
            name, scenario_a, scenario_b, valid_by_scenario, expected_set)
    all_scenarios_common = None
    for required in REQUIRED_SCENARIOS:
        valid_ids = set(valid_by_scenario.get(required, {})).intersection(expected_set)
        all_scenarios_common = (valid_ids if all_scenarios_common is None
                                else all_scenarios_common.intersection(valid_ids))
    if all_scenarios_common is None:
        all_scenarios_common = set()

    missing_required_scenarios = sorted(set(REQUIRED_SCENARIOS) - set(scenario_roots))
    all_scenario_complete = all(info["complete"] for info in scenario_info.values())
    complete = (bool(expected) and not missing_required_scenarios and
                all_scenario_complete and
                all(expected_set.issubset(set(valid_by_scenario.get(name, {})))
                    for name in REQUIRED_SCENARIOS))

    invalid_rows.sort(key=lambda row: (row.get("scenario", ""),
                                       _id_key(row.get("sample_id", "0-0")),
                                       row.get("trace_path", "")))
    trace_rows.sort(key=lambda row: (row["scenario"], _id_key(row["sample_id"]),
                                     row["trace_path"]))

    per_trace_columns = ["scenario", "sample_id", "source_group_id", "class_id",
                         "status", "error", "trace_path", "sha256", "line_count"] + list(
                             FEATURE_COLUMNS)
    with open(str(output_root / "per_trace_features.csv"), "w", newline="",
              encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=per_trace_columns, extrasaction="ignore")
        writer.writeheader()
        for row in trace_rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in per_trace_columns})

    source_ids = sorted(expected_set.union(all_seen_ids), key=_id_key)
    source_group_columns = ["source_group_id", "sample_id", "class_id",
                            "present_scenarios", "valid_scenarios", "invalid_scenarios",
                            "missing_scenarios", "expected_scenario_count"]
    with open(str(output_root / "source_groups.csv"), "w", newline="",
              encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=source_group_columns)
        writer.writeheader()
        for sample_id in source_ids:
            parsed = SAMPLE_ID_RE.fullmatch(sample_id)
            class_id = int(parsed.group("class_id")) if parsed else ""
            present = []
            valid = []
            invalid = []
            for scenario in sorted(scenario_roots):
                row = scenario_rows.get(scenario, {}).get(sample_id)
                if row is not None:
                    present.append(scenario)
                    if row.get("status") == "valid":
                        valid.append(scenario)
                    else:
                        invalid.append(scenario)
            missing = sorted(set(scenario_roots) - set(present))
            writer.writerow({
                "source_group_id": sample_id,
                "sample_id": sample_id,
                "class_id": class_id,
                "present_scenarios": ";".join(present),
                "valid_scenarios": ";".join(valid),
                "invalid_scenarios": ";".join(invalid),
                "missing_scenarios": ";".join(missing),
                "expected_scenario_count": len(scenario_roots),
            })

    summary = {
        "status": "complete" if complete else "incomplete",
        "complete": complete,
        "expected_ids": expected,
        "expected_count": len(expected),
        "required_scenarios": list(REQUIRED_SCENARIOS),
        "missing_required_scenarios": missing_required_scenarios,
        "scenario_coverage": scenario_info,
        "common_source_ids": sorted(all_scenarios_common, key=_id_key),
        "common_source_count": len(all_scenarios_common),
        "comparisons": comparison_results,
        "invalid_trajectories": invalid_rows,
        "metric_definitions": {
            "duration_seconds": "last timestamp minus first timestamp",
            "iat": "adjacent event timestamp differences",
            "iat_std": "population standard deviation",
            "iat_p90": "empirical nearest rank ceil(0.90*n)",
            "burst": "maximal consecutive run of events with the same direction",
            "mean_burst_events": "mean number of events per directional burst",
        },
        "interpretation": (
            "Scenario contrasts are descriptive feature differences on common valid "
            "source IDs; empirical KS distances have no p-values and do not establish "
            "causality or statistical significance."
        ),
        "outputs": ["per_trace_features.csv", "source_groups.csv",
                    "distribution_summary.json"],
    }
    with open(str(output_root / "distribution_summary.json"), "w",
              encoding="utf-8") as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2, sort_keys=True,
                  allow_nan=False)
        stream.write("\n")
    return summary
