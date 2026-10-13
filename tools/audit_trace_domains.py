#!/usr/bin/env python3
"""Audit F/S/E timestamp-direction traces without changing the dataset.

The audit deliberately reports the trace contract, not a scientific claim. It
checks filename/sample-ID coverage, timestamp and direction validity, hashes
the exact files, and compares domain intersections.  A report can be written
with ``--output`` for use as a frozen pre-processing input manifest.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import sys


SAMPLE_RE = re.compile(r"^(?P<class_id>\d+)-(?P<repeat_id>\d+)(?:\.[^.]+)?$")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--domain", action="append", dest="domains", metavar="NAME=PATH",
        help="Domain root; repeat for F/S/E. Defaults to the repository datasets.")
    parser.add_argument("--output", type=Path,
                        help="Optional JSON report path; input files are read-only")
    parser.add_argument("--max-errors", type=int, default=50,
                        help="Maximum example errors retained per domain")
    parser.add_argument("--timestamp-tolerance", type=float, default=0.005,
                        help="Small backward timestamp tolerance in seconds; "
                             "larger reversals are structural errors")
    return parser.parse_args()


def domain_roots(values):
    if not values:
        return {"F": Path("dataset/tor_fiber"),
                "S": Path("dataset/tor_starlink"),
                "E": Path("dataset/tor_satellite")}
    result = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--domain must use NAME=PATH: " + value)
        name, path = value.split("=", 1)
        name = name.strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", name):
            raise ValueError("Invalid domain name: " + name)
        if name in result:
            raise ValueError("Duplicate domain: " + name)
        result[name] = Path(path).expanduser()
    return result


def parse_sample_id(path):
    match = SAMPLE_RE.fullmatch(path.name)
    if not match:
        return None
    return "{0}-{1}".format(match.group("class_id"), match.group("repeat_id"))


def audit_file(path, max_errors, timestamp_tolerance):
    errors = []
    rows = 0
    directions = Counter()
    first_time = None
    last_time = None
    decreasing = 0
    small_reversals = 0
    large_reversals = 0
    max_backward_delta = 0.0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                text = line.strip()
                if not text:
                    errors.append("line {0}: blank line".format(line_number))
                    if len(errors) >= max_errors:
                        break
                    continue
                fields = re.split(r"\s+", text)
                if len(fields) != 2:
                    errors.append("line {0}: expected timestamp and direction".format(
                        line_number))
                    if len(errors) >= max_errors:
                        break
                    continue
                try:
                    timestamp = float(fields[0])
                    direction = int(fields[1])
                except ValueError:
                    errors.append("line {0}: non-numeric value".format(line_number))
                    if len(errors) >= max_errors:
                        break
                    continue
                if not math.isfinite(timestamp):
                    errors.append("line {0}: timestamp is not finite".format(line_number))
                if direction not in (-1, 1):
                    errors.append("line {0}: direction must be -1 or +1".format(line_number))
                if last_time is not None and timestamp < last_time:
                    decreasing += 1
                    backward_delta = last_time - timestamp
                    max_backward_delta = max(max_backward_delta, backward_delta)
                    if backward_delta <= timestamp_tolerance:
                        small_reversals += 1
                    else:
                        large_reversals += 1
                        if len(errors) < max_errors:
                            errors.append("line {0}: timestamp decreases by {1:.9g}s".format(
                                line_number, backward_delta))
                if first_time is None:
                    first_time = timestamp
                last_time = timestamp
                directions[str(direction)] += 1
                rows += 1
    except (OSError, UnicodeError) as exc:
        errors.append("read failed: " + str(exc))
    return {"rows": rows, "directions": dict(directions),
            "first_timestamp": first_time, "last_timestamp": last_time,
            "duration": (None if first_time is None or last_time is None
                          else last_time - first_time),
            "decreasing_timestamp_count": decreasing,
            "small_reversal_count": small_reversals,
            "large_reversal_count": large_reversals,
            "max_backward_delta": max_backward_delta,
            "timestamp_tolerance": timestamp_tolerance, "errors": errors}


def audit_domain(name, root, max_errors, timestamp_tolerance):
    report = {"domain": name, "root": str(root.resolve()), "exists": root.is_dir(),
              "sample_count": 0, "sample_ids": [], "duplicate_ids": [],
              "class_counts": {}, "repeat_counts": {}, "files": {},
              "errors": [], "file_bytes": 0, "content_sha256": None,
              "trace_contract": "timestamp + direction",
              "timestamp_tolerance": timestamp_tolerance}
    if not root.is_dir():
        report["errors"].append("dataset root does not exist or is not a directory")
        return report
    files = sorted(path for path in root.iterdir() if path.is_file())
    digest = hashlib.sha256()
    seen = {}
    class_counts = Counter()
    repeat_counts = Counter()
    for path in files:
        sample_id = parse_sample_id(path)
        if sample_id is None:
            if len(report["errors"]) < max_errors:
                report["errors"].append("unrecognized sample filename: " + path.name)
            continue
        if sample_id in seen:
            report["duplicate_ids"].append(sample_id)
        seen[sample_id] = path.name
        class_id, repeat_id = sample_id.split("-", 1)
        class_counts[class_id] += 1
        repeat_counts[repeat_id] += 1
        try:
            data = path.read_bytes()
            report["file_bytes"] += len(data)
            digest.update(path.name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(data)
        except OSError as exc:
            if len(report["errors"]) < max_errors:
                report["errors"].append("read failed for {0}: {1}".format(path.name, exc))
            continue
        file_report = audit_file(path, max_errors, timestamp_tolerance)
        report["files"][sample_id] = {"filename": path.name, **file_report}
        if file_report["errors"] and len(report["errors"]) < max_errors:
            report["errors"].append("{0}: {1}".format(path.name,
                                                       file_report["errors"][0]))
    report["sample_ids"] = sorted(seen)
    report["sample_count"] = len(seen)
    report["class_counts"] = dict(sorted(class_counts.items(), key=lambda item: int(item[0])))
    report["repeat_counts"] = dict(sorted(repeat_counts.items(), key=lambda item: int(item[0])))
    report["duplicate_ids"] = sorted(set(report["duplicate_ids"]))
    report["content_sha256"] = digest.hexdigest()
    report["valid_file_count"] = sum(not item["errors"] for item in report["files"].values())
    report["valid"] = bool(report["exists"] and report["sample_count"]
                           and not report["errors"] and not report["duplicate_ids"]
                           and report["valid_file_count"] == report["sample_count"])
    # The current checked-in E directory is a historical timing-only dataset.
    if name == "E" and root.name == "tor_satellite":
        report["semantic_note"] = (
            "Existing tor_satellite files are timing-direction traces; this audit "
            "does not certify that they came from the new P2/P3 Tor browser loop.")
    return report


def compare_domains(reports):
    ids = {name: set(report.get("sample_ids", []))
           for name, report in reports.items()}
    names = sorted(ids)
    pairwise = {}
    for left_index, left in enumerate(names):
        for right in names[left_index + 1:]:
            pairwise[left + "∩" + right] = len(ids[left] & ids[right])
    intersection = set.intersection(*(ids[name] for name in names)) if names else set()
    union = set.union(*(ids[name] for name in names)) if names else set()
    return {"pairwise_intersection_counts": pairwise,
            "all_domain_intersection_count": len(intersection),
            "union_count": len(union),
            "sample_id_semantics": "filename class-repeat; no cross-domain leakage decision made"}


def main():
    args = parse_args()
    try:
        roots = domain_roots(args.domains)
        if args.timestamp_tolerance < 0:
            raise ValueError("--timestamp-tolerance must be nonnegative")
        reports = {name: audit_domain(name, root, max(1, args.max_errors),
                                      args.timestamp_tolerance)
                   for name, root in roots.items()}
    except ValueError as exc:
        raise SystemExit(str(exc))
    result = {"schema_version": 1, "tool": "audit_trace_domains",
              "domains": reports, "comparison": compare_domains(reports),
              "policy": {
                  "requires_semantic_review_before_training": True,
                  "timing_direction_only_cannot_infer_bandwidth_loss_or_handover": True,
                  "E_is_not_automatically_a_true_Starlink_label": True,
                  "small_timestamp_reversals_require_explicit_nonnegative_dt_policy": True}}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    if any(not report.get("valid") for report in reports.values()):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
