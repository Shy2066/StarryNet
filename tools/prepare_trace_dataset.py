#!/usr/bin/env python3
"""Convert audited timestamp-direction traces into a versioned fixed array.

This is a conservative, model-agnostic converter.  It preserves packet order,
supports the SatLumen raw ``timestamp + direction`` representation and an
explicit ``delta_direction`` audit representation, clamps only explicitly
tolerated small backward timestamps in the latter, and refuses large reversals
unless the caller opts into an audit-only conversion.  It does not invent a
train/validation/test split; pass an existing split manifest when one is already
protocol-compatible.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys

import numpy as np


SAMPLE_RE = re.compile(r"^(?P<class_id>\d+)-(?P<repeat_id>\d+)(?:\.[^.]+)?$")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def parse_domains(values):
    if not values:
        values = ["F=dataset/tor_fiber", "S=dataset/tor_starlink",
                  "E=dataset/tor_satellite"]
    result = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--domain must use NAME=PATH: " + value)
        name, path = value.split("=", 1)
        name = name.strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", name) or name in result:
            raise ValueError("invalid or duplicate domain: " + name)
        result[name] = Path(path).expanduser()
    return result


def parse_split_manifest(path):
    if not path:
        return {}
    value = json.loads(Path(path).read_text())
    split_map = {}
    if isinstance(value, dict) and all(key in {"train", "valid", "validation", "test"}
                                       for key in value):
        for split, ids in value.items():
            normalized = "valid" if split == "validation" else split
            for sample_id in ids:
                split_map[(None, str(sample_id))] = normalized
        return split_map
    if isinstance(value, dict):
        for domain, domain_value in value.items():
            if not isinstance(domain_value, dict):
                continue
            for split, ids in domain_value.items():
                normalized = "valid" if split == "validation" else split
                for sample_id in ids:
                    split_map[(str(domain).upper(), str(sample_id))] = normalized
        return split_map
    if isinstance(value, list):
        for row in value:
            if not isinstance(row, dict) or "sample_id" not in row or "split" not in row:
                raise ValueError("split list rows require sample_id and split")
            domain = row.get("domain", None)
            split_map[(None if domain is None else str(domain).upper(),
                       str(row["sample_id"]))] = str(row["split"])
        return split_map
    raise ValueError("unsupported split manifest shape")


def sample_id(path):
    match = SAMPLE_RE.fullmatch(path.name)
    if not match:
        return None
    return path.name


def read_trace(path, tolerance, allow_large_reversal):
    times = []
    directions = []
    small_reversals = 0
    large_reversals = 0
    max_backward = 0.0
    previous = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise ValueError("{0}: blank line {1}".format(path, line_number))
        fields = re.split(r"\s+", line.strip())
        if len(fields) != 2:
            raise ValueError("{0}: line {1} is not timestamp + direction".format(
                path, line_number))
        try:
            timestamp = float(fields[0])
            direction = int(fields[1])
        except ValueError as exc:
            raise ValueError("{0}: line {1} is not numeric".format(path, line_number)) from exc
        if not math.isfinite(timestamp) or direction not in (-1, 1):
            raise ValueError("{0}: invalid value at line {1}".format(path, line_number))
        if previous is None:
            delta = 0.0
        else:
            delta = timestamp - previous
            if delta < 0:
                backward = -delta
                max_backward = max(max_backward, backward)
                if backward <= tolerance:
                    small_reversals += 1
                else:
                    large_reversals += 1
                    if not allow_large_reversal:
                        raise ValueError(
                            "{0}: large timestamp reversal {1:.9g}s at line {2}; "
                            "use --allow-large-reversal only for an explicit audit conversion".format(
                                path, backward, line_number))
                delta = 0.0
        times.append(timestamp)
        directions.append(direction)
        previous = timestamp
    if not times:
        raise ValueError("empty trace: " + str(path))
    return np.asarray(times, dtype=np.float64), np.asarray(directions, dtype=np.int8), {
        "rows": len(times), "small_reversal_count": small_reversals,
        "large_reversal_count": large_reversals, "max_backward_delta": max_backward,
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", action="append", dest="domains", metavar="NAME=PATH")
    parser.add_argument("--output", type=Path, required=True,
                        help="Output directory containing data.npz and manifest.json")
    parser.add_argument("--max-length", type=int, required=True,
                        help="Fixed sequence length; overflow is an error by default")
    parser.add_argument("--representation", choices=("satlumen_raw", "delta_direction"),
                        default="satlumen_raw",
                        help="satlumen_raw keeps timestamp+direction; "
                             "delta_direction emits elapsed nonnegative deltas")
    parser.add_argument("--truncate", action="store_true",
                        help="Explicitly truncate traces longer than --max-length")
    parser.add_argument("--timestamp-tolerance", type=float, default=0.005)
    parser.add_argument("--split-manifest", type=Path)
    parser.add_argument("--allow-large-reversal", action="store_true",
                        help="Convert despite large reversals and record that exception")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.max_length < 1 or args.timestamp_tolerance < 0:
        raise SystemExit("max-length must be positive and timestamp-tolerance nonnegative")
    try:
        domains = parse_domains(args.domains)
        split_map = parse_split_manifest(args.split_manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc))
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()) and not args.force:
        raise SystemExit("Refusing to overwrite non-empty output; use --force")
    output.mkdir(parents=True, exist_ok=True)

    rows = []
    seen = set()
    source_summary = {}
    for domain, root in domains.items():
        if not root.is_dir():
            raise SystemExit("dataset root does not exist: " + str(root))
        domain_digest = hashlib.sha256()
        domain_files = 0
        domain_events = 0
        domain_small = 0
        domain_large = 0
        domain_truncated_files = 0
        domain_truncated_events = 0
        domain_classes = Counter()
        for path in sorted(item for item in root.iterdir() if item.is_file()):
            sid = sample_id(path)
            if sid is None:
                raise SystemExit("unrecognized sample filename: " + str(path))
            key = (domain, sid)
            if key in seen:
                raise SystemExit("duplicate sample ID: " + str(key))
            seen.add(key)
            data = path.read_bytes()
            domain_digest.update(path.name.encode("utf-8"))
            domain_digest.update(b"\0")
            domain_digest.update(data)
            times, directions, stats = read_trace(path, args.timestamp_tolerance,
                                                   args.allow_large_reversal)
            original_length = len(times)
            if original_length > args.max_length:
                if not args.truncate:
                    raise SystemExit(
                        "trace exceeds --max-length ({0} > {1}): {2}; "
                        "pass --truncate only when this matches the target "
                        "preprocessing contract".format(
                            original_length, args.max_length, path))
                times = times[:args.max_length]
                directions = directions[:args.max_length]
                domain_truncated_files += 1
                domain_truncated_events += original_length - len(times)
            class_id = int(sid.split("-", 1)[0])
            split = split_map.get((domain, sid), split_map.get((None, sid), "unspecified"))
            sequence = np.zeros((args.max_length, 2), dtype=np.float32)
            if args.representation == "satlumen_raw":
                # SatLumen's convert_to_npz.py keeps raw timestamps, replaces
                # non-padding zeros by 1e-6, and stores direction as channel 2.
                raw_times = np.where(times == 0.0, 1e-6, times)
                sequence[:len(times), 0] = raw_times.astype(np.float32)
            else:
                sequence[:len(times), 0] = np.maximum(
                    np.diff(times, prepend=times[0]), 0.0).astype(np.float32)
            sequence[:len(times), 1] = directions
            rows.append({"sequence": sequence, "length": len(times),
                         "original_length": original_length,
                         "label": class_id, "sample_id": sid, "domain": domain,
                         "split": split})
            domain_files += 1
            domain_events += len(times)
            domain_small += stats["small_reversal_count"]
            domain_large += stats["large_reversal_count"]
            domain_classes[str(class_id)] += 1
        source_summary[domain] = {"root": str(root.resolve()), "files": domain_files,
            "events": domain_events, "small_reversal_count": domain_small,
            "large_reversal_count": domain_large,
            "truncated_file_count": domain_truncated_files,
            "truncated_event_count": domain_truncated_events,
            "class_counts": dict(domain_classes),
            "content_sha256": domain_digest.hexdigest()}

    sequences = np.stack([row["sequence"] for row in rows]).astype(np.float32)
    lengths = np.asarray([row["length"] for row in rows], dtype=np.int32)
    labels = np.asarray([row["label"] for row in rows], dtype=np.int64)
    sample_ids = np.asarray([row["sample_id"] for row in rows], dtype="U128")
    domain_values = np.asarray([row["domain"] for row in rows], dtype="U32")
    split_values = np.asarray([row["split"] for row in rows], dtype="U32")
    np.savez_compressed(output / "data.npz", sequences=sequences, lengths=lengths,
                        labels=labels, sample_ids=sample_ids, domains=domain_values,
                        splits=split_values)
    manifest = {"schema_version": 1, "tool": "prepare_trace_dataset",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "representation": {
            "input": "timestamp + direction",
            "mode": args.representation,
            "output": ("(N, max_length, 2), [timestamp, direction]"
                        if args.representation == "satlumen_raw" else
                        "(N, max_length, 2), [nonnegative delta_seconds, direction]"),
            "time_zero": ("raw input timestamp"
                           if args.representation == "satlumen_raw" else
                           "first event per trace"),
            "padding": "zero rows",
            "zero_timestamp_policy": ("non-padding zeros become 1e-6"
                                       if args.representation == "satlumen_raw" else
                                       "not applicable"),
            "direction_values": [-1, 1],
            "overflow_policy": "truncate" if args.truncate else "error",
            "timestamp_tolerance_seconds": args.timestamp_tolerance,
            "large_reversal_allowed": args.allow_large_reversal,
            "truncate_requested": args.truncate,
        },
        "shape": list(sequences.shape), "sample_count": len(rows),
        "source_domains": source_summary,
        "split_manifest": (None if not args.split_manifest else
                            str(args.split_manifest.resolve())),
        "split_counts": dict(Counter(split_values.tolist())),
        "outputs": {"data": "data.npz",
                     "data_sha256": sha256_bytes((output / "data.npz").read_bytes())}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
