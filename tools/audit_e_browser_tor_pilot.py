#!/usr/bin/env python3
"""Audit completion, sample identities, artifacts, cleanup, and page repeatability."""

import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
import stat
from pathlib import Path
import statistics
import subprocess
import sys

from batch_manifest import (artifact_ok, load_records, read_json,
                           successful_record, validate_manifest)


PROTOCOL_DOMAINS = {
    "starrynet-e-browser-tor-v1-v27-warm-refresh": "E_BROWSER_TOR",
    "starrynet-e-browser-tor-v1-1-warm-refresh-bridge-only": "E_BROWSER_TOR_V1_1",
    "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain": "E_BROWSER_TOR_V1_2",
    "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected": "E_BROWSER_TOR_V1_3",
    "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization": "E_BROWSER_TOR_V1_4",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path):
    target = Path(path)
    if target.is_file():
        return sha256_file(target)
    if not target.is_dir():
        return None
    digest = hashlib.sha256()
    for current, directories, files in os.walk(str(target), followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in directories:
            item = current_path / name
            relative = item.relative_to(target).as_posix().encode("utf-8")
            if item.is_symlink():
                digest.update(b"L\0" + relative + b"\0")
                digest.update(os.readlink(str(item)).encode("utf-8") + b"\0")
            else:
                digest.update(b"D\0" + relative + b"\0")
                digest.update(("{:o}".format(
                    stat.S_IMODE(item.lstat().st_mode))).encode("ascii") + b"\0")
        for name in files:
            item = current_path / name
            relative = item.relative_to(target).as_posix().encode("utf-8")
            if item.is_symlink():
                digest.update(b"L\0" + relative + b"\0")
                digest.update(os.readlink(str(item)).encode("utf-8") + b"\0")
                if item.is_file():
                    digest.update(bytes.fromhex(sha256_file(item)))
            elif item.is_file():
                digest.update(b"F\0" + relative + b"\0")
                digest.update(("{:o}".format(
                    stat.S_IMODE(item.lstat().st_mode))).encode("ascii") + b"\0")
                digest.update(bytes.fromhex(sha256_file(item)))
    return digest.hexdigest()


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")


def file_tree_bytes(root):
    return sum(path.stat().st_size for path in Path(root).rglob("*")
               if path.is_file())


def parse_utc(value):
    if not value:
        return None
    value = value.replace("Z", "+0000")
    if len(value) >= 6 and value[-6] in "+-" and value[-3] == ":":
        value = value[:-3] + value[-2:]
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.datetime.strptime(value, pattern)
        except (TypeError, ValueError):
            pass
    return None


def audit_page(page, successful_rows, auditor, output_root):
    page_id = page["page_id"]
    run_dirs = [Path(row["run_dir"]).resolve() for row in successful_rows
                if row.get("run_dir")]
    if len(run_dirs) < 3:
        return {"page_id": page_id, "run_count": len(run_dirs),
                "passed": False,
                "failures": ["fewer than three successful runs; repeatability cannot be audited"]}
    page_output = Path(output_root) / "page_repeatability" / page_id
    page_output.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(auditor)]
    for run_dir in run_dirs:
        command.extend(["--run-dir", str(run_dir)])
    command.extend(["--output-dir", str(page_output)])
    completed = subprocess.run(command, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True)
    (page_output / "auditor.stdout.log").write_text(
        completed.stdout, encoding="utf-8")
    (page_output / "auditor.stderr.log").write_text(
        completed.stderr, encoding="utf-8")
    result_path = page_output / "repeatability.json"
    result = (read_json(result_path) if result_path.is_file() else {})
    return {
        "page_id": page_id,
        "run_count": len(run_dirs),
        "run_dirs": [str(path) for path in run_dirs],
        "passed": bool(completed.returncode == 0 and result.get(
            "profile_stable_in_run_set") is True
            and result.get("run_gates_passed") is True),
        "returncode": completed.returncode,
        "status": result.get("status"),
        "profile_stable_in_run_set": result.get(
            "profile_stable_in_run_set"),
        "capture_protocol_reproducible": result.get(
            "capture_protocol_reproducible"),
        "run_gates_passed": result.get("run_gates_passed"),
        "protocol_metadata_agrees": result.get("protocol_metadata_agrees"),
        "repeatability_json": str(result_path),
        "repeatability_report": str(page_output / "REPEATABILITY.md"),
        "failures": result.get("failures", []),
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def summarize_target_paths(rows):
    paths = [path for row in rows
             for path in row.get("target_circuit_paths", [])]
    routes = [tuple(str(value).upper() for value in
                    path.get("relay_fingerprints", [])) for path in paths]
    complete = [route for route in routes if len(route) >= 3]
    return {
        "observed_target_circuit_count": len(paths),
        "complete_three_or_more_relay_paths": len(complete),
        "unique_full_relay_paths": len(set(complete)),
        "unique_entry_fingerprints": len({route[0] for route in complete}),
        "unique_middle_fingerprints": len({route[1] for route in complete}),
        "unique_exit_fingerprints": len({route[-1] for route in complete}),
        "middle_exit_pair_variability_observed": len({
            (route[1], route[-1]) for route in complete}) > 1,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--attempts")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--auditor", default=str(
        Path(__file__).resolve().with_name("audit_site_trace_repeatability.py")))
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    root = manifest_path.parent
    manifest = read_json(manifest_path)
    records_path = Path(args.attempts).resolve() if args.attempts else root / "attempts.jsonl"
    records = load_records(records_path)
    errors = validate_manifest(manifest)
    protocol_metadata = manifest.get("protocol_metadata", {})
    protocol_id = protocol_metadata.get("protocol_id")
    data_domain = manifest.get("domain")
    if PROTOCOL_DOMAINS.get(protocol_id) != data_domain:
        errors.append("batch protocol ID and data-domain namespace are not a registered pair")
    pages = manifest.get("pages", [])
    samples = manifest.get("samples", [])
    page_map = {str(page.get("page_id")): page for page in pages}
    planned = {row.get("sample_id"): row for row in samples}

    if data_domain not in set(PROTOCOL_DOMAINS.values()):
        errors.append("batch domain is not a registered E browser namespace")
    if manifest.get("retry_limit") != 1:
        errors.append("retry limit differs from the frozen one-retry policy")
    if len(pages) != 5 or manifest.get("repetitions_per_page") != 10:
        errors.append("pilot manifest is not exactly five pages by ten repetitions")
    if len(samples) != 50:
        errors.append("pilot manifest does not contain exactly 50 planned sample IDs")

    sample_ids = [row.get("sample_id") for row in samples]
    if len(sample_ids) != len(set(sample_ids)):
        errors.append("planned sample IDs are not unique")
    for row in samples:
        page = page_map.get(str(row.get("page_id")))
        if page is None:
            continue
        repetition = row.get("repetition")
        expected_id = "{}-{}-r{:03d}".format(
            data_domain, page["page_id"], int(repetition))
        if row.get("sample_id") != expected_id:
            errors.append("sample ID does not follow the frozen page-repeat format")
        for key in ("url", "class_label", "source_rank", "source_domain"):
            if str(row.get(key)) != str(page.get(key)):
                errors.append("sample/page manifest mismatch for {}: {}".format(
                    key, row.get("sample_id")))

    freeze_path = root / "protocol" / "freeze_hashes.json"
    freeze_errors = []
    freeze = {}
    if not freeze_path.is_file():
        freeze_errors.append("protocol freeze_hashes.json is missing")
    else:
        freeze = read_json(freeze_path)
        for name, item in freeze.get("hashes", {}).items():
            path = Path(item.get("path", ""))
            if sha256_path(path) != item.get("sha256"):
                freeze_errors.append("frozen artifact hash changed or is missing: " + name)
    if freeze_errors:
        errors.extend(freeze_errors)
    if protocol_id == "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain":
        expected_image_id = (manifest.get("protocol_metadata", {})
                             .get("runtime_assets", {})
                             .get("helper_image_id"))
        if (not expected_image_id
                or freeze.get("helper_image_id") != expected_image_id):
            errors.append("frozen helper image ID differs from protocol metadata")

    by_sample = {sample_id: [] for sample_id in planned}
    foreign_ids = []
    attempt_ids = set()
    artifact_failures = []
    for record in records:
        if record.get("_record_error"):
            errors.append(record["_record_error"])
            continue
        attempt_id = record.get("attempt_id")
        if not attempt_id or attempt_id in attempt_ids:
            errors.append("missing or duplicate attempt ID: " + str(attempt_id))
        attempt_ids.add(attempt_id)
        sample_id = record.get("sample_id")
        if sample_id not in by_sample:
            foreign_ids.append(sample_id)
            continue
        by_sample[sample_id].append(record)
        if record.get("run_id") != manifest.get("run_id"):
            errors.append("attempt has a foreign batch run ID: " + str(attempt_id))
        valid, why = artifact_ok(record, root)
        if record.get("artifacts") and not valid:
            artifact_failures.append({"attempt_id": attempt_id, "reason": why})
        page = page_map.get(str(record.get("page_id")))
        if page is not None:
            for key in ("class_label", "source_rank", "source_domain", "url"):
                if str(record.get(key)) != str(page.get(key)):
                    errors.append("attempt/page metadata mismatch for {}: {}".format(
                        key, attempt_id))
        if record.get("cleanup_verified") is not True:
            errors.append("attempt cleanup was not verified: " + str(attempt_id))
        if record.get("protocol_id") != protocol_id:
            errors.append("attempt protocol ID mismatch: " + str(attempt_id))

    if foreign_ids:
        errors.append("attempt ledger contains unplanned sample IDs")
    retries_exceeded = []
    successes = {}
    final_success_rows = {}
    for sample_id, rows in by_sample.items():
        if len(rows) > 1 + int(manifest.get("retry_limit", 1)):
            retries_exceeded.append(sample_id)
        valid = [row for row in rows if successful_record(row, root)]
        if len(valid) > 1:
            errors.append("sample has more than one successful attempt: " + sample_id)
        if valid:
            successes[sample_id] = valid[-1].get("attempt_id")
            final_success_rows[sample_id] = valid[-1]
            if valid[-1].get("single_run_audit_passed") is not True:
                errors.append("successful sample lacks a passing single-run audit: " + sample_id)
            if valid[-1].get("identity_matches") is not True:
                errors.append("successful sample identity check failed: " + sample_id)
        elif not rows:
            errors.append("planned sample has no attempt record: " + sample_id)
    if retries_exceeded:
        errors.append("sample attempt count exceeds the one-retry limit")

    per_page = []
    for page in pages:
        page_samples = [row for row in samples if row.get("page_id") == page["page_id"]]
        page_successes = [final_success_rows[row["sample_id"]]
                          for row in page_samples
                          if row["sample_id"] in final_success_rows]
        page_attempts = [attempt for row in page_samples
                         for attempt in by_sample.get(row["sample_id"], [])]
        good_attempts = [row for row in page_attempts
                         if successful_record(row, root)]
        route_observation = summarize_target_paths(page_successes)
        page_ok = (len(page_successes) == 10 and len(good_attempts) == 10
                   and all(row.get("single_run_audit_passed") is True
                           and row.get("identity_matches") is True
                           for row in good_attempts))
        per_page.append({
            "page_id": page["page_id"],
            "class_label": page["class_label"],
            "source_rank": page["source_rank"],
            "source_domain": page["source_domain"],
            "planned_samples": len(page_samples),
            "successful_samples": len(page_successes),
            "attempt_count": len(page_attempts),
            "attempt_success_rate": (len(good_attempts) / len(page_attempts)
                                     if page_attempts else 0.0),
            "page_complete": page_ok,
            "tor_route_observation": route_observation,
            "repeatability": audit_page(
                page, page_successes, args.auditor, args.output_dir),
        })

    all_attempts_cleanup = bool(records) and all(
        row.get("cleanup_verified") is True for row in records
        if not row.get("_record_error"))
    all_samples_succeeded = len(successes) == 50 and all(
        len(rows) == 1 for rows in final_success_rows.values())
    page_repeatability_passed = (len(per_page) == 5 and all(
        item["repeatability"].get("passed") is True for item in per_page))
    accounting_passed = (not errors and not foreign_ids and not retries_exceeded
                         and len(records) >= 50)

    elapsed = [float(row.get("elapsed_seconds")) for row in final_success_rows.values()
               if isinstance(row.get("elapsed_seconds"), (int, float))]
    init_cost = [float((row.get("runner_timing") or {}).get(
        "dynamic_emulation_started_seconds_from_runner_start"))
        for row in final_success_rows.values()
        if isinstance((row.get("runner_timing") or {}).get(
            "dynamic_emulation_started_seconds_from_runner_start"), (int, float))]
    starts = [parse_utc(row.get("started_utc")) for row in records]
    ends = [parse_utc(row.get("ended_utc")) for row in records]
    starts = [value for value in starts if value]
    ends = [value for value in ends if value]
    wall_seconds = ((max(ends) - min(starts)).total_seconds()
                    if starts and ends else None)
    failure_causes = Counter()
    for record in records:
        if successful_record(record, root):
            continue
        causes = record.get("single_run_audit_failures", [])
        if not causes and record.get("error"):
            causes = [record["error"]]
        if not causes and record.get("stderr_tail"):
            causes = [record["stderr_tail"].splitlines()[-1]]
        if not causes:
            causes = ["collector failed without a classified cause"]
        for cause in causes:
            failure_causes[str(cause)] += 1

    output_root = Path(args.output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": 1,
        "protocol_id": protocol_id,
        "data_domain": data_domain,
        "batch_run_id": manifest.get("run_id"),
        "status": ("expansion_eligible" if accounting_passed
                   and all_samples_succeeded and all_attempts_cleanup
                   and page_repeatability_passed else "do_not_expand_under_frozen_protocol"),
        "expansion_eligible": bool(accounting_passed and all_samples_succeeded
                                    and all_attempts_cleanup
                                    and page_repeatability_passed),
        "sample_count": len(samples),
        "successful_sample_count": len(successes),
        "attempt_count": len(records),
        "failed_or_retried_sample_count": sum(
            1 for rows in by_sample.values() if any(not successful_record(row, root)
                                                    for row in rows)),
        "overall_completion_rate": len(successes) / float(len(samples) or 1),
        "all_attempts_cleanup_verified": all_attempts_cleanup,
        "accounting_passed": accounting_passed,
        "page_repeatability_passed": page_repeatability_passed,
        "criteria": {
            "one_success_per_planned_sample_after_at_most_one_retry": all_samples_succeeded,
            "single_run_audit_and_identity_pass_for_every_success": not any(
                "successful sample" in error for error in errors),
            "all_attempts_cleanup_verified": all_attempts_cleanup,
            "unique_planned_and_attempt_ids": not any(
                "unique" in error or "duplicate" in error for error in errors),
            "protocol_and_source_hashes_unchanged": not freeze_errors,
            "all_five_page_repeatability_sets_pass": page_repeatability_passed,
        },
        "errors": errors,
        "artifact_hash_failures": artifact_failures,
        "foreign_sample_ids": foreign_ids,
        "retry_limit_exceeded": retries_exceeded,
        "failure_causes": dict(failure_causes),
        "tor_route_observation": summarize_target_paths(
            list(final_success_rows.values())),
        "duration_seconds_successful_attempts": {
            "count": len(elapsed),
            "mean": statistics.mean(elapsed) if elapsed else None,
            "median": statistics.median(elapsed) if elapsed else None,
            "sum": sum(elapsed) if elapsed else None,
        },
        "topology_initialization_seconds_to_dynamic_start": {
            "count": len(init_cost),
            "median": statistics.median(init_cost) if init_cost else None,
            "mean": statistics.mean(init_cost) if init_cost else None,
        },
        "batch_wall_clock_seconds": wall_seconds,
        "sample_artifact_bytes": file_tree_bytes(root / "samples"),
        "per_page": per_page,
    }
    write_json(output_root / "pilot_audit.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["expansion_eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
