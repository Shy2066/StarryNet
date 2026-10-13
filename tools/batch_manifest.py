#!/usr/bin/env python3
"""Plan, resume, and verify auditable browser-sample batches.

This coordinator intentionally does not start StarryNet, Firefox, Tor, or a
training job by itself.  ``run`` invokes a user-supplied collector command and
stores every attempt, including failures.  The command must print a final JSON
object and should report its output files as ``artifacts`` entries containing a
path and SHA-256; this makes ``--resume`` safe against skipped/corrupt samples.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import uuid


SCHEMA_VERSION = 1


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    return json.loads(Path(path).read_text())


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sample_rows(pages, repeats, domain):
    rows = []
    for page in pages:
        page_id = str(page["page_id"])
        for repetition in range(1, repeats + 1):
            sample_id = "{0}-{1}-r{2:03d}".format(domain, page_id, repetition)
            rows.append({"sample_id": sample_id, "domain": domain,
                         "page_id": page_id, "url": str(page["url"]),
                         "repetition": repetition, "target": "independent_sample"})
    return rows


def load_pages(path):
    value = read_json(path)
    if isinstance(value, dict):
        value = value.get("pages", [])
    if not isinstance(value, list) or not value:
        raise ValueError("pages JSON must contain a non-empty list")
    seen = set()
    result = []
    for page in value:
        if not isinstance(page, dict) or not page.get("page_id") or not page.get("url"):
            raise ValueError("each page requires page_id and url")
        page_id = str(page["page_id"])
        if page_id in seen:
            raise ValueError("duplicate page_id: " + page_id)
        seen.add(page_id)
        result.append({"page_id": page_id, "url": str(page["url"]),
                       "label": page.get("label", page_id),
                       "expected_marker": page.get("expected_marker")})
    return result


def cmd_plan(args):
    pages = load_pages(args.pages)
    output = Path(args.output)
    if output.exists() and not args.force:
        raise SystemExit("Refusing to overwrite existing batch manifest; use --force")
    rows = sample_rows(pages, args.repeats, args.domain)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "manifest_type": "starrynet_browser_batch",
        "run_id": args.run_id or ("batch-" + uuid.uuid4().hex[:12]),
        "created_utc": utc_now(),
        "domain": args.domain,
        "pages": pages,
        "repetitions_per_page": args.repeats,
        "retry_limit": args.retry_limit,
        "sample_count": len(rows),
        "samples": rows,
        "semantic_policy": {
            "E_is_simulation_and_not_automatically_S": True,
            "fresh_profile_per_attempt": True,
            "concurrency": 1,
            "failed_attempts_are_retained": True,
            "retry_does_not_increase_independent_sample_count": True,
        },
    }
    write_json(output, manifest)
    records = output.with_name("attempts.jsonl")
    records.touch(exist_ok=True)
    print(json.dumps({"manifest": str(output.resolve()), "attempts": str(records.resolve()),
                      "sample_count": len(rows)}, indent=2))


def validate_manifest(manifest):
    errors = []
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported schema_version")
    samples = manifest.get("samples", [])
    sample_ids = [row.get("sample_id") for row in samples]
    if len(sample_ids) != len(set(sample_ids)):
        errors.append("duplicate sample IDs")
    if manifest.get("sample_count") != len(samples):
        errors.append("sample_count does not match samples")
    if int(manifest.get("repetitions_per_page", 0)) < 1:
        errors.append("repetitions_per_page must be positive")
    return errors


def artifact_ok(record, root):
    artifacts = record.get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        return False, "result has no artifacts"
    for item in artifacts:
        if isinstance(item, str):
            relative = item
            expected = None
        elif isinstance(item, dict):
            relative = item.get("path")
            expected = item.get("sha256")
        else:
            return False, "invalid artifact entry"
        if not relative:
            return False, "artifact path is missing"
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            return False, "artifact escapes batch directory"
        if not path.is_file():
            return False, "missing artifact: " + str(relative)
        if expected and sha256(path) != expected:
            return False, "artifact hash mismatch: " + str(relative)
    return True, "ok"


def load_records(path):
    records = []
    if not path.is_file():
        return records
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            records.append({"_record_error": "line {0}: {1}".format(line_number, exc)})
            continue
        record["_line"] = line_number
        records.append(record)
    return records


def parse_last_json(stdout):
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def attempt_id_for(sample_id, records):
    prefix = sample_id + "-a"
    numbers = []
    for record in records:
        value = str(record.get("attempt_id", ""))
        if value.startswith(prefix):
            try:
                numbers.append(int(value[len(prefix):]))
            except ValueError:
                pass
    return "{0}{1:02d}".format(prefix, max(numbers, default=-1) + 1)


def successful_record(record, root):
    if not record.get("ok"):
        return False
    valid, _ = artifact_ok(record, root)
    return valid


def cmd_preflight(args):
    manifest = read_json(args.manifest)
    errors = validate_manifest(manifest)
    result = {"manifest": str(Path(args.manifest).resolve()), "passed": not errors,
              "errors": errors, "sample_count": len(manifest.get("samples", [])),
              "concurrency": manifest.get("semantic_policy", {}).get("concurrency")}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


def cmd_run(args):
    manifest_path = Path(args.manifest).resolve()
    manifest = read_json(manifest_path)
    errors = validate_manifest(manifest)
    if errors:
        raise SystemExit("Manifest preflight failed: " + "; ".join(errors))
    root = Path(args.work_dir or manifest_path.parent).resolve()
    root.mkdir(parents=True, exist_ok=True)
    records_path = Path(args.records or (root / "attempts.jsonl"))
    records = load_records(records_path)
    if any("_record_error" in item for item in records):
        raise SystemExit("Cannot resume a malformed attempts.jsonl")
    if records and not args.resume:
        raise SystemExit("Existing attempts found; use --resume to continue the same manifest")
    template = shlex.split(args.collector_command)
    if not template:
        raise SystemExit("--command must not be empty")
    planned = {row["sample_id"]: row for row in manifest["samples"]}
    existing_success = {record.get("sample_id") for record in records
                        if record.get("sample_id") in planned
                        and successful_record(record, root)}
    if args.resume:
        pending = [row for row in manifest["samples"] if row["sample_id"] not in existing_success]
    else:
        pending = manifest["samples"]
    with records_path.open("a", buffering=1) as output:
        for sample in pending:
            prior = [record for record in records if record.get("sample_id") == sample["sample_id"]]
            attempts = prior if args.resume else []
            max_attempts = 1 + int(manifest.get("retry_limit", 1))
            while len(attempts) < max_attempts:
                attempt_id = attempt_id_for(sample["sample_id"], records)
                values = {**sample, "attempt_id": attempt_id,
                          "output_dir": str(root / "samples" / attempt_id)}
                command = [part.format(**values) for part in template]
                started = utc_now()
                try:
                    completed = subprocess.run(command, cwd=str(root), text=True,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               timeout=args.timeout)
                    returncode = completed.returncode
                    stdout = completed.stdout
                    stderr = completed.stderr
                except subprocess.TimeoutExpired as exc:
                    returncode = 124
                    stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
                    stderr = "collector timed out after {0}s".format(args.timeout)
                except OSError as exc:
                    returncode = 127
                    stdout = ""
                    stderr = "collector could not start: " + str(exc)
                result = parse_last_json(stdout) or {}
                record = {"schema_version": SCHEMA_VERSION, "run_id": manifest["run_id"],
                          "sample_id": sample["sample_id"], "attempt_id": attempt_id,
                          "page_id": sample["page_id"], "repetition": sample["repetition"],
                          "started_utc": started, "ended_utc": utc_now(),
                          "returncode": returncode, "stdout_tail": stdout[-4000:],
                          "stderr_tail": stderr[-4000:], **result}
                record["ok"] = bool(record.get("ok") and returncode == 0)
                valid, reason = artifact_ok(record, root)
                record["artifacts_valid"] = valid
                if not valid:
                    record["ok"] = False
                    record["artifact_error"] = reason
                output.write(json.dumps(record, sort_keys=True) + "\n")
                output.flush()
                records.append(record)
                attempts.append(record)
                if successful_record(record, root):
                    break
            # A failed sample remains represented by all its attempts; do not
            # silently replace it with a synthetic success or create extra IDs.
    verification = cmd_verify_values(manifest, records, root)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0 if verification["passed"] else 1


def cmd_verify_values(manifest, records, root):
    planned = {row["sample_id"] for row in manifest.get("samples", [])}
    by_sample = {sample_id: [] for sample_id in planned}
    errors = []
    attempt_ids = set()
    for record in records:
        if record.get("attempt_id") in attempt_ids:
            errors.append("duplicate attempt_id: " + str(record.get("attempt_id")))
        attempt_ids.add(record.get("attempt_id"))
        if record.get("sample_id") in by_sample:
            by_sample[record["sample_id"]].append(record)
    successes = {}
    for sample_id, rows in by_sample.items():
        valid = [row for row in rows if successful_record(row, root)]
        if len(valid) > 1:
            errors.append("more than one successful attempt: " + sample_id)
        if valid:
            successes[sample_id] = valid[-1].get("attempt_id")
        else:
            errors.append("no successful attempt: " + sample_id)
    foreign = [record.get("sample_id") for record in records
               if record.get("sample_id") not in planned]
    if foreign:
        errors.append("records contain unknown sample IDs: " + str(sorted(set(foreign))))
    return {"run_id": manifest.get("run_id"), "sample_count": len(planned),
            "successful_sample_count": len(successes),
            "failed_or_missing_sample_count": len(planned) - len(successes),
            "attempt_count": len(records), "success_attempts": successes,
            "passed": not errors, "errors": errors}


def cmd_verify(args):
    manifest_path = Path(args.manifest).resolve()
    manifest = read_json(manifest_path)
    root = Path(args.work_dir or manifest_path.parent).resolve()
    records = load_records(Path(args.records or root / "attempts.jsonl"))
    result = cmd_verify_values(manifest, records, root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # Keep the subcommand selector separate from the collector's --command
    # option.  Sharing the same argparse destination makes every `run` call
    # fall through to `verify`, because the collector string overwrites the
    # value "run".
    sub = parser.add_subparsers(dest="subcommand", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--pages", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--domain", default="E", choices=("F", "S", "E"))
    plan.add_argument("--repeats", type=int, default=10)
    plan.add_argument("--retry-limit", type=int, default=1)
    plan.add_argument("--run-id")
    plan.add_argument("--force", action="store_true")
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--manifest", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--command", dest="collector_command", required=True,
                     help="argv template; supports {sample_id}, {attempt_id}, {page_id}, {url}, {output_dir}")
    run.add_argument("--work-dir", type=Path)
    run.add_argument("--records", type=Path)
    run.add_argument("--resume", action="store_true")
    run.add_argument("--timeout", type=int, default=900)
    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--work-dir", type=Path)
    verify.add_argument("--records", type=Path)
    args = parser.parse_args()
    if args.subcommand == "plan":
        if args.repeats < 1 or args.retry_limit < 0:
            raise SystemExit("repeats must be positive and retry-limit nonnegative")
        cmd_plan(args)
        return 0
    if args.subcommand == "preflight":
        return cmd_preflight(args)
    if args.subcommand == "run":
        return cmd_run(args)
    return cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
