#!/usr/bin/env python3
"""Continuation coordinator for the frozen E Browser/Tor V2 pilot.

V2.2 keeps the V2 protocol identity and sample contract. Its implementation
adds timeout-stop behavior and an auditable, offline continuation migration.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

import run_e_browser_pilot_v2 as v21
import batch_manifest as manifest_module


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT / "artifacts" / "e_browser_tor_pilot_v2_2_20261021"
IMPLEMENTATION_ID = "starrynet-e-browser-tor-v2-2-timeout-stop-continuation"
ORIGINAL_VERIFY_FREEZE = v21.verify_freeze
ORIGINAL_ARTIFACT_OK = manifest_module.artifact_ok
ORIGINAL_FAILURE_POLICY = v21.failure_policy
ORIGINAL_FATAL_FAILURES = v21.COLLECTION_FATAL_FAILURES


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def json_dump(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path):
    return v21.sha256_path(path)


def v22_failure_policy(failure_class, consecutive_failures, attempts_for_sample):
    if failure_class == "timeout":
        return "pause"
    return ORIGINAL_FAILURE_POLICY(failure_class, consecutive_failures,
                                   attempts_for_sample)


def v22_artifact_ok(record, root):
    if (record.get("timed_out") is True or record.get("returncode") == 124
            or record.get("failure_class") == "timeout"):
        record["ok"] = False
        record["failure_class"] = "timeout"
    return ORIGINAL_ARTIFACT_OK(record, Path(root))


def install_runtime_policy():
    """Install policy hooks used by the unchanged V2.1 coordinator loop."""
    v21.failure_policy = v22_failure_policy
    manifest_module.artifact_ok = v22_artifact_ok
    v21.COLLECTION_FATAL_FAILURES = frozenset(
        set(ORIGINAL_FATAL_FAILURES) | {"timeout"})
    v21.verify_freeze = verify_freeze


def verify_freeze(root):
    errors = ORIGINAL_VERIFY_FREEZE(root)
    freeze_path = Path(root) / "protocol" / "freeze_hashes.json"
    if not freeze_path.is_file():
        return errors
    try:
        freeze = v21.read_json(freeze_path)
    except (OSError, ValueError) as exc:
        return errors + ["cannot read continuation freeze: {}".format(exc)]
    item = freeze.get("hashes", {}).get("v2_2_entrypoint")
    if not item:
        errors.append("V2.2 entrypoint is absent from the continuation freeze")
    elif sha256_path(item.get("path", "")) != item.get("sha256"):
        errors.append("V2.2 continuation entrypoint changed or is missing")
    return errors


def _replace_root(value, old_root, new_root):
    if isinstance(value, str):
        return value.replace(str(old_root), str(new_root))
    if isinstance(value, list):
        return [_replace_root(item, old_root, new_root) for item in value]
    if isinstance(value, dict):
        return {key: _replace_root(item, old_root, new_root)
                for key, item in value.items()}
    return value


def _source_ready(source):
    source = Path(source).resolve()
    errors = ORIGINAL_VERIFY_FREEZE(source)
    if errors:
        raise RuntimeError("source freeze check failed: " + "; ".join(errors))
    for name in ("active_attempt.json", "v2_online_action_lock.json"):
        if (source / name).exists():
            raise RuntimeError("source has an active marker: " + name)
    if v21.active_collection_processes():
        raise RuntimeError("an E Browser/Tor collection process is active")

    budget_path = source / "online_budget.json"
    budget = v21.read_json(budget_path)
    if budget.get("active_started_utc") or budget.get("active_phase"):
        raise RuntimeError("source has an unfinished online budget action")
    for action in budget.get("actions", []):
        if action.get("ended_utc") is None:
            raise RuntimeError("source contains an unfinished budget action")

    attempts = v21.read_jsonl(source / "attempts.jsonl")
    for row in attempts:
        if row.get("_record_error"):
            raise RuntimeError("source attempt ledger is malformed")
        if (row.get("cleanup_verified") is not True
                or row.get("process_group_cleanup_verified") is not True):
            raise RuntimeError("attempt cleanup is not verified: {}".format(
                row.get("attempt_id", "unknown")))
    return source, budget, attempts


def _retarget_freeze(source, target):
    freeze_path = target / "protocol" / "freeze_hashes.json"
    freeze = v21.read_json(freeze_path)
    for item in freeze.get("hashes", {}).values():
        original = Path(item.get("path", ""))
        try:
            relative = original.resolve().relative_to(source)
        except (ValueError, OSError):
            continue
        item["path"] = str(target / relative)

    config_path = target / "protocol" / "runtime_config.json"
    config = v21.read_json(config_path)
    config["batch_root"] = str(target)
    config["coordinator_entrypoint"] = str(Path(__file__).resolve())
    json_dump(config_path, config)

    freeze["hashes"]["runtime_config"]["path"] = str(config_path)
    freeze["hashes"]["runtime_config"]["sha256"] = sha256_path(config_path)
    freeze["hashes"]["v2_2_entrypoint"] = {
        "kind": "file", "path": str(Path(__file__).resolve()),
        "sha256": sha256(__file__)}
    continuation_doc = target / "continuation" / "IMPLEMENTATION.md"
    migration_record = target / "continuation" / "migration.json"
    freeze["hashes"]["continuation_implementation"] = {
        "kind": "file", "path": str(continuation_doc),
        "sha256": sha256(continuation_doc)}
    freeze["hashes"]["continuation_migration_record"] = {
        "kind": "file", "path": str(migration_record),
        "sha256": sha256(migration_record)}
    json_dump(freeze_path, freeze)


def continue_from(source_root, output_root):
    source_input = Path(source_root).expanduser().resolve()
    target = Path(output_root).expanduser().resolve()
    source, budget, attempts = _source_ready(source_input)
    if source == target:
        raise RuntimeError("source and continuation output roots must differ")
    if target.exists():
        raise RuntimeError("continuation output already exists; refusing overwrite")

    target.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        shutil.copytree(source, target, symlinks=False)
        created = True
        for copied in target.rglob("*"):
            if copied.is_symlink():
                raise RuntimeError("symlink found in copied continuation tree")

        # Keep a byte-identical ledger as migration evidence, then rebase only
        # path references in the active continuation ledger.
        migration_dir = target / "continuation"
        migration_dir.mkdir(parents=True, exist_ok=True)
        original_ledger = source / "attempts.jsonl"
        ledger_archive = migration_dir / "source_attempts.jsonl"
        shutil.copy2(original_ledger, ledger_archive)
        records = [_replace_root(row, source, target) for row in attempts]
        active_ledger = target / "attempts.jsonl"
        active_ledger.write_text("".join(json.dumps(row, sort_keys=True) + "\n"
                                             for row in records), encoding="utf-8")

        implementation_doc = migration_dir / "IMPLEMENTATION.md"
        implementation_doc.write_text(
            "# V2.2 continuation implementation\n\n"
            "The V2.1 protocol identity, sample manifest, collection settings, "
            "and acceptance gates are retained. This entrypoint pauses on any "
            "collector or coordinator timeout. The original V2.1 coordinator "
            "and source evidence remain unchanged.\n", encoding="utf-8")

        source_freeze = source / "protocol" / "freeze_hashes.json"
        source_summary = v21.read_json(source / "execution_summary.json")
        inherited_ids = sorted({row.get("sample_id") for row in records
                                if row.get("ok") is True
                                and row.get("artifacts_valid") is True})
        copied_artifact_hashes = {}
        for path in sorted((target / "samples").rglob("*")):
            if path.is_file():
                rel_path = path.relative_to(target)
                rel = rel_path.as_posix()
                source_path = source / rel_path
                source_hash = sha256(source_path)
                target_hash = sha256(path)
                if source_hash != target_hash:
                    raise RuntimeError("sample copy hash mismatch: " + rel)
                copied_artifact_hashes[rel] = {
                    "source_sha256": source_hash,
                    "continuation_sha256": target_hash,
                }
        migration = {
            "schema_version": 1,
            "implementation_id": IMPLEMENTATION_ID,
            "protocol_id": source_summary["protocol_id"],
            "created_utc": utc_now(),
            "implementation_entrypoint_sha256": sha256(__file__),
            "source_root": str(source), "target_root": str(target),
            "source_freeze_sha256": sha256(source_freeze),
            "source_attempt_ledger_sha256": sha256(original_ledger),
            "copied_original_attempt_ledger_sha256": sha256(ledger_archive),
            "source_summary_sha256": sha256(source / "execution_summary.json"),
            "source_attempt_count": len(attempts),
            "inherited_successful_samples": len(inherited_ids),
            "inherited_successful_sample_ids": inherited_ids,
            "inherited_online_budget_seconds": float(
                budget.get("accrued_seconds", 0.0)),
            "sample_file_count": len(copied_artifact_hashes),
            "copied_sample_file_sha256": copied_artifact_hashes,
        }
        json_dump(migration_dir / "migration.json", migration)

        # Point frozen root-local inputs at their copies; preserve the protocol
        # source paths for all external, byte-identical implementation inputs.
        _retarget_freeze(source, target)
        inherited_note = {
            "implementation_id": IMPLEMENTATION_ID,
            "inherited_successful_samples": len(inherited_ids),
            "inherited_successful_sample_ids": inherited_ids,
            "new_successful_samples": 0,
            "new_attempts": 0,
            "source_attempt_count": len(attempts),
        }
        json_dump(target / "continuation" / "continuation_state.json",
                  inherited_note)
        # Include the derived continuation state in the freeze.
        freeze_path = target / "protocol" / "freeze_hashes.json"
        freeze = v21.read_json(freeze_path)
        state_path = target / "continuation" / "continuation_state.json"
        freeze["hashes"]["continuation_state"] = {
            "kind": "file", "path": str(state_path), "sha256": sha256(state_path)}
        json_dump(freeze_path, freeze)

        state_path = target / "execution_state.json"
        state = v21.read_json(state_path)
        state["stopped_reason"] = "migrated_from_v2_1"
        state["continuation_implementation"] = IMPLEMENTATION_ID
        json_dump(state_path, state)
        _update_summary(target)

        errors = verify_freeze(target)
        if errors:
            raise RuntimeError("new continuation freeze failed: " + "; ".join(errors))
        for row in records:
            valid, reason = manifest_module.artifact_ok(row, target)
            if row.get("artifacts") and not valid:
                raise RuntimeError("migrated artifact check failed: " + reason)
        return _update_summary(target)
    except Exception:
        if created and target.exists():
            shutil.rmtree(target)
        raise


def _counts(root):
    rows = v21.read_jsonl(Path(root) / "attempts.jsonl")
    successes = {row.get("sample_id") for row in rows
                 if row.get("ok") is True and row.get("artifacts_valid") is True}
    return rows, successes


def _update_summary(root, stopped_reason=None, error=None, clear_stop=False):
    root = Path(root)
    rows, successes = _counts(root)
    state_path = root / "execution_state.json"
    state = v21.read_json(state_path) if state_path.exists() else {}
    if stopped_reason is not None or clear_stop:
        state["stopped_reason"] = stopped_reason
        state["updated_utc"] = utc_now()
        json_dump(state_path, state)
    elif state.get("stopped_reason") == "migrated_from_v2_1":
        state["stopped_reason"] = None
        state["updated_utc"] = utc_now()
        json_dump(state_path, state)

    continuation_path = root / "continuation" / "continuation_state.json"
    continuation = (v21.read_json(continuation_path)
                    if continuation_path.exists() else {})
    inherited = int(continuation.get("inherited_successful_samples", 0))
    budget = v21.budget_used(root)
    summary = {
        "protocol_id": (v21.read_json(root / "batch_manifest.json")
                        .get("protocol_metadata", {}).get("protocol_id")),
        "implementation_id": IMPLEMENTATION_ID,
        "planned_samples": len(v21.read_json(root / "batch_manifest.json")
                                .get("samples", [])),
        "successful_samples": len(successes),
        "inherited_successful_samples": inherited,
        "new_successful_samples": max(0, len(successes) - inherited),
        "attempt_count": len(rows),
        "inherited_attempt_count": int(continuation.get("source_attempt_count", 0)),
        "new_attempt_count": max(0, len(rows) - int(
            continuation.get("source_attempt_count", 0))),
        "consecutive_failures": int(state.get("consecutive_failures", 0)),
        "stopped_reason": stopped_reason or state.get("stopped_reason"),
        "online_budget_used_seconds": budget,
        "remaining_online_budget_seconds": max(0, v21.TOTAL_BUDGET_SECONDS - budget),
    }
    if error:
        summary["last_error"] = error
    json_dump(root / "execution_summary.json", summary)
    return summary


def _reason_from_error(error):
    lowered = str(error).lower()
    if "freeze check failed" in lowered:
        return "frozen_hash_changed"
    if "runtime preflight failed" in lowered:
        return "runtime_preflight_failed"
    if "existing collector is active" in lowered:
        return "existing_collector_active"
    if "interrupted attempt cleanup" in lowered:
        return "interrupted_cleanup_unverified"
    if "less than 22" in lowered:
        return "less_than_22_minutes_remain"
    if "lock" in lowered:
        return "collection_lock_failure"
    return "coordinator_start_failed"


def cmd_doctor(args):
    try:
        errors = verify_freeze(args.output_root)
        if errors:
            _update_summary(args.output_root, "frozen_hash_changed",
                            "; ".join(errors))
            print("V2.2 freeze check failed: " + "; ".join(errors), file=sys.stderr)
            return 2
        result = v21.cmd_doctor(args)
        runtime_path = Path(args.output_root) / "diagnostics" / "runtime_preflight.json"
        runtime = v21.read_json(runtime_path) if runtime_path.exists() else {}
        reason = None if runtime.get("passed") is True else "runtime_preflight_failed"
        _update_summary(args.output_root, reason,
                        "; ".join(runtime.get("errors", [])) or None,
                        clear_stop=reason is None)
        return result
    except Exception as exc:
        _update_summary(args.output_root, "runtime_preflight_failed", str(exc))
        raise


def cmd_run(args):
    install_runtime_policy()
    stopped = None
    error = None
    try:
        return v21.cmd_run(args)
    except SystemExit as exc:
        error = str(exc)
        stopped = _reason_from_error(error)
        raise
    except KeyboardInterrupt:
        error = "operator interrupted the V2.2 coordinator"
        stopped = "operator_interrupt"
        raise
    finally:
        _update_summary(args.output_root, stopped, error)


def cmd_audit(args):
    install_runtime_policy()
    result = v21.cmd_audit(args)
    root = Path(args.output_root)
    summary = _update_summary(root)
    audit = {
        "implementation_id": IMPLEMENTATION_ID,
        "protocol_id": summary["protocol_id"],
        "pilot_audit_returncode": result,
        "successful_samples": summary["successful_samples"],
        "inherited_successful_samples": summary["inherited_successful_samples"],
        "new_successful_samples": summary["new_successful_samples"],
        "attempt_count": summary["attempt_count"],
        "new_attempt_count": summary["new_attempt_count"],
        "stopped_reason": summary["stopped_reason"],
        "online_budget_used_seconds": summary["online_budget_used_seconds"],
        "remaining_online_budget_seconds": summary[
            "remaining_online_budget_seconds"],
    }
    json_dump(root / "final_audit" / "continuation_audit.json", audit)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_ROOT))
    sub = parser.add_subparsers(dest="command")
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--config", default=None)
    run = sub.add_parser("run")
    run.add_argument("--resume", action="store_true")
    sub.add_parser("audit")
    continuation = sub.add_parser("continue-from")
    continuation.add_argument("--source-root", required=True)
    args = parser.parse_args(argv)
    if not args.command:
        parser.error("a subcommand is required")
    args.output_root = str(Path(args.output_root).expanduser().resolve())
    if args.command == "continue-from":
        expected = DEFAULT_ROOT.resolve()
        if Path(args.output_root) != expected:
            raise SystemExit("continuation output must be the frozen V2.2 root: "
                             + str(expected))
        result = continue_from(args.source_root, args.output_root)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    root = Path(args.output_root)
    if not root.is_dir():
        raise SystemExit("V2.2 continuation root does not exist; run continue-from first")
    if args.command == "doctor":
        if args.config is None:
            args.config = str(root / "protocol" / "runtime_config.json")
        return cmd_doctor(args)
    if args.command == "run":
        return cmd_run(args)
    return cmd_audit(args)


if __name__ == "__main__":
    sys.exit(main())
