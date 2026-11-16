#!/usr/bin/env python3
"""Plan, run, and inspect the Research 2 controlled replay batch."""

from __future__ import print_function

import argparse
import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent
CORE_SCRIPT = TOOLS / "replay_trace_over_starrynet.py"
DEFAULT_INPUT = ROOT / "dataset" / "tor_fiber"
DEFAULT_ARTIFACTS_ROOT = ROOT / "artifacts" / "research2_tcp_drift"
SCENARIOS = ("base", "delay25", "jitter25_10", "loss0p1")
PROFILES = {
    "base": {"delay_ms": 0.0, "jitter_ms": 0.0, "loss_percent": 0.0},
    "delay25": {"delay_ms": 25.0, "jitter_ms": 0.0, "loss_percent": 0.0},
    "jitter25_10": {"delay_ms": 25.0, "jitter_ms": 10.0, "loss_percent": 0.0},
    "loss0p1": {"delay_ms": 0.0, "jitter_ms": 0.0, "loss_percent": 0.1},
}
SAMPLE_RE = re.compile(r"^(?P<class_id>\d+)-(?P<repeat_id>\d+)$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
GIB = 1024 ** 3

try:
    import replay_trace_over_starrynet as replay_core
except ImportError:
    sys.path.insert(0, str(TOOLS))
    import replay_trace_over_starrynet as replay_core


class BatchError(RuntimeError):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _batch_id_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")


def _id_key(sample_id):
    match = SAMPLE_RE.fullmatch(sample_id)
    if not match:
        return (float("inf"), float("inf"), sample_id)
    return (int(match.group("class_id")), int(match.group("repeat_id")), sample_id)


def _atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with open(str(temporary), "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(str(temporary), str(path))


def _write_exact_json(path, data):
    """Write deterministic compact JSON and return SHA256 of the exact bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(data, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
    with open(str(path), "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(payload).hexdigest()


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_sha256(value):
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _driver_code_hashes():
    paths = [CORE_SCRIPT, TOOLS / "e_replay_agent.py",
             TOOLS / "research2_evidence.py", TOOLS / "research2_reports.py",
             TOOLS / "research2_batch.py"]
    paths.extend(getattr(replay_core, "RUNTIME_SOURCE_FILES", ()))
    paths.extend(getattr(replay_core, "FROZEN_HELPER_FILES", ()))
    result = {}
    for path in paths:
        resolved = Path(path).resolve()
        result[str(resolved.relative_to(ROOT.resolve()))] = _sha256_file(resolved)
    return result


def _append_ledger(batch_dir, entry):
    path = Path(batch_dir) / "events.jsonl"
    payload = dict(entry)
    payload.setdefault("time_utc", utc_now())
    with open(str(path), "a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def update_batch(batch_manifest_path, updates, ledger_entry=None):
    """Update selected state fields after re-reading the latest manifest.

    The core writes ``frozen_topology`` into this same file.  Re-reading before
    every update prevents a stale driver snapshot from deleting that evidence.
    """
    path = Path(batch_manifest_path)
    state = _read_json(path)
    state.update(updates)
    state["updated_utc"] = utc_now()
    _atomic_write(path, state)
    if ledger_entry is not None:
        _append_ledger(path.parent, ledger_entry)
    return state


def _parse_id_file(path):
    data = _read_json(path)
    values = data.get("sample_ids") if isinstance(data, dict) else data
    if not isinstance(values, list):
        raise BatchError("sample ID file must contain a sample_ids array")
    if len(values) != len(set(values)):
        raise BatchError("sample ID file contains duplicate IDs")
    if any(not isinstance(value, str) or not SAMPLE_RE.fullmatch(value) for value in values):
        raise BatchError("sample ID file contains an invalid class-repeat ID")
    return values


def discover_sources(input_root):
    """Read and hash source traces, enforcing the frozen 75 x 80 cohort."""
    root = Path(input_root).resolve()
    if not root.is_dir():
        raise BatchError("input root is not a directory: " + str(root))
    source_rows = []
    seen = set()
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.is_file():
            continue
        match = SAMPLE_RE.fullmatch(path.name)
        if not match:
            continue
        sample_id = path.name
        if sample_id in seen:
            raise BatchError("duplicate source ID: " + sample_id)
        seen.add(sample_id)
        try:
            info = replay_core.read_trace(path)
        except (OSError, replay_core.ReplayError, ValueError) as exc:
            raise BatchError("invalid source trace {0}: {1}".format(path.name, exc))
        source_rows.append({
            "sample_id": sample_id,
            "class_id": int(match.group("class_id")),
            "repeat_id": int(match.group("repeat_id")),
            "source_path": str(path.resolve()),
            "source_sha256": info["sha256"],
            "source_bytes": path.stat().st_size,
            "event_count": info["event_count"],
            "duration_seconds": info["duration_seconds"],
            "direction_counts": {str(key): int(value)
                                 for key, value in info["direction_counts"].items()},
        })
    source_rows.sort(key=lambda row: _id_key(row["sample_id"]))
    classes = {}
    for row in source_rows:
        classes.setdefault(row["class_id"], []).append(row)
    if len(source_rows) != 6000 or sorted(classes) != list(range(75)):
        raise BatchError("input must contain exactly 75 classes by 80 traces (6000 total)")
    wrong_counts = {class_id: len(rows) for class_id, rows in classes.items()
                    if len(rows) != 80}
    if wrong_counts:
        raise BatchError("each source class must have exactly 80 traces: "
                         + json.dumps(wrong_counts, sort_keys=True))
    return source_rows


def select_cohorts(source_rows):
    """Choose 150 extrema IDs plus deterministic five-ID and three-ID cohorts."""
    by_class = {}
    for row in source_rows:
        by_class.setdefault(row["class_id"], []).append(row)
    pilot_ids = []
    for class_id in range(75):
        rows = sorted(by_class[class_id], key=lambda row: (
            row["duration_seconds"], row["repeat_id"]))
        shortest = rows[0]
        longest = next(row for row in sorted(
            rows, key=lambda item: (-item["duration_seconds"], item["repeat_id"]))
                       if row_id(row) != row_id(shortest))
        pilot_ids.extend((shortest["sample_id"], longest["sample_id"]))
    pilot_ids = sorted(set(pilot_ids), key=_id_key)
    if len(pilot_ids) != 150:
        raise BatchError("pilot selection did not produce 150 distinct source IDs")

    dynamic_ids = []
    for class_id in (0, 18, 37, 56, 74):
        candidates = sorted(by_class[class_id], key=lambda row: row["repeat_id"])
        selected = next((row for row in candidates
                         if int(row["direction_counts"].get("1", 0)) > 0 and
                         int(row["direction_counts"].get("-1", 0)) > 0), None)
        if selected is None:
            raise BatchError("no bidirectional source trace for dynamic class "
                             + str(class_id))
        dynamic_ids.append(selected["sample_id"])
    dynamic_ids = sorted(dynamic_ids, key=_id_key)

    # The bounded 30s-vs-120s diagnostic uses short, median, and long
    # bidirectional source traces, in that order with numeric ID tie breaks.
    bidirectional = [row for row in source_rows
                     if int(row["direction_counts"].get("1", 0)) > 0 and
                     int(row["direction_counts"].get("-1", 0)) > 0]
    if len(bidirectional) < 3:
        raise BatchError("deadline diagnostic requires at least three bidirectional traces")
    by_duration = sorted(bidirectional, key=lambda row: (
        row["duration_seconds"], row["class_id"], row["repeat_id"]))
    deadline_rows = [by_duration[0], by_duration[len(by_duration) // 2], by_duration[-1]]
    deadline_ids = sorted(set(row["sample_id"] for row in deadline_rows), key=_id_key)
    if len(deadline_ids) != 3:
        raise BatchError("deadline diagnostic selection must contain three distinct IDs")
    return {"pilot": pilot_ids,
            "full": [row["sample_id"] for row in source_rows],
            "dynamic": dynamic_ids,
            "deadline": deadline_ids}


def row_id(row):
    return row["sample_id"]


def _cohort_file(batch_dir, key, ids):
    path = Path(batch_dir) / (key + "_ids.json")
    digest = _write_exact_json(path, {"sample_ids": ids})
    return {"ids_file": str(path.resolve()), "sha256": digest,
            "sample_ids": list(ids)}


def _command_result(runner, command):
    return runner(command, cwd=str(ROOT), stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, universal_newlines=True)


def _extract_json_output(text):
    lines = text.splitlines()
    # Some core commands print progress JSON before their final result.  Start
    # at the end so the returned object describes the completed command.
    for index in range(len(lines) - 1, -1, -1):
        candidate = "\n".join(lines[index:]).strip()
        if not candidate.startswith("{"):
            continue
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _path_under(path, root):
    try:
        return os.path.commonpath((str(Path(path).resolve()), str(Path(root).resolve()))) == str(Path(root).resolve())
    except (ValueError, OSError):
        return False


def _core_plan_command(input_root, batch_dir, batch_manifest_path, cohort,
                       cohort_key, run_type, name, owner_id, service_name,
                       seed, speed, session_seconds):
    if run_type == "pilot":
        run_root = Path(batch_dir) / "pilot" / name / "runs"
        dataset_root = Path(batch_dir) / "pilot" / name / "dataset"
    elif run_type == "full":
        run_root = Path(batch_dir) / "full" / name / "runs"
        dataset_root = Path(batch_dir) / "full" / name / "dataset"
    else:
        run_root = Path(batch_dir) / "diagnostics" / run_type / name / "runs"
        dataset_root = Path(batch_dir) / "diagnostics" / run_type / name / "dataset"
    run_root.mkdir(parents=True, exist_ok=True)
    dataset_root.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(CORE_SCRIPT), "plan",
               "--input", str(Path(input_root).resolve()),
               "--run-root", str(run_root.resolve()),
               "--dataset-output", str(dataset_root.resolve()),
               "--seed", str(seed), "--speed", str(speed),
               "--session-seconds", str(session_seconds),
               "--sample-ids", cohort["ids_file"],
               "--cohort-key", cohort_key,
               "--batch-id", Path(batch_dir).name,
               "--owner-id", owner_id, "--service-name", service_name,
               "--transport", "tcp"]
    if run_type in ("pilot", "full"):
        command.extend(["--topology-mode", "fixed", "--scenario", name,
                        "--batch-manifest", str(batch_manifest_path)])
        if run_type == "pilot":
            command.append("--pilot")
    elif run_type == "dynamic":
        command.extend(["--topology-mode", "dynamic", "--diagnostic-mode", name,
                        "--link-loss-percent", "0",
                        "--batch-manifest", str(batch_manifest_path)])
    elif run_type == "deadline":
        completion_seconds = int(name[:-1])
        command.extend(["--topology-mode", "fixed", "--scenario", "base",
                        "--diagnostic-mode", "deadline",
                        "--tcp-completion-seconds", str(completion_seconds),
                        "--batch-manifest", str(batch_manifest_path)])
    else:
        raise BatchError("unknown plan run type: " + run_type)
    return command, run_root, dataset_root


def plan_batch(input_root=DEFAULT_INPUT, artifacts_root=DEFAULT_ARTIFACTS_ROOT,
               owner_id=None, service_name=None, batch_id=None, seed=2024,
               speed=1.0, pilot_session_seconds=900, full_session_seconds=9000,
               runner=None):
    runner = runner or subprocess.run
    if not owner_id or not SAFE_ID_RE.fullmatch(owner_id):
        raise BatchError("a safe --owner-id is required")
    if not service_name or not SAFE_ID_RE.fullmatch(service_name):
        raise BatchError("a safe --service-name is required")
    batch_id = batch_id or _batch_id_now()
    if not SAFE_ID_RE.fullmatch(batch_id):
        raise BatchError("batch_id must be a safe identifier")
    batch_dir = Path(artifacts_root).resolve() / batch_id
    if batch_dir.exists():
        raise BatchError("refusing to overwrite existing batch: " + str(batch_dir))
    source_rows = discover_sources(input_root)
    cohorts = select_cohorts(source_rows)
    source_by_id = {row["sample_id"]: row for row in source_rows}
    dynamic_total_seconds = sum(source_by_id[item]["duration_seconds"] / speed
                                for item in cohorts["dynamic"])
    dynamic_session_seconds = max(
        pilot_session_seconds,
        int(math.ceil(dynamic_total_seconds + 15 + 60 + 120)))
    batch_dir.mkdir(parents=True)
    cohort_files = {}
    for key in ("pilot", "full", "dynamic", "deadline"):
        cohort_files[key] = _cohort_file(batch_dir, key, cohorts[key])
    # The stable full-source input file is the identity anchored in the
    # top-level source_ids_sha256 required by fixed replay manifests.
    source_ids_path = batch_dir / "source_ids.json"
    source_ids_sha256 = _write_exact_json(
        source_ids_path, {"sample_ids": cohorts["full"]})
    cohort_files["full"]["ids_file"] = str(source_ids_path.resolve())
    cohort_files["full"]["sha256"] = source_ids_sha256

    manifest_path = batch_dir / "batch_manifest.json"
    state = {
        "schema_version": 1,
        "batch_id": batch_id,
        "owner_id": owner_id,
        "service_name": service_name,
        "source_ids_sha256": source_ids_sha256,
        "source_ids_file": str(source_ids_path.resolve()),
        "source_ids": {"sample_ids": cohorts["full"]},
        "source_hashes": {row["sample_id"]: row["source_sha256"]
                           for row in source_rows},
        "source_rows": source_rows,
        "input_root": str(Path(input_root).resolve()),
        "input_file_count": len(source_rows),
        "input_total_bytes": sum(row["source_bytes"] for row in source_rows),
        "pilot_ids": cohorts["pilot"],
        "dynamic_ids": cohorts["dynamic"],
        "deadline_ids": cohorts["deadline"],
        "cohorts": cohort_files,
        "profiles": PROFILES,
        "config_sha256": _canonical_sha256({
            "profiles": PROFILES, "seed": seed, "speed": speed,
            "pilot_session_seconds": pilot_session_seconds,
            "full_session_seconds": full_session_seconds,
            "dynamic_session_seconds": dynamic_session_seconds}),
        "code_hashes": _driver_code_hashes(),
        "manifests": {"pilot": {}, "full": {}, "dynamic": {}, "deadline": {}},
        "stage": "planning",
        "status": "planning",
        "created_utc": utc_now(),
        "seed": seed,
        "speed": speed,
        "pilot_session_seconds": pilot_session_seconds,
        "full_session_seconds": full_session_seconds,
        "dynamic_session_seconds": dynamic_session_seconds,
        "event_ledger": str((batch_dir / "events.jsonl").resolve()),
    }
    _atomic_write(manifest_path, state)
    _append_ledger(batch_dir, {"event": "batch_created", "batch_id": batch_id,
                               "input_root": state["input_root"],
                               "source_count": len(source_rows)})

    if runner is None:
        runner = subprocess.run
    plan_items = []
    for condition in SCENARIOS:
        plan_items.append(("pilot", condition, "pilot", "pilot", pilot_session_seconds))
    for condition in SCENARIOS:
        plan_items.append(("full", condition, "full", "full", full_session_seconds))
    for mode in ("stable", "crossing"):
        plan_items.append(("dynamic", mode, "dynamic", "dynamic",
                           dynamic_session_seconds))
    # Each deadline arm is a distinct fixed baseline manifest.  They share
    # the exact three frozen IDs and differ only in the completion window.
    for completion_seconds in (30, 120):
        arm = "{0}s".format(completion_seconds)
        plan_items.append(("deadline", arm, "deadline", "deadline",
                           pilot_session_seconds))

    try:
        for manifest_group, name, run_type, cohort_key, session_seconds in plan_items:
            command, run_root, dataset_root = _core_plan_command(
                input_root, batch_dir, manifest_path, cohort_files[cohort_key],
                cohort_key, run_type, name, owner_id, service_name,
                seed, speed, session_seconds)
            stage = "plan:{0}:{1}".format(manifest_group, name)
            update_batch(manifest_path, {"stage": stage, "status": "planning"},
                         {"event": "command_started", "stage": stage,
                          "command": command})
            started = time.monotonic()
            result = _command_result(runner, command)
            elapsed = time.monotonic() - started
            output = _extract_json_output(result.stdout or "")
            if result.returncode != 0 or not output or output.get("planned") is not True:
                raise BatchError("{0} failed (exit {1}): {2}".format(
                    stage, result.returncode, (result.stderr or result.stdout or "no output").strip()))
            child_path = Path(output.get("manifest", ""))
            if not child_path.is_file() or not _path_under(child_path, run_root):
                raise BatchError(stage + " returned a manifest outside its planned run root")
            child = _read_json(child_path)
            if child.get("cohort_key") != cohort_key:
                raise BatchError(stage + " manifest has unexpected cohort_key")
            expected_topology = "dynamic" if run_type == "dynamic" else "fixed"
            expected_diag = name if run_type == "dynamic" else (
                "deadline" if run_type == "deadline" else None)
            expected_scenario = "base" if run_type == "deadline" else (
                name if run_type in ("pilot", "full") else None)
            if child.get("topology", {}).get("mode") != expected_topology:
                raise BatchError(stage + " manifest has unexpected topology mode")
            if child.get("diagnostic_mode") != expected_diag:
                raise BatchError(stage + " manifest has unexpected diagnostic mode")
            if child.get("scenario") != expected_scenario:
                raise BatchError(stage + " manifest has unexpected fixed scenario")
            expected_window = int(name[:-1]) if run_type == "deadline" else 120
            if child.get("tcp_completion_timeout_seconds") != expected_window:
                raise BatchError(stage + " manifest has unexpected TCP completion window")
            expected_mode = ("diagnostic" if expected_diag else
                             "pilot" if run_type == "pilot" else "formal")
            if child.get("mode") != expected_mode:
                raise BatchError(stage + " manifest has unexpected replay mode")
            expected_ids = cohort_files[cohort_key]["sample_ids"]
            planned_ids = [row.get("sample_id") for row in child.get("source_rows", [])]
            if planned_ids != expected_ids:
                raise BatchError(stage + " manifest source ID coverage differs from frozen cohort")
            if (child.get("source_ids_sha256") != cohort_files[cohort_key]["sha256"]
                    or child.get("source_count") != len(expected_ids)):
                raise BatchError(stage + " manifest source cohort hash/count mismatch")
            for row in child.get("source_rows", []):
                if row.get("source_sha256") != state["source_hashes"].get(row["sample_id"]):
                    raise BatchError(stage + " source hash changed after inventory: "
                                     + row.get("sample_id", "unknown"))
            latest = _read_json(manifest_path)
            manifests = latest.setdefault("manifests", {})
            manifests.setdefault(manifest_group, {})[name] = {
                "manifest": str(child_path.resolve()),
                "run_root": str(run_root.resolve()),
                "dataset_output": str(dataset_root.resolve()),
                "cohort_key": cohort_key,
                "planned_samples": len(expected_ids),
                "planned_utc": utc_now(),
            }
            latest.setdefault("plan_elapsed_seconds", {})[stage] = elapsed
            _atomic_write(manifest_path, latest)
            _append_ledger(batch_dir, {"event": "child_planned", "stage": stage,
                                       "manifest": str(child_path.resolve()),
                                       "sample_count": len(expected_ids),
                                       "elapsed_seconds": elapsed})
    except (BatchError, OSError, ValueError) as exc:
        update_batch(manifest_path, {"stage": "plan_failed", "status": "failed",
                                     "error": str(exc)},
                     {"event": "batch_failed", "stage": "plan", "error": str(exc)})
        raise
    update_batch(manifest_path, {"stage": "planned", "status": "planned"},
                 {"event": "planning_complete", "manifest_count": sum(
                     len(rows) for rows in _read_json(manifest_path)["manifests"].values())})
    return {"batch_id": batch_id, "batch_dir": str(batch_dir),
            "batch_manifest": str(manifest_path), "source_count": len(source_rows),
            "pilot_count": len(cohorts["pilot"]), "dynamic_count": len(cohorts["dynamic"]),
            "deadline_count": len(cohorts["deadline"])}


def _manifest_file(value):
    path = Path(value)
    if path.is_dir():
        path = path / "batch_manifest.json"
    if not path.is_file():
        raise BatchError("batch manifest not found: " + str(path))
    return path.resolve()


def _core_command(manifest_path, command, resume=False):
    values = [sys.executable, str(CORE_SCRIPT), command,
              "--manifest", str(Path(manifest_path).resolve())]
    if command == "run" and resume:
        values.append("--resume")
    return values


def _check_frozen_code(batch_manifest_path):
    state = _read_json(batch_manifest_path)
    if state.get("code_hashes") != _driver_code_hashes():
        raise BatchError("frozen replay/driver/report code changed after plan; create a new batch")
    config = {"profiles": state.get("profiles"), "seed": state.get("seed"),
              "speed": state.get("speed"),
              "pilot_session_seconds": state.get("pilot_session_seconds"),
              "full_session_seconds": state.get("full_session_seconds"),
              "dynamic_session_seconds": state.get("dynamic_session_seconds")}
    if state.get("config_sha256") != _canonical_sha256(config):
        raise BatchError("frozen batch configuration was modified after plan")
    source_ids = state.get("source_ids", {}).get("sample_ids")
    if not isinstance(source_ids, list) or len(source_ids) != 6000 or len(set(source_ids)) != 6000:
        raise BatchError("frozen full cohort is not exactly 6000 unique source IDs")
    if state.get("source_ids_sha256") != state.get("cohorts", {}).get("full", {}).get("sha256"):
        raise BatchError("top-level source ID hash differs from frozen full cohort hash")
    source_id_set = set(source_ids)
    for key in ("pilot", "full", "dynamic", "deadline"):
        cohort = state.get("cohorts", {}).get(key, {})
        ids_path = Path(cohort.get("ids_file", ""))
        if not ids_path.is_absolute():
            ids_path = Path(batch_manifest_path).parent / ids_path
        if not ids_path.is_file() or _sha256_file(ids_path) != cohort.get("sha256"):
            raise BatchError("frozen {0} cohort ID file/hash is missing or changed".format(key))
        ids = _parse_id_file(ids_path)
        if ids != cohort.get("sample_ids"):
            raise BatchError("frozen {0} cohort ID list was modified".format(key))
        if any(sample_id not in source_id_set for sample_id in ids):
            raise BatchError("frozen {0} cohort contains a non-source ID".format(key))
    return state


def _run_child_command(batch_manifest_path, stage, manifest_path, command,
                       runner, resume=False):
    _check_frozen_code(batch_manifest_path)
    batch_dir = Path(batch_manifest_path).parent
    values = _core_command(manifest_path, command, resume=resume)
    update_batch(batch_manifest_path, {"stage": stage, "status": "running"},
                 {"event": "command_started", "stage": stage,
                  "command": values, "manifest": str(manifest_path)})
    started = time.monotonic()
    result = _command_result(runner, values)
    elapsed = time.monotonic() - started
    log_dir = batch_dir / "command_logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / ("{0:04d}_{1}.json".format(
        len(list(log_dir.glob("*.json"))) + 1, stage.replace(":", "_")))
    _atomic_write(log_path, {"command": values, "returncode": result.returncode,
                             "stdout": result.stdout or "", "stderr": result.stderr or "",
                             "elapsed_seconds": elapsed})
    output = _extract_json_output(result.stdout or "")
    _append_ledger(batch_dir, {"event": "command_finished", "stage": stage,
                               "returncode": result.returncode,
                               "elapsed_seconds": elapsed,
                               "log": str(log_path.resolve())})
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "command returned nonzero").strip()
        update_batch(batch_manifest_path, {"stage": stage, "status": "failed",
                                           "error": message},
                     {"event": "batch_failed", "stage": stage, "error": message})
        raise BatchError("{0} failed: {1}".format(stage, message))
    if not isinstance(output, dict):
        message = "command produced no JSON result"
        update_batch(batch_manifest_path, {"stage": stage, "status": "failed",
                                           "error": message},
                     {"event": "batch_failed", "stage": stage, "error": message})
        raise BatchError(stage + ": " + message)
    update_batch(batch_manifest_path, {"stage": stage, "last_command_result": output,
                                       "last_command_elapsed_seconds": elapsed},
                 {"event": "progress", "stage": stage,
                  "result": output, "elapsed_seconds": elapsed})
    return output


def _child_paths(batch_manifest, group):
    entries = batch_manifest.get("manifests", {}).get(group)
    if not isinstance(entries, dict):
        raise BatchError("batch has no planned manifests for " + group)
    return entries


def _load_child(child_entry):
    path = Path(child_entry["manifest"])
    if not path.is_file():
        raise BatchError("planned child manifest is missing: " + str(path))
    return _read_json(path)


def _verify_child_outputs(child_entry, expected_ids, require_handover=False):
    manifest_path = Path(child_entry["manifest"])
    manifest = _read_json(manifest_path)
    run_dir = Path(manifest.get("run_dir", manifest_path.parent))
    verification_path = run_dir / "verification.json"
    dataset_path = Path(manifest.get("dataset_output", child_entry["dataset_output"]))
    dataset_manifest_path = run_dir / "dataset_manifest.json"
    if manifest.get("status") != "finalized":
        return False, "child manifest is not finalized"
    if not verification_path.is_file() or not dataset_manifest_path.is_file():
        return False, "verification or dataset manifest is missing"
    verification = _read_json(verification_path)
    dataset_manifest = _read_json(dataset_manifest_path)
    dataset_ids = [row.get("sample_id") for row in dataset_manifest.get("samples", [])]
    if verification.get("passed") is not True:
        return False, "child verification did not pass"
    if verification.get("successful_samples") != len(expected_ids):
        return False, "verification successful sample count does not match cohort"
    if dataset_manifest.get("sample_count") != len(expected_ids):
        return False, "finalized dataset sample count does not match cohort"
    if sorted(dataset_ids, key=_id_key) != sorted(expected_ids, key=_id_key):
        return False, "finalized dataset IDs do not exactly match cohort"
    if not dataset_path.is_dir():
        return False, "finalized dataset directory is missing"
    files = {path.name for path in dataset_path.iterdir() if path.is_file()
             and SAMPLE_RE.fullmatch(path.name)}
    if files != set(expected_ids):
        return False, "exported trajectory files do not exactly match cohort"
    if require_handover:
        sessions_root = Path(manifest.get("run_dir", manifest_path.parent)) / "sessions"
        summaries = []
        if sessions_root.is_dir():
            for path in sorted(sessions_root.glob("*/summary.json")):
                try:
                    summaries.append(_read_json(path))
                except (OSError, ValueError):
                    continue
        if not summaries or not any(
                summary.get("dynamic_matrix_changed") is True and
                int(summary.get("handover_count", 0)) >= 1 for summary in summaries):
            return False, "dynamic handover evidence is absent"
    return True, {"verification": verification, "dataset_manifest": dataset_manifest}


def _ensure_child_complete(batch_manifest_path, stage_prefix, child_entry,
                           expected_ids, runner, resume=False,
                           require_handover=False):
    manifest_path = Path(child_entry["manifest"])
    child = _load_child(child_entry)
    if child.get("preflight", {}).get("status") != "passed" and child.get("status") not in (
            "run_completed", "finalized"):
        _run_child_command(batch_manifest_path, stage_prefix + ":preflight",
                           manifest_path, "preflight", runner)
        child = _load_child(child_entry)
        if child.get("preflight", {}).get("status") != "passed":
            raise BatchError(stage_prefix + ": preflight did not record passed evidence")
    if child.get("status") != "finalized":
        if child.get("status") != "run_completed":
            if child.get("status") not in ("preflight_passed", "planned") and not resume:
                raise BatchError(stage_prefix + ": child is incomplete; resume requires --resume")
            result = _run_child_command(batch_manifest_path, stage_prefix + ":run",
                                        manifest_path, "run", runner, resume=resume)
            if result.get("run_completed") is not True:
                raise BatchError(stage_prefix + ": core run did not complete all samples")
        verification = _run_child_command(batch_manifest_path,
                                          stage_prefix + ":verify", manifest_path,
                                          "verify", runner)
        if verification.get("passed") is not True:
            raise BatchError(stage_prefix + ": core verify did not pass")
        finalized = _run_child_command(batch_manifest_path,
                                       stage_prefix + ":finalize", manifest_path,
                                       "finalize", runner)
        if finalized.get("finalized") is not True:
            raise BatchError(stage_prefix + ": core finalize did not report finalized")
    passed, evidence = _verify_child_outputs(child_entry, expected_ids,
                                              require_handover=require_handover)
    if not passed:
        raise BatchError(stage_prefix + ": " + evidence)
    return evidence


def _pilot_gate(report):
    if not isinstance(report, dict) or report.get("complete") is not True:
        raise BatchError("pilot gate failed: four-scenario report does not have complete coverage")
    return True


def _tree_bytes(root):
    root = Path(root)
    total = 0
    if not root.exists():
        return 0
    for directory, _, files in os.walk(str(root)):
        for name in files:
            path = Path(directory) / name
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


def build_capacity_estimates(batch_manifest_path):
    state = _read_json(batch_manifest_path)
    source_by_id = {row["sample_id"]: row for row in state.get("source_rows", [])}
    pilot_ids = state.get("pilot_ids", [])
    full_ids = state.get("source_ids", {}).get("sample_ids", [])
    pilot_events = sum(int(source_by_id[item]["event_count"]) for item in pilot_ids)
    full_events = sum(int(source_by_id[item]["event_count"]) for item in full_ids)
    if pilot_events <= 0 or full_events <= 0:
        raise BatchError("capacity estimate needs positive pilot and full source event counts")
    estimates = {}
    pilot_gates = {}
    for scenario in SCENARIOS:
        pilot_entry = _child_paths(state, "pilot").get(scenario)
        if not pilot_entry:
            raise BatchError("missing pilot manifest for capacity estimate: " + scenario)
        pilot_manifest = _load_child(pilot_entry)
        core_gate = pilot_manifest.get("storage_guard")
        if not isinstance(core_gate, dict) or not core_gate.get("free_bytes"):
            raise BatchError("pilot core storage gate is missing for " + scenario)
        pilot_gates[scenario] = core_gate
        pilot_bytes = _tree_bytes(pilot_entry["run_root"]) + _tree_bytes(
            pilot_entry["dataset_output"])
        if pilot_bytes <= 0:
            raise BatchError("pilot produced no measurable bytes for " + scenario)
        estimates[scenario] = {
            "pilot_bytes": pilot_bytes,
            "pilot_source_events": pilot_events,
            "full_source_events": full_events,
            "estimated_full_bytes": int(math_ceil_ratio(pilot_bytes * full_events,
                                                         pilot_events)),
            "bytes_per_source_event": pilot_bytes / float(pilot_events),
            "core_storage_guard": core_gate,
        }
    return {"per_scenario": estimates, "pilot_core_storage_guards": pilot_gates,
            "estimated_all_full_bytes": sum(row["estimated_full_bytes"]
                                             for row in estimates.values()),
            "pilot_wall_seconds": sum(state.get("pilot_run_seconds", {}).values()),
            "estimated_full_runtime_seconds": (
                sum(state.get("pilot_run_seconds", {}).values()) *
                (full_events * len(SCENARIOS)) /
                max(1, pilot_events * len(SCENARIOS))),
            "full_source_event_count": full_events}


def math_ceil_ratio(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def capacity_gate(free_bytes, estimated_remaining_bytes, safety_bytes=20 * GIB):
    required = int(estimated_remaining_bytes * 1.5) + int(safety_bytes)
    return {"free_bytes": int(free_bytes),
            "estimated_remaining_bytes": int(estimated_remaining_bytes),
            "required_free_bytes": required,
            "safety_bytes": int(safety_bytes),
            "passed": int(free_bytes) >= required}


def _free_bytes(path):
    return shutil.disk_usage(str(path)).free


def _reports(batch_manifest_path, group, expected_ids, report_generator=None):
    _check_frozen_code(batch_manifest_path)
    if report_generator is None:
        try:
            from research2_reports import generate_reports
        except ImportError:
            sys.path.insert(0, str(TOOLS))
            from research2_reports import generate_reports
        report_generator = generate_reports
    state = _read_json(batch_manifest_path)
    roots = {scenario: _child_paths(state, group)[scenario]["dataset_output"]
             for scenario in SCENARIOS}
    output_dir = Path(batch_manifest_path).parent / "reports" / group
    return report_generator(roots, output_dir, expected_ids=expected_ids)


def _dynamic_summary(batch_manifest_path, runner, resume=False):
    state = _read_json(batch_manifest_path)
    expected = state["dynamic_ids"]
    results = {}
    for diagnostic in ("stable", "crossing"):
        entry = _child_paths(state, "dynamic").get(diagnostic)
        if not entry:
            raise BatchError("dynamic diagnostic manifest is missing: " + diagnostic)
        evidence = _ensure_child_complete(batch_manifest_path,
                                          "dynamic:" + diagnostic, entry, expected,
                                          runner, resume=resume,
                                          require_handover=(diagnostic == "crossing"))
        results[diagnostic] = {
            "manifest": entry["manifest"],
            "verification_passed": evidence["verification"].get("passed") is True,
            "dataset_sample_count": evidence["dataset_manifest"].get("sample_count"),
        }
    if not all(row["verification_passed"] and row["dataset_sample_count"] == len(expected)
               for row in results.values()):
        raise BatchError("dynamic diagnostic evidence is incomplete")
    result_path = Path(batch_manifest_path).parent / "reports" / "dynamic_validation.json"
    _atomic_write(result_path, {
        "status": "passed", "complete": True, "sample_ids": expected,
        "diagnostics": results,
        "interpretation": "Independent stable and handover-crossing replay evidence; "
                          "not mixed into fixed-condition datasets.",
    })
    return {"path": str(result_path), "complete": True, "diagnostics": results}


def _deadline_gate(batch_manifest_path, runner, resume=False):
    """Compare paired real three-sample 30s/120s baseline arms.

    These are isolated diagnostic manifests.  They are preflighted and
    verified, never finalized as formal trajectories.  A fully recorded 30s
    failure is usable diagnostic evidence; the 120s arm must succeed.
    """
    state = _read_json(batch_manifest_path)
    expected = state.get("deadline_ids", [])
    arms = {}
    for seconds, key in ((30, "30s"), (120, "120s")):
        entry = _child_paths(state, "deadline").get(key)
        if not entry:
            raise BatchError("deadline diagnostic manifest is missing: " + key)
        manifest_path = Path(entry["manifest"])
        manifest = _load_child(entry)
        run_dir = Path(manifest.get("run_dir", manifest_path.parent))
        diagnostic_path = run_dir / "deadline_diagnostic.json"
        if not diagnostic_path.is_file():
            if manifest.get("preflight", {}).get("status") == "passed":
                raise BatchError(key + " preflight is recorded but diagnostic evidence is missing; refusing to replay")
            _run_child_command(batch_manifest_path, "deadline:" + key + ":preflight",
                               manifest_path, "preflight", runner)
        if not diagnostic_path.is_file():
            raise BatchError(key + " preflight did not create deadline_diagnostic.json")
        # Core verify is an offline evidence check and must not initiate a
        # second measurement.  It updates verification fields in this record.
        _run_child_command(batch_manifest_path, "deadline:" + key + ":verify",
                           manifest_path, "verify", runner)
        diagnostic = _read_json(diagnostic_path)
        complete = (diagnostic.get("execution_complete") is True and
                    diagnostic.get("endpoint_evidence_complete") is True and
                    diagnostic.get("cleanup_verified") is True and
                    diagnostic.get("sample_ids") == expected and
                    diagnostic.get("tcp_completion_seconds") == seconds and
                    diagnostic.get("planned_samples") == len(expected) and
                    (diagnostic.get("verification") or {}).get(
                        "execution_verified") is True)
        if not complete:
            raise BatchError(key + " deadline attempt/endpoint/cleanup evidence is incomplete")
        if seconds == 120 and diagnostic.get("all_samples_success") is not True:
            raise BatchError("120s deadline arm did not complete all diagnostic samples")
        arms[key] = {"manifest": entry["manifest"], "diagnostic": diagnostic}
    result = {"status": "diagnostics_complete", "arms": arms,
              "sample_ids": expected,
              "interpretation": "Paired completion-window diagnostic; the 30s arm may contain complete recorded failures. No causal claim is made."}
    output_path = Path(batch_manifest_path).parent / "reports" / "deadline_diagnostic.json"
    _atomic_write(output_path, result)
    result["path"] = str(output_path)
    return result


def _capacity_gate(batch_manifest_path, runner):
    """Ask the core to size all four formal scenarios from the four pilots."""
    _check_frozen_code(batch_manifest_path)
    state = _read_json(batch_manifest_path)
    pilots = _child_paths(state, "pilot")
    full = _child_paths(state, "full")
    pilot_paths = [pilots[name]["manifest"] for name in SCENARIOS]
    full_paths = [full[name]["manifest"] for name in SCENARIOS]
    output_path = Path(batch_manifest_path).parent / "capacity_gate.json"
    command = ([sys.executable, str(CORE_SCRIPT), "capacity",
                "--batch-manifest", str(Path(batch_manifest_path).resolve()),
                "--pilot-manifests"] + pilot_paths + ["--full-manifests"] +
               full_paths + ["--output", str(output_path.resolve())])
    _append_ledger(Path(batch_manifest_path).parent,
                   {"event": "command_started", "stage": "capacity_gate",
                    "command": command})
    started = time.monotonic()
    result = _command_result(runner, command)
    elapsed = time.monotonic() - started
    gate = _read_json(output_path) if output_path.is_file() else None
    _append_ledger(Path(batch_manifest_path).parent,
                   {"event": "command_finished", "stage": "capacity_gate",
                    "returncode": result.returncode, "elapsed_seconds": elapsed,
                    "gate": gate})
    if not isinstance(gate, dict):
        raise BatchError("core capacity command produced no capacity_gate.json: " +
                         (result.stderr or result.stdout or "no output").strip())
    if result.returncode != 0 or gate.get("passed") is not True:
        update_batch(batch_manifest_path,
                     {"status": "paused_capacity", "stage": "capacity_gate_failed",
                      "capacity_gate": gate},
                     {"event": "capacity_gate_failed", "gate": gate})
        raise BatchError("core capacity gate did not pass; no full replay was started")
    pilot_ids = state.get("pilot_ids", [])
    full_ids = state.get("source_ids", {}).get("sample_ids", [])
    source_by_id = {row["sample_id"]: row for row in state.get("source_rows", [])}
    pilot_events = sum(int(source_by_id[item]["event_count"]) for item in pilot_ids)
    full_events = sum(int(source_by_id[item]["event_count"]) for item in full_ids)
    pilot_wall_seconds = sum(state.get("pilot_run_seconds", {}).values())
    runtime_estimate_seconds = (pilot_wall_seconds * full_events / float(pilot_events)
                                if pilot_events else None)
    return {"path": str(output_path), "gate": gate,
            "pilot_wall_seconds": pilot_wall_seconds,
            "pilot_event_count": pilot_events,
            "full_event_count": full_events,
            "estimated_full_runtime_seconds": runtime_estimate_seconds,
            "estimated_full_runtime_hours": (
                runtime_estimate_seconds / 3600.0
                if runtime_estimate_seconds is not None else None),
            "runtime_estimate_basis": "pilot wall time scaled by full/pilot source event counts"}


def _child_is_finalized(entry):
    try:
        child = _load_child(entry)
    except (BatchError, OSError, ValueError):
        return False
    return child.get("status") == "finalized"


def run_batch(batch_path, resume=False, runner=None, free_bytes_fn=None,
              report_generator=None):
    runner = runner or subprocess.run
    free_bytes_fn = free_bytes_fn or _free_bytes
    batch_manifest_path = _manifest_file(batch_path)
    batch_dir = batch_manifest_path.parent
    lock_path = batch_dir / ".driver.lock"
    with open(str(lock_path), "a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as exc:
            raise BatchError("another batch driver holds .driver.lock") from exc
        state = _read_json(batch_manifest_path)
        _check_frozen_code(batch_manifest_path)
        for row in state.get("source_rows", []):
            source_path = Path(row["source_path"])
            if not source_path.is_file() or _sha256_file(source_path) != row.get("source_sha256"):
                raise BatchError("frozen source changed after plan: " + row.get("sample_id", "unknown"))
        if state.get("status") == "complete":
            audit = audit_full_coverage(batch_manifest_path)
            if not audit["complete"]:
                raise BatchError("batch claims complete but artifact audit failed")
            return audit
        if state.get("status") == "planning":
            raise BatchError("batch planning is incomplete; refusing to replan during run")
        if state.get("status") == "failed" and not resume:
            raise BatchError("batch is failed; rerun with --resume to use existing manifests")
        if not state.get("manifests", {}).get("full"):
            raise BatchError("batch has no frozen full manifests; run plan first")
        update_batch(batch_manifest_path, {"status": "running", "stage": "pilot"},
                     {"event": "run_started", "resume": bool(resume)})
        try:
            pilot_ids = state.get("pilot_ids", [])
            pilot_elapsed = state.setdefault("pilot_run_seconds", {})
            for scenario in SCENARIOS:
                entry = _child_paths(state, "pilot").get(scenario)
                if not entry:
                    raise BatchError("pilot manifest missing for " + scenario)
                old_status = _load_child(entry).get("status")
                before = time.monotonic()
                _ensure_child_complete(batch_manifest_path, "pilot:" + scenario,
                                       entry, pilot_ids, runner, resume=resume)
                if old_status not in ("run_completed", "finalized"):
                    pilot_elapsed[scenario] = time.monotonic() - before
                    state = update_batch(batch_manifest_path,
                                         {"pilot_run_seconds": dict(pilot_elapsed),
                                          "stage": "pilot:" + scenario + ":complete",
                                          "status": "running"},
                                         {"event": "pilot_scenario_complete",
                                          "scenario": scenario,
                                          "elapsed_seconds": pilot_elapsed[scenario]})
                else:
                    state = _read_json(batch_manifest_path)

            pilot_report = _reports(batch_manifest_path, "pilot", pilot_ids,
                                    report_generator=report_generator)
            update_batch(batch_manifest_path,
                         {"pilot_report": pilot_report,
                          "stage": "pilot_gate", "status": "running"},
                         {"event": "pilot_report_generated",
                          "complete": pilot_report.get("complete")})
            _pilot_gate(pilot_report)

            dynamic = _dynamic_summary(batch_manifest_path, runner, resume=resume)
            update_batch(batch_manifest_path,
                         {"dynamic_validation": dynamic, "stage": "dynamic_complete",
                          "status": "running"},
                         {"event": "dynamic_validation_complete",
                          "report": dynamic["path"]})
            deadline = _deadline_gate(batch_manifest_path, runner, resume=resume)
            update_batch(batch_manifest_path,
                         {"deadline_diagnostic": deadline,
                          "stage": "deadline_diagnostic_complete", "status": "running"},
                         {"event": "deadline_diagnostic_complete",
                          "path": deadline["path"]})

            full_ids = state["source_ids"]["sample_ids"]
            for scenario in SCENARIOS:
                state = _read_json(batch_manifest_path)
                entry = _child_paths(state, "full").get(scenario)
                if not entry:
                    raise BatchError("full manifest missing for " + scenario)
                if _child_is_finalized(entry):
                    passed, _ = _verify_child_outputs(entry, full_ids)
                    if not passed:
                        raise BatchError("previously finalized full cohort is invalid: " + scenario)
                    continue
                # Recalculate before each new condition.  The core excludes
                # already finalized cohorts and checks current free space;
                # cmd_run repeats this check after preflight at run time.
                capacity = _capacity_gate(batch_manifest_path, runner)
                update_batch(batch_manifest_path,
                             {"capacity_estimate": capacity,
                              "stage": "capacity_gate:" + scenario,
                              "status": "running"},
                             {"event": "capacity_estimated",
                              "scenario": scenario,
                              "capacity_gate_path": capacity["path"],
                              "capacity_gate": capacity["gate"],
                              "estimated_full_runtime_seconds": capacity[
                                  "estimated_full_runtime_seconds"]})
                update_batch(batch_manifest_path,
                             {"stage": "full_capacity:" + scenario,
                              "status": "running"},
                             {"event": "full_capacity_gate_requested",
                              "scenario": scenario})
                # The core run command rechecks the shared gate against the
                # current free space and all unfinished full manifests.
                _ensure_child_complete(batch_manifest_path, "full:" + scenario,
                                       entry, full_ids, runner, resume=resume)
                update_batch(batch_manifest_path,
                             {"stage": "full:" + scenario + ":complete",
                              "status": "running"},
                             {"event": "full_scenario_complete", "scenario": scenario})

            full_report = _reports(batch_manifest_path, "full", full_ids,
                                   report_generator=report_generator)
            update_batch(batch_manifest_path,
                         {"full_report": full_report, "stage": "full_coverage_gate",
                          "status": "running"},
                         {"event": "full_report_generated",
                          "complete": full_report.get("complete")})
            _pilot_gate(full_report)
            audit = audit_full_coverage(batch_manifest_path,
                                        report_override=full_report)
            if not audit["complete"]:
                raise BatchError("full artifact audit failed; batch remains incomplete")
            update_batch(batch_manifest_path,
                         {"status": "complete", "stage": "complete",
                          "completed_utc": utc_now(), "final_audit": audit},
                         {"event": "batch_complete", "full_source_count": len(full_ids)})
            return audit
        except BatchError as exc:
            current = _read_json(batch_manifest_path)
            if current.get("status") not in ("paused_capacity", "failed"):
                update_batch(batch_manifest_path,
                             {"status": "failed", "error": str(exc)},
                             {"event": "batch_failed", "stage": current.get("stage"),
                              "error": str(exc)})
            raise
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def audit_full_coverage(batch_path, report_override=None):
    batch_manifest_path = _manifest_file(batch_path)
    state = _read_json(batch_manifest_path)
    expected_ids = state.get("source_ids", {}).get("sample_ids", [])
    problems = []
    if len(expected_ids) != 6000 or len(set(expected_ids)) != 6000:
        problems.append("frozen full source ID cohort is not exactly 6000 IDs")
    for scenario in SCENARIOS:
        entry = state.get("manifests", {}).get("full", {}).get(scenario)
        if not entry:
            problems.append("missing full manifest: " + scenario)
            continue
        passed, evidence = _verify_child_outputs(entry, expected_ids)
        if not passed:
            problems.append("{0}: {1}".format(scenario, evidence))
        elif evidence["verification"].get("successful_samples") != 6000:
            problems.append(scenario + ": verification does not cover all 6000 IDs")
    report = report_override or state.get("full_report")
    if not isinstance(report, dict) or report.get("complete") is not True:
        problems.append("full report does not prove complete coverage")
    report_path = Path(batch_manifest_path).parent / "reports" / "full" / "distribution_summary.json"
    if not report_path.is_file():
        problems.append("full distribution report file is missing")
    else:
        try:
            report_file = _read_json(report_path)
            if report_file.get("complete") is not True or report_file.get("expected_ids") != expected_ids:
                problems.append("saved full report does not match frozen 6000-ID cohort")
        except (OSError, ValueError):
            problems.append("saved full report cannot be read")
    return {"complete": not problems,
            "status": "complete" if not problems else "incomplete",
            "expected_count": len(expected_ids),
            "errors": problems}


def status_batch(batch_path):
    batch_manifest_path = _manifest_file(batch_path)
    state = _read_json(batch_manifest_path)
    child_status = {}
    for group, entries in state.get("manifests", {}).items():
        child_status[group] = {}
        for name, entry in entries.items():
            try:
                child_status[group][name] = _load_child(entry).get("status", "unknown")
            except (BatchError, OSError, ValueError):
                child_status[group][name] = "missing_manifest"
    active = False
    lock_path = batch_manifest_path.parent / ".driver.lock"
    if lock_path.exists():
        with open(str(lock_path), "a") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError):
                active = True
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    audit = audit_full_coverage(batch_manifest_path)
    computed_status = state.get("status", "unknown")
    if computed_status == "complete" and not audit["complete"]:
        computed_status = "integrity_error"
    return {"batch_id": state.get("batch_id"), "status": computed_status,
            "stage": state.get("stage"), "active": active,
            "complete": computed_status == "complete" and audit["complete"],
            "child_status": child_status, "full_audit": audit,
            "frozen_topology": _read_json(batch_manifest_path).get("frozen_topology")}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    plan = sub.add_parser("plan")
    plan.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    plan.add_argument("--artifacts-root", type=Path, default=DEFAULT_ARTIFACTS_ROOT)
    plan.add_argument("--batch-id")
    plan.add_argument("--owner-id", required=True)
    plan.add_argument("--service-name", required=True)
    plan.add_argument("--seed", type=int, default=2024)
    plan.add_argument("--speed", type=float, default=1.0)
    plan.add_argument("--pilot-session-seconds", type=int, default=900)
    plan.add_argument("--full-session-seconds", type=int, default=9000)
    run = sub.add_parser("run")
    run.add_argument("--batch", type=Path, required=True)
    run.add_argument("--resume", action="store_true")
    status = sub.add_parser("status")
    status.add_argument("--batch", type=Path, required=True)
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.error("a command is required")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.command == "plan":
            result = plan_batch(args.input, args.artifacts_root, args.owner_id,
                                args.service_name, batch_id=args.batch_id,
                                seed=args.seed, speed=args.speed,
                                pilot_session_seconds=args.pilot_session_seconds,
                                full_session_seconds=args.full_session_seconds)
        elif args.command == "run":
            result = run_batch(args.batch, resume=args.resume)
        else:
            result = status_batch(args.batch)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        # `status` is an inspection command; an incomplete planned/running
        # batch is an ordinary state and must not look like a CLI failure.
        if args.command == "status":
            return 0
        return 0 if result.get("complete", True) else 1
    except (BatchError, OSError, ValueError) as exc:
        print("research2_batch ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
