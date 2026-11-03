#!/usr/bin/env python3
"""Freeze and serially collect the 2026-10-29 V5 Browser/Tor dataset candidate."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import audit_v3_dataset_sample_20261029_v5 as sample_auditor
import satellite_wf_v3 as v3
import satellite_wf_v3_browser_tor_collector_py36compat_20261029_v5 as collector


OUT_DIR = ROOT / "artifacts/reports/satellite_wf_v3_20261021/five_class_candidate_20261029_v5"
CONFIG_PATH = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/runtime_config.json"
TEMPLATE_PLAN = ROOT / "artifacts/reports/satellite_wf_v3_20261021/five_class_candidate_readiness_20261027/class_0_execution_plan_20261027.json"
SOURCE_AUDIT = ROOT / "artifacts/reports/satellite_wf_v3_20261021/source_audit.json"
ATTESTATION = ROOT / "artifacts/reports/satellite_wf_v3_20261021/dataset_identity_attestation.json"
NETWORK_ACCEPTANCE = ROOT / "artifacts/reports/satellite_wf_v3_20261021/dynamic_network_acceptance/dynamic_acceptance_summary.json"
SOURCE_REVIEW = ROOT / "artifacts/reports/satellite_wf_v3_20261021/source_semantic_review_20261027/source_semantic_review_20261027.json"
BASE_BROWSER_CONFIG = ROOT / "artifacts/e_browser_tor_pilot_v2_2_runtime_rebase_20261026/protocol/runtime_config.json"
BASE_BROWSER_FREEZE = ROOT / "artifacts/e_browser_tor_pilot_v2_2_runtime_rebase_20261026/protocol/freeze_hashes.json"
BROWSER_CONFIG = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/browser_original/runtime_config.json"
BROWSER_FREEZE = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/browser_original/freeze_hashes.json"
RUNNER_PATH = Path(__file__).resolve()
AUDITOR_PATH = Path(sample_auditor.__file__).resolve()
SELECTION_PATH = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/bridge_selection.json"
PROTOCOL_STATE_PATH = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/protocol_state.json"
COHORT_PLAN = OUT_DIR / "five_class_x10_dataset_plan_20261029_v5.json"
COHORT_AUDIT = OUT_DIR / "five_class_x10_dataset_plan_audit_20261029_v5.json"
COHORT_FREEZE = OUT_DIR / "five_class_x10_dataset_plan_freeze_20261029_v5.json"
ATTEMPT_LEDGER = OUT_DIR / "dataset_attempt_ledger.jsonl"
ACCEPTED_LEDGER = OUT_DIR / "accepted_ledger.jsonl"
OUTCOME_LEDGER = OUT_DIR / "outcome_ledger.jsonl"
COLLECTOR_ATTEMPT_LEDGER = OUT_DIR / "collector_attempt_ledger.jsonl"
BASE_SAMPLE_FROM_SUMMARY = collector.sample_from_summary
BASE_ROUTE_NAT_INSTALL = collector.route_nat.install
BASE_ROUTE_NAT_VALIDATE = collector.route_nat.validate_runtime_config
ACTIVE_EXECUTION_PLAN = None

CLASS_MAP = {
    "0": "http://adobe.com",
    "1": "http://amazon.co.jp",
    "2": "http://amazon.in",
    "3": "http://apache.org",
    "4": "http://apple.com",
}
SPLIT_BY_REPLICATE = {
    1: "train", 2: "train", 3: "train", 4: "train", 5: "train",
    6: "train", 7: "train", 8: "validation", 9: "test", 10: "test",
}
REPLICATE_ORDER = (1, 8, 9, 2, 3, 4, 5, 6, 7, 10)
HARD_STOP_UTC = datetime.datetime(2026, 10, 29, 0, 0, 0,
                                  tzinfo=datetime.timezone.utc)
NO_START_UTC = datetime.datetime(2026, 10, 28, 23, 35, 0,
                                 tzinfo=datetime.timezone.utc)
ATTEMPT_WORK_SECONDS = 23 * 60
CLEANUP_GRACE_SECONDS = 2 * 60
ATTEMPT_TOTAL_SECONDS = ATTEMPT_WORK_SECONDS + CLEANUP_GRACE_SECONDS
TASK_LOCK = OUT_DIR / "dataset_candidate.lock"


class AttemptDeadlineExceeded(TimeoutError):
    pass


def start_attempt_watchdog():
    state = {"cleanup_grace_started": False, "hard_deadline_reached": False}
    previous = signal.getsignal(signal.SIGALRM)

    def expire(_signum, _frame):
        if state["cleanup_grace_started"]:
            state["hard_deadline_reached"] = True
            raise AttemptDeadlineExceeded(
                "hard 25-minute attempt deadline reached during cleanup")
        state["cleanup_grace_started"] = True
        signal.setitimer(signal.ITIMER_REAL, CLEANUP_GRACE_SECONDS)
        raise AttemptDeadlineExceeded(
            "23-minute work deadline reached; beginning bounded cleanup")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, ATTEMPT_WORK_SECONDS)
    return previous, state


def stop_attempt_watchdog(previous):
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, previous)


def activate_browser_runtime():
    global BROWSER_CONFIG, BROWSER_FREEZE
    if not SELECTION_PATH.is_file():
        raise RuntimeError("bridge qualification is incomplete; run the bounded startup diagnostic first")
    selection = read_json(SELECTION_PATH)
    if selection.get("qualified") is not True:
        raise RuntimeError("selected bridge has no two-success startup qualification")
    variant = selection.get("selected_variant")
    if variant not in ("browser_original", "browser_bridge2"):
        raise RuntimeError("selected bridge variant is outside the frozen candidate set")
    BROWSER_CONFIG = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5" / variant / "runtime_config.json"
    BROWSER_FREEZE = ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5" / variant / "freeze_hashes.json"
    if not BROWSER_CONFIG.is_file() or not BROWSER_FREEZE.is_file():
        raise RuntimeError("selected bridge runtime freeze is missing")
    if selection.get("runtime_config_sha256") != sha256(BROWSER_CONFIG):
        raise RuntimeError("selected runtime config changed after bridge qualification")
    if selection.get("runtime_freeze_sha256") != sha256(BROWSER_FREEZE):
        raise RuntimeError("selected runtime freeze changed after bridge qualification")
    if not selection.get("diagnostic_summary_path"):
        raise RuntimeError("bridge qualification is missing its diagnostic evidence")
    diagnostic = ROOT / selection["diagnostic_summary_path"]
    if not diagnostic.is_file() or sha256(diagnostic) != selection.get("diagnostic_summary_sha256"):
        raise RuntimeError("bridge startup diagnostic evidence is missing or changed")
    return selection


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_ref(path):
    path = Path(path).resolve()
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def jsonl_rows(path):
    path = Path(path)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def append_jsonl(path, row):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True,
                                    ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def frozen_inputs():
    import satellite_wf_v3_dynamic_fixed_object as dynamic
    import satellite_wf_v3_route_nat as route_nat
    import satellite_wf_v3_trace_extractor as trace_extractor
    import tor_browser_site_smoke_20261029_v5 as helper

    activate_browser_runtime()

    paths = {
        "runtime_config": CONFIG_PATH,
        "template_plan": TEMPLATE_PLAN,
        "source_audit": SOURCE_AUDIT,
        "dataset_identity_attestation": ATTESTATION,
        "dynamic_network_acceptance": NETWORK_ACCEPTANCE,
        "source_semantic_review": SOURCE_REVIEW,
        "browser_runtime_config": BROWSER_CONFIG,
        "browser_runtime_freeze": BROWSER_FREEZE,
        "selected_bridge": ROOT / read_json(SELECTION_PATH)["bridge_file_path"],
        "bridge_selection": SELECTION_PATH,
        "bridge_diagnostic_summary": ROOT / read_json(SELECTION_PATH)["diagnostic_summary_path"],
        "browser_tor_collector": collector.__file__,
        "dynamic_network_controller": dynamic.__file__,
        "route_nat_controller": route_nat.__file__,
        "browser_helper": helper.__file__,
        "trace_extractor": trace_extractor.__file__,
        "dataset_runner": RUNNER_PATH,
        "independent_sample_auditor": AUDITOR_PATH,
        "collector_interface_tests": ROOT / "tools/test_satellite_wf_v3_dataset_candidate_20261029_v5.py",
        "model_data_builder": ROOT / "tools/build_satellite_wf_v3_model_data_20261029_v5.py",
        "satlumen_evaluator": ROOT / "tools/evaluate_satlumen_v3_dataset_candidate_20261029_v5.py",
        "meeting_report_builder": ROOT / "tools/build_satellite_wf_v3_dataset_report_20261029_v5.py",
        "dataset_packager": ROOT / "tools/package_satellite_wf_v3_dataset_candidate_20261029_v5.py",
        "satlumen_candidate_config": ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/satlumen_candidate.yaml",
        "satlumen_fiber_config": ROOT / "protocols/satellite_wf_v3_candidate_20261029_v5/satlumen_candidate_fiber.yaml",
        "runbook": OUT_DIR / "RUNBOOK_20261029_v5.md",
        "protocol_state": PROTOCOL_STATE_PATH,
    }
    return {key: file_ref(path) for key, path in paths.items()}


def build_plan():
    selection = activate_browser_runtime()
    source = read_json(SOURCE_AUDIT)
    template = read_json(TEMPLATE_PLAN)
    attestation = read_json(ATTESTATION)
    runtime = read_json(CONFIG_PATH)
    config_errors = v3.validate_config(runtime)
    if config_errors:
        raise RuntimeError("new runtime config failed validation: " + "; ".join(config_errors))
    collector.route_nat.validate_runtime_config(CONFIG_PATH)
    network_acceptance = read_json(NETWORK_ACCEPTANCE)
    dynamic_no_handover = next((row for row in network_acceptance.get("results", [])
                                if row.get("scenario_id") == "dynamic_no_handover"), {})
    if (network_acceptance.get("all_passed") is not True
            or dynamic_no_handover.get("status") != "passed"
            or dynamic_no_handover.get("cleanup_verified") is not True):
        raise RuntimeError("existing dynamic_no_handover network acceptance is not passed")
    if source.get("status") != "user_attested_with_unresolved_semantics":
        raise RuntimeError("source audit status changed; review before freezing a new cohort")
    if source.get("errors") or attestation.get("confirmed_by_user") is not True:
        raise RuntimeError("source audit errors or required user attestation are missing")
    actual_map = {str(key): value for key, value in
                  source.get("common_class_map", {}).items()}
    if any(actual_map.get(key) != value for key, value in CLASS_MAP.items()):
        raise RuntimeError("the five-site class mapping differs from the audited source map")
    template_inputs = template.get("frozen_inputs", {})
    for key, path in (("browser_runtime_config", BASE_BROWSER_CONFIG),
                      ("browser_runtime_freeze", BASE_BROWSER_FREEZE)):
        row = template_inputs.get(key, {})
        if row.get("sha256") != sha256(path):
            raise RuntimeError("Browser/Tor runtime freeze changed: " + key)
    if template.get("browser_capture_window_contract", {}).get(
            "capture_window_seconds") != 180:
        raise RuntimeError("the template does not bind the existing 180-second capture")
    if template.get("browser_capture_window_contract", {}).get(
            "topology_duration_seconds") != 300:
        raise RuntimeError("the dynamic no-handover topology window changed")
    samples = []
    for replicate in REPLICATE_ORDER:
        for class_id in range(5):
            class_text = str(class_id)
            sample_id = "v3-candidate-20261029-v5-class-{}-r{:03d}".format(
                class_text, replicate)
            session = "v3-candidate-20261029-v5-class-{}-session-{:03d}".format(
                class_text, replicate)
            samples.append({
                "sample_id": sample_id,
                "class_id": class_text,
                "site_url": CLASS_MAP[class_text],
                "source_domain": "E",
                "session_id": session,
                "split_group_id": session,
                "split": SPLIT_BY_REPLICATE[replicate],
                "replicate": replicate,
                "network_scenario_id": "dynamic_no_handover",
                "planned_run_order": len(samples) + 1,
                "state": "planned_not_collected",
            })
    return {
        "schema_version": 1,
        "plan_id": "v3-five-class-x10-browser-tor-dataset-20261029-v5",
        "plan_status": "frozen_precollection",
        "objective": "50 independently visited real web targets through the fixed StarryNet V3 path; engineering dataset candidate only.",
        "planned_utc_date": "2026-10-29",
        "sample_count": 50,
        "class_count": 5,
        "replicates_per_class": 10,
        "class_mapping": CLASS_MAP,
        "class_mapping_sha256": source.get("class_mapping_sha256"),
        "frozen_inputs": frozen_inputs(),
        "network_contract": {
            "protocol_id": "starrynet-browser-tor-route-nat-v3-v5-20261029",
            "scenario": "dynamic_no_handover",
            "capture_interface": "wf-gre0",
            "egress_interface": "B27-default",
            "capture_seconds": 180,
            "max_parallel_collectors": 1,
            "online_budget_seconds": 50400,
            "attempt_timeout_seconds": 1500,
            "attempt_work_timeout_seconds": ATTEMPT_WORK_SECONDS,
            "tor_bootstrap_timeout_seconds": 600,
            "tor_ready_timeout_seconds": 780,
            "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
            "max_attempts_per_sample": 2,
            "startup_gate_accepted_sessions": 2,
            "live_proxy_preflight": "3 consecutive HTTPS CONNECT responses with HTTP 200 before every attempt",
            "scientific_fidelity_verified": False,
            "browser_runtime_variant": selection["selected_variant"],
            "browser_runtime_config_sha256": sha256(BROWSER_CONFIG),
            "bridge_diagnostic_summary_sha256": selection["diagnostic_summary_sha256"],
        },
        "split_policy": {
            "train_replicates": [1, 2, 3, 4, 5, 6, 7],
            "validation_replicate": 8,
            "test_replicates": [9, 10],
            "split_group_equals_session_id": True,
        },
        "sample_contract": {
            "required_sample_gates": 16,
            "independent_audit_checks": 17,
            "required_hashed_artifact_kinds": [
                "trace", "pcap", "sample_manifest", "packet_audit",
                "topology_events", "route_events"],
            "failed_browser_or_tor_startup_must_be_logged_before_sample_construction": True,
        },
        "semantics": {
            "trace": "existing V3 navigation-bounded trace; raw PCAP and original trace are retained",
            "scientific_fidelity_verified": False,
            "source_semantic_caveat_count": len(source.get("unresolved_semantics", [])),
        },
        "samples": samples,
    }


def audit_plan(plan):
    activate_browser_runtime()
    errors = []
    if plan.get("plan_id") != "v3-five-class-x10-browser-tor-dataset-20261029-v5":
        errors.append("unexpected plan id")
    if plan.get("plan_status") != "frozen_precollection":
        errors.append("plan must remain a precollection plan")
    if plan.get("sample_count") != 50 or len(plan.get("samples", [])) != 50:
        errors.append("plan must contain exactly 50 candidate samples")
    contract = plan.get("network_contract", {})
    if any(contract.get(key) != value for key, value in {
            "scenario": "dynamic_no_handover", "capture_interface": "wf-gre0",
            "egress_interface": "B27-default", "capture_seconds": 180,
            "max_parallel_collectors": 1, "online_budget_seconds": 50400,
            "attempt_timeout_seconds": 1500, "max_attempts_per_sample": 2,
            "attempt_work_timeout_seconds": ATTEMPT_WORK_SECONDS,
            "tor_bootstrap_timeout_seconds": 600,
            "tor_ready_timeout_seconds": 780,
            "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
            "scientific_fidelity_verified": False}.items()):
        errors.append("network collection contract differs from the approved plan")
    if plan.get("sample_contract", {}).get("required_sample_gates") != 16:
        errors.append("candidate sample contract must preserve all 16 collection gates")
    if plan.get("sample_contract", {}).get("independent_audit_checks") != 17:
        errors.append("candidate sample contract must preserve all 17 independent checks")
    for key, item in plan.get("frozen_inputs", {}).items():
        path = Path(item.get("path", ""))
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_file() or sha256(path) != item.get("sha256"):
            errors.append("frozen input changed or missing: " + key)
    source = read_json(SOURCE_AUDIT)
    if (plan.get("class_mapping") != CLASS_MAP
            or plan.get("class_mapping_sha256") != source.get("class_mapping_sha256")):
        errors.append("class map binding mismatch")
    expected_order = 1
    for replicate in REPLICATE_ORDER:
        for class_id in range(5):
            row = plan.get("samples", [])[expected_order - 1]
            expected = {
                "sample_id": "v3-candidate-20261029-v5-class-{}-r{:03d}".format(
                    class_id, replicate),
                "class_id": str(class_id), "site_url": CLASS_MAP[str(class_id)],
                "source_domain": "E", "replicate": replicate,
                "split": SPLIT_BY_REPLICATE[replicate],
                "planned_run_order": expected_order,
                "network_scenario_id": "dynamic_no_handover",
            }
            if any(row.get(key) != value for key, value in expected.items()):
                errors.append("round-robin cohort identity mismatch at order {}".format(
                    expected_order))
            if row.get("session_id") != row.get("split_group_id"):
                errors.append("session group differs from session at order {}".format(
                    expected_order))
            expected_order += 1
    if len({row.get("sample_id") for row in plan.get("samples", [])}) != 50:
        errors.append("sample IDs are not unique")
    if len({row.get("session_id") for row in plan.get("samples", [])}) != 50:
        errors.append("session IDs are not unique")
    for class_id in range(5):
        class_samples = [row for row in plan.get("samples", [])
                         if row.get("class_id") == str(class_id)]
        if len(class_samples) != 10:
            errors.append("class {} does not have ten planned samples".format(class_id))
        for split, count in (("train", 7), ("validation", 1), ("test", 2)):
            if sum(1 for row in class_samples if row.get("split") == split) != count:
                errors.append("class {} split {} count mismatch".format(class_id, split))
    return {
        "audit_status": "passed" if not errors else "failed",
        "errors": errors,
        "plan_sha256": sha256(COHORT_PLAN) if COHORT_PLAN.is_file() else None,
        "sample_count": len(plan.get("samples", [])),
        "class_counts": {str(class_id): sum(
            1 for row in plan.get("samples", [])
            if row.get("class_id") == str(class_id)) for class_id in range(5)},
        "source_semantics_preserved": plan.get("semantics", {}).get(
            "source_semantic_caveat_count") == len(source.get("unresolved_semantics", [])),
    }


def freeze_plan():
    if any(path.exists() for path in (COHORT_PLAN, COHORT_AUDIT, COHORT_FREEZE)):
        raise RuntimeError("refusing to replace an existing 20261029_v5 cohort artifact")
    activate_browser_runtime()
    plan = build_plan()
    write_json(COHORT_PLAN, plan)
    audit = audit_plan(plan)
    write_json(COHORT_AUDIT, audit)
    if audit.get("audit_status") != "passed":
        raise RuntimeError("cohort audit failed: " + "; ".join(audit.get("errors", [])))
    freeze = {
        "plan_id": plan["plan_id"],
        "plan": file_ref(COHORT_PLAN),
        "audit": file_ref(COHORT_AUDIT),
        "frozen_utc": utc_now(),
    }
    write_json(COHORT_FREEZE, freeze)
    return {"plan": str(COHORT_PLAN), "plan_sha256": sha256(COHORT_PLAN),
            "audit": audit, "freeze": str(COHORT_FREEZE)}


def verify_cohort():
    activate_browser_runtime()
    plan = read_json(COHORT_PLAN)
    freeze = read_json(COHORT_FREEZE)
    recorded_audit = read_json(COHORT_AUDIT)
    digest = sha256(COHORT_PLAN)
    if (freeze.get("plan", {}).get("sha256") != digest
            or freeze.get("audit", {}).get("sha256") != sha256(COHORT_AUDIT)
            or recorded_audit.get("plan_sha256") != digest):
        raise RuntimeError("cohort freeze/audit hash mismatch")
    audit = audit_plan(plan)
    if audit.get("audit_status") != "passed":
        raise RuntimeError("cohort failed current offline audit: "
                           + "; ".join(audit.get("errors", [])))
    return plan


def configure_collector():
    import satellite_wf_v3_dynamic_fixed_object as dynamic
    import satellite_wf_v3_route_nat as route_nat

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    activate_browser_runtime()
    v3.DEFAULT_CONFIG = CONFIG_PATH
    collector.DEFAULT_V2_CONFIG = BROWSER_CONFIG
    collector.DEFAULT_V2_FREEZE = BROWSER_FREEZE
    collector.v3.DEFAULT_CONFIG = CONFIG_PATH
    collector.dynamic.v3.DEFAULT_CONFIG = CONFIG_PATH
    collector.dynamic.fixed.v3.DEFAULT_CONFIG = CONFIG_PATH
    collector.route_nat.DEFAULT_CONFIG = CONFIG_PATH
    route_nat.DEFAULT_CONFIG = CONFIG_PATH
    collector.route_nat.validate_runtime_config = lambda config_path=None: (
        BASE_ROUTE_NAT_VALIDATE(CONFIG_PATH if config_path is None else config_path))
    collector.route_nat.install = lambda *args, **kwargs: BASE_ROUTE_NAT_INSTALL(
        *args, **dict(kwargs, config_path=kwargs.get("config_path", CONFIG_PATH)))
    dynamic.DYNAMIC_ARTIFACTS = OUT_DIR / "collection"
    collector.READINESS_DIR = OUT_DIR
    collector.ATTEMPT_LEDGER = COLLECTOR_ATTEMPT_LEDGER
    collector.ATTEMPT_LEDGER_CORRECTIONS = None
    collector._read_attempt_ledger = lambda path=None, corrections_path=None: jsonl_rows(
        COLLECTOR_ATTEMPT_LEDGER)
    collector.sample_from_summary = write_candidate_sample
    collector.offline_audit = offline_execution_plan_audit
    dynamic.verify_route_state = verify_candidate_route_state


def verify_candidate_route_state(state_path):
    """Carry the frozen config across the verifier subprocess boundary."""
    state_path = Path(state_path).resolve()
    state = read_json(state_path)
    if (Path(state.get("runtime_config_path", "")).resolve() != CONFIG_PATH.resolve()
            or state.get("runtime_config_sha256") != sha256(CONFIG_PATH)):
        raise RuntimeError("installed route state is not bound to the frozen candidate config")
    result = collector.dynamic.fixed.run_command(
        [sys.executable, ROOT / "tools/satellite_wf_v3_route_nat.py",
         "verify", "--state", state_path, "--config", CONFIG_PATH],
        timeout=60, check=False)
    try:
        verification = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("route/NAT verifier returned invalid JSON: " +
                           (result.stderr or result.stdout).strip()) from exc
    verification["command_returncode"] = result.returncode
    verification["runtime_config_path"] = str(CONFIG_PATH)
    verification["runtime_config_sha256"] = sha256(CONFIG_PATH)
    if result.returncode != 0:
        verification["status"] = "failed"
    write_json(state_path.parent / "route_nat_verification_latest.json", verification)
    append_jsonl(state_path.parent / "route_nat_verification_history.jsonl",
                 {"utc": utc_now(), **verification})
    return verification


def make_execution_plan(sample, attempt_number):
    template = read_json(TEMPLATE_PLAN)
    run = {
        "sample_id": sample["sample_id"],
        "planned_run_id": sample["sample_id"],
        "session_id": sample["session_id"],
        "split_group_id": sample["split_group_id"],
        "split": sample["split"],
        "class_id": sample["class_id"],
        "requested_url": sample["site_url"],
        "source_domain": "E",
        "network_scenario_id": "dynamic_no_handover",
        "planned_run_order": sample["planned_run_order"],
        "replicate": sample["replicate"],
        "fresh_browser_profile_required": True,
        "fresh_tor_process_and_circuit_required": True,
        "reuse_profile_circuit_or_target_tab": False,
        "state": "planned_not_collected",
    }
    template["plan_id"] = "v3-candidate-20261029-v5-{}-attempt-{:02d}".format(
        sample["sample_id"], attempt_number)
    template["plan_status"] = "frozen_precollection"
    template["attempt_number"] = attempt_number
    template["collection_started"] = False
    template["training_started"] = False
    template["scope"].update({"site_count": 5, "samples_per_site": 10,
                              "candidate_dataset": True,
                              "network_scenario_id": "dynamic_no_handover"})
    template["class_binding"] = {
        "class_id": sample["class_id"], "requested_url": sample["site_url"],
        "class_mapping_sha256": verify_cohort()["class_mapping_sha256"],
    }
    template["runs"] = [run]
    template["frozen_inputs"]["protocol_config"] = file_ref(CONFIG_PATH)
    template["frozen_inputs"]["browser_runtime_config"] = file_ref(BROWSER_CONFIG)
    template["frozen_inputs"]["browser_runtime_freeze"] = file_ref(BROWSER_FREEZE)
    template["frozen_inputs"]["browser_helper"] = file_ref(
        ROOT / "tools/tor_browser_site_smoke_20261029_v5.py")
    template["frozen_inputs"]["v3_collector"] = file_ref(collector.__file__)
    browser_config = collector.proxy_runtime.read_json(BROWSER_CONFIG)
    browser_assets = collector.runtime_asset_snapshot(
        browser_config, BROWSER_CONFIG, verify_image=False)
    template["browser_runtime_assets_contract"]["asset_hashes"] = {
        "browser_directory": browser_assets["browser_tree_sha256"],
        "expert_bundle": browser_assets["expert_bundle_tree_sha256"],
        "webtunnel_bridge_file": browser_assets["bridge_file_sha256"],
        "geckodriver": browser_assets["geckodriver_sha256"],
        "browser_helper_packages": browser_assets[
            "python_site_packages_tree_sha256"],
    }
    template["browser_runtime_assets_contract"]["frozen_by"] = file_ref(BROWSER_FREEZE)
    template["browser_runtime_assets_contract"]["runtime_variant_id"] = (
        browser_config.get("runtime_variant_id"))
    template["candidate_contract"] = {
        "cohort_plan_path": str(COHORT_PLAN.resolve()),
        "cohort_plan_sha256": sha256(COHORT_PLAN),
        "attempt_number": attempt_number,
        "runner_sha256": sha256(RUNNER_PATH),
        "independent_auditor_sha256": sha256(AUDITOR_PATH),
    }
    template["provenance_state"]["scientific_fidelity_verified"] = False
    template["not_in_scope"] = ["training during collection",
                                "scientific-fidelity claim",
                                "reusing earlier engineering pilot samples"]
    directory = OUT_DIR / "execution_plans"
    directory.mkdir(parents=True, exist_ok=True)
    plan_path = directory / (sample["sample_id"] + ".attempt{:02d}.json".format(
        attempt_number))
    if plan_path.exists():
        raise RuntimeError("refusing to overwrite an execution plan: " + str(plan_path))
    write_json(plan_path, template)
    freeze_path = Path(str(plan_path) + ".freeze.json")
    plan_audit = {
        "plan_sha256": sha256(plan_path),
        "plan_id": template["plan_id"],
        "cohort_plan_sha256": sha256(COHORT_PLAN),
        "manual_execution_ready": offline_execution_plan_audit(plan_path).get("passed") is True,
        "requires_fresh_proxy_preflight_per_attempt": True,
        "training_started": False,
    }
    write_json(Path(str(plan_path) + ".audit.json"), plan_audit)
    write_json(freeze_path, {"plan": file_ref(plan_path),
                             "audit": file_ref(Path(str(plan_path) + ".audit.json")),
                             "frozen_utc": utc_now()})
    if not plan_audit["manual_execution_ready"]:
        raise RuntimeError("execution-plan offline audit failed")
    return plan_path


def offline_execution_plan_audit(plan_path, v2_config_path=None):
    try:
        activate_browser_runtime()
        v2_config_path = Path(v2_config_path or BROWSER_CONFIG).resolve()
        if v2_config_path != BROWSER_CONFIG.resolve():
            raise RuntimeError("Browser/Tor runtime path differs from the frozen candidate runtime")
        plan = read_json(plan_path)
        cohort = verify_cohort()
        errors = []
        errors.extend(v3.validate_config(read_json(CONFIG_PATH)))
        collector.route_nat.validate_runtime_config(CONFIG_PATH)
        contract = plan.get("candidate_contract", {})
        if contract.get("cohort_plan_sha256") != sha256(COHORT_PLAN):
            errors.append("cohort plan hash differs")
        if contract.get("runner_sha256") != sha256(RUNNER_PATH):
            errors.append("runner source hash differs")
        if contract.get("independent_auditor_sha256") != sha256(AUDITOR_PATH):
            errors.append("independent auditor source hash differs")
        class_binding = plan.get("class_binding", {})
        planned_run = plan.get("runs", [{}])[0]
        sample = next((row for row in cohort["samples"]
                       if row.get("sample_id") == planned_run.get("sample_id")), None)
        if not sample:
            errors.append("sample is not in the frozen 50-row cohort")
        else:
            for key, value in (("class_id", sample["class_id"]),
                               ("requested_url", sample["site_url"])):
                if class_binding.get(key) != value or planned_run.get(
                        key if key != "requested_url" else "requested_url") != value:
                    errors.append("execution plan sample identity mismatch: " + key)
            if planned_run.get("sample_id") != sample["sample_id"]:
                errors.append("execution plan sample id mismatch")
            if planned_run.get("split") != sample["split"]:
                errors.append("execution plan split mismatch")
            if planned_run.get("session_id") != sample["session_id"]:
                errors.append("execution plan session mismatch")
        if len(plan.get("runs", [])) != 1:
            errors.append("execution plan must isolate exactly one browser session")
        if plan.get("training_started") is not False:
            errors.append("training may not run inside a collection plan")
        if plan.get("browser_capture_window_contract", {}).get(
                "capture_window_seconds") != 180:
            errors.append("execution plan does not preserve the 180-second capture")
        attempt_audit_path = Path(str(plan_path) + ".audit.json")
        attempt_freeze_path = Path(str(plan_path) + ".freeze.json")
        if attempt_freeze_path.is_file():
            attempt_audit = read_json(attempt_audit_path)
            attempt_freeze = read_json(attempt_freeze_path)
            if (attempt_audit.get("manual_execution_ready") is not True
                    or attempt_audit.get("plan_sha256") != sha256(plan_path)
                    or attempt_freeze.get("plan", {}).get("sha256") != sha256(plan_path)
                    or attempt_freeze.get("audit", {}).get("sha256")
                    != sha256(attempt_audit_path)):
                errors.append("execution plan freeze/audit binding changed")
        config_ref = plan.get("frozen_inputs", {}).get("protocol_config", {})
        if (config_ref.get("path") != str(CONFIG_PATH.relative_to(ROOT))
                or config_ref.get("sha256") != sha256(CONFIG_PATH)):
            errors.append("execution plan runtime config is not frozen to 20261029_v5")
        # Re-check Browser/Tor files and runtime image using the old verified
        # asset contract; the live three-connect probe still happens per run.
        config = collector.proxy_runtime.read_json(v2_config_path)
        assets = collector.runtime_asset_snapshot(
            config, v2_config_path, verify_image=False)
        expected = plan.get("browser_runtime_assets_contract", {}).get(
            "asset_hashes", {})
        actual = {
            "browser_directory": assets.get("browser_tree_sha256"),
            "expert_bundle": assets.get("expert_bundle_tree_sha256"),
            "webtunnel_bridge_file": assets.get("bridge_file_sha256"),
            "geckodriver": assets.get("geckodriver_sha256"),
            "browser_helper_packages": assets.get("python_site_packages_tree_sha256"),
        }
        if expected != actual:
            errors.append("Browser/Tor assets differ from the frozen runtime")
        return {"passed": not errors, "errors": errors,
                "plan_id": plan.get("plan_id"), "training_started": False,
                "plan": {"manual_execution_ready": not errors,
                         "plan_id": plan.get("plan_id")},
                "live_preflight_performed": False}
    except Exception as exc:
        return {"passed": False, "errors": [str(exc)],
                "plan": {"manual_execution_ready": False},
                "training_started": False, "live_preflight_performed": False}


def write_candidate_sample(plan, planned_run, run_dir, network_summary,
                           source_audit_path):
    if network_summary.get("status") != "passed":
        errors = network_summary.get("errors") or ["network runtime did not pass"]
        reason = "; ".join(str(item) for item in errors)
        browser = network_summary.get("browser_tor") or {}
        if "initial GRE/NAT" in reason:
            stage = "initial_route_nat_verification"
        elif (browser.get("passed") is not True
              or browser.get("bootstrap_status")
              or "bootstrap" in reason.lower()):
            stage = "tor_bootstrap_or_browser_check"
        else:
            stage = "network_runtime"
        write_json(Path(run_dir) / "failure_stage.json",
                   {"failure_stage": stage, "reason": reason})
        raise RuntimeError(reason)
    browser = network_summary.get("browser_tor") or {}
    capture = Path(run_dir) / "captures/gs26-wf-gre0.pcap"
    helper_path = Path(browser.get("helper_summary_path", ""))
    # Preserve the Tor/bootstrap/page failure as the primary record. Do not
    # invoke sample construction when it could only report a secondary missing
    # capture/PCAP error.
    if browser.get("passed") is not True or not helper_path.is_file() or not capture.is_file():
        network_summary["dataset_sample_construction_skipped"] = {
            "reason": "Browser/Tor helper or wf-gre0 PCAP did not pass its prerequisite",
            "failure_stage": browser.get("failure_stage") or
                             browser.get("bootstrap_status") or "browser_tor_or_capture",
            "primary_browser_summary": str(helper_path) if helper_path.is_file() else None,
        }
        write_json(Path(run_dir) / "failure_stage.json",
                   network_summary["dataset_sample_construction_skipped"])
        raise RuntimeError("sample construction skipped; inspect the primary Browser/Tor failure stage")
    sample = BASE_SAMPLE_FROM_SUMMARY(
        plan, planned_run, run_dir, network_summary, source_audit_path)
    sample["split"] = planned_run["split"]
    sample["split_group_id"] = planned_run["split_group_id"]
    sample["pilot_only"] = False
    sample["training_eligible"] = False
    sample["candidate_cohort_plan_sha256"] = sha256(COHORT_PLAN)
    if ACTIVE_EXECUTION_PLAN is None:
        raise RuntimeError("active execution plan path was not bound")
    sample["candidate_execution_plan_sha256"] = sha256(ACTIVE_EXECUTION_PLAN)
    sample["planned_run_order"] = planned_run["planned_run_order"]
    sample["replicate"] = planned_run["replicate"]
    sample_path = Path(run_dir) / "sample_manifest.json"
    write_json(sample_path, sample)
    index_path = Path(run_dir) / "sample_artifacts.json"
    index = read_json(index_path)
    manifest_rows = [row for row in index.get("artifacts", [])
                     if row.get("kind") == "sample_manifest"]
    if len(manifest_rows) != 1:
        raise RuntimeError("sample artifact index does not have one sample manifest")
    manifest_rows[0]["sha256"] = sha256(sample_path)
    write_json(index_path, index)
    return sample


def accepted_rows():
    return jsonl_rows(ACCEPTED_LEDGER)


def get_next_sample(cohort):
    accepted = accepted_rows()
    expected_order = len(accepted) + 1
    if expected_order > len(cohort["samples"]):
        return None
    for row in accepted:
        if not row.get("audit_passed"):
            raise RuntimeError("accepted ledger contains an unaudited sample")
    return cohort["samples"][expected_order - 1]


def sample_attempt_count(sample_id):
    rows = [row for row in jsonl_rows(ATTEMPT_LEDGER)
            if row.get("sample_id") == sample_id and row.get("event") == "finished"]
    recovery_path = OUT_DIR / "protocol_state.json"
    recovery = read_json(recovery_path) if recovery_path.is_file() else {}
    cohort = read_json(COHORT_PLAN)
    planned = next(row for row in cohort["samples"] if row["sample_id"] == sample_id)
    inherited = recovery.get("inherited_attempts_by_order", {}).get(
        str(planned["planned_run_order"]), 0)
    return len(rows) + int(inherited)


def run_one(sample):
    global ACTIVE_EXECUTION_PLAN
    configure_collector()
    cohort = verify_cohort()
    if collector.active_v3_collectors():
        raise RuntimeError("another V3 collector is active; refusing a duplicate collection")
    attempt_number = sample_attempt_count(sample["sample_id"]) + 1
    if attempt_number > 2:
        raise RuntimeError("two attempts already recorded for this sample; stop for review")
    previous_attempts = [row for row in jsonl_rows(ATTEMPT_LEDGER)
                         if row.get("sample_id") == sample["sample_id"]
                         and row.get("event") == "finished"]
    if previous_attempts:
        if previous_attempts[-1].get("sample_status") == "passed":
            raise RuntimeError("collector passed but independent audit/acceptance failed; do not retry")
    execution_path = make_execution_plan(sample, attempt_number)
    ACTIVE_EXECUTION_PLAN = execution_path
    start_monotonic = time.monotonic()
    start_utc = utc_now()
    append_jsonl(ATTEMPT_LEDGER, {
        "event": "started", "utc": start_utc, "sample_id": sample["sample_id"],
        "attempt_number": attempt_number,
        "planned_run_order": sample["planned_run_order"],
        "execution_plan": str(execution_path), "plan_sha256": sha256(execution_path),
        "stage": "collector_live_preflight_and_v3_run",
    })
    previous_alarm, alarm_state = start_attempt_watchdog()
    try:
        result = collector.run_one(execution_path, 1, BROWSER_CONFIG)
        if result.get("sample_status") != "passed" or result.get("cleanup_verified") is not True:
            raise RuntimeError("collector sample gates or cleanup failed")
        audit = sample_auditor.audit_sample(
            result["run_dir"], sample["sample_id"], COHORT_PLAN, execution_path,
            COLLECTOR_ATTEMPT_LEDGER, ACCEPTED_LEDGER)
        audit_path = OUT_DIR / "audits" / (sample["sample_id"] + ".json")
        if audit_path.exists():
            raise RuntimeError("refusing to overwrite an independent audit")
        write_json(audit_path, audit)
        if audit.get("passed") is not True or len(audit.get("checks", {})) != 17:
            raise RuntimeError("independent 17-check sample audit failed")
        acceptance = {
            "sample_id": sample["sample_id"],
            "planned_run_order": sample["planned_run_order"],
            "class_id": sample["class_id"], "split": sample["split"],
            "session_id": sample["session_id"],
            "run_dir": result["run_dir"],
            "execution_plan": str(execution_path),
            "execution_plan_sha256": sha256(execution_path),
            "audit_path": str(audit_path), "audit_sha256": sha256(audit_path),
            "audit_passed": True, "accepted_utc": utc_now(),
            "training_eligible": False,
        }
        append_jsonl(ACCEPTED_LEDGER, acceptance)
        append_jsonl(OUTCOME_LEDGER, {"event": "accepted", "utc": utc_now(), **acceptance})
        append_jsonl(ATTEMPT_LEDGER, {
            "event": "finished", "utc": utc_now(), "sample_id": sample["sample_id"],
            "attempt_number": attempt_number, "sample_status": "passed",
            "failure_stage": None, "run_dir": result["run_dir"],
            "audit_passed": True,
            "elapsed_seconds": round(time.monotonic() - start_monotonic, 3),
        })
        if len(accepted_rows()) == 2:
            append_jsonl(OUTCOME_LEDGER, {
                "event": "bootstrap_gate_passed", "utc": utc_now(),
                "accepted_count": 2,
                "meaning": "two independently audited Browser/Tor website sessions",
            })
        return acceptance
    except Exception as exc:
        collector_rows = [row for row in jsonl_rows(COLLECTOR_ATTEMPT_LEDGER)
                          if row.get("sample_id") == sample["sample_id"]
                          and row.get("event") == "finished"]
        last = collector_rows[-1] if collector_rows else {}
        stage = ("attempt_cleanup_deadline" if alarm_state["hard_deadline_reached"]
                 else "attempt_work_deadline" if alarm_state["cleanup_grace_started"]
                 else "collector_live_preflight_or_topology_setup")
        detail = str(exc)
        summary = {}
        if last.get("network_run_id"):
            summary_path = OUT_DIR / "collection" / last["network_run_id"] / "summary.json"
            if summary_path.is_file():
                summary = read_json(summary_path)
                browser = summary.get("browser_tor", {})
                if browser and browser.get("passed") is not True:
                    stage = "tor_bootstrap_or_browser_page_gate"
                    detail = browser.get("failure_reason") or detail
                elif not summary.get("captures"):
                    stage = "capture_start_or_network_run"
                else:
                    stage = "sample_gate_or_independent_audit"
                failure_path = summary_path.parent / "failure_stage.json"
                if failure_path.is_file():
                    failure = read_json(failure_path)
                    stage = failure.get("failure_stage", stage)
                    detail = failure.get("reason", detail)
        append_jsonl(ATTEMPT_LEDGER, {
            "event": "finished", "utc": utc_now(), "sample_id": sample["sample_id"],
            "attempt_number": attempt_number, "sample_status": "failed",
            "failure_stage": stage, "error": detail,
            "network_run_id": last.get("network_run_id"),
            "cleanup_verified": last.get("cleanup_verified"),
            "execution_plan": str(execution_path),
            "elapsed_seconds": round(time.monotonic() - start_monotonic, 3),
        })
        append_jsonl(OUTCOME_LEDGER, {
            "event": "failed", "utc": utc_now(), "sample_id": sample["sample_id"],
            "attempt_number": attempt_number, "failure_stage": stage,
            "error": detail, "training_started": False,
            "watchdog_enforced": isinstance(exc, AttemptDeadlineExceeded),
            "cleanup_grace_started": alarm_state["cleanup_grace_started"],
            "hard_deadline_reached": alarm_state["hard_deadline_reached"],
        })
        raise
    finally:
        stop_attempt_watchdog(previous_alarm)
        ACTIVE_EXECUTION_PLAN = None


def collect_next():
    cohort = verify_cohort()
    sample = get_next_sample(cohort)
    if sample is None:
        return {"status": "complete", "accepted_count": len(accepted_rows())}
    now = datetime.datetime.now(datetime.timezone.utc)
    if now >= HARD_STOP_UTC:
        raise RuntimeError("hard collection stop reached: 2026-10-29 08:00 Asia/Shanghai")
    finished = [row for row in jsonl_rows(ATTEMPT_LEDGER)
                if row.get("event") == "finished"]
    spent = sum(float(row.get("elapsed_seconds", 0.0)) for row in finished)
    recovery_path = OUT_DIR / "protocol_state.json"
    recovery = read_json(recovery_path) if recovery_path.is_file() else {}
    spent += float(recovery.get("prior_online_elapsed_seconds", 0.0))
    budget = 14 * 60 * 60
    diagnostics_elapsed = float(recovery.get("diagnostic_elapsed_seconds", 0.0))
    spent += diagnostics_elapsed
    if spent + 25 * 60 > budget:
        raise RuntimeError("14-hour online collection budget is exhausted or below one attempt")
    if sample["planned_run_order"] <= 2 and spent + 25 * 60 > 2 * 60 * 60:
        raise RuntimeError("two-hour bootstrap gate expired before two audited sessions")
    if now + datetime.timedelta(minutes=25) > NO_START_UTC:
        raise RuntimeError("no new 25-minute collection attempts may start after 07:35 Asia/Shanghai")
    if sample["planned_run_order"] <= 2 and recovery.get("startup_gate_started_utc"):
        timestamp = recovery["startup_gate_started_utc"].replace("+00:00", "+0000")
        time_format = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in timestamp else "%Y-%m-%dT%H:%M:%S%z"
        start = datetime.datetime.strptime(timestamp, time_format)
        if now + datetime.timedelta(minutes=25) > start + datetime.timedelta(hours=2):
            raise RuntimeError("original two-hour startup wall-clock budget is exhausted")
    return run_one(sample)


def collect_wave(through_order):
    if through_order not in (2, 15, 50):
        raise ValueError("wave boundary must be 2, 15, or 50")
    if len(accepted_rows()) > through_order:
        raise RuntimeError("accepted prefix has passed the requested wave boundary")
    if through_order >= 15 and len(accepted_rows()) < 2:
        raise RuntimeError("first pass the two-sample startup gate")
    if through_order == 50 and len(accepted_rows()) < 15:
        raise RuntimeError("first complete and review the five-class x three-sample gate")
    last = None
    while len(accepted_rows()) < through_order:
        last = collect_next()
    return {"status": "wave_complete", "accepted_count": len(accepted_rows()),
            "through_order": through_order, "last_acceptance": last}


def status():
    cohort = verify_cohort()
    accepted = accepted_rows()
    attempts = jsonl_rows(ATTEMPT_LEDGER)
    counts = {str(class_id): sum(1 for row in accepted
                                 if row.get("class_id") == str(class_id))
              for class_id in range(5)}
    return {
        "plan_id": cohort["plan_id"],
        "accepted_count": len(accepted),
        "accepted_by_class": counts,
        "failed_attempts": [row for row in attempts
                            if row.get("event") == "finished"
                            and row.get("sample_status") == "failed"],
        "next_sample": get_next_sample(cohort),
        "collection_started": bool(attempts),
        "training_started": False,
        "hard_stop_utc": HARD_STOP_UTC.isoformat(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("freeze", help="create and freeze the 50-sample plan after bridge qualification")
    sub.add_parser("audit-plan", help="verify the frozen 50-sample plan")
    sub.add_parser("status", help="show accepted samples and the next sample")
    sub.add_parser("collect-next", help="attempt the next sample once; rerun after review for its sole retry")
    wave = sub.add_parser("collect-wave", help="collect serially through a frozen gate; stop on any failed sample")
    wave.add_argument("--through-order", type=int, choices=(2, 15, 50), required=True)
    args = parser.parse_args(argv)
    try:
        lock_handle = None
        if args.command == "freeze":
            result = freeze_plan()
        elif args.command == "audit-plan":
            result = audit_plan(verify_cohort())
        elif args.command == "status":
            result = status()
        elif args.command == "collect-next":
            lock_handle = acquire_task_lock()
            result = collect_next()
        elif args.command == "collect-wave":
            lock_handle = acquire_task_lock()
            result = collect_wave(args.through_order)
        else:
            parser.error("a subcommand is required")
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True,
                         default=str))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "stopped", "reason": str(exc),
                          "collection_started": any(row.get("network_run_id")
                              for row in jsonl_rows(ATTEMPT_LEDGER)),
                          "training_started": False}, indent=2,
                         ensure_ascii=False))
        return 3
    finally:
        if "lock_handle" in locals() and lock_handle is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()


def acquire_task_lock():
    TASK_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = TASK_LOCK.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError("another 20261029_v5 dataset runner is already active")
    return handle


if __name__ == "__main__":
    sys.exit(main())
