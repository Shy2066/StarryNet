#!/usr/bin/env python3
"""Freeze and audit a fresh class-2 V3 plan with circuit-status snapshots.

This plan is intentionally distinct from the final candidate dataset manifest:
it contains no collected samples and cannot admit training data.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import satellite_wf_v3_dynamic_fixed_object as dynamic_window

DEFAULT_CONFIG = Path("protocols/satellite_wf_v3/runtime_config.json")
DEFAULT_SOURCE_AUDIT = Path(
    "artifacts/reports/satellite_wf_v3_20261021/source_audit.json")
DEFAULT_NETWORK_SUMMARY = Path(
    "artifacts/reports/satellite_wf_v3_20261021/dynamic_network_acceptance/"
    "dynamic_acceptance_summary.json")
DEFAULT_OUTPUT = Path(
    "artifacts/reports/satellite_wf_v3_20261021/"
    "matched_class_x3_readiness_20261022/pilot_plan_class2_x3_circuit_snapshot_py36compat_20261026.json")
DEFAULT_ATTEMPT_CORRECTIONS = Path(
    "artifacts/reports/satellite_wf_v3_20261021/"
    "matched_class_x3_readiness_20261022/attempt_ledger_corrections.jsonl")
DEFAULT_BROWSER_RUNTIME_CONFIG = Path(
    "artifacts/e_browser_tor_pilot_v2_2_runtime_rebase_20261026/protocol/runtime_config.json")
DEFAULT_BROWSER_RUNTIME_FREEZE = Path(
    "artifacts/e_browser_tor_pilot_v2_2_runtime_rebase_20261026/protocol/freeze_hashes.json")
PROTOCOL_ID = "starrynet-browser-tor-route-nat-v3"
SAMPLE_COUNT = 3
START_INDEX = 4
FINAL_SAMPLE_FIELDS = [
    "sample_id", "class_id", "site_url", "source_domain", "session_id",
    "split_group_id", "split", "protocol_config_sha256",
    "class_mapping_sha256", "network_scenario_id", "page_identity",
    "tor_path", "network_path", "time_boundaries", "browser_tor",
    "handover", "gates",
]
FINAL_SAMPLE_GATES = [
    "target_identity_verified", "target_page_success_verified",
    "access_challenge_absent", "tor_target_stream_verified",
    "target_tor_circuit_three_hops_verified", "route_nat_verified",
    "bidirectional_satellite_route_verified", "capture_interface_verified",
    "capture_loss_zero", "offloads_disabled_verified",
    "pcap_trace_audit_passed", "topology_events_recorded",
    "actual_tor_path_recorded", "capture_window_order_verified",
    "clock_pair_verified", "cleanup_verified",
]
FINAL_ARTIFACT_KINDS = [
    "trace", "pcap", "sample_manifest", "packet_audit",
    "topology_events", "route_events",
]


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def repo_path(path):
    path = Path(path).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def evidence_ref(path):
    path = Path(path).resolve()
    return {"path": repo_path(path), "sha256": sha256_file(path)}


def build_plan(class_id, proxy_readiness_path, config_path=DEFAULT_CONFIG,
               source_audit_path=DEFAULT_SOURCE_AUDIT,
               network_summary_path=DEFAULT_NETWORK_SUMMARY):
    config_path = (ROOT / config_path).resolve()
    source_audit_path = (ROOT / source_audit_path).resolve()
    network_summary_path = (ROOT / network_summary_path).resolve()
    proxy_readiness_path = Path(proxy_readiness_path).resolve()
    browser_runtime_config_path = (ROOT / DEFAULT_BROWSER_RUNTIME_CONFIG).resolve()
    browser_runtime_freeze_path = (ROOT / DEFAULT_BROWSER_RUNTIME_FREEZE).resolve()
    config = read_json(config_path)
    source_audit = read_json(source_audit_path)
    network_summary = read_json(network_summary_path)
    proxy_readiness = read_json(proxy_readiness_path)
    class_id = str(class_id)
    class_map = source_audit.get("common_class_map", {})
    if class_id not in source_audit.get("common_class_ids", []):
        raise ValueError("class_id is not in the audited common-class set")
    if class_id not in class_map:
        raise ValueError("class_id has no audited URL mapping")
    if config.get("protocol_id") != PROTOCOL_ID:
        raise ValueError("runtime config protocol_id is not the V3 protocol")
    if network_summary.get("protocol_id") != PROTOCOL_ID:
        raise ValueError("network acceptance summary is not for the V3 protocol")
    if network_summary.get("all_passed") is not True:
        raise ValueError("dynamic V3 GRE/NAT acceptance has not passed")
    accepted_source_statuses = config.get("training", {}).get(
        "accepted_source_audit_statuses", [])
    if source_audit.get("status") not in accepted_source_statuses:
        raise ValueError("source audit status is not accepted by the frozen V3 config")
    if source_audit.get("errors"):
        raise ValueError("source audit contains errors")
    attestation_path = Path(source_audit.get("user_attestation", {}).get("path", ""))
    attestation = read_json(attestation_path)
    if (source_audit.get("user_attestation", {}).get("sha256")
            != sha256_file(attestation_path)
            or attestation.get("confirmed_by_user") is not True):
        raise ValueError("source audit user attestation is missing, changed, or invalid")
    current_config_hash = sha256_file(config_path)

    network_runs = []
    for result in network_summary.get("results", []):
        summary_path = Path(result.get("summary", ""))
        if not summary_path.is_absolute():
            summary_path = ROOT / summary_path
        run_summary = read_json(summary_path)
        if run_summary.get("runtime_config_sha256") != current_config_hash:
            raise ValueError("dynamic network run used a different runtime config: "
                             + str(summary_path))
        network_runs.append({
            "scenario_id": result.get("scenario_id"),
            "run_id": result.get("run_id"),
            "status": result.get("status"),
            "cleanup_verified": result.get("cleanup_verified"),
            "summary": evidence_ref(summary_path),
        })
    for scenario_id in ("dynamic_no_handover", "dynamic_handover"):
        scenario_runs = [row for row in network_runs
                         if row["scenario_id"] == scenario_id]
        if not scenario_runs or not any(
                row["status"] == "passed" and row["cleanup_verified"] is True
                for row in scenario_runs):
            raise ValueError("a passed and cleaned {} network run is required".format(
                scenario_id))

    proxy_sequence = proxy_readiness.get("https_connect_probe", {}).get(
        "sequence", [])
    proxy_passed = (
        proxy_readiness.get("runtime_doctor", {}).get("passed") is True
        and len(proxy_sequence) >= 3
        and all(item.get("https_connect_passed") is True
                and item.get("listener_reachable") is True
                and item.get("target_http_status") == 200
                for item in proxy_sequence[:3]))
    if not proxy_passed:
        raise ValueError("proxy readiness evidence must contain a passed doctor and 3 consecutive HTTP 200 CONNECT probes")
    if (proxy_readiness.get("runtime_doctor", {}).get("tmux_starrynet") is not True
            or proxy_readiness.get("runtime_doctor", {}).get("docker", {}).get(
                "available") is not True
            or proxy_readiness.get("runtime_doctor", {}).get(
                "starrynet_resources_clean") is not True
            or proxy_readiness.get("runtime_doctor", {}).get(
                "active_collection_processes") != []):
        raise ValueError("runtime doctor must prove tmux, Docker, clean resources, and no active collection")

    runs = []
    for index in range(START_INDEX, START_INDEX + SAMPLE_COUNT):
        suffix = "r{:03d}".format(index)
        runs.append({
            "sample_id": "v3-class-{}-{}".format(class_id, suffix),
            "planned_run_id": "v3-class-{}-{}".format(class_id, suffix),
            "session_id": "v3-class-{}-session-{:03d}".format(class_id, index),
            "class_id": class_id,
            "requested_url": class_map[class_id],
            "source_domain": "E",
            "network_scenario_id": "dynamic_no_handover",
            "fresh_browser_profile_required": True,
            "fresh_tor_process_and_circuit_required": True,
            "reuse_profile_circuit_or_target_tab": False,
            "state": "planned_not_collected",
        })

    caveats = source_audit.get("unresolved_semantics", [])
    collector_sources = {
        "v3_collector": ROOT / "tools/satellite_wf_v3_browser_tor_collector_circuit_snapshot_py36compat_20261026.py",
        "v3_dynamic_network_controller": ROOT / "tools/satellite_wf_v3_dynamic_fixed_object.py",
        "v3_route_nat": ROOT / "tools/satellite_wf_v3_route_nat.py",
        "v3_browser_helper": ROOT / "tools/tor_browser_site_smoke_circuit_snapshot_20261026.py",
        "v2_host_proxy_relay": ROOT / "tools/tor_browser_starrynet_smoke_v2.py",
        "v3_trace_extractor": ROOT / "tools/satellite_wf_v3_trace_extractor.py",
    }
    collector_integrated = all(path.is_file() for path in collector_sources.values())
    collector_integrated = collector_integrated and all(
        marker in (ROOT / "tools/satellite_wf_v3_dynamic_fixed_object.py").read_text(
            encoding="utf-8") for marker in
        ("browser_session.prepare", "browser_session.finish", "route_nat.install("))
    runtime_status = ("collector_integrated_offline_only" if collector_integrated
                      else "collector_not_connected")
    browser_freeze = read_json(browser_runtime_freeze_path)
    runtime_config_hash = sha256_file(browser_runtime_config_path)
    if browser_freeze.get("hashes", {}).get("runtime_config", {}).get(
            "sha256") != runtime_config_hash:
        raise ValueError("V2 Browser/Tor runtime config differs from its frozen runtime")
    if browser_freeze.get("helper_image_id") != read_json(
            browser_runtime_config_path).get("helper_image_id"):
        raise ValueError("V2 Browser/Tor helper image ID differs from its frozen runtime")
    asset_keys = ("browser_directory", "expert_bundle", "webtunnel_bridge_file",
                  "geckodriver", "browser_helper_packages")
    frozen_runtime_assets = {
        key: browser_freeze.get("hashes", {}).get(key, {}).get("sha256")
        for key in asset_keys}
    collector_connected = collector_integrated
    return {
        "schema_version": 1,
        "plan_id": "v3-browser-tor-class-{}-x3-circuit-snapshot-py36compat-20261026".format(class_id),
        "runtime_variant_id": "browser-tor-circuit-snapshot-py36compat-20261026",
        "plan_type": "precollection_plan_not_candidate_dataset_manifest",
        "plan_status": "frozen_precollection",
        "collection_started": False,
        "training_started": False,
        "attempt_classification_review": evidence_ref(DEFAULT_ATTEMPT_CORRECTIONS),
        "protocol_id": PROTOCOL_ID,
        "scope": {
            "site_count": 1,
            "samples_per_site": SAMPLE_COUNT,
            "max_parallel_collectors": 1,
            "source_domain": "E",
            "network_scenario_id": "dynamic_no_handover",
            "capture_interface": config["network"]["capture_interface"],
            "egress_interface": config["network"]["egress_interface"],
            "candidate_dataset": False,
            "training_eligible": False,
        },
        "class_binding": {
            "class_id": class_id,
            "requested_url": class_map[class_id],
            "class_mapping_sha256": source_audit.get("class_mapping_sha256"),
            "binding_status": source_audit.get("status"),
            "final_url_policy": "record_observed_final_and_canonical_urls; do not assume redirect",
        },
        "independence_contract": {
            "sequential_only": True,
            "distinct_session_per_run": True,
            "fresh_browser_profile_per_run": True,
            "fresh_tor_process_and_circuit_per_run": True,
            "clear_cookies_and_site_storage_before_each_run": True,
            "reuse_profile_circuit_or_target_tab": False,
        },
        "target_tor_circuit_path_evidence_contract": {
            "required_source": "controller_get_circuits_snapshot_after_capture",
            "must_match_successful_target_stream_circuit_id": True,
            "required_status": "BUILT",
            "required_hop_count": 3,
            "required_unique_fingerprints": 3,
            "preserve_circ_event_history_as_supplemental_evidence": True,
        },
        "runs": runs,
        "frozen_inputs": {
            "protocol_config": evidence_ref(config_path),
            "source_audit": evidence_ref(source_audit_path),
            "dataset_identity_attestation": evidence_ref(
                Path(source_audit["user_attestation"]["path"])),
            "dynamic_network_acceptance": evidence_ref(network_summary_path),
            "dynamic_network_runs": network_runs,
            "proxy_readiness_snapshot": evidence_ref(proxy_readiness_path),
            "browser_helper": evidence_ref(
                ROOT / "tools" / "tor_browser_site_smoke_circuit_snapshot_20261026.py"),
            "p0_topology_audit": evidence_ref(
                ROOT / "tools" / "p0_smoke.py"),
            "v3_collector": evidence_ref(collector_sources["v3_collector"]),
            "v3_dynamic_network_controller": evidence_ref(
                collector_sources["v3_dynamic_network_controller"]),
            "v3_route_nat": evidence_ref(collector_sources["v3_route_nat"]),
            "v2_host_proxy_relay": evidence_ref(
                collector_sources["v2_host_proxy_relay"]),
            "trace_extractor": evidence_ref(
                ROOT / "tools" / "satellite_wf_v3_trace_extractor.py"),
            "browser_runtime_config": evidence_ref(browser_runtime_config_path),
            "browser_runtime_freeze": evidence_ref(browser_runtime_freeze_path),
            "runtime_rebase_plan_builder": evidence_ref(Path(__file__)),
            **{
                "starrynet_source_file_{:03d}".format(index): evidence_ref(source_path)
                for index, source_path in enumerate(
                    sorted((ROOT / "starrynet").rglob("*.py")))
            },
        },
        "browser_runtime_assets_contract": {
            "runtime_variant_id": "browser-tor-circuit-snapshot-py36compat-20261026",
            "frozen_by": evidence_ref(browser_runtime_freeze_path),
            "asset_hashes": frozen_runtime_assets,
            "helper_image_id": browser_freeze.get("helper_image_id"),
        },
        "browser_capture_window_contract": {
            "capture_window_seconds": dynamic_window.BROWSER_CAPTURE_SECONDS,
            "page_load_timeout_seconds": dynamic_window.BROWSER_PAGE_LOAD_TIMEOUT_SECONDS,
            "page_content_timeout_seconds": dynamic_window.BROWSER_PAGE_CONTENT_TIMEOUT_SECONDS,
            "capture_setup_allowance_seconds": dynamic_window.BROWSER_CAPTURE_SETUP_SECONDS,
            "capture_settle_seconds": dynamic_window.BROWSER_CAPTURE_SETTLE_SECONDS,
            "pre_handover_safety_seconds": dynamic_window.BROWSER_CAPTURE_SAFETY_SECONDS,
            "topology_duration_seconds": dynamic_window.BROWSER_TOPOLOGY_SECONDS,
            "simulation_start_utc": dynamic_window.BROWSER_SIMULATION_START_UTC,
            "expected_first_topology_event_seconds": (
                dynamic_window.BROWSER_EXPECTED_FIRST_TOPOLOGY_EVENT_SECONDS),
            "capture_window_logical_seconds": [67, 264],
            "topology_event_window": "capture ends before first topology event",
        },
        "provenance_state": {
            "source_audit_status": source_audit.get("status"),
            "source_semantic_caveat_count": len(caveats),
            "source_semantic_caveats": caveats,
            "scientific_fidelity_verified": False,
            "training_admission_inferred_from_this_plan": False,
            "prior_r004_attempt_reclassified_as_infrastructure": True,
            "prior_r004_attempt_id": "20261026T211721_964015Z",
        },
        "collector_gate": {
            "runtime_status": runtime_status,
            "connected": collector_connected,
            "implemented_offline": collector_integrated,
            "live_sample_verified": False,
            "v3_collector_path": evidence_ref(collector_sources["v3_collector"]),
            "required_capture_interface": "wf-gre0",
            "current_blocker": (None if collector_connected else
                                "V3 Browser/Tor collector source integration is incomplete"),
        },
        "readiness_snapshot": {
            "runtime_doctor_passed": proxy_readiness["runtime_doctor"]["passed"],
            "consecutive_https_connect_count": len(proxy_sequence[:3]),
            "consecutive_https_connect_all_http_200": proxy_passed,
            "requires_live_recheck_before_any_collection": True,
            "v2_2_wrapper_doctor_status": proxy_readiness.get(
                "v2_2_wrapper_doctor", {}).get("status"),
        },
        "acceptance_gates": [
            "V3 collector is integrated with the frozen runtime config and uses wf-gre0",
            "target site identity and observed final canonical URL are audited without access challenge",
            "target Tor stream succeeds on its recorded three-hop circuit",
            "GS26-to-GS27 and return route remain on the satellite path through GRE/NAT",
            "capture and egress interfaces match wf-gre0 and B27-default",
            "capture window is monotonic-clock bracketed and kernel drops are zero",
            "offloads are disabled and verified on wf-gre0",
            "raw PCAP, raw trace, topology events, route events, packet audit, and sample manifest are hashed",
            "cleanup is verified after each independent run",
        ],
        "final_candidate_manifest_contract": {
            "required_sample_fields": FINAL_SAMPLE_FIELDS,
            "required_true_sample_gates": FINAL_SAMPLE_GATES,
            "required_hashed_artifact_kinds": FINAL_ARTIFACT_KINDS,
            "required_splits": ["train", "validation", "test"],
            "session_group_must_not_cross_splits": True,
            "minimum_common_classes_for_training_admission": 5,
            "this_one_class_pilot_is_final_candidate_data": False,
        },
        "stop_conditions": [
            "collector is disconnected or capture interface differs from wf-gre0",
            "any of the 3 consecutive real HTTPS CONNECT probes fails or is not HTTP 200",
            "route bypass, missing bidirectional satellite route, or unexpected handover in the selected scenario",
            "Tor stream or page gate fails, challenge/captcha appears, or final identity is unresolved",
            "kernel capture drops are nonzero, timing order is invalid, artifacts fail hash audit, or cleanup fails",
        ],
        "not_in_scope": [
            "starting StarryNet topology or Browser/Tor collection during readiness",
            "training or declaring scientific fidelity",
            "expanding beyond this one matched class x 3 runs",
            "counting V1/V2 samples as V3 samples",
        ],
    }


def _resolve_ref(reference):
    path = Path(reference.get("path", ""))
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def audit_plan(manifest_path):
    manifest_path = Path(manifest_path).resolve()
    plan = read_json(manifest_path)
    errors = []
    if str(plan.get("plan_status", "")).startswith("stopped_"):
        errors.append("pilot plan is stopped after an acceptance gate failure")
    for required_ref in ("protocol_config", "source_audit",
                         "dataset_identity_attestation",
                         "dynamic_network_acceptance",
                         "proxy_readiness_snapshot", "browser_helper",
                         "p0_topology_audit",
                         "v3_collector", "v3_dynamic_network_controller",
                         "v3_route_nat", "v2_host_proxy_relay",
                         "trace_extractor", "browser_runtime_config",
                         "browser_runtime_freeze"):
        if required_ref not in plan.get("frozen_inputs", {}):
            errors.append("frozen input reference is missing: " + required_ref)
    for label, ref in plan.get("frozen_inputs", {}).items():
        if label == "dynamic_network_runs":
            for item in ref:
                path = _resolve_ref(item.get("summary", {}))
                expected = item.get("summary", {}).get("sha256")
                if not path.is_file() or sha256_file(path) != expected:
                    errors.append("dynamic network run summary hash mismatch: " + str(path))
            continue
        path = _resolve_ref(ref)
        expected = ref.get("sha256")
        if not path.is_file():
            errors.append("frozen input is missing: " + str(path))
        elif sha256_file(path) != expected:
            errors.append("frozen input hash mismatch: " + str(path))

    classification_review = plan.get("attempt_classification_review")
    if classification_review:
        review_path = _resolve_ref(classification_review)
        expected_review_hash = classification_review.get("sha256")
        if not review_path.is_file():
            errors.append("attempt classification review is missing: " + str(review_path))
        elif sha256_file(review_path) != expected_review_hash:
            errors.append("attempt classification review hash mismatch: " + str(review_path))

    runtime_freeze_path = _resolve_ref(
        plan.get("frozen_inputs", {}).get("browser_runtime_freeze", {}))
    if runtime_freeze_path.is_file():
        runtime_freeze = read_json(runtime_freeze_path)
        frozen_assets = plan.get("browser_runtime_assets_contract", {})
        required_asset_keys = ("browser_directory", "expert_bundle",
                               "webtunnel_bridge_file", "geckodriver",
                               "browser_helper_packages")
        actual_asset_hashes = {
            key: runtime_freeze.get("hashes", {}).get(key, {}).get("sha256")
            for key in required_asset_keys}
        if frozen_assets.get("asset_hashes") != actual_asset_hashes:
            errors.append("Browser/Tor runtime asset hashes differ from the V2 freeze")
        runtime_config_path = _resolve_ref(
            plan.get("frozen_inputs", {}).get("browser_runtime_config", {}))
        runtime_config_freeze_hash = runtime_freeze.get("hashes", {}).get(
            "runtime_config", {}).get("sha256")
        if (not runtime_config_path.is_file()
                or sha256_file(runtime_config_path) != runtime_config_freeze_hash):
            errors.append("Browser/Tor runtime config differs from its V2 freeze")
        browser_config = read_json(runtime_config_path) if runtime_config_path.is_file() else {}
        if browser_config.get("helper_image_id") != runtime_freeze.get("helper_image_id"):
            errors.append("Browser/Tor helper image ID differs from the V2 freeze")

    config = read_json(_resolve_ref(plan["frozen_inputs"]["protocol_config"]))
    source_audit = read_json(_resolve_ref(plan["frozen_inputs"]["source_audit"]))
    network_summary = read_json(_resolve_ref(
        plan["frozen_inputs"]["dynamic_network_acceptance"]))
    proxy = read_json(_resolve_ref(plan["frozen_inputs"]["proxy_readiness_snapshot"]))
    class_id = str(plan.get("class_binding", {}).get("class_id", ""))
    runs = plan.get("runs", [])
    sample_ids = [row.get("sample_id") for row in runs]
    session_ids = [row.get("session_id") for row in runs]

    if plan.get("protocol_id") != PROTOCOL_ID:
        errors.append("plan protocol_id does not match V3")
    expected_sample_ids = ["v3-class-2-r{:03d}".format(index)
                          for index in range(START_INDEX,
                                             START_INDEX + SAMPLE_COUNT)]
    expected_session_ids = ["v3-class-2-session-{:03d}".format(index)
                            for index in range(START_INDEX,
                                               START_INDEX + SAMPLE_COUNT)]
    if plan.get("plan_id") != "v3-browser-tor-class-2-x3-circuit-snapshot-py36compat-20261026":
        errors.append("plan_id does not identify the Python 3.6-compatible circuit-snapshot stage")
    if plan.get("runtime_variant_id") != "browser-tor-circuit-snapshot-py36compat-20261026":
        errors.append("runtime_variant_id does not identify the Python 3.6-compatible circuit snapshot")
    if sample_ids != expected_sample_ids or session_ids != expected_session_ids:
        errors.append("plan must use the fresh class-2 r004-r006 sample/session IDs")
    circuit_evidence_contract = plan.get(
        "target_tor_circuit_path_evidence_contract", {})
    if circuit_evidence_contract != {
            "required_source": "controller_get_circuits_snapshot_after_capture",
            "must_match_successful_target_stream_circuit_id": True,
            "required_status": "BUILT",
            "required_hop_count": 3,
            "required_unique_fingerprints": 3,
            "preserve_circ_event_history_as_supplemental_evidence": True,
    }:
        errors.append("target circuit path evidence contract is missing or changed")
    final_contract = plan.get("final_candidate_manifest_contract", {})
    if final_contract.get("required_sample_fields") != FINAL_SAMPLE_FIELDS:
        errors.append("final candidate manifest sample-field contract is incomplete or changed")
    if final_contract.get("required_true_sample_gates") != FINAL_SAMPLE_GATES:
        errors.append("final candidate manifest gate contract is incomplete or changed")
    if final_contract.get("required_hashed_artifact_kinds") != FINAL_ARTIFACT_KINDS:
        errors.append("final candidate manifest artifact contract is incomplete or changed")
    if (final_contract.get("required_splits") != ["train", "validation", "test"]
            or final_contract.get("minimum_common_classes_for_training_admission") != 5
            or final_contract.get("this_one_class_pilot_is_final_candidate_data") is not False):
        errors.append("one-class pilot was confused with final training candidate data")
    capture_contract = plan.get("browser_capture_window_contract", {})
    expected_capture_contract = {
        "capture_window_seconds": dynamic_window.BROWSER_CAPTURE_SECONDS,
        "page_load_timeout_seconds": dynamic_window.BROWSER_PAGE_LOAD_TIMEOUT_SECONDS,
        "page_content_timeout_seconds": dynamic_window.BROWSER_PAGE_CONTENT_TIMEOUT_SECONDS,
        "capture_setup_allowance_seconds": dynamic_window.BROWSER_CAPTURE_SETUP_SECONDS,
        "capture_settle_seconds": dynamic_window.BROWSER_CAPTURE_SETTLE_SECONDS,
        "pre_handover_safety_seconds": dynamic_window.BROWSER_CAPTURE_SAFETY_SECONDS,
        "topology_duration_seconds": dynamic_window.BROWSER_TOPOLOGY_SECONDS,
        "simulation_start_utc": dynamic_window.BROWSER_SIMULATION_START_UTC,
        "expected_first_topology_event_seconds": (
            dynamic_window.BROWSER_EXPECTED_FIRST_TOPOLOGY_EVENT_SECONDS),
        "capture_window_logical_seconds": [67, 264],
        "topology_event_window": "capture ends before first topology event",
    }
    if capture_contract != expected_capture_contract:
        errors.append("Browser/Tor capture-window contract differs from the audited runtime")
    if config.get("protocol_id") != plan.get("protocol_id"):
        errors.append("plan protocol_id differs from frozen runtime config")
    if len(runs) != SAMPLE_COUNT:
        errors.append("plan must contain exactly 3 planned runs")
    if len(set(sample_ids)) != SAMPLE_COUNT:
        errors.append("planned sample IDs must be unique")
    if len(set(session_ids)) != SAMPLE_COUNT:
        errors.append("planned session IDs must be unique")
    if class_id not in source_audit.get("common_class_ids", []):
        errors.append("class_id is not in the audited common-class set")
    accepted_source_statuses = config.get("training", {}).get(
        "accepted_source_audit_statuses", [])
    if source_audit.get("status") not in accepted_source_statuses:
        errors.append("source audit status is not accepted by the frozen V3 config")
    if source_audit.get("errors"):
        errors.append("source audit contains errors")
    mapped_url = source_audit.get("common_class_map", {}).get(class_id)
    if mapped_url != plan.get("class_binding", {}).get("requested_url"):
        errors.append("planned URL differs from the audited class mapping")
    if plan.get("class_binding", {}).get("class_mapping_sha256") != source_audit.get(
            "class_mapping_sha256"):
        errors.append("class mapping hash differs from the frozen source audit")
    for index, row in enumerate(runs):
        prefix = "runs[{}]".format(index)
        if str(row.get("class_id")) != class_id:
            errors.append(prefix + ": run class_id differs from frozen class")
        if row.get("requested_url") != mapped_url:
            errors.append(prefix + ": run URL differs from audited class mapping")
        if row.get("source_domain") != "E":
            errors.append(prefix + ": planned source_domain must be E")
        if row.get("network_scenario_id") != "dynamic_no_handover":
            errors.append(prefix + ": run scenario differs from frozen pilot scenario")
        if (row.get("fresh_browser_profile_required") is not True
                or row.get("fresh_tor_process_and_circuit_required") is not True
                or row.get("reuse_profile_circuit_or_target_tab") is not False):
            errors.append(prefix + ": run does not satisfy the independence contract")
    if network_summary.get("all_passed") is not True:
        errors.append("frozen dynamic network acceptance is not all_passed")
    if network_summary.get("protocol_id") != PROTOCOL_ID:
        errors.append("network acceptance protocol_id differs from V3")
    for scenario_id in ("dynamic_no_handover", "dynamic_handover"):
        passed = any(item.get("scenario_id") == scenario_id
                     and item.get("status") == "passed"
                     and item.get("cleanup_verified") is True
                     for item in network_summary.get("results", []))
        if not passed:
            errors.append("network acceptance lacks passed cleaned scenario: "
                          + scenario_id)
    current_config_hash = sha256_file(_resolve_ref(
        plan["frozen_inputs"]["protocol_config"]))
    for row in plan.get("frozen_inputs", {}).get("dynamic_network_runs", []):
        run_summary_path = _resolve_ref(row.get("summary", {}))
        if run_summary_path.is_file():
            run_summary = read_json(run_summary_path)
            if run_summary.get("runtime_config_sha256") != current_config_hash:
                errors.append("network run used a different runtime config: "
                              + str(run_summary_path))
    proxy_sequence = proxy.get("https_connect_probe", {}).get("sequence", [])
    proxy_passed = (proxy.get("runtime_doctor", {}).get("passed") is True
                    and proxy.get("runtime_doctor", {}).get("tmux_starrynet") is True
                    and proxy.get("runtime_doctor", {}).get("docker", {}).get(
                        "available") is True
                    and proxy.get("runtime_doctor", {}).get(
                        "starrynet_resources_clean") is True
                    and proxy.get("runtime_doctor", {}).get(
                        "active_collection_processes") == []
                    and len(proxy_sequence) >= 3
                    and all(item.get("https_connect_passed") is True
                            and item.get("listener_reachable") is True
                            and item.get("target_http_status") == 200
                            for item in proxy_sequence[:3]))
    if not proxy_passed:
        errors.append("proxy snapshot does not prove doctor plus 3 HTTPS CONNECT HTTP 200 results")

    collector_gate = plan.get("collector_gate", {})
    collector_path = _resolve_ref(collector_gate.get("v3_collector_path", {}))
    collector_ref_hash = collector_gate.get("v3_collector_path", {}).get("sha256")
    collector_ready = (
        collector_gate.get("implemented_offline") is True
        and collector_gate.get("connected") is True
        and collector_path.is_file()
        and sha256_file(collector_path) == collector_ref_hash
        and collector_gate.get("required_capture_interface") == "wf-gre0")
    if not collector_ready:
        errors.append("V3 collector offline implementation gate is incomplete")
    plan_valid = not errors
    return {
        "manifest": str(manifest_path),
        "plan_id": plan.get("plan_id"),
        "plan_valid": plan_valid,
        "errors": errors,
        "source_gate_passed": source_audit.get("status") in config.get(
            "training", {}).get("accepted_source_audit_statuses", []),
        "dynamic_network_gate_passed": network_summary.get("all_passed") is True,
        "proxy_snapshot_gate_passed": proxy_passed,
        "collector_gate_passed": collector_ready,
        "live_sample_verified": collector_gate.get("live_sample_verified") is True,
        "manual_execution_ready": bool(plan_valid and collector_ready),
        "collection_started": plan.get("collection_started") is True,
        "training_started": plan.get("training_started") is True,
        "requires_live_preflight_before_collection": True,
        "scientific_fidelity_verified": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    freeze = sub.add_parser("freeze", help="write a precollection-only plan manifest")
    freeze.add_argument("--class-id", default="1")
    freeze.add_argument("--proxy-readiness", required=True)
    freeze.add_argument("--output", default=str(ROOT / DEFAULT_OUTPUT))
    freeze.add_argument("--replace", action="store_true",
                        help="replace an existing precollection plan after reviewing its diff")
    audit = sub.add_parser("audit", help="verify frozen hashes and readiness gates")
    audit.add_argument("--manifest", required=True)
    audit.add_argument("--require-ready", action="store_true",
                       help="return 2 when the collector gate is not connected")
    args = parser.parse_args(argv)
    if args.command == "freeze":
        output = Path(args.output).resolve()
        if output.exists() and not args.replace:
            raise SystemExit("refusing to overwrite existing plan: " + str(output))
        plan = build_plan(args.class_id, args.proxy_readiness)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
        print(json.dumps({"written": str(output), "plan_id": plan["plan_id"],
                          "collector_connected": plan["collector_gate"]["connected"]},
                         indent=2, sort_keys=True))
        return 0
    if args.command == "audit":
        result = audit_plan(args.manifest)
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result["plan_valid"]:
            return 2
        if args.require_ready and not result["manual_execution_ready"]:
            return 3
        return 0
    parser.error("a subcommand is required")


if __name__ == "__main__":
    sys.exit(main())
