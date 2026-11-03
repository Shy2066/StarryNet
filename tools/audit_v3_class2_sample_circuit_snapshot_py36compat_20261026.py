#!/usr/bin/env python3
"""Independently audit one class-2 V3 Browser/Tor sample and its artifacts."""

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
READINESS = ROOT / "artifacts/reports/satellite_wf_v3_20261021/"
READINESS /= "matched_class_x3_readiness_20261022"
DEFAULT_PLAN = READINESS / "pilot_plan_class2_x3_circuit_snapshot_py36compat_20261026.json"
DEFAULT_ATTEMPT_LEDGER = READINESS / "attempt_ledger.jsonl"
DEFAULT_ATTEMPT_LEDGER_CORRECTIONS = READINESS / "attempt_ledger_corrections.jsonl"
DEFAULT_EXECUTION_LEDGER = READINESS / "execution_ledger.jsonl"
REQUIRED_CAPTURE_NAMES = (
    "gs26-wf-gre0.pcap",
    "gs27-wf-gre0.pcap",
    "gs27-b27-default.pcap",
    "gs26-gre-outer.pcap",
    "gs27-gre-outer.pcap",
)
REQUIRED_ARTIFACT_KINDS = {
    "trace", "pcap", "sample_manifest", "packet_audit",
    "topology_events", "route_events",
}


def read_json(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve(path, base):
    value = Path(path)
    return value if value.is_absolute() else (Path(base) / value).resolve()


def load_jsonl(path):
    rows = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def capinfos_packet_count(path):
    completed = subprocess.run(
        ["capinfos", "-c", str(path)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, universal_newlines=True)
    if completed.returncode:
        raise RuntimeError("capinfos failed for {}: {}".format(
            path, completed.stderr.strip()))
    match = re.search(r"Number of packets:\s*([\d,]+)", completed.stdout)
    if not match:
        raise RuntimeError("capinfos did not report packet count for {}".format(path))
    return int(match.group(1).replace(",", ""))


def audit(run_dir, run_index, plan_path, attempt_ledger_path,
          execution_ledger_path):
    run_dir = Path(run_dir).resolve()
    plan_path = Path(plan_path).resolve()
    plan = read_json(plan_path)
    sample = read_json(run_dir / "sample_manifest.json")
    network = read_json(run_dir / "summary.json")
    packet_audit = read_json(run_dir / "trace_audit/packet_audit.json")
    artifact_index_path = resolve(sample["artifact_index_path"], run_dir)
    artifact_index = read_json(artifact_index_path)
    topology = read_json(run_dir / "topology_events.json")
    route_rows = load_jsonl(run_dir / "route_events.jsonl")
    capture_stop = read_json(
        run_dir / "browser_tor/capture_control/capture_stop_ack.json")
    helper_files = sorted((run_dir / "browser_runs").glob("*/summary.json"))
    helper = read_json(helper_files[-1]) if helper_files else {}

    expected = plan.get("runs", [])[run_index - 1]
    expected_sample_id = expected.get("sample_id")
    expected_session_id = expected.get("session_id")
    requested_url = plan.get("class_binding", {}).get("requested_url")
    checks = {}
    details = {}

    checks["class2_x3_frozen_plan_binding"] = (
        plan.get("plan_id") == "v3-browser-tor-class-2-x3-circuit-snapshot-py36compat-20261026"
        and plan.get("runtime_variant_id") == "browser-tor-circuit-snapshot-py36compat-20261026"
        and plan.get("target_tor_circuit_path_evidence_contract", {}).get(
            "required_source") == "controller_get_circuits_snapshot_after_capture"
        and plan.get("plan_status") == "frozen_precollection"
        and plan.get("class_binding", {}).get("class_id") == "2"
        and requested_url == "http://amazon.in"
        and plan.get("class_binding", {}).get("binding_status")
        == "user_attested_with_unresolved_semantics"
        and plan.get("scope", {}).get("site_count") == 1
        and plan.get("scope", {}).get("samples_per_site") == 3
        and plan.get("scope", {}).get("training_eligible") is False
        and len(plan.get("runs", [])) == 3
        and expected_sample_id == "v3-class-2-r{:03d}".format(run_index + 3)
        and expected_session_id == "v3-class-2-session-{:03d}".format(run_index + 3)
        and expected.get("sample_id") == expected_sample_id
        and expected.get("session_id") == expected_session_id
        and expected.get("class_id") == "2"
        and expected.get("requested_url") == requested_url
        and expected.get("fresh_browser_profile_required") is True
        and expected.get("fresh_tor_process_and_circuit_required") is True
        and expected.get("reuse_profile_circuit_or_target_tab") is False
        and plan.get("independence_contract", {}).get("sequential_only") is True
        and plan.get("independence_contract", {}).get("distinct_session_per_run")
        is True
        and plan.get("independence_contract", {}).get("fresh_browser_profile_per_run")
        is True
        and plan.get("independence_contract", {}).get("fresh_tor_process_and_circuit_per_run")
        is True
        and plan.get("training_started") is False
    )

    source_ref = plan.get("frozen_inputs", {}).get("source_audit", {})
    source_path = resolve(source_ref.get("path", ""), ROOT)
    source_audit = read_json(source_path) if source_path.is_file() else {}
    checks["source_mapping_and_caveat_retained"] = (
        source_path.is_file()
        and sha256_file(source_path) == source_ref.get("sha256")
        and source_audit.get("status") == "user_attested_with_unresolved_semantics"
        and len(source_audit.get("unresolved_semantics", [])) == 16
        and source_audit.get("class_mapping_sha256")
        == plan.get("class_binding", {}).get("class_mapping_sha256")
        and source_audit.get("common_class_map", {}).get("2") == requested_url
    )

    checks["sample_identity_and_engineering_scope"] = (
        sample.get("sample_id") == expected_sample_id
        and sample.get("sample_status") == "passed"
        and sample.get("class_id") == "2"
        and sample.get("session_id") == expected_session_id
        and sample.get("site_url") == requested_url
        and sample.get("source_domain") == "E"
        and sample.get("network_scenario_id") == "dynamic_no_handover"
        and sample.get("training_eligible") is False
        and sample.get("pilot_only") is True
        and network.get("scientific_fidelity_verified") is False
        and network.get("training_eligible") is False
    )

    final_contract = plan.get("final_candidate_manifest_contract", {})
    required_fields = final_contract.get("required_sample_fields", [])
    required_gates = final_contract.get("required_true_sample_gates", [])
    gates = sample.get("gates", {})
    checks["required_sample_fields_present"] = bool(required_fields) and all(
        field in sample for field in required_fields)
    checks["all_16_sample_gates_true"] = (
        len(required_gates) == 16
        and all(gates.get(name) is True for name in required_gates)
        and len(gates) == 16
        and all(value is True for value in gates.values())
    )
    details["required_sample_fields"] = required_fields
    details["sample_gates"] = gates

    listed = artifact_index.get("artifacts", [])
    kinds = [row.get("kind") for row in listed]
    artifact_hashes = {}
    hash_errors = []
    for row in listed:
        path = resolve(row.get("path", ""), run_dir)
        expected_hash = row.get("sha256")
        if not path.is_file():
            hash_errors.append("missing artifact: {}".format(path))
            continue
        actual_hash = sha256_file(path)
        artifact_hashes[row.get("kind")] = {
            "path": str(path), "sha256": actual_hash,
            "expected_sha256": expected_hash,
            "matches": actual_hash == expected_hash,
            "size_bytes": path.stat().st_size,
        }
        if actual_hash != expected_hash:
            hash_errors.append("artifact hash mismatch: {}".format(path))
    checks["six_required_artifact_kinds"] = (
        set(kinds) == REQUIRED_ARTIFACT_KINDS and len(kinds) == 6)
    checks["all_required_artifact_hashes_match"] = (
        artifact_index.get("all_gates_passed") is True
        and artifact_index.get("sample_status") in (None, "passed")
        and not hash_errors and len(artifact_hashes) == 6
    )
    details["artifact_hashes"] = artifact_hashes
    details["artifact_hash_errors"] = hash_errors
    details["artifact_index_sha256"] = sha256_file(artifact_index_path)

    checks["packet_audit_bidirectional_and_classified"] = (
        packet_audit.get("passed") is True
        and packet_audit.get("capture_packet_count", 0) > 0
        and packet_audit.get("navigation_window_packet_count", 0) > 0
        and packet_audit.get("unclassified_navigation_window_packet_count") == 0
        and packet_audit.get("direction_counts", {}).get("client_to_network", 0) > 0
        and packet_audit.get("direction_counts", {}).get("network_to_client", 0) > 0
    )
    details["packet_audit"] = {
        key: packet_audit.get(key) for key in (
            "capture_packet_count", "navigation_window_packet_count",
            "outside_navigation_window_packet_count",
            "unclassified_navigation_window_packet_count",
            "direction_counts", "navigation_duration_seconds", "passed")
    }

    capture_counts = {}
    capture_errors = []
    for name in REQUIRED_CAPTURE_NAMES:
        path = run_dir / "captures" / name
        if not path.is_file() or path.stat().st_size <= 0:
            capture_errors.append("missing or empty capture: {}".format(path))
            continue
        try:
            count = capinfos_packet_count(path)
        except Exception as exc:
            capture_errors.append(str(exc))
            continue
        capture_counts[name] = {
            "packets": count, "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        if count <= 0:
            capture_errors.append("capture has no packets: {}".format(path))
    checks["five_capture_points_nonempty"] = (
        len(capture_counts) == len(REQUIRED_CAPTURE_NAMES) and not capture_errors)
    details["capture_points"] = capture_counts
    details["capture_errors"] = capture_errors

    route_snapshots = sample.get("network_path", {}).get("route_snapshots", [])
    route_rows_valid = bool(route_rows) and all(
        row.get("client_endpoint_route", {}).get("dev") == "wf-gre0"
        and row.get("egress_endpoint_route", {}).get("dev") == "B27-default"
        and bool(row.get("satellite_route_checks"))
        and all(value is True for value in row.get("satellite_route_checks", {}).values())
        for row in route_rows
    )
    qdisc_rows = [row for row in route_snapshots if row.get("qdisc")]
    qdisc_rows_valid = bool(qdisc_rows) and all(
        row.get("qdisc", {}).get("GS26", {}).get(
            "all_observed_drop_counters_zero") is True
        and row.get("qdisc", {}).get("GS27", {}).get(
            "all_observed_drop_counters_zero") is True
        for row in qdisc_rows
    )
    checks["all_route_snapshots_use_satellite_path"] = (
        route_rows_valid and len(route_rows) == len(route_snapshots)
        and qdisc_rows_valid
    )
    details["route_event_count"] = len(route_rows)
    details["qdisc_sample_count"] = len(qdisc_rows)

    planned_events = topology.get("planned", [])
    first_topology_event = min(
        [row.get("logical_second", float("inf")) for row in planned_events]
        or [float("inf")])
    logical_capture_stop = capture_stop.get("logical_second")
    checks["capture_stopped_before_first_topology_change"] = (
        capture_stop.get("ok") is True
        and isinstance(logical_capture_stop, (int, float))
        and logical_capture_stop < first_topology_event
        and first_topology_event == 272
        and sample.get("handover", {}).get("occurred") is False
    )
    details["capture_stop_logical_second"] = logical_capture_stop
    details["first_planned_topology_event_second"] = first_topology_event

    page = sample.get("page_identity", {})
    page_hosts = [urlparse(page.get(key, "")).hostname or "" for key in
                  ("final_url", "canonical_url")]
    page_matches_class = any(
        host == "amazon.in" or host.endswith(".amazon.in") for host in page_hosts)
    tor = sample.get("tor_path", {})
    tor_path = tor.get("circuit_path", [])
    checks["target_identity_page_and_tor_path"] = (
        page.get("requested_url") == requested_url
        and page.get("http_status") == 200
        and page_matches_class
        and page.get("access_challenge_detected") is False
        and len(tor_path) == 3
        and len({row.get("fingerprint") for row in tor_path}) == 3
        and all(re.fullmatch(r"[0-9A-Fa-f]{40}",
                             str(row.get("fingerprint", "")))
                for row in tor_path)
        and tor.get("circuit_status") == "BUILT"
        and tor.get("stream_status") == "SUCCEEDED"
        and tor.get("circuit_id") == tor.get("stream_circuit_id")
        and tor.get("path_evidence_source")
        == "controller_get_circuits_snapshot_after_capture"
    )
    helper_visit = (helper.get("visits", [{}])[0]
                    if helper.get("visits") else {})
    requested_host = (urlparse(requested_url).hostname or "").lower()
    requested_domain = requested_host[4:] if requested_host.startswith("www.") else requested_host
    helper_stream_events = helper_visit.get("capture_window", {}).get(
        "site_stream_events", [])
    target_stream_ids = {row.get("id") for row in helper_stream_events
                         if row.get("status") in ("NEW", "SENTCONNECT")
                         and row.get("address")
                         and ((row.get("address").lower().rstrip(".")
                               == requested_domain)
                              or row.get("address").lower().rstrip(".").endswith(
                                  "." + requested_domain))}
    target_success_streams = [
        row for row in helper_stream_events
        if row.get("id") in target_stream_ids
        and row.get("status") == "SUCCEEDED" and row.get("circuit_id")
    ]
    bound_stream = target_success_streams[0] if target_success_streams else {}
    status_snapshots = helper_visit.get("target_circuit_status_snapshots", [])
    bound_snapshot = next((row for row in status_snapshots
                           if row.get("circuit_id") == bound_stream.get("circuit_id")
                           and row.get("evidence_source")
                           == "controller_get_circuits_snapshot_after_capture"), {})
    checks["target_circuit_snapshot_bound_to_successful_stream"] = (
        bool(bound_stream)
        and bound_stream.get("id") == tor.get("target_stream_id")
        and bound_stream.get("circuit_id") == tor.get("stream_circuit_id")
        and bound_snapshot.get("status") == "BUILT"
        and len(bound_snapshot.get("path", [])) == 3
        and bound_snapshot.get("path") == tor_path
        and isinstance(bound_stream.get("observed_monotonic"), (int, float))
        and isinstance(bound_snapshot.get("observed_monotonic"), (int, float))
        and bound_snapshot.get("observed_monotonic")
        >= bound_stream.get("observed_monotonic")
    )
    details["page_identity"] = {
        key: page.get(key) for key in (
            "requested_url", "final_url", "canonical_url", "http_status",
            "access_challenge_detected")
    }
    details["tor_path"] = {
        "circuit_id": tor.get("circuit_id"),
        "stream_status": tor.get("stream_status"),
        "path_evidence_source": tor.get("path_evidence_source"),
        "path_observed_utc": tor.get("path_observed_utc"),
        "hop_fingerprints": [row.get("fingerprint") for row in tor_path],
        "hop_count": len(tor_path),
        "hop_nicknames": [row.get("nickname") for row in tor_path],
    }
    details["target_stream_and_snapshot"] = {
        "stream_id": bound_stream.get("id"),
        "stream_circuit_id": bound_stream.get("circuit_id"),
        "stream_status": bound_stream.get("status"),
        "snapshot_status": bound_snapshot.get("status"),
        "snapshot_circuit_id": bound_snapshot.get("circuit_id"),
        "snapshot_evidence_source": bound_snapshot.get("evidence_source"),
        "snapshot_observed_utc": bound_snapshot.get("observed_utc"),
    }

    checks["network_and_browser_cleanup"] = (
        network.get("status") == "passed"
        and network.get("cleanup_verified") is True
        and network.get("route_nat_restored") is True
        and network.get("docker_inventory_restored") is True
        and network.get("browser_tor", {}).get("cleanup_verified") is True
        and network.get("browser_tor_cleanup_errors") == []
        and helper.get("passed") is True
        and helper.get("cleanup_verified") is True
    )

    attempts = load_jsonl(attempt_ledger_path)
    sample_attempt_rows = [row for row in attempts
                           if row.get("sample_id") == expected_sample_id]
    sample_starts = [row for row in sample_attempt_rows
                     if row.get("event") == "started"]
    sample_finishes = [row for row in sample_attempt_rows
                       if row.get("event") == "finished"]
    attempt = next((row for row in reversed(sample_attempt_rows)
                    if row.get("event") == "finished"
                    and row.get("network_run_id") == network.get("run_id")), {})
    prior_attempt = next((row for row in sample_finishes
                          if row.get("attempt_number") == 1), {})
    corrections_path = DEFAULT_ATTEMPT_LEDGER_CORRECTIONS
    corrections = load_jsonl(corrections_path) if corrections_path.is_file() else []
    review_ref = plan.get("attempt_classification_review", {})
    review_file = resolve(review_ref.get("path", ""), ROOT)
    review_rows = load_jsonl(review_file) if review_file.is_file() else []
    prior_review = next((row for row in review_rows
                         if row.get("event") == "classification_review"
                         and row.get("attempt_id") == prior_attempt.get("attempt_id")), {})
    prior_r004_attempt_id = plan.get("provenance_state", {}).get(
        "prior_r004_attempt_id")
    prior_r004_attempt = next((row for row in attempts
                               if row.get("event") == "finished"
                               and row.get("attempt_id") == prior_r004_attempt_id), {})
    prior_r004_review = next((row for row in review_rows
                              if row.get("event") == "classification_review"
                              and row.get("attempt_id") == prior_r004_attempt_id), {})
    review_hash_matches = (review_file.is_file()
                           and sha256_file(review_file) == review_ref.get("sha256"))
    if run_index == 1:
        attempt_count_valid = len(sample_starts) == 2 and len(sample_finishes) == 2
        reviewed_infra_failure = (
            prior_attempt.get("sample_status") == "failed"
            and prior_attempt.get("failure_class") == "sample_gate"
            and prior_attempt.get("retry_consumed") is False
            and prior_review.get("recorded_failure_class") == "sample_gate"
            and prior_review.get("recorded_retry_consumed") is False
            and prior_review.get("reviewed_failure_class") == "infrastructure"
            and prior_review.get("reviewed_retry_consumed") is False
            and "Python 3.6" in prior_review.get("reason", "")
        )
    else:
        attempt_count_valid = len(sample_starts) == 1 and len(sample_finishes) == 1
        reviewed_infra_failure = (
            len([row for row in review_rows
                 if row.get("attempt_id") == prior_attempt.get("attempt_id")]) == 0
        )
    live_snapshot = Path(attempt.get("live_proxy_snapshot", ""))
    if not live_snapshot.is_absolute():
        live_snapshot = (ROOT / live_snapshot).resolve()
    live_preflight = read_json(live_snapshot) if live_snapshot.is_file() else {}
    connect_checks = live_preflight.get("https_connect_probe", {}).get("sequence", [])
    runtime_ref = plan.get("frozen_inputs", {}).get("browser_runtime_config", {})
    checks["runtime_preflight_and_attempt_binding"] = (
        attempt_count_valid
        and attempt.get("attempt_number") == (2 if run_index == 1 else 1)
        and attempt.get("run_index") == run_index
        and attempt.get("retry_reserved") is False
        and attempt.get("sample_status") == "passed"
        and attempt.get("failure_class") is None
        and attempt.get("retry_consumed") is False
        and attempt.get("plan_sha256") == sha256_file(plan_path)
        and live_preflight.get("passed") is True
        and live_preflight.get("runtime_config", {}).get("sha256")
        == runtime_ref.get("sha256")
        and live_preflight.get("runtime_doctor", {}).get("passed") is True
        and live_preflight.get("runtime_doctor", {}).get("tmux_starrynet") is True
        and live_preflight.get("runtime_doctor", {}).get("docker", {}).get("available")
        is True
        and live_preflight.get("runtime_doctor", {}).get("starrynet_resources_clean")
        is True
        and live_preflight.get("runtime_doctor", {}).get("active_collection_processes")
        == []
        and live_preflight.get("https_connect_probe", {}).get("consecutive_count") == 3
        and len(connect_checks) == 3
        and all(row.get("https_connect_passed") is True
                and row.get("target_http_status") == 200 for row in connect_checks)
    )
    checks["prior_r004_postprocessing_failure_reviewed"] = (
        review_hash_matches
        and prior_r004_attempt.get("sample_status") == "failed"
        and prior_r004_attempt.get("failure_class") == "sample_gate"
        and prior_r004_attempt.get("retry_consumed") is False
        and prior_r004_review.get("recorded_failure_class") == "sample_gate"
        and prior_r004_review.get("recorded_retry_consumed") is False
        and prior_r004_review.get("reviewed_failure_class") == "infrastructure"
        and prior_r004_review.get("reviewed_retry_consumed") is False
        and "Python 3.6" in prior_r004_review.get("reason", "")
        and prior_r004_review.get("review_id")
        == "class2-r004-python36-postprocessing-infrastructure-review-20261026"
    )
    details["attempt"] = {
        key: attempt.get(key) for key in (
            "attempt_number", "sample_id", "run_index", "plan_sha256",
            "sample_status", "failure_class", "retry_consumed", "network_run_id",
            "live_proxy_snapshot", "cleanup_verified")
    }
    details["prior_attempt_review"] = {
        "attempt_id": prior_r004_attempt.get("attempt_id"),
        "recorded_failure_class": prior_r004_attempt.get("failure_class"),
        "reviewed_failure_class": prior_r004_review.get("reviewed_failure_class"),
        "review_id": prior_r004_review.get("review_id"),
        "review_file_sha256": sha256_file(review_file) if review_file.is_file() else None,
    }
    details["live_preflight"] = {
        "path": str(live_snapshot) if live_snapshot.is_file() else None,
        "sha256": sha256_file(live_snapshot) if live_snapshot.is_file() else None,
        "passed": live_preflight.get("passed"),
        "connect_checks": connect_checks,
    }

    executions = load_jsonl(execution_ledger_path)
    sample_executions = [row for row in executions
                         if row.get("sample_id") == expected_sample_id
                         and row.get("sample_status") == "passed"]
    execution = next((row for row in reversed(sample_executions)
                      if row.get("network_run_id") == network.get("run_id")), {})
    checks["single_execution_ledger_record"] = (
        len(sample_executions) == 1
        and execution.get("run_index") == run_index
        and execution.get("cleanup_verified") is True
        and execution.get("training_eligible") is False
        and execution.get("live_proxy_snapshot") == attempt.get("live_proxy_snapshot")
    )
    details["execution_ledger_record"] = execution

    return {
        "schema_version": 1,
        "audited_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit_method": "independent contract, capture, route, runtime, and SHA-256 verification",
        "auditor_path": str(Path(__file__).resolve()),
        "auditor_sha256": sha256_file(__file__),
        "plan_path": str(plan_path),
        "plan_sha256": sha256_file(plan_path),
        "run_index": run_index,
        "run_dir": str(run_dir),
        "sample_id": sample.get("sample_id"),
        "checks": checks,
        "details": details,
        "passed": all(checks.values()),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-index", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--attempt-ledger", default=str(DEFAULT_ATTEMPT_LEDGER))
    parser.add_argument("--execution-ledger", default=str(DEFAULT_EXECUTION_LEDGER))
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    result = audit(args.run_dir, args.run_index, args.plan,
                   args.attempt_ledger, args.execution_ledger)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({
        "passed": result["passed"],
        "sample_id": result["sample_id"],
        "checks": result["checks"],
        "artifact_hashes": result["details"]["artifact_hashes"],
        "output_path": str(output),
    }, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
