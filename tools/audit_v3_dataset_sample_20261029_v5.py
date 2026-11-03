#!/usr/bin/env python3
"""Independent 17-check audit for one V3 dataset-candidate sample."""

import datetime
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_GATES = (
    "target_identity_verified", "target_page_success_verified",
    "access_challenge_absent", "tor_target_stream_verified",
    "target_tor_circuit_three_hops_verified", "route_nat_verified",
    "bidirectional_satellite_route_verified", "capture_interface_verified",
    "capture_loss_zero", "offloads_disabled_verified",
    "pcap_trace_audit_passed", "topology_events_recorded",
    "actual_tor_path_recorded", "capture_window_order_verified",
    "clock_pair_verified", "cleanup_verified",
)
REQUIRED_ARTIFACTS = {
    "trace", "pcap", "sample_manifest", "packet_audit",
    "topology_events", "route_events",
}
CAPTURES = (
    "gs26-wf-gre0.pcap", "gs27-wf-gre0.pcap", "gs27-b27-default.pcap",
    "gs26-gre-outer.pcap", "gs27-gre-outer.pcap",
)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path):
    path = Path(path)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _capinfos_count(path):
    result = subprocess.run(["capinfos", "-c", str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True,
                            timeout=30)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    for line in result.stdout.splitlines():
        if "Number of packets" in line:
            return int(line.rsplit(":", 1)[1].strip().replace(",", ""))
    raise RuntimeError("capinfos did not report packet count")


def _within(root, value):
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def audit_sample(run_dir, sample_id, cohort_plan_path, execution_plan_path,
                 attempt_ledger_path, accepted_ledger_path):
    run_dir = Path(run_dir).resolve()
    cohort_path = Path(cohort_plan_path).resolve()
    execution_path = Path(execution_plan_path).resolve()
    cohort = read_json(cohort_path)
    execution = read_json(execution_path)
    manifest_path = run_dir / "sample_manifest.json"
    artifact_index_path = run_dir / "sample_artifacts.json"
    summary_path = run_dir / "summary.json"
    packet_audit_path = run_dir / "trace_audit/packet_audit.json"
    browser_summary_path = run_dir / "browser_tor/browser_summary.json"
    sample = read_json(manifest_path)
    artifact_index = read_json(artifact_index_path)
    network = read_json(summary_path)
    packet_audit = read_json(packet_audit_path)
    browser = read_json(browser_summary_path) if browser_summary_path.is_file() else {}
    planned_rows = cohort.get("samples", [])
    planned = next((row for row in planned_rows
                    if row.get("sample_id") == sample_id), {})
    checks = {}
    details = {}

    checks["cohort_plan_binding"] = (
        planned and execution.get("candidate_contract", {}).get(
            "cohort_plan_sha256") == sha256(cohort_path)
        and sample.get("candidate_cohort_plan_sha256") == sha256(cohort_path)
        and execution.get("plan_id") == "v3-candidate-20261029-v5-{}-attempt-{:02d}".format(
            sample_id, execution.get("attempt_number", 0))
        and sample.get("candidate_execution_plan_sha256") == sha256(execution_path)
        and read_json(Path(str(execution_path) + ".audit.json")).get(
            "plan_sha256") == sha256(execution_path)
        and read_json(Path(str(execution_path) + ".audit.json")).get(
            "manual_execution_ready") is True
        and read_json(Path(str(execution_path) + ".freeze.json")).get(
            "plan", {}).get("sha256") == sha256(execution_path))

    frozen_errors = []
    for label, item in cohort.get("frozen_inputs", {}).items():
        path = _within(ROOT, item.get("path", ""))
        if not path.is_file() or sha256(path) != item.get("sha256"):
            frozen_errors.append(label)
    checks["frozen_inputs_unchanged"] = not frozen_errors
    details["frozen_input_errors"] = frozen_errors

    checks["sample_identity_and_scope"] = (
        sample.get("sample_id") == sample_id == planned.get("sample_id")
        and sample.get("class_id") == planned.get("class_id")
        and sample.get("site_url") == planned.get("site_url")
        and sample.get("session_id") == planned.get("session_id")
        and sample.get("split") == planned.get("split")
        and sample.get("split_group_id") == sample.get("session_id")
        and sample.get("source_domain") == "E"
        and sample.get("network_scenario_id") == "dynamic_no_handover"
        and sample.get("pilot_only") is False
        and sample.get("training_eligible") is False
    )
    checks["class_map_matches_frozen_source"] = (
        sample.get("class_mapping_sha256") == cohort.get("class_mapping_sha256")
        and sample.get("site_url") == cohort.get("class_mapping", {}).get(
            sample.get("class_id"))
    )
    checks["required_sample_fields_present"] = all(
        key in sample for key in (
            "sample_id", "class_id", "site_url", "source_domain", "session_id",
            "split_group_id", "split", "protocol_config_sha256",
            "class_mapping_sha256", "network_scenario_id", "page_identity",
            "tor_path", "network_path", "time_boundaries", "browser_tor",
            "handover", "gates"))
    gates = sample.get("gates", {})
    checks["all_16_collection_gates_true"] = (
        len(gates) == 16 and set(gates) == set(REQUIRED_GATES)
        and all(gates.get(name) is True for name in REQUIRED_GATES))
    checks["network_run_and_cleanup_passed"] = (
        network.get("status") == "passed"
        and network.get("cleanup_verified") is True
        and network.get("route_nat_restored") is True
        and network.get("docker_inventory_restored") is True
        and browser.get("passed") is True
        and browser.get("cleanup_verified") is True
    )

    artifact_rows = artifact_index.get("artifacts", [])
    kinds = [row.get("kind") for row in artifact_rows]
    artifact_hashes = {}
    artifact_errors = []
    for row in artifact_rows:
        path = _within(run_dir, row.get("path", ""))
        actual = sha256(path) if path.is_file() else None
        artifact_hashes[row.get("kind")] = {
            "path": str(path), "sha256": actual,
            "expected_sha256": row.get("sha256"),
            "matches": actual == row.get("sha256"),
        }
        if actual is None or actual != row.get("sha256"):
            artifact_errors.append(str(path))
    checks["six_required_artifacts_and_hashes"] = (
        len(kinds) == 6 and set(kinds) == REQUIRED_ARTIFACTS
        and not artifact_errors and artifact_index.get("all_gates_passed") is True
    )
    details["artifact_hashes"] = artifact_hashes
    details["artifact_errors"] = artifact_errors

    directions = packet_audit.get("direction_counts", {})
    checks["trace_nonempty_and_bidirectional"] = (
        packet_audit.get("passed") is True
        and packet_audit.get("trace_row_count", 0) > 0
        and directions.get("client_to_network", 0) > 0
        and directions.get("network_to_client", 0) > 0
        and packet_audit.get("unclassified_navigation_window_packet_count") == 0
    )
    capture_rows, capture_errors = {}, []
    for name in CAPTURES:
        path = run_dir / "captures" / name
        try:
            count = _capinfos_count(path) if path.is_file() and path.stat().st_size else 0
        except Exception as exc:
            count = 0
            capture_errors.append(name + ": " + str(exc))
        capture_rows[name] = count
        if count <= 0:
            capture_errors.append(name + ": empty or missing")
    checks["five_capture_points_nonempty"] = (
        len(capture_rows) == len(CAPTURES) and not capture_errors)
    details["capture_packet_counts"] = capture_rows
    details["capture_errors"] = capture_errors

    route_samples = sample.get("network_path", {}).get("route_snapshots", [])
    checks["satellite_routes_and_capture_interface"] = (
        bool(route_samples) and sample.get("network_path", {}).get(
            "capture_interface") == "wf-gre0"
        and sample.get("network_path", {}).get("egress_interface") == "B27-default"
        and all(row.get("client_endpoint_route", {}).get("dev") == "wf-gre0"
                and row.get("egress_endpoint_route", {}).get("dev") == "B27-default"
                and all(value is True for value in row.get(
                    "satellite_route_checks", {}).values())
                for row in route_samples)
    )
    fixed_object = network.get("fixed_object", {})
    checks["fixed_object_integrity_and_claim_boundary"] = (
        fixed_object.get("sha256") == fixed_object.get("expected_sha256")
        and fixed_object.get("bytes") == 1048576
        and network.get("scientific_fidelity_verified") is False
        and network.get("training_eligible") is False
    )
    tor = sample.get("tor_path", {})
    hops = tor.get("circuit_path", [])
    fingerprints = [row.get("fingerprint") for row in hops]
    checks["target_tor_stream_and_circuit_match"] = (
        tor.get("stream_status") == "SUCCEEDED"
        and tor.get("circuit_status") == "BUILT"
        and tor.get("circuit_id") == tor.get("stream_circuit_id")
        and len(hops) == 3 and len(set(fingerprints)) == 3
        and all(isinstance(value, str) and len(value) == 40 for value in fingerprints)
    )
    page = sample.get("page_identity", {})
    requested_host = (urlsplit(planned.get("site_url", "")).hostname or "").lower()
    observed_hosts = [(urlsplit(page.get(key, "")).hostname or "").lower()
                      for key in ("final_url", "canonical_url")]
    identity_matches = any(
        host == requested_host or host.endswith("." + requested_host)
        for host in observed_hosts if host)
    checks["target_page_identity_and_no_challenge"] = (
        page.get("requested_url") == planned.get("site_url")
        and page.get("http_status") == 200
        and page.get("access_challenge_detected") is False
        and page.get("final_url") and page.get("canonical_url")
        and identity_matches
    )
    boundaries = sample.get("time_boundaries", {})
    monotonic = [boundaries.get(key) for key in (
        "raw_capture_start_monotonic", "navigation_start_monotonic",
        "navigation_complete_monotonic", "raw_capture_end_monotonic")]
    checks["capture_window_and_no_handover"] = (
        all(isinstance(value, (int, float)) for value in monotonic)
        and monotonic[0] <= monotonic[1] < monotonic[2] <= monotonic[3]
        and sample.get("handover", {}).get("occurred") is False
        and bool(network.get("topology_events"))
    )

    attempts = read_jsonl(attempt_ledger_path)
    sample_attempts = [row for row in attempts if row.get("sample_id") == sample_id]
    starts = [row for row in sample_attempts if row.get("event") == "started"]
    finishes = [row for row in sample_attempts if row.get("event") == "finished"]
    successful = [row for row in finishes if row.get("sample_status") == "passed"]
    attempt = next((row for row in reversed(finishes)
                    if row.get("sample_status") == "passed"), {})
    live_path = Path(attempt.get("live_proxy_snapshot", ""))
    if not live_path.is_absolute():
        live_path = ROOT / live_path
    live = read_json(live_path) if live_path.is_file() else {}
    probes = live.get("https_connect_probe", {}).get("sequence", [])
    checks["fresh_live_proxy_preflight_and_attempt_stage"] = (
        bool(starts) and bool(successful) and len(finishes) <= 2
        and attempt.get("plan_sha256") == sha256(execution_path)
        and live.get("passed") is True
        and len(probes) >= 3
        and all(row.get("https_connect_passed") is True
                and row.get("target_http_status") == 200 for row in probes[:3])
    )
    details["attempts"] = sample_attempts
    details["fresh_proxy_preflight"] = {
        "path": str(live_path), "passed": live.get("passed"),
        "three_http_200_connects": len(probes) >= 3 and all(
            row.get("https_connect_passed") is True
            and row.get("target_http_status") == 200 for row in probes[:3]),
    }

    accepted = read_jsonl(accepted_ledger_path)
    expected_order = planned.get("planned_run_order")
    preceding = [row for row in accepted
                 if row.get("planned_run_order", 0) < expected_order]
    seen = [row.get("sample_id") for row in accepted]
    order_ok = (
        len(preceding) == expected_order - 1
        and all(row.get("audit_passed") is True for row in preceding)
        and all(seen.count(value) == 1 for value in seen)
        and all(planned_rows[index].get("sample_id") == row.get("sample_id")
                and row.get("audit_passed") is True
                for index, row in enumerate(accepted))
    )
    checks["sequential_cohort_acceptance_and_split_isolation"] = (
        len(planned_rows) == 50 and 1 <= expected_order <= 50
        and planned_rows[expected_order - 1].get("sample_id") == sample_id
        and order_ok
        and sample.get("split_group_id") == sample.get("session_id")
        and len({row.get("session_id") for row in planned_rows}) == 50
        and len({row.get("split_group_id") for row in planned_rows}) == 50
        and all(row.get("split_group_id") == row.get("session_id")
                for row in planned_rows)
        and all(sum(1 for row in planned_rows
                    if row.get("class_id") == str(class_id)
                    and row.get("split") == split) == expected
                for class_id in range(5)
                for split, expected in (("train", 7), ("validation", 1), ("test", 2)))
    )
    details["accepted_prefix_count"] = len(accepted)
    details["planned_run_order"] = expected_order

    result = {
        "schema_version": 1,
        "audit_method": "independent 17-check V3 route, browser, artifact, and cohort audit",
        "audited_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "auditor_path": str(Path(__file__).resolve()),
        "auditor_sha256": sha256(__file__),
        "sample_id": sample_id,
        "run_dir": str(run_dir),
        "cohort_plan_sha256": sha256(cohort_path),
        "execution_plan_sha256": sha256(execution_path),
        "checks": checks,
        "details": details,
        "passed": len(checks) == 17 and all(checks.values()),
    }
    return result

