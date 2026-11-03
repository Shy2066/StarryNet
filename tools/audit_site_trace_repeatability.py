#!/usr/bin/env python3
"""Audit repeated Tor Browser website-window trace runs."""

import argparse
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import statistics
import sys
from urllib.parse import urlsplit


PROTOCOL_IDS = {
    "starrynet-tor-site-window-v2",
    "starrynet-tor-site-window-v3",
    "starrynet-tor-site-window-v4",
    "starrynet-tor-site-window-v5",
    "starrynet-tor-site-window-v6",
    "starrynet-tor-site-window-v7",
    "starrynet-tor-site-window-v8",
    "starrynet-tor-site-window-v9",
    "starrynet-tor-site-window-v10",
    "starrynet-tor-site-window-v11",
    "starrynet-tor-site-window-v12",
    "starrynet-tor-site-window-v13",
    "starrynet-tor-site-window-v14",
    "starrynet-tor-site-window-v15",
    "starrynet-tor-site-window-v17-phase-resource-observability",
    "starrynet-tor-site-window-v18-phase-resource-route-settled",
    "starrynet-tor-site-window-v20-phase-matched-independent",
    "starrynet-tor-site-window-v21-circuit-path-diagnostic",
    "starrynet-tor-site-window-v22-cache-on-matched-phase",
    "starrynet-tor-site-window-v23-cache-on-after-warmup-phase-matched",
    "starrynet-tor-site-window-v24-cache-on-phase-route-reaudit",
    "starrynet-tor-site-window-v25-cache-on-phase-route-reaudit",
    "starrynet-tor-site-window-v26-cache-on-phase-route-reaudit-fixed-middle-exit",
    "starrynet-tor-site-window-v27-cache-on-phase-route-reaudit-fixed-entry-middle-exit",
    "starrynet-e-browser-tor-v1-v27-warm-refresh",
    "starrynet-e-browser-tor-v1-1-warm-refresh-bridge-only",
    "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain",
    "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected",
    "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization",
}
TARGET_PAGE_REFRESH_PROTOCOL_IDS = {
    "starrynet-tor-site-window-v12",
    "starrynet-tor-site-window-v13",
    "starrynet-tor-site-window-v14",
    "starrynet-tor-site-window-v15",
    "starrynet-tor-site-window-v17-phase-resource-observability",
    "starrynet-tor-site-window-v18-phase-resource-route-settled",
    "starrynet-tor-site-window-v20-phase-matched-independent",
    "starrynet-tor-site-window-v21-circuit-path-diagnostic",
    "starrynet-tor-site-window-v22-cache-on-matched-phase",
    "starrynet-tor-site-window-v23-cache-on-after-warmup-phase-matched",
    "starrynet-tor-site-window-v24-cache-on-phase-route-reaudit",
    "starrynet-tor-site-window-v25-cache-on-phase-route-reaudit",
    "starrynet-tor-site-window-v26-cache-on-phase-route-reaudit-fixed-middle-exit",
    "starrynet-tor-site-window-v27-cache-on-phase-route-reaudit-fixed-entry-middle-exit",
    "starrynet-e-browser-tor-v1-v27-warm-refresh",
    "starrynet-e-browser-tor-v1-1-warm-refresh-bridge-only",
    "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain",
    "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected",
    "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization",
}
PHASE_RESOURCE_PROTOCOL_IDS = {
    "starrynet-tor-site-window-v17-phase-resource-observability",
    "starrynet-tor-site-window-v18-phase-resource-route-settled",
    "starrynet-tor-site-window-v20-phase-matched-independent",
    "starrynet-tor-site-window-v21-circuit-path-diagnostic",
    "starrynet-tor-site-window-v22-cache-on-matched-phase",
    "starrynet-tor-site-window-v23-cache-on-after-warmup-phase-matched",
    "starrynet-tor-site-window-v24-cache-on-phase-route-reaudit",
    "starrynet-tor-site-window-v25-cache-on-phase-route-reaudit",
    "starrynet-tor-site-window-v26-cache-on-phase-route-reaudit-fixed-middle-exit",
    "starrynet-tor-site-window-v27-cache-on-phase-route-reaudit-fixed-entry-middle-exit",
    "starrynet-e-browser-tor-v1-v27-warm-refresh",
    "starrynet-e-browser-tor-v1-1-warm-refresh-bridge-only",
    "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain",
    "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected",
    "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization",
}
V20_PROTOCOL_ID = "starrynet-tor-site-window-v20-phase-matched-independent"
V21_PROTOCOL_ID = "starrynet-tor-site-window-v21-circuit-path-diagnostic"
V22_PROTOCOL_ID = "starrynet-tor-site-window-v22-cache-on-matched-phase"
V23_PROTOCOL_ID = "starrynet-tor-site-window-v23-cache-on-after-warmup-phase-matched"
V24_PROTOCOL_ID = "starrynet-tor-site-window-v24-cache-on-phase-route-reaudit"
V25_PROTOCOL_ID = "starrynet-tor-site-window-v25-cache-on-phase-route-reaudit"
V26_PROTOCOL_ID = "starrynet-tor-site-window-v26-cache-on-phase-route-reaudit-fixed-middle-exit"
V27_PROTOCOL_ID = "starrynet-tor-site-window-v27-cache-on-phase-route-reaudit-fixed-entry-middle-exit"
E_BROWSER_PROTOCOL_ID = "starrynet-e-browser-tor-v1-v27-warm-refresh"
E_BROWSER_V1_1_PROTOCOL_ID = "starrynet-e-browser-tor-v1-1-warm-refresh-bridge-only"
E_BROWSER_V1_2_PROTOCOL_ID = "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain"
E_BROWSER_V1_3_PROTOCOL_ID = "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected"
E_BROWSER_V1_4_PROTOCOL_ID = "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization"
E_BROWSER_PROTOCOL_IDS = (E_BROWSER_PROTOCOL_ID, E_BROWSER_V1_1_PROTOCOL_ID,
                          E_BROWSER_V1_2_PROTOCOL_ID, E_BROWSER_V1_3_PROTOCOL_ID,
                          E_BROWSER_V1_4_PROTOCOL_ID)
E_BROWSER_ENTRY_ONLY_PROTOCOL_IDS = (E_BROWSER_V1_1_PROTOCOL_ID,
                                     E_BROWSER_V1_2_PROTOCOL_ID,
                                     E_BROWSER_V1_3_PROTOCOL_ID,
                                     E_BROWSER_V1_4_PROTOCOL_ID)
E_BROWSER_V1_1_DOMAIN = "E_BROWSER_TOR_V1_1"
E_BROWSER_V1_2_DOMAIN = "E_BROWSER_TOR_V1_2"
E_BROWSER_V1_3_DOMAIN = "E_BROWSER_TOR_V1_3"
E_BROWSER_V1_4_DOMAIN = "E_BROWSER_TOR_V1_4"
E_BROWSER_V1_2_HELPER_IMAGE_ID = (
    "sha256:168196aef4661dbe43899fb144428a1c68ccb0391a0bb5520c63d606464aa27c")
E_BROWSER_V1_2_WARMUP_REDIRECT_POLICY = {
    "requested_url_must_be_https": True,
    "redirects_within_source_domain_host_family_allowed": True,
    "redirects_outside_source_domain_host_family_allowed": False,
    "retain_final_https_host_and_path_for_same_tab_refresh": True,
    "record_warmup_final_url": True,
}
V27_BRIDGE_FINGERPRINT = "F99CFE52EDFF8EAA332CD73C1E638035210C0336"
V26_TOR_PATH_CONTROL = {
    "mode": "fixed_middle_exit_diagnostic",
    "middle_fingerprint": "DBCBB4CEF0FC8E32BE674D4B19A964CB2981CF5D",
    "exit_fingerprint": "3C89C80E2699FB6358BBB64FDC9547AFCB5C03F7",
    "torrc_options": [
        "MiddleNodes $DBCBB4CEF0FC8E32BE674D4B19A964CB2981CF5D",
        "ExitNodes $3C89C80E2699FB6358BBB64FDC9547AFCB5C03F7",
    ],
    "expected_target_relay_fingerprints": [
        "F99CFE52EDFF8EAA332CD73C1E638035210C0336",
        "DBCBB4CEF0FC8E32BE674D4B19A964CB2981CF5D",
        "3C89C80E2699FB6358BBB64FDC9547AFCB5C03F7",
    ],
    "entry_node_pinned": False,
}
PHASE_ROUTE_REAUDIT_PROTOCOL_IDS = (V24_PROTOCOL_ID, V25_PROTOCOL_ID,
                                    V26_PROTOCOL_ID, V27_PROTOCOL_ID,
                                    *E_BROWSER_PROTOCOL_IDS)
MATCHED_PHASE_PROTOCOL_IDS = (V20_PROTOCOL_ID, V21_PROTOCOL_ID,
                              V22_PROTOCOL_ID, V23_PROTOCOL_ID,
                              V24_PROTOCOL_ID, V25_PROTOCOL_ID,
                              V26_PROTOCOL_ID, V27_PROTOCOL_ID,
                              *E_BROWSER_PROTOCOL_IDS)
EXPECTED_URL = "https://www.adobe.com/"
PROFILE_BINS = 50
CV_LIMIT = 0.20
DIRECTION_SHARE_RANGE_LIMIT = 0.10
PROFILE_CORRELATION_FLOOR = 0.80
OFFLOAD_FEATURES = (
    "tcp-segmentation-offload",
    "generic-segmentation-offload",
    "generic-receive-offload",
    "large-receive-offload",
    "tx-gso-list",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path):
    with Path(path).open(encoding="utf-8") as source:
        return json.load(source)


def resolve_artifact(path, run_dir):
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = run_dir / candidate
    return candidate.resolve()


def pairwise_pearson(left, right):
    if len(left) != len(right) or len(left) < 2:
        return None
    mean_left = statistics.mean(left)
    mean_right = statistics.mean(right)
    centered_left = [value - mean_left for value in left]
    centered_right = [value - mean_right for value in right]
    sum_left = sum(value * value for value in centered_left)
    sum_right = sum(value * value for value in centered_right)
    if sum_left <= 0 or sum_right <= 0:
        return None
    covariance = sum(a * b for a, b in zip(centered_left, centered_right))
    return covariance / math.sqrt(sum_left * sum_right)


def offload_is_disabled(summary):
    audit = summary.get("packetization_offload_audit", {})
    if audit.get("mode") != "disable_path" or audit.get("verified_disabled") is not True:
        return False, "path offload audit is not verified disabled"
    endpoints = audit.get("endpoints", [])
    four_endpoint_protocols = (
        "starrynet-e-browser-tor-v1-1-warm-refresh-bridge-only",
        "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain",
        "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected",
        "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization",
    )
    expected_count = (4 if summary.get("acquisition_protocol", {}).get(
        "protocol_id") in ("starrynet-tor-site-window-v7",
                            "starrynet-tor-site-window-v8",
                            "starrynet-tor-site-window-v9",
                            "starrynet-tor-site-window-v10",
                            "starrynet-tor-site-window-v11",
                            "starrynet-tor-site-window-v12",
                            "starrynet-tor-site-window-v13",
                            "starrynet-tor-site-window-v14",
                            "starrynet-tor-site-window-v15",
                            "starrynet-tor-site-window-v17-phase-resource-observability",
                            "starrynet-tor-site-window-v18-phase-resource-route-settled",
                            "starrynet-tor-site-window-v20-phase-matched-independent",
                            "starrynet-tor-site-window-v21-circuit-path-diagnostic",
                            "starrynet-tor-site-window-v22-cache-on-matched-phase",
                            "starrynet-tor-site-window-v23-cache-on-after-warmup-phase-matched",
                            "starrynet-tor-site-window-v24-cache-on-phase-route-reaudit",
                            "starrynet-tor-site-window-v25-cache-on-phase-route-reaudit",
                            "starrynet-tor-site-window-v26-cache-on-phase-route-reaudit-fixed-middle-exit",
                            "starrynet-tor-site-window-v27-cache-on-phase-route-reaudit-fixed-entry-middle-exit",
                            *four_endpoint_protocols) else 2)
    if len(endpoints) != expected_count:
        return False, "offload audit does not contain {} route endpoints".format(
            expected_count)
    for endpoint in endpoints:
        features = endpoint.get("after", {}).get("features", {})
        for feature in OFFLOAD_FEATURES:
            state = features.get(feature, {}).get("state")
            if state != "off":
                return False, "{} is {} on {}".format(
                    feature, state, endpoint.get("interface", "unknown interface"))
    return True, None


def route_monitor_failures(summary, run_dir, visits):
    monitor = summary.get("route_monitor", {})
    sample_path_value = monitor.get("sample_path")
    if not sample_path_value:
        return ["route-monitor sample file is missing"]
    sample_path = resolve_artifact(sample_path_value, run_dir)
    if not sample_path.is_file():
        return ["route-monitor sample file is missing: {}".format(sample_path)]
    failures = []
    expected_hash = monitor.get("sample_sha256")
    if not expected_hash or sha256_file(sample_path) != expected_hash:
        failures.append("route-monitor sample hash is missing or mismatched")
    try:
        samples = [json.loads(line) for line in
                   sample_path.read_text(encoding="utf-8").splitlines()
                   if line.strip()]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return failures + ["route-monitor samples cannot be read: {}".format(exc)]
    if len(samples) != monitor.get("sample_count"):
        failures.append("route-monitor sample count differs from summary")
    interval = float(monitor.get("sample_interval_seconds", 0))
    if interval <= 0:
        return failures + ["route-monitor sample interval is invalid"]
    max_gap_limit = max(2.5, interval * 2.5)
    run_id_match = re.search(r"_visit_(\d+)$", summary.get("run_id", ""))
    for visit_index, visit in enumerate(visits, 1):
        display_index = int(run_id_match.group(1)) if run_id_match else visit_index
        window = visit.get("capture_window", {})
        start = (window.get("start_ack") or {}).get("tcpdump_ready_monotonic")
        end = (window.get("stop_ack") or {}).get("tcpdump_stopped_monotonic")
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            failures.append("visit {} lacks capture-window route-monitor markers".format(
                display_index))
            continue
        selected = [sample for sample in samples
                    if start <= sample.get("sampled_monotonic", -1) <= end]
        if not selected:
            failures.append("visit {} has no route samples during capture".format(
                display_index))
            continue
        if any(sample.get("client_to_egress", {}).get("satellite_route") is not True
               or sample.get("egress_to_client", {}).get("satellite_route") is not True
               for sample in selected):
            failures.append("visit {} has a sampled non-satellite route".format(
                display_index))
        times = [float(start)] + [float(sample["sampled_monotonic"])
                                  for sample in selected] + [float(end)]
        max_gap = max((right - left for left, right in zip(times, times[1:])),
                      default=None)
        if max_gap is None or max_gap > max_gap_limit:
            failures.append("visit {} route samples leave a {:.3f}s coverage gap".format(
                display_index, max_gap if max_gap is not None else float("inf")))
        recorded = [item for item in monitor.get("visit_windows", [])
                    if item.get("capture_start_monotonic") == start
                    and item.get("capture_stop_monotonic") == end]
        if len(recorded) != 1 or recorded[0].get("passed") is not True:
            failures.append("visit {} route-window result is absent or failed".format(
                display_index))
    return failures


def is_per_visit_v7_package(summary, visits):
    return (summary.get("acquisition_protocol", {}).get("protocol_id")
            == "starrynet-tor-site-window-v7"
            and "_visit_" in summary.get("run_id", "")
            and len(visits) == 1)


def is_per_visit_v8_package(summary, visits):
    return (summary.get("acquisition_protocol", {}).get("protocol_id")
            == "starrynet-tor-site-window-v8"
            and re.search(r"_visit_\d+$", summary.get("run_id", "")) is not None
            and len(visits) == 1)


def is_per_visit_v9_package(summary, visits):
    return (summary.get("acquisition_protocol", {}).get("protocol_id")
            == "starrynet-tor-site-window-v9"
            and re.search(r"_visit_\d+$", summary.get("run_id", "")) is not None
            and len(visits) == 1)


def is_per_visit_v10_package(summary, visits):
    return (summary.get("acquisition_protocol", {}).get("protocol_id")
            == "starrynet-tor-site-window-v10"
            and re.search(r"_visit_\d+$", summary.get("run_id", "")) is not None
            and len(visits) == 1)


def is_per_visit_v11_package(summary, visits):
    return (summary.get("acquisition_protocol", {}).get("protocol_id")
            == "starrynet-tor-site-window-v11"
            and re.search(r"_visit_\d+$", summary.get("run_id", "")) is not None
            and len(visits) == 1)


def is_per_visit_v12_package(summary, visits):
    return (summary.get("acquisition_protocol", {}).get("protocol_id")
            in TARGET_PAGE_REFRESH_PROTOCOL_IDS
            and re.search(r"_visit_\d+$", summary.get("run_id", "")) is not None
            and len(visits) == 1)


def route_readiness_failures(summary, run_dir, readiness_override=None,
                             label=None, ack_override=None):
    failures = []
    match = re.search(r"_visit_(\d+)$", summary.get("run_id", ""))
    if readiness_override is None and not match:
        return ["route-ready audit is not scoped to a single visit package"]
    visit_index = label or (match.group(1) if match else "warmup")
    readiness = (readiness_override if readiness_override is not None else
                 summary.get("route_readiness_by_visit", {}).get(visit_index))
    if not isinstance(readiness, dict):
        return ["visit {} route-readiness evidence is missing".format(visit_index)]
    protocol = summary.get("acquisition_protocol", {})
    required_seconds = protocol.get("route_readiness", {}).get(
        "stable_seconds_required")
    if not isinstance(required_seconds, (int, float)) or required_seconds < 5:
        failures.append("protocol route-stability requirement is below five seconds")
        return failures
    if readiness.get("passed") is not True:
        failures.append("visit {} did not pass route readiness".format(visit_index))
        return failures
    if readiness.get("stable_seconds_observed", 0) < required_seconds:
        failures.append("visit {} stable route evidence is shorter than required".format(
            visit_index))
    route_devices = readiness.get("route_devices", {})
    client_device = route_devices.get("client_to_egress")
    egress_device = route_devices.get("egress_to_client")
    if client_device != readiness.get("capture_interface"):
        failures.append("visit {} capture interface differs from its ready route".format(
            visit_index))
    if not re.fullmatch(r"B26-eth\d+", client_device or ""):
        failures.append("visit {} client route device is not a GS26 satellite veth".format(
            visit_index))
    if not re.fullmatch(r"B27-eth\d+", egress_device or ""):
        failures.append("visit {} return route device is not a GS27 satellite veth".format(
            visit_index))
    samples = readiness.get("route_samples", [])
    if len(samples) < 2:
        failures.append("visit {} has too few stable route samples".format(visit_index))
    else:
        times = [sample.get("sampled_monotonic") for sample in samples]
        stable_start = None
        if any(not isinstance(value, (int, float)) for value in times):
            failures.append("visit {} stable route sample times are invalid".format(
                visit_index))
        else:
            stable_start = readiness.get("route_stability_start_monotonic")
            stable_start = (stable_start if isinstance(stable_start, (int, float))
                            else min(times))
            stable_end = readiness.get("route_stability_end_monotonic")
            stable_end = (stable_end if isinstance(stable_end, (int, float))
                          else max(times))
            if stable_end - stable_start < required_seconds:
                failures.append("visit {} stable route samples span less than required".format(
                    visit_index))
        for sample in samples:
            forward = sample.get("client_to_egress", {})
            reverse = sample.get("egress_to_client", {})
            if (forward.get("satellite_route") is not True
                    or reverse.get("satellite_route") is not True
                    or forward.get("device") != client_device
                    or reverse.get("device") != egress_device):
                failures.append("visit {} stable route samples change route or leave satellite path".format(
                    visit_index))
                break
        monitor = summary.get("route_monitor", {})
        sample_path_value = monitor.get("sample_path")
        if not sample_path_value:
            failures.append("visit {} route monitor is missing for stable-window verification".format(
                visit_index))
        else:
            sample_path = resolve_artifact(sample_path_value, run_dir)
            if not sample_path.is_file():
                failures.append("visit {} route-monitor sample file is missing".format(
                    visit_index))
            else:
                try:
                    monitor_samples = [json.loads(line) for line in
                                       sample_path.read_text(encoding="utf-8").splitlines()
                                       if line.strip()]
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    monitor_samples = []
                    failures.append("visit {} route-monitor samples cannot be read: {}".format(
                        visit_index, exc))
                if (not monitor.get("sample_sha256")
                        or sha256_file(sample_path) != monitor.get("sample_sha256")):
                    failures.append("visit {} route-monitor sample hash is missing or mismatched".format(
                        visit_index))
                if monitor.get("sample_count") != len(monitor_samples):
                    failures.append("visit {} route-monitor sample count differs from summary".format(
                        visit_index))
                recheck = readiness.get(
                    "route_recheck_immediately_before_capture", {})
                evidence_start = readiness.get(
                    "route_stability_start_monotonic")
                evidence_start = (evidence_start if isinstance(
                    evidence_start, (int, float)) else stable_start)
                monitor_end = recheck.get("sampled_monotonic")
                if isinstance(evidence_start, (int, float)) and isinstance(
                        monitor_end, (int, float)):
                    selected = [sample for sample in monitor_samples
                                if evidence_start <= sample.get(
                                    "sampled_monotonic", -1) <= monitor_end]
                    monitor_times = [float(sample["sampled_monotonic"])
                                     for sample in selected]
                    coverage_times = [float(evidence_start)] + monitor_times + [
                        float(monitor_end)]
                    max_gap = max((right - left for left, right in zip(
                        coverage_times, coverage_times[1:])),
                        default=float("inf"))
                    if (not selected or max_gap > 2.5
                            or monitor_end - evidence_start < required_seconds):
                        failures.append("visit {} one-second route monitor does not cover the required stable pre-capture interval".format(
                            visit_index))
                    elif any(
                            sample.get("client_to_egress", {}).get(
                                "satellite_route") is not True
                            or sample.get("egress_to_client", {}).get(
                                "satellite_route") is not True
                            or sample.get("client_to_egress", {}).get(
                                "device") != client_device
                            or sample.get("egress_to_client", {}).get(
                                "device") != egress_device
                            for sample in selected):
                        failures.append("visit {} one-second route monitor changed route during the stable pre-capture interval".format(
                            visit_index))
                else:
                    failures.append("visit {} route-ready stability interval markers are invalid".format(
                        visit_index))
    attempts = readiness.get("route_attempt_samples", [])
    attempts_hash = hashlib.sha256(json.dumps(
        attempts, sort_keys=True).encode("utf-8")).hexdigest()
    if len(attempts) != readiness.get("attempt_count") or attempts_hash != readiness.get(
            "attempt_sample_sha256"):
        failures.append("visit {} route-readiness attempt samples fail count or hash verification".format(
            visit_index))
    for audit_name in ("offload_audit_at_route_entry",
                       "offload_audit_immediately_before_capture"):
        audit = readiness.get(audit_name, {}).get("endpoints", {})
        if audit.get("mode") != "disable_path" or audit.get(
                "verified_disabled") is not True:
            failures.append("visit {} {} did not verify active path offloads disabled".format(
                visit_index, audit_name))
            continue
        if len(audit.get("endpoints", [])) != 4:
            failures.append("visit {} {} does not cover four path endpoints".format(
                visit_index, audit_name))
        endpoint_interfaces = {endpoint.get("role"): endpoint.get("interface")
                               for endpoint in audit.get("endpoints", [])}
        expected_peer = re.fullmatch(r"B26-eth(\d+)", client_device or "")
        expected_return_peer = re.fullmatch(r"B27-eth(\d+)", egress_device or "")
        if expected_peer and expected_return_peer:
            expected_interfaces = {
                "GS26_capture_interface": client_device,
                "next_hop_veth_peer": "B{}-eth26".format(expected_peer.group(1)),
                "GS27_return_sender_interface": egress_device,
                "GS27_return_next_hop_veth_peer": "B{}-eth27".format(
                    expected_return_peer.group(1)),
            }
            if any(endpoint_interfaces.get(role) != expected
                   for role, expected in expected_interfaces.items()):
                failures.append("visit {} {} audited different interfaces from the stable route".format(
                    visit_index, audit_name))
        for endpoint in audit.get("endpoints", []):
            features = endpoint.get("after", {}).get("features", {})
            if any(features.get(feature, {}).get("state") != "off"
                   for feature in OFFLOAD_FEATURES):
                failures.append("visit {} {} leaves a required offload enabled".format(
                    visit_index, audit_name))
                break
    recheck = readiness.get("route_recheck_immediately_before_capture", {})
    if (recheck.get("client_to_egress", {}).get("device") != client_device
            or recheck.get("egress_to_client", {}).get("device") != egress_device
            or recheck.get("client_to_egress", {}).get("satellite_route") is not True
            or recheck.get("egress_to_client", {}).get("satellite_route") is not True):
        failures.append("visit {} route changed at the pre-capture recheck".format(
            visit_index))
    visits = summary.get("browser_summary", {}).get("visits", [])
    visit = visits[0] if visits else {}
    start_ack = (ack_override if ack_override is not None else
                 visit.get("capture_window", {}).get("start_ack", {}))
    ack_monotonic = start_ack.get("tcpdump_ready_monotonic")
    if ack_monotonic is None:
        ack_monotonic = start_ack.get("route_ready_monotonic")
    if (start_ack.get("route_readiness") != readiness
            or not isinstance(ack_monotonic, (int, float))
            or ack_monotonic
            < recheck.get("sampled_monotonic", float("inf"))):
        failures.append("visit {} capture start acknowledgement does not follow its route-ready evidence".format(
            visit_index))
    return failures


def dynamic_route_offload_failures(summary, run_dir, visits):
    if not is_per_visit_v7_package(summary, visits):
        return []
    failures = []
    monitor = summary.get("route_monitor", {})
    sample_path_value = monitor.get("sample_path")
    if not sample_path_value:
        return ["dynamic route offload evidence has no route-sample path"]
    sample_path = resolve_artifact(sample_path_value, run_dir)
    intervention_path = sample_path.parent / "dynamic_offload_interventions.jsonl"
    if not intervention_path.is_file():
        return ["dynamic route offload intervention record is missing"]
    try:
        samples = [json.loads(line) for line in
                   sample_path.read_text(encoding="utf-8").splitlines()
                   if line.strip()]
        interventions = [json.loads(line) for line in
                        intervention_path.read_text(encoding="utf-8").splitlines()
                        if line.strip()]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return ["dynamic route offload evidence cannot be read: {}".format(exc)]
    visit = visits[0]
    window = visit.get("capture_window", {})
    start_monotonic = (window.get("start_ack") or {}).get(
        "tcpdump_ready_monotonic")
    start_utc = (window.get("start_ack") or {}).get("tcpdump_ready_utc")
    end_monotonic = (window.get("stop_ack") or {}).get(
        "tcpdump_stopped_monotonic")
    if (not isinstance(start_monotonic, (int, float))
            or not isinstance(end_monotonic, (int, float)) or not start_utc):
        return ["visit lacks route-window markers for dynamic offload audit"]
    selected = [sample for sample in samples
                if start_monotonic <= sample.get("sampled_monotonic", -1)
                <= end_monotonic]
    active_devices = sorted({
        sample.get("egress_to_client", {}).get("device")
        for sample in selected
        if sample.get("egress_to_client", {}).get("satellite_route") is True
        and sample.get("egress_to_client", {}).get("device")
    })
    initial_devices = {
        endpoint.get("interface")
        for endpoint in summary.get("packetization_offload_audit", {}).get(
            "endpoints", [])
        if endpoint.get("role") == "GS27_return_sender_interface"
        and endpoint.get("after", {}).get("returncode") == 0
        and all(endpoint.get("after", {}).get("features", {}).get(
            feature, {}).get("state") == "off" for feature in OFFLOAD_FEATURES)
    }
    for device in active_devices:
        if device in initial_devices:
            continue
        match = re.fullmatch(r"B27-eth(\d+)", device)
        if not match:
            failures.append("active return route interface is not auditable: "
                            + device)
            continue
        peer_interface = "B{}-eth27".format(match.group(1))
        valid_records = []
        for record in interventions:
            if record.get("observed_utc", "") > start_utc:
                continue
            by_role = {endpoint.get("role"): endpoint
                       for endpoint in record.get("interfaces", [])}
            sender = by_role.get("GS27_return_sender_interface", {})
            peer = by_role.get("GS27_return_next_hop_veth_peer", {})
            if sender.get("interface") != device or peer.get(
                    "interface") != peer_interface:
                continue
            endpoints_ok = True
            for endpoint in (sender, peer):
                if (endpoint.get("change", {}).get("returncode") != 0
                        or endpoint.get("after", {}).get("returncode") != 0):
                    endpoints_ok = False
                    break
                states = {}
                for line in endpoint.get("after", {}).get("text", "").splitlines():
                    if ":" not in line:
                        continue
                    name, value = line.split(":", 1)
                    if name.strip() in OFFLOAD_FEATURES:
                        states[name.strip()] = value.strip().split()[0]
                if any(states.get(feature) != "off" for feature in OFFLOAD_FEATURES):
                    endpoints_ok = False
                    break
            if endpoints_ok:
                valid_records.append(record)
        if not valid_records:
            failures.append("{} and {} lack verified offload disable evidence before "
                            "this capture window".format(device, peer_interface))
    return failures


def read_trace(path, duration):
    times = []
    directions = []
    profiles = {1: [0] * PROFILE_BINS, -1: [0] * PROFILE_BINS}
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            fields = line.rstrip("\r\n").split("\t")
            if len(fields) != 2:
                raise ValueError("trace line {} does not have two tab-separated fields".format(
                    line_number))
            timestamp = float(fields[0])
            direction = int(fields[1])
            if not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError("trace line {} has invalid timestamp".format(line_number))
            if direction not in (-1, 1):
                raise ValueError("trace line {} has invalid direction".format(line_number))
            if times and timestamp < times[-1]:
                raise ValueError("trace timestamps decrease at line {}".format(line_number))
            if timestamp > duration + 0.01:
                raise ValueError("trace timestamp exceeds the capture window")
            fraction = 0 if duration <= 0 else min(timestamp / duration, 1.0)
            bin_index = min(int(fraction * PROFILE_BINS), PROFILE_BINS - 1)
            profiles[direction][bin_index] += 1
            times.append(timestamp)
            directions.append(direction)
    return times, directions, profiles


def target_circuit_paths(visit):
    circuit_ids = sorted(set(str(value) for value in
                             visit.get("target_circuit_ids", []) if value))
    events = visit.get("target_circuit_path_events", [])
    paths = []
    failures = []
    if not circuit_ids:
        return paths, ["measured target stream has no circuit ID"]
    for circuit_id in circuit_ids:
        built = [event for event in events
                 if str(event.get("circuit_id", "")) == circuit_id
                 and event.get("status") == "BUILT"]
        if not built:
            failures.append("target circuit {} has no BUILT path event".format(
                circuit_id))
            continue
        hops = built[-1].get("path", [])
        fingerprints = [str(hop.get("fingerprint")) for hop in hops
                        if isinstance(hop, dict) and hop.get("fingerprint")]
        if len(fingerprints) < 3 or len(fingerprints) != len(hops):
            failures.append("target circuit {} has an incomplete relay path".format(
                circuit_id))
        paths.append({
            "circuit_id": circuit_id,
            "status": built[-1].get("status"),
            "relay_fingerprints": fingerprints,
            "relay_count": len(fingerprints),
        })
    return paths, failures


def audit_one(run_dir):
    run_dir = Path(run_dir).resolve()
    failures = []
    target_paths = []
    summary_path = run_dir / "summary.json"
    if not summary_path.is_file():
        return {"run_dir": str(run_dir), "passed": False,
                "failures": ["summary.json is missing"]}
    summary = load_json(summary_path)
    protocol = summary.get("acquisition_protocol")
    if not protocol:
        failures.append("acquisition_protocol metadata is missing")
        protocol = {}
    protocol_path = run_dir / "acquisition_protocol.json"
    if not protocol_path.is_file():
        failures.append("acquisition_protocol.json is missing")
    elif load_json(protocol_path) != protocol:
        failures.append("summary and acquisition_protocol.json disagree")
    protocol_id = protocol.get("protocol_id")
    reported_protocol_id = protocol_id
    browser = summary.get("browser_summary", {})
    visits = browser.get("visits", [])
    if protocol_id not in PROTOCOL_IDS:
        failures.append("unexpected or missing protocol_id")
    if protocol_id in PHASE_RESOURCE_PROTOCOL_IDS:
        if protocol.get("topology_phase_and_ground_station_qdisc_monitoring") is not True:
            failures.append("v17 does not declare topology-phase and qdisc monitoring")
        if protocol.get("browser_resource_timing_snapshots") != \
                "at_visible_content_readiness_and_fixed_window_end":
            failures.append("v17 does not declare both browser resource-timing snapshots")
        monitor_windows = summary.get("route_monitor", {}).get("visit_windows", [])
        for visit_index, visit in enumerate(visits, 1):
            for key in ("resource_timing_at_readiness",
                        "resource_timing_at_window_end"):
                snapshot = visit.get(key, {})
                if snapshot.get("available") is not True or not isinstance(
                        snapshot.get("resources"), list):
                    failures.append("visit {} lacks {}".format(visit_index, key))
            capture_window = visit.get("capture_window", {})
            start = (capture_window.get("start_ack") or {}).get(
                "tcpdump_ready_monotonic")
            end = (capture_window.get("stop_ack") or {}).get(
                "tcpdump_stopped_monotonic")
            matches = [item for item in monitor_windows
                       if item.get("capture_start_monotonic") == start
                       and item.get("capture_stop_monotonic") == end]
            if len(matches) != 1:
                failures.append("visit {} lacks a unique v17 topology-phase window".format(
                    visit_index))
                continue
            phase = matches[0].get("topology_phase_seconds")
            qdiscs = matches[0].get("ground_station_qdisc_delay_ms", {})
            if not isinstance(phase, dict) or not isinstance(
                    phase.get("minimum"), (int, float)):
                failures.append("visit {} lacks dynamic topology-phase samples".format(
                    visit_index))
            for direction in ("client_to_egress", "egress_to_client"):
                if qdiscs.get(direction, {}).get("sample_count", 0) < 1:
                    failures.append("visit {} lacks {} active qdisc delay samples".format(
                        visit_index, direction))
    if protocol_id in MATCHED_PHASE_PROTOCOL_IDS:
        phase_spec = protocol.get("matched_dynamic_phase", {})
        route_spec = protocol.get("route_readiness", {})
        warmup_spec = protocol.get("premeasurement_site_warmup", {})
        exact_values = {
            "visits_per_dynamic_topology": 1,
            "single_tor_process_for_all_visits": True,
            "single_browser_process_for_all_visits": True,
            "one_fresh_browser_profile_per_visit": True,
            "persistent_browser_profile_for_all_visits":
                protocol.get("persistent_browser_profile_for_all_visits") is False,
            "single_warmup_refresh_cache_configuration": (
                (protocol_id in (V22_PROTOCOL_ID, V23_PROTOCOL_ID)
                 or protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS
                 and protocol.get("browser_cache_enabled_for_warmup_refresh") is True
                 and protocol.get("cache_disabled_for_warmup_refresh") is False
                 and protocol.get("cache_mode") == "enabled_from_warmup_to_single_refresh"
                 and browser.get("browser_cache_enabled_between_visits") is True)
                or (protocol_id != V22_PROTOCOL_ID
                    and protocol.get("cache_disabled_for_warmup_refresh") is True
                    and protocol.get("cache_mode") == "disabled_for_single_warmup_refresh"
                    and browser.get("browser_cache_enabled_between_visits") is False)),
            "warmup_page_retained_for_measurement":
                protocol.get("warmup_page_retained_for_measurement") is True
                and protocol.get("target_page_reused_between_measured_visits") is False
                and protocol.get("measured_site_navigation_action") == "same_tab_refresh",
            "phase_origin": phase_spec.get("phase_origin")
                == "dynamic_emulation_start.started_monotonic",
            "phase_gate": phase_spec.get("gate")
                == ("audit_current_route_before_phase_window_then_verify_phase_aligned_route_qdisc_monitor_gate"
                    if protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS else
                    "verify_route_and_offloads_then_phase_aligned_route_qdisc_monitor_gate"),
            "phase_route_offload_audit_lead_seconds": (
                phase_spec.get("phase_route_offload_audit_lead_seconds") == 10
                if protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS else
                phase_spec.get("phase_route_offload_audit_lead_seconds") is None),
            "fixed_capture_phase":
                phase_spec.get("target_capture_start_seconds") == 120
                and phase_spec.get("tolerance_seconds") == 1.5,
            "fixed_capture_window": protocol.get("page_readiness", {}).get(
                "fixed_window_seconds_after_navigation_start") == 85,
            "route_gate": route_spec.get("stable_seconds_required") == 5
                and route_spec.get("wait_timeout_seconds") == 90
                and route_spec.get("stability_evidence_source")
                    == ("phase_aligned_one_second_route_monitor_after_phase_path_offload_audit"
                        if protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS else
                        "phase_aligned_one_second_route_monitor_after_prior_path_offload_audit")
                and route_spec.get("required_before_initial_tor_check") is True
                and route_spec.get("same_forward_and_return_route_devices_required") is True
                and route_spec.get("active_path_offloads_reverified_before_each_capture") is True,
            "warmup_contract": warmup_spec.get("enabled") is True
                and warmup_spec.get("before_each_measured_visit") is False
                and warmup_spec.get("settle_seconds_after_page_ready") == 25
                and warmup_spec.get("captured_as_a_trace") is False
                and warmup_spec.get("cookies_and_site_storage_cleared_after_warmup") is True
                and warmup_spec.get("target_page_retained_after_warmup") is True,
            "deferred_dynamic_start": protocol.get("dynamic_emulation_start_policy")
                == ("after_uncaptured_site_warmup_before_measured_capture"
                    if protocol_id == V23_PROTOCOL_ID
                    or protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS else
                    "after_initial_tor_check_before_uncaptured_site_warmup")
                and protocol.get("initial_tor_check_topology_state")
                == "verified_initial_satellite_route_before_dynamic_updates",
        }
        for check, passed in exact_values.items():
            if not passed:
                failures.append("matched-phase protocol requirement failed: " + check)
        if protocol.get("repeat_design") != (
                "one_visit_per_independent_dynamic_topology_with_capture_phase_matched"):
            failures.append("matched-phase repeat design metadata is inconsistent")
        if protocol.get("topology_phase_and_ground_station_qdisc_monitoring") is not True:
            failures.append("matched-phase protocol does not declare dynamic phase and qdisc monitoring")
        if protocol.get("browser_resource_timing_snapshots") != (
                "at_visible_content_readiness_and_fixed_window_end"):
            failures.append("matched-phase protocol does not declare readiness and window-end resource snapshots")
        if protocol.get("cache_disabled_for_persistent_profile") is not False:
            failures.append("matched-phase protocol unexpectedly claims a persistent browser profile")
        if protocol.get("reuse_check_circuit_for_site_visit") is not True:
            failures.append("matched-phase protocol did not request reuse of the verified Tor-check circuit")
        if protocol_id in (V21_PROTOCOL_ID, V22_PROTOCOL_ID, V23_PROTOCOL_ID,
                           V24_PROTOCOL_ID, V25_PROTOCOL_ID, V26_PROTOCOL_ID,
                           V27_PROTOCOL_ID, *E_BROWSER_PROTOCOL_IDS):
            if protocol.get("target_circuit_path_fingerprints") != \
                    "CIRC_BUILT_path_for_each_measured_target_stream":
                failures.append("matched-phase protocol does not declare measured target-circuit path fingerprints")

        dynamic_start = summary.get("dynamic_emulation_start", {}).get(
            "started_monotonic")
        initial_check = browser.get("initial_tor_check", {})
        warmup = browser.get("site_warmup", {})
        initial_route = summary.get("route_readiness_before_tor_check", {})
        initial_route_ack = summary.get(
            "route_readiness_before_tor_check_ack", {})
        warmup_route = summary.get("warmup_route_readiness", {})
        warmup_ack = warmup.get("route_ready_ack", {})
        if (not isinstance(dynamic_start, (int, float))
                or initial_check.get("tor_check_passed") is not True
                or initial_check.get("check_stream_succeeded") is not True
                or initial_check.get("check_streams_closed_before_capture") is not True
                or initial_check.get("check_page_closed_before_capture") is not True
                or not isinstance(initial_check.get("tor_check_completed_monotonic"),
                                   (int, float))
                or dynamic_start < initial_check.get(
                    "tor_check_completed_monotonic", float("inf"))):
            failures.append("matched-phase initial Tor check did not pass before dynamic updates")
        if (initial_route.get("passed") is not True
                or initial_route_ack.get("ok") is not True):
            failures.append("matched-phase initial Tor check route gate did not pass")
        failures.extend(route_readiness_failures(
            summary, run_dir, readiness_override=initial_route,
            label="initial Tor check", ack_override=initial_route_ack))
        if (warmup.get("passed") is not True
                or warmup.get("captured_as_a_trace") is not False
                or warmup.get("page_loaded") is not True
                or warmup.get("page_content_ready") is not True
                or warmup.get("page_content_character_count", 0) < 40
                or warmup.get("http_status") != 200
                or warmup.get("site_state_cleared") is not True
                or warmup.get("target_page_retained_after_warmup") is not True
                or warmup.get("target_stream_succeeded") is not True
                or not warmup.get("target_stream_ids")):
            failures.append("matched-phase uncaptured warm-up failed its site and cleanup gates")
        if warmup.get("route_readiness") != warmup_route:
            failures.append("matched-phase warm-up route evidence differs from the run summary")
        failures.extend(route_readiness_failures(
            summary, run_dir, readiness_override=warmup_route,
            label="warmup", ack_override=warmup_ack))
        warmup_precedes_dynamic_start = protocol_id in (
            V23_PROTOCOL_ID,) + PHASE_ROUTE_REAUDIT_PROTOCOL_IDS
        warmup_completed = warmup.get("completed_monotonic")
        if (not isinstance(warmup_completed, (int, float))
                or not isinstance(dynamic_start, (int, float))
                or (warmup_precedes_dynamic_start
                    and warmup_completed > dynamic_start)
                or (not warmup_precedes_dynamic_start
                    and warmup_completed < dynamic_start)):
            expected_order = ("before" if warmup_precedes_dynamic_start
                              else "after")
            failures.append(
                "matched-phase warm-up did not complete {} dynamic-emulation start".format(
                    expected_order))

        if len(visits) == 1:
            visit = visits[0]
            window = visit.get("capture_window", {})
            start_ack = window.get("start_ack", {})
            gate = summary.get("capture_phase_gate_by_visit", {}).get("1")
            ack_gate = start_ack.get("dynamic_phase_gate")
            expected_actual = None
            start_monotonic = start_ack.get("tcpdump_ready_monotonic")
            tolerance = phase_spec.get("tolerance_seconds")
            target_phase = phase_spec.get("target_capture_start_seconds")
            if (isinstance(dynamic_start, (int, float))
                    and isinstance(start_monotonic, (int, float))):
                expected_actual = start_monotonic - dynamic_start
            phase_route_check = gate.get("phase_aligned_route_check", {}) if isinstance(
                gate, dict) else {}
            route_visit = summary.get("route_readiness_by_visit", {}).get("1", {})
            route_devices = route_visit.get("route_devices", {})
            phase_route_devices = phase_route_check.get("route_devices", {})
            if protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS:
                route_devices_for_phase = phase_route_devices
            else:
                route_devices_for_phase = route_devices
            phase_monitor_ok = False
            phase_audit_ok = protocol_id not in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS
            try:
                monitor = summary.get("route_monitor", {})
                sample_path = resolve_artifact(monitor["sample_path"], run_dir)
                samples = [json.loads(line) for line in
                           sample_path.read_text(encoding="utf-8").splitlines()
                           if line.strip()]
                required_stable = phase_spec.get("target_capture_start_seconds")
                stable_seconds = route_spec.get("stable_seconds_required")
                phase_start = dynamic_start + target_phase - stable_seconds
                check_end = phase_route_check.get(
                    "phase_interval_end_monotonic")
                selected_at_check = [sample for sample in samples
                                     if phase_start <= sample.get(
                                         "sampled_monotonic", -1) <= check_end]
                selected_through_capture = [sample for sample in samples
                                            if phase_start <= sample.get(
                                                "sampled_monotonic", -1)
                                            <= start_monotonic]

                def phase_samples_pass(selected, end_monotonic):
                    times = [phase_start] + [float(sample[
                        "sampled_monotonic"]) for sample in selected] + [
                            float(end_monotonic)]
                    max_gap = max((right - left for left, right in zip(
                        times, times[1:])), default=float("inf"))
                    routes_match = bool(selected) and all(
                        sample.get("client_to_egress", {}).get(
                            "satellite_route") is True
                        and sample.get("egress_to_client", {}).get(
                            "satellite_route") is True
                        and sample.get("client_to_egress", {}).get("device")
                            == route_devices_for_phase.get("client_to_egress")
                        and sample.get("egress_to_client", {}).get("device")
                            == route_devices_for_phase.get("egress_to_client")
                        for sample in selected)
                    qdiscs_ok = bool(selected) and all(
                        sample.get(direction, {}).get("qdisc")
                        and sample.get(direction, {}).get("qdisc_error") is None
                        for sample in selected
                        for direction in ("client_to_egress", "egress_to_client"))
                    latest_age = (end_monotonic - selected[-1].get(
                        "sampled_monotonic", -1) if selected else float("inf"))
                    return (routes_match and qdiscs_ok and max_gap <= 2.5
                            and latest_age <= 2.5), len(selected), max_gap

                recorded_pass, recorded_count, recorded_gap = phase_samples_pass(
                    selected_at_check, check_end)
                capture_pass, _, _ = phase_samples_pass(
                    selected_through_capture, start_monotonic)
                if protocol_id in PHASE_ROUTE_REAUDIT_PROTOCOL_IDS:
                    phase_audit = phase_route_check.get(
                        "phase_route_offload_audit", {})
                    phase_audit_sample = phase_route_check.get(
                        "phase_route_audit_sample", {})
                    phase_audit_completed = phase_route_check.get(
                        "phase_route_offload_audit_completed_monotonic")
                    audit_endpoints = phase_audit.get("endpoints", {})
                    sample_forward = phase_audit_sample.get(
                        "client_to_egress", {})
                    sample_reverse = phase_audit_sample.get(
                        "egress_to_client", {})
                    phase_audit_time = phase_audit_sample.get(
                        "sampled_monotonic")
                    phase_start = dynamic_start + target_phase - stable_seconds
                    expected_audit_time = (
                        phase_start - phase_spec.get(
                            "phase_route_offload_audit_lead_seconds", float("inf")))
                    phase_audit_ok = (
                        phase_route_check.get("route_offload_audit_reverified") is True
                        and phase_route_check.get(
                            "route_offload_audit_completed_before_window") is True
                        and phase_route_check.get(
                            "phase_route_offload_audit_lead_seconds") == 10
                        and audit_endpoints.get("verified_disabled") is True
                        and phase_audit.get("client_route_device")
                            == route_devices_for_phase.get("client_to_egress")
                        and phase_audit.get("egress_route_device")
                            == route_devices_for_phase.get("egress_to_client")
                        and sample_forward.get("satellite_route") is True
                        and sample_reverse.get("satellite_route") is True
                        and sample_forward.get("device")
                            == route_devices_for_phase.get("client_to_egress")
                        and sample_reverse.get("device")
                            == route_devices_for_phase.get("egress_to_client")
                        and bool(sample_forward.get("qdisc"))
                        and sample_forward.get("qdisc_error") is None
                        and bool(sample_reverse.get("qdisc"))
                        and sample_reverse.get("qdisc_error") is None
                        and isinstance(phase_audit_time, (int, float))
                        and isinstance(phase_audit_completed, (int, float))
                        and phase_audit_time <= phase_audit_completed
                        and phase_audit_completed <= phase_start
                        and abs(phase_audit_time - expected_audit_time) <= 2.5)
                phase_monitor_ok = (
                    recorded_pass and capture_pass
                    and phase_audit_ok
                    and phase_route_check.get("passed") is True
                    and phase_route_check.get("sample_count") == recorded_count
                    and phase_route_check.get("routes_match_audited_devices") is True
                    and phase_route_check.get("qdisc_samples_complete") is True
                    and phase_route_check.get("maximum_sample_gap_seconds") is not None
                    and abs(phase_route_check.get("maximum_sample_gap_seconds")
                            - recorded_gap) <= 0.05
                    and phase_route_check.get("phase_interval_start_monotonic")
                        == phase_start
                    and isinstance(check_end, (int, float))
                    and abs(check_end - (dynamic_start + target_phase)) <= tolerance
                    and check_end <= start_monotonic
                    and start_monotonic - check_end <= 2.5)
            except (KeyError, OSError, ValueError, TypeError,
                    json.JSONDecodeError):
                phase_monitor_ok = False
            if (not isinstance(gate, dict) or not isinstance(ack_gate, dict)
                    or gate != ack_gate
                    or gate.get("passed") is not True
                    or phase_route_check.get("passed") is not True
                    or not phase_monitor_ok
                    or expected_actual is None
                    or abs(expected_actual - target_phase) > tolerance
                    or abs(gate.get("actual_capture_start_seconds", -1)
                           - expected_actual) > 0.05
                    or not isinstance(gate.get("capture_started_monotonic"),
                                       (int, float))
                    or abs(gate.get("capture_started_monotonic")
                           - start_monotonic) > 0.05):
                failures.append("matched-phase capture did not start in its requested dynamic phase")
            if (visit.get("site_navigation_action") != "refresh"
                    or visit.get("check_page_closed_before_capture") is not True
                    or visit.get("check_streams_closed_before_capture") is not True
                    or visit.get("target_stream_succeeded") is not True
                    or visit.get("target_stream_evidence_source")
                        != "measured_visit_stream"
                    or visit.get("site_cookies_cleared_after_visit") is not True
                    or visit.get("site_storage_cleared_after_visit") is not True):
                failures.append("matched-phase measured refresh lacks clean Tor-stream or browser-state evidence")
            if route_visit != start_ack.get("route_readiness"):
                failures.append("matched-phase capture route evidence differs from the run summary")
            failures.extend(route_readiness_failures(
                summary, run_dir, readiness_override=route_visit,
                label="visit_1", ack_override={
                    "ok": start_ack.get("ok"),
                    "tcpdump_ready_monotonic": start_ack.get(
                        "tcpdump_ready_monotonic"),
                    "route_readiness": route_visit}))
        else:
            failures.append("matched-phase run does not contain exactly one measured visit")
        if protocol_id in (V21_PROTOCOL_ID, V22_PROTOCOL_ID, V23_PROTOCOL_ID,
                           V24_PROTOCOL_ID, V25_PROTOCOL_ID,
                           V26_PROTOCOL_ID, V27_PROTOCOL_ID,
                           *E_BROWSER_PROTOCOL_IDS) and len(visits) == 1:
            _paths, path_failures = target_circuit_paths(visits[0])
            failures.extend("matched-phase circuit-path audit: " + item
                            for item in path_failures)
        if protocol_id in (V26_PROTOCOL_ID, V27_PROTOCOL_ID,
                           E_BROWSER_PROTOCOL_ID):
                if protocol.get("tor_path_control") != V26_TOR_PATH_CONTROL:
                    failures.append("fixed-path diagnostic metadata differs from its registered Tor fingerprints")
                expected_browser_control = {
                    key: value for key, value in V26_TOR_PATH_CONTROL.items()
                    if key not in ("expected_target_relay_fingerprints",
                                   "entry_node_pinned")
                }
                expected_browser_control["torrc_configuration_verified"] = True
                if browser.get("tor_path_constraints") != expected_browser_control:
                    failures.append("fixed-path browser summary does not prove the registered Tor options were applied and parsed")
                for target_path in _paths:
                    if target_path.get("relay_fingerprints") != \
                            V26_TOR_PATH_CONTROL["expected_target_relay_fingerprints"]:
                        failures.append(
                            "fixed-path diagnostic target circuit {} differs from the registered full relay path".format(
                                target_path.get("circuit_id")))
                if protocol_id == V26_PROTOCOL_ID and protocol.get(
                        "bridge_selection") is not None:
                    failures.append("V26 unexpectedly changes the configured bridge list")
                if protocol_id in (V27_PROTOCOL_ID, *E_BROWSER_PROTOCOL_IDS):
                    bridge_selection = protocol.get("bridge_selection") or {}
                    source_bridge_hash = str(bridge_selection.get(
                        "source_file_sha256", ""))
                    selected_bridge_hash = str(bridge_selection.get(
                        "selected_file_sha256", ""))
                    expected_shape = (
                        bridge_selection.get("mode") == "single_configured_webtunnel_bridge"
                        and bridge_selection.get("bridge_fingerprint")
                            == V27_BRIDGE_FINGERPRINT
                        and bridge_selection.get("selected_line_count") == 1
                        and bridge_selection.get("selected_file_deleted_after_run") is True
                        and bool(re.fullmatch(r"[0-9a-f]{64}", source_bridge_hash))
                        and bool(re.fullmatch(r"[0-9a-f]{64}", selected_bridge_hash))
                    )
                    if not expected_shape:
                        failures.append("V27 bridge-selection metadata is incomplete or inconsistent")
                    if (summary.get("bridge_selection_file_deleted_verified") is not True
                            or browser.get("bridge_count") != 1
                            or browser.get("bridge_configuration_sha256")
                                != bridge_selection.get("selected_file_sha256")):
                        failures.append("V27 did not prove a single registered bridge was used and removed after the run")
                    source_path_value = bridge_selection.get("source_file_path")
                    source_path = Path(source_path_value) if source_path_value else None
                    if not source_path or not source_path.is_file():
                        failures.append("V27 source bridge file is unavailable for selection audit")
                    else:
                        if sha256_file(source_path) != bridge_selection.get(
                                "source_file_sha256"):
                            failures.append("V27 source bridge file hash differs from the registered input")
                        source_lines = source_path.read_text(
                            encoding="utf-8").splitlines()
                        matching_lines = []
                        for line in source_lines:
                            fingerprints = re.findall(
                                r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])",
                                line)
                            if V27_BRIDGE_FINGERPRINT in [
                                    item.upper() for item in fingerprints]:
                                matching_lines.append(line.rstrip() + "\n")
                        if (len(matching_lines) != 1 or hashlib.sha256(
                                matching_lines[0].encode("utf-8")).hexdigest()
                                != bridge_selection.get("selected_file_sha256")):
                            failures.append("V27 selected bridge hash does not match the uniquely registered entry line")
        if protocol_id in E_BROWSER_ENTRY_ONLY_PROTOCOL_IDS and len(visits) == 1:
            if protocol.get("tor_path_control") != {
                    "mode": "pinned_bridge_entry_only_default_middle_exit",
                    "entry_fingerprint": V27_BRIDGE_FINGERPRINT,
                    "middle_exit_selection": "Tor default selection",
                    "torrc_options": []}:
                failures.append("E entry-only protocol must pin only the configured bridge")
            if (browser.get("tor_path_constraints") is not None
                    or browser.get("tor_path_constraints") == {}):
                failures.append("E entry-only protocol unexpectedly applied fixed middle/exit constraints")
            for target_path in _paths:
                fingerprints = target_path.get("relay_fingerprints", [])
                if (len(fingerprints) < 3
                        or fingerprints[0].upper() != V27_BRIDGE_FINGERPRINT):
                    failures.append(
                        "E entry-only target circuit {} does not show the registered entry bridge and complete relay path".format(
                            target_path.get("circuit_id")))
    if (reported_protocol_id in PHASE_RESOURCE_PROTOCOL_IDS
            and reported_protocol_id not in MATCHED_PHASE_PROTOCOL_IDS):
        protocol_id = "starrynet-tor-site-window-v14"
    if protocol_id in E_BROWSER_PROTOCOL_IDS:
        site_url = protocol.get("site_url", "")
        parsed_site_url = urlsplit(site_url)
        if (parsed_site_url.scheme != "https" or not parsed_site_url.hostname
                or parsed_site_url.username or parsed_site_url.password):
            failures.append("E browser target is not an absolute HTTPS URL")
        if summary.get("site_url") != site_url:
            failures.append("run summary and E browser protocol target URLs differ")
        expected_e_domain = {
            E_BROWSER_V1_1_PROTOCOL_ID: E_BROWSER_V1_1_DOMAIN,
            E_BROWSER_V1_2_PROTOCOL_ID: E_BROWSER_V1_2_DOMAIN,
            E_BROWSER_V1_3_PROTOCOL_ID: E_BROWSER_V1_3_DOMAIN,
            E_BROWSER_V1_4_PROTOCOL_ID: E_BROWSER_V1_4_DOMAIN,
        }.get(protocol_id, "E_BROWSER_TOR")
        if (summary.get("data_domain") != expected_e_domain
                or protocol.get("data_domain") != expected_e_domain):
            failures.append("E browser data-domain namespace is missing or inconsistent")
        for key in ("page_id", "class_label", "source_rank", "source_domain"):
            if summary.get(key) != protocol.get(key):
                failures.append("run summary and E browser protocol {} differ".format(key))
        if not summary.get("sample_id"):
            failures.append("E browser sample_id is missing")
        if not re.fullmatch(r"[0-9a-f]{64}",
                            str(protocol.get("source_list_sha256", ""))):
            failures.append("E browser frozen source-list hash is missing or malformed")
        if protocol_id in (E_BROWSER_V1_2_PROTOCOL_ID, E_BROWSER_V1_3_PROTOCOL_ID,
                           E_BROWSER_V1_4_PROTOCOL_ID):
            runtime_inputs = protocol.get("runtime_inputs", {})
            if (runtime_inputs.get("helper_image_id")
                    != E_BROWSER_V1_2_HELPER_IMAGE_ID):
                failures.append("E v1.2/v1.3/v1.4 helper image ID differs from the frozen runtime")
            if protocol.get("warmup_redirect_policy") != \
                    E_BROWSER_V1_2_WARMUP_REDIRECT_POLICY:
                failures.append("E v1.2/v1.3/v1.4 canonical warm-up redirect policy differs from the frozen contract")
            warmups = browser.get("site_warmups", [])
            if len(warmups) != 1:
                failures.append("E v1.2/v1.3/v1.4 must report exactly one uncaptured warm-up")
            else:
                warmup = warmups[0]
                requested_host = (urlsplit(site_url).hostname or "").lower()
                target_domain = (requested_host[4:]
                                 if requested_host.startswith("www.")
                                 else requested_host)
                warmup_url = warmup.get("warmup_final_url") or ""
                retained_url = warmup.get("retained_url_after_state_clear") or ""
                warmup_parts = urlsplit(warmup_url)
                retained_parts = urlsplit(retained_url)
                warmup_host = (warmup_parts.hostname or "").lower()
                retained_host = (retained_parts.hostname or "").lower()
                if (warmup_parts.scheme.lower() != "https"
                        or warmup.get("warmup_final_url_https") is not True
                        or not (warmup_host == target_domain
                                or warmup_host.endswith("." + target_domain))):
                    failures.append("E v1.2/v1.3/v1.4 warm-up final URL left the frozen target domain")
                warmup_path = warmup_parts.path.rstrip("/") or "/"
                retained_path = retained_parts.path.rstrip("/") or "/"
                if (warmup.get("target_page_retained_after_warmup") is not True
                        or retained_parts.scheme.lower() != "https"
                        or retained_host != warmup_host
                        or retained_path != warmup_path):
                    failures.append("E v1.2/v1.3/v1.4 did not retain the same canonical target page for refresh")
    elif protocol.get("site_url") != EXPECTED_URL:
        failures.append("site URL differs from the fixed protocol")
    if protocol.get("topology_mode") != "dynamic":
        failures.append("topology is not dynamic")
    if protocol.get("offload_mode") != "disable_path":
        failures.append("offload mode is not disable_path")
    if protocol.get("capture_peer_veth") is not False:
        failures.append("peer capture setting differs from the fixed protocol")
    if protocol.get("reuse_check_circuit_for_site_visit") is not True:
        failures.append("check-circuit reuse is not enabled")
    if protocol_id in ("starrynet-tor-site-window-v3",
                       "starrynet-tor-site-window-v4",
                       "starrynet-tor-site-window-v5",
                       "starrynet-tor-site-window-v6",
                       "starrynet-tor-site-window-v7",
                       "starrynet-tor-site-window-v8",
                       "starrynet-tor-site-window-v9",
                       "starrynet-tor-site-window-v10",
                       "starrynet-tor-site-window-v11",
                       "starrynet-tor-site-window-v12",
                       "starrynet-tor-site-window-v13",
                       "starrynet-tor-site-window-v14",
                       "starrynet-tor-site-window-v15"):
        if protocol.get("visits_per_dynamic_topology") != 3:
            failures.append("v3 repeat set does not contain three same-topology visits")
        if protocol.get("single_tor_process_for_all_visits") is not True:
            failures.append("v3 visits did not share one Tor process")
        if protocol.get("reuse_tor_circuit_between_visits_requested") is not True:
            failures.append("v3 did not request Tor circuit reuse between visits")
        expected_design = {
            "starrynet-tor-site-window-v3":
                "same_dynamic_topology_and_tor_process_fresh_profile_per_visit",
            "starrynet-tor-site-window-v4":
                "same_dynamic_topology_and_tor_process_persistent_browser_profile",
            "starrynet-tor-site-window-v5":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v6":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v7":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v8":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v9":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v10":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v11":
                "same_dynamic_topology_tor_process_browser_profile_and_browser_process",
            "starrynet-tor-site-window-v12":
                "same_dynamic_topology_tor_process_browser_profile_and_target_page_refreshes",
            "starrynet-tor-site-window-v13":
                "same_dynamic_topology_tor_process_browser_profile_and_target_page_refreshes",
            "starrynet-tor-site-window-v14":
                "same_dynamic_topology_tor_process_browser_profile_and_target_page_refreshes",
            "starrynet-tor-site-window-v15":
                "same_dynamic_topology_tor_process_browser_profile_and_target_page_refreshes",
        }[protocol_id]
        if protocol.get("repeat_design") != expected_design:
            failures.append("repeat design metadata is inconsistent")
        if protocol_id in ("starrynet-tor-site-window-v4",
                           "starrynet-tor-site-window-v5",
                           "starrynet-tor-site-window-v6",
                           "starrynet-tor-site-window-v7",
                           "starrynet-tor-site-window-v8",
                           "starrynet-tor-site-window-v9",
                           "starrynet-tor-site-window-v10",
                           "starrynet-tor-site-window-v11",
                           "starrynet-tor-site-window-v12",
                           "starrynet-tor-site-window-v13",
                           "starrynet-tor-site-window-v14",
                           "starrynet-tor-site-window-v15"):
            if protocol.get("persistent_browser_profile_for_all_visits") is not True:
                failures.append("repeat set did not retain one browser profile across visits")
            if protocol_id == "starrynet-tor-site-window-v15":
                if (protocol.get("cache_disabled_for_persistent_profile") is not False
                        or protocol.get("cache_enabled_for_persistent_profile") is not True
                        or protocol.get("cache_mode") != "persistent_between_measured_visits"):
                    failures.append("v15 does not retain the browser HTTP cache between visits")
            elif protocol.get("cache_disabled_for_persistent_profile") is not True:
                failures.append("browser cache was not disabled")
        if protocol_id in ("starrynet-tor-site-window-v5",
                           "starrynet-tor-site-window-v6",
                           "starrynet-tor-site-window-v7",
                           "starrynet-tor-site-window-v8",
                           "starrynet-tor-site-window-v9",
                           "starrynet-tor-site-window-v10",
                           "starrynet-tor-site-window-v11",
                           "starrynet-tor-site-window-v12",
                           "starrynet-tor-site-window-v13",
                           "starrynet-tor-site-window-v14",
                           "starrynet-tor-site-window-v15") and protocol.get(
                "single_browser_process_for_all_visits") is not True:
            failures.append("repeat set did not keep one browser process across visits")
        if protocol_id in ("starrynet-tor-site-window-v6",
                           "starrynet-tor-site-window-v7"):
            readiness = protocol.get("page_readiness", {})
            if readiness.get("resource_timing_idle_required") is not False:
                failures.append("fixed-window protocol unexpectedly requires resource-timing idle")
            if readiness.get("fixed_window_seconds_after_navigation_start") != 120:
                failures.append("fixed capture window is not 120 seconds")
        if protocol_id in ("starrynet-tor-site-window-v8",
                           "starrynet-tor-site-window-v9",
                           "starrynet-tor-site-window-v10",
                           "starrynet-tor-site-window-v11",
                           "starrynet-tor-site-window-v12",
                           "starrynet-tor-site-window-v13",
                           "starrynet-tor-site-window-v14",
                           "starrynet-tor-site-window-v15"):
            page_readiness = protocol.get("page_readiness", {})
            route_readiness = protocol.get("route_readiness", {})
            expected_window = (60 if protocol_id == "starrynet-tor-site-window-v13"
                               else 85)
            if page_readiness.get("fixed_window_seconds_after_navigation_start") != expected_window:
                failures.append("fixed capture window differs from protocol version")
            if page_readiness.get("resource_timing_idle_required") is not False:
                failures.append("v8 fixed-window protocol requires resource-timing idle")
            if route_readiness.get("stable_seconds_required", 0) < 5:
                failures.append("v8 route-ready gate is shorter than five seconds")
            if route_readiness.get("same_forward_and_return_route_devices_required") is not True:
                failures.append("v8 does not require stable devices in both directions")
            if route_readiness.get("active_path_offloads_reverified_before_each_capture") is not True:
                failures.append("v8 does not reverify active-path offloads per visit")
            if (protocol_id in ("starrynet-tor-site-window-v9",
                                "starrynet-tor-site-window-v10",
                                "starrynet-tor-site-window-v11",
                                "starrynet-tor-site-window-v12",
                                "starrynet-tor-site-window-v13",
                                "starrynet-tor-site-window-v14",
                                "starrynet-tor-site-window-v15")
                    and route_readiness.get("stability_evidence_source")
                    != "one_second_route_monitor_after_path_offload_audit"):
                failures.append("warm-up route stability is not bound to the one-second monitor")
        if protocol_id in ("starrynet-tor-site-window-v9",
                           "starrynet-tor-site-window-v10",
                           "starrynet-tor-site-window-v11",
                           "starrynet-tor-site-window-v12",
                           "starrynet-tor-site-window-v13",
                           "starrynet-tor-site-window-v14",
                           "starrynet-tor-site-window-v15"):
            warmup_protocol = protocol.get("premeasurement_site_warmup", {})
            if warmup_protocol.get("enabled") is not True:
                failures.append("protocol did not declare the uncaptured site warm-up")
            if warmup_protocol.get("captured_as_a_trace") is not False:
                failures.append("warm-up is not excluded from captured traces")
            if warmup_protocol.get("cookies_and_site_storage_cleared_after_warmup") is not True:
                failures.append("protocol does not clear site state after warm-up")
            if protocol_id in ("starrynet-tor-site-window-v10",
                               "starrynet-tor-site-window-v11",
                               "starrynet-tor-site-window-v12",
                               "starrynet-tor-site-window-v13",
                               "starrynet-tor-site-window-v14",
                               "starrynet-tor-site-window-v15") and route_readiness.get(
                    "required_before_initial_tor_check") is not True:
                failures.append("protocol does not require stable routes before the initial Tor check")
            if (protocol_id == "starrynet-tor-site-window-v11"
                    and warmup_protocol.get("before_each_measured_visit") is not True):
                failures.append("v11 does not declare a warm-up before each measured visit")
            if protocol_id in TARGET_PAGE_REFRESH_PROTOCOL_IDS:
                if warmup_protocol.get("before_each_measured_visit") is not False:
                    failures.append("v12 must use one initial site warm-up")
                if warmup_protocol.get("target_page_retained_after_warmup") is not True:
                    failures.append("v12 does not retain the target page after warm-up")
                if protocol.get("target_page_reused_between_measured_visits") is not True:
                    failures.append("v12 does not declare same-page reuse")
                if protocol.get("tor_check_frequency") != "once_before_initial_site_warmup":
                    failures.append("v12 Tor check frequency is not one initial check")
                if protocol.get("measured_site_navigation_action") != "same_tab_refresh":
                    failures.append("v12 measured visits are not same-tab refreshes")
                expected_window = (85 if protocol_id in (
                    "starrynet-tor-site-window-v12",
                    "starrynet-tor-site-window-v14",
                    "starrynet-tor-site-window-v15",
                    *MATCHED_PHASE_PROTOCOL_IDS)
                                   else 60)
                if protocol_id in ("starrynet-tor-site-window-v14",
                                   "starrynet-tor-site-window-v15"):
                    if protocol.get("dynamic_emulation_start_policy") != (
                            "after_initial_tor_check_before_uncaptured_site_warmup"):
                        failures.append("v14 dynamic updates do not start after the initial Tor check")
                    if protocol.get("initial_tor_check_topology_state") != (
                            "verified_initial_satellite_route_before_dynamic_updates"):
                        failures.append("v14 does not declare the initial satellite route used by the Tor check")
                if protocol_id == "starrynet-tor-site-window-v15":
                    if (protocol.get("cache_disabled_for_persistent_profile") is not False
                            or protocol.get("cache_enabled_for_persistent_profile") is not True):
                        failures.append("v15 does not enable persistent browser cache")
                if protocol.get("page_readiness", {}).get(
                        "fixed_window_seconds_after_navigation_start") != expected_window:
                    failures.append("target-page refresh capture window differs from protocol version")
                if protocol.get("target_page_refresh_window_seconds") != expected_window:
                    failures.append("target-page refresh window metadata is inconsistent")

    circuit_reuse_observed = summary.get(
        "same_target_tor_circuit_reused_across_visits")
    per_visit_v7 = is_per_visit_v7_package(
        summary, summary.get("browser_summary", {}).get("visits", []))
    per_visit_v8 = is_per_visit_v8_package(summary, visits)
    per_visit_v9 = is_per_visit_v9_package(summary, visits)
    per_visit_v10 = is_per_visit_v10_package(summary, visits)
    per_visit_v11 = is_per_visit_v11_package(summary, visits)
    per_visit_v12 = is_per_visit_v12_package(summary, visits)
    per_visit_route_package = (per_visit_v7 or per_visit_v8 or per_visit_v9
                               or per_visit_v10 or per_visit_v11 or per_visit_v12)
    if (summary.get("passed") is not True and not per_visit_route_package
            and not (protocol_id in ("starrynet-tor-site-window-v3",
                                     "starrynet-tor-site-window-v4",
                                     "starrynet-tor-site-window-v5",
                                     "starrynet-tor-site-window-v6",
                                     "starrynet-tor-site-window-v7",
                                     "starrynet-tor-site-window-v8",
                                     "starrynet-tor-site-window-v9",
                                     "starrynet-tor-site-window-v10",
                                     "starrynet-tor-site-window-v11",
                                     "starrynet-tor-site-window-v12",
                                     "starrynet-tor-site-window-v13",
                                     "starrynet-tor-site-window-v14",
                                     "starrynet-tor-site-window-v15")
                     and circuit_reuse_observed is False)):
        failures.append("summary.passed is not true")
    if summary.get("cleanup_verified") is not True:
        failures.append("resource cleanup is not verified")
    if summary.get("dataset_sample_created") is not False:
        failures.append("run unexpectedly created or failed to deny a dataset sample")
    if summary.get("topology_update_mode") != "dynamic" or summary.get(
            "emulation_started") is not True:
        failures.append("dynamic topology updater was not active")
    acceptance = summary.get("acceptance", {})
    trace_acceptance = dict(acceptance)
    if protocol_id in ("starrynet-tor-site-window-v3",
                       "starrynet-tor-site-window-v4",
                       "starrynet-tor-site-window-v5",
                       "starrynet-tor-site-window-v6",
                       "starrynet-tor-site-window-v7",
                       "starrynet-tor-site-window-v8",
                       "starrynet-tor-site-window-v9",
                       "starrynet-tor-site-window-v10",
                       "starrynet-tor-site-window-v11",
                       "starrynet-tor-site-window-v12",
                       "starrynet-tor-site-window-v13",
                       "starrynet-tor-site-window-v14",
                       "starrynet-tor-site-window-v15",
                       *MATCHED_PHASE_PROTOCOL_IDS):
        trace_acceptance.pop("same_target_tor_circuit_reused_across_visits", None)
    if per_visit_route_package:
        for aggregate_key in (
                "client_to_GS27_route_uses_satellite_interface",
                "satellite_route_sampled_through_each_capture_window",
                "zero_over_mtu_packets",
                "route_ready_and_active_path_offloads_verified_before_each_capture"):
            trace_acceptance.pop(aggregate_key, None)
    if not trace_acceptance or not all(value is True for value in trace_acceptance.values()):
        failures.append("one or more runtime acceptance flags are false or missing")
    if browser.get("passed") is not True or len(visits) != 1:
        failures.append("browser summary is not one successful visit")
    else:
        visit = visits[0]
        if visit.get("passed") is not True or visit.get("http_200_confirmed") is not True:
            failures.append("target visit did not pass the HTTP 200 gate")
        if protocol_id in ("starrynet-tor-site-window-v4",
                           "starrynet-tor-site-window-v5",
                           "starrynet-tor-site-window-v6",
                           "starrynet-tor-site-window-v7",
                           "starrynet-tor-site-window-v8",
                           "starrynet-tor-site-window-v9",
                           "starrynet-tor-site-window-v10",
                           "starrynet-tor-site-window-v11",
                           "starrynet-tor-site-window-v12",
                           "starrynet-tor-site-window-v13",
                           "starrynet-tor-site-window-v14",
                           "starrynet-tor-site-window-v15"):
            if visit.get("fresh_profile") is not False or visit.get(
                    "persistent_profile_across_visits") is not True:
                failures.append("v4 visit did not use the shared persistent profile")
            if visit.get("site_cookies_cleared_after_visit") is not True:
                failures.append("persistent-profile visit did not clear site cookies")
            if protocol_id in ("starrynet-tor-site-window-v5",
                               "starrynet-tor-site-window-v6",
                               "starrynet-tor-site-window-v7",
                               "starrynet-tor-site-window-v8",
                               "starrynet-tor-site-window-v9",
                               "starrynet-tor-site-window-v10",
                               "starrynet-tor-site-window-v11",
                               "starrynet-tor-site-window-v12",
                               "starrynet-tor-site-window-v13",
                               "starrynet-tor-site-window-v14",
                               "starrynet-tor-site-window-v15") and visit.get(
                    "browser_process_reused_for_series") is not True:
                failures.append("repeat visit did not use the shared browser process")
        elif visit.get("fresh_profile") is not True:
            failures.append("browser visit did not use a fresh profile")
        if protocol_id in ("starrynet-tor-site-window-v6",
                           "starrynet-tor-site-window-v7"):
            if visit.get("page_content_ready") is not True or visit.get(
                    "page_content_character_count", 0) < 40:
                failures.append("fixed-window target page did not pass visible-content readiness")
            observed_window = visit.get("fixed_capture_window_seconds")
            if observed_window is None or abs(float(observed_window) - 120) > 1.0:
                failures.append("fixed-window navigation interval is not exactly 120 seconds")
        elif protocol_id == "starrynet-tor-site-window-v8":
            if visit.get("page_content_ready") is not True or visit.get(
                    "page_content_character_count", 0) < 40:
                failures.append("v8 fixed-window target page did not pass visible-content readiness")
            observed_window = visit.get("fixed_capture_window_seconds")
            if observed_window is None or abs(float(observed_window) - 85) > 1.0:
                failures.append("v8 fixed-window navigation interval is not exactly 85 seconds")
        elif protocol_id in ("starrynet-tor-site-window-v9",
                             "starrynet-tor-site-window-v10",
                             "starrynet-tor-site-window-v11",
                             "starrynet-tor-site-window-v12",
                             "starrynet-tor-site-window-v13",
                             "starrynet-tor-site-window-v14",
                             "starrynet-tor-site-window-v15",
                             *MATCHED_PHASE_PROTOCOL_IDS):
            if visit.get("page_content_ready") is not True or visit.get(
                    "page_content_character_count", 0) < 40:
                failures.append("v9 fixed-window target page did not pass visible-content readiness")
            observed_window = visit.get("fixed_capture_window_seconds")
            expected_window = (60 if protocol_id == "starrynet-tor-site-window-v13"
                               else 85)
            if observed_window is None or abs(float(observed_window) - expected_window) > 1.0:
                failures.append("fixed-window navigation interval differs from protocol version")
        elif visit.get("page_content_stable") is not True or visit.get(
                "page_content_character_count", 0) < 40:
            failures.append("target page did not pass visible-content and resource-idle readiness")
    if protocol_id in ("starrynet-tor-site-window-v7",
                       "starrynet-tor-site-window-v8",
                       "starrynet-tor-site-window-v9",
                       "starrynet-tor-site-window-v10",
                       "starrynet-tor-site-window-v11",
                       "starrynet-tor-site-window-v12",
                       "starrynet-tor-site-window-v13",
                       "starrynet-tor-site-window-v14",
                       "starrynet-tor-site-window-v15",
                       *MATCHED_PHASE_PROTOCOL_IDS):
        failures.extend(route_monitor_failures(summary, run_dir, visits))
    if protocol_id == "starrynet-tor-site-window-v7":
        failures.extend(dynamic_route_offload_failures(summary, run_dir, visits))
    if per_visit_v8:
        failures.extend(route_readiness_failures(summary, run_dir))
        if visits:
            ack_evidence = (visits[0].get("capture_window", {}).get(
                "start_ack", {}).get("route_readiness"))
            visit_index = re.search(r"_visit_(\d+)$", summary.get("run_id", ""))
            package_evidence = summary.get("route_readiness_by_visit", {}).get(
                visit_index.group(1) if visit_index else "")
            if ack_evidence != package_evidence:
                failures.append("route-readiness summary differs from capture-start acknowledgement")
    if per_visit_v9 or per_visit_v10 or per_visit_v11 or per_visit_v12:
        failures.extend(route_readiness_failures(summary, run_dir))
        warmup = browser.get("site_warmup", {})
        expected_warmup_exit = (warmup.get("target_page_retained_after_warmup") is True
                                if per_visit_v12 else
                                warmup.get("about_blank_after_warmup") is True)
        if (warmup.get("passed") is not True
                or warmup.get("captured_as_a_trace") is not False
                or warmup.get("page_loaded") is not True
                or warmup.get("page_content_ready") is not True
                or warmup.get("page_content_character_count", 0) < 40
                or warmup.get("http_status") != 200
                or warmup.get("site_state_cleared") is not True
                or not expected_warmup_exit):
            failures.append("v9 uncaptured site warm-up did not pass its readiness and cleanup gates")
        if (per_visit_v12 and (warmup.get("target_stream_succeeded") is not True
                or not warmup.get("target_stream_ids"))):
            failures.append("v12 initial warm-up lacks successful target-stream evidence")
        capture_start = (visits[0].get("capture_window", {}).get(
            "start_ack", {}).get("tcpdump_ready_monotonic") if visits else None)
        if (not isinstance(warmup.get("completed_monotonic"), (int, float))
                or not isinstance(capture_start, (int, float))
                or warmup.get("completed_monotonic") > capture_start):
            failures.append("v9 measured capture did not start after its uncaptured warm-up")
        warmup_ack = warmup.get("route_ready_ack", {})
        warmup_readiness = summary.get("warmup_route_readiness", {})
        if warmup.get("route_readiness") != warmup_readiness:
            failures.append("warm-up route-ready record differs from the run summary")
        failures.extend(route_readiness_failures(
            summary, run_dir, readiness_override=warmup_readiness,
            label="warmup", ack_override=warmup_ack))
        if per_visit_v10 or per_visit_v11 or per_visit_v12:
            initial_readiness = summary.get(
                "route_readiness_before_tor_check", {})
            initial_ack = summary.get(
                "route_readiness_before_tor_check_ack", {})
            if (initial_readiness.get("passed") is not True
                    or initial_ack.get("ok") is not True):
                failures.append("protocol did not pass the route-ready gate before the initial Tor check")
            failures.extend(route_readiness_failures(
                summary, run_dir, readiness_override=initial_readiness,
                label="initial Tor check", ack_override=initial_ack))
            if per_visit_v12:
                initial_check = browser.get("initial_tor_check", {})
                if (initial_check.get("tor_check_passed") is not True
                        or initial_check.get("check_stream_succeeded") is not True
                        or initial_check.get("check_streams_closed_before_capture") is not True
                        or initial_check.get("check_page_closed_before_capture") is not True):
                    failures.append("v12 initial Tor check evidence did not pass")
                if protocol_id in ("starrynet-tor-site-window-v14",
                                   "starrynet-tor-site-window-v15"):
                    dynamic_start = summary.get("dynamic_emulation_start", {})
                    tor_check_completed = initial_check.get(
                        "tor_check_completed_monotonic")
                    warmup_route_ready = warmup.get("route_ready_ack", {}).get(
                        "route_ready_monotonic")
                    started = dynamic_start.get("started_monotonic")
                    if (not isinstance(started, (int, float))
                            or not isinstance(tor_check_completed, (int, float))
                            or started < tor_check_completed):
                        failures.append("v14 dynamic emulation did not start after the initial Tor check")
                    if (not isinstance(warmup_route_ready, (int, float))
                            or not isinstance(started, (int, float))
                            or warmup_route_ready < started):
                        failures.append("v14 site warm-up route gate did not follow dynamic emulation start")
                check_start = initial_check.get("tor_check_started_monotonic")
                if (visit.get("tor_check_evidence_source") != "initial_session_check"
                        or visit.get("check_page_closed_before_capture") is not True
                        or visit.get("check_streams_closed_before_capture") is not True):
                    failures.append("v12 visit does not reuse a closed initial Tor-check session")
                if (visit.get("site_navigation_action") != "refresh"
                        or visit.get("target_stream_evidence_source") not in (
                            "initial_uncaptured_site_warmup", "measured_visit_stream")):
                    failures.append("v12 visit is not an audited target-page refresh")
                if (visit.get("site_storage_cleared_after_visit") is not True
                        or visit.get("site_cookies_cleared_after_visit") is not True):
                    failures.append("v12 did not clear target-site state after the visit")
                visit_match = re.search(r"_visit_(\d+)$", summary.get("run_id", ""))
                expected_reuse = bool(visit_match and int(visit_match.group(1)) > 1)
                if visit.get("tor_check_reused_from_initial_visit") is not expected_reuse:
                    failures.append("v12 visit Tor-check reuse flag is inconsistent with visit index")
                if (visit.get("target_stream_succeeded") is not True
                        or (visit.get("target_stream_evidence_source")
                            == "initial_uncaptured_site_warmup"
                            and visit.get("target_warmup_stream_ids")
                            != warmup.get("target_stream_ids"))):
                    failures.append("v12 target-stream evidence is missing or mismatched")
            else:
                check_start = (visits[0].get(
                    "tor_check_started_monotonic") if visits else None)
            ready_time = initial_ack.get("route_ready_monotonic")
            if (not isinstance(check_start, (int, float))
                    or not isinstance(ready_time, (int, float))
                    or check_start < ready_time):
                failures.append("initial Tor check did not start after its route-ready acknowledgement")
        if per_visit_v11:
            if warmup.get("visit_index") != int(
                    re.search(r"_visit_(\d+)$", summary.get("run_id", "")).group(1)):
                failures.append("v11 warm-up does not match the measured visit index")

    offloads_ok, offload_error = offload_is_disabled(summary)
    if not offloads_ok:
        failures.append(offload_error)
    network_capture = summary.get("network_capture", {})
    interface = network_capture.get("interface")
    mtu = network_capture.get("interface_mtu_bytes")
    if not interface or not mtu:
        failures.append("capture interface or MTU is missing")
    if network_capture.get("path_packet_offloads_disabled_verified") is not True:
        failures.append("summary does not record verified path offloads disabled")

    extraction = summary.get("trace_extraction", {})
    try:
        trace_path = resolve_artifact(extraction["trace_path"], run_dir)
        packet_audit_path = resolve_artifact(extraction["packet_audit_path"], run_dir)
        manifest_path = resolve_artifact(extraction["manifest_path"], run_dir)
        pcap_path = resolve_artifact(extraction["source_pcap"], run_dir)
        for path in (trace_path, packet_audit_path, manifest_path, pcap_path):
            if not path.is_file():
                failures.append("required artifact is missing: {}".format(path))
        manifest = load_json(manifest_path)
        hashes = {
            "trace": sha256_file(trace_path),
            "packet_audit": sha256_file(packet_audit_path),
            "pcap": sha256_file(pcap_path),
        }
        if hashes["trace"] != manifest.get("trace_sha256"):
            failures.append("trace SHA-256 differs from extraction manifest")
        if hashes["packet_audit"] != manifest.get("packet_audit_sha256"):
            failures.append("packet-audit SHA-256 differs from extraction manifest")
        if hashes["pcap"] != manifest.get("source_pcap_sha256"):
            failures.append("PCAP SHA-256 differs from extraction manifest")
        if hashes["pcap"] != summary.get("pcap_sha256"):
            failures.append("PCAP SHA-256 differs from run summary")
        if manifest.get("window_markers_verified") is not True:
            failures.append("capture window markers are not verified")
        if manifest.get("page_http_200_and_tor_stream_verified") is not True:
            failures.append("extractor did not verify the Tor HTTP 200 visit")
        if ((per_visit_v12 or protocol_id in MATCHED_PHASE_PROTOCOL_IDS)
                and manifest.get("target_stream_evidence_source")
                != visits[0].get("target_stream_evidence_source")):
            failures.append("v12 extractor target-stream provenance differs from browser evidence")
        if ((per_visit_v12 or protocol_id in MATCHED_PHASE_PROTOCOL_IDS)
                and manifest.get("target_stream_observed_during_capture")
                is not (visits[0].get("target_stream_evidence_source")
                       == "measured_visit_stream")):
            failures.append("v12 extractor does not preserve target-stream timing provenance")
        if manifest.get("tor_check_streams_closed_before_capture") is not True:
            failures.append("Tor check streams were not verified closed before capture")
        if manifest.get("check_page_stream_seen_during_navigation") is not False:
            failures.append("Tor check-page stream was observed during target navigation")
        if manifest.get("bidirectional") is not True:
            failures.append("extracted trace is not bidirectional")
        if manifest.get("unmatched_or_non_tcp_packets") != 0:
            failures.append("extractor found unmatched or non-TCP records")
        if manifest.get("ip_length_bytes", {}).get("over_interface_mtu_count") != 0:
            failures.append("trace contains packets above the interface MTU")
        if manifest.get("capture_interface") != interface:
            failures.append("summary and extraction manifest capture interfaces disagree")
        if manifest.get("capture_interface_mtu_bytes") != mtu:
            failures.append("summary and extraction manifest MTUs disagree")
        duration = float(manifest["window_duration_seconds"])
        times, directions, profiles = read_trace(trace_path, duration)
        if len(times) != manifest.get("trace_row_count"):
            failures.append("trace row count differs from extraction manifest")
        if len(times) != manifest.get("packet_count"):
            failures.append("trace row count differs from extracted packet count")
        if set(directions) != {-1, 1}:
            failures.append("trace does not contain both direction values")
        with packet_audit_path.open(encoding="utf-8", newline="") as source:
            rows = list(csv.DictReader(source))
        if len(rows) != len(times):
            failures.append("packet-audit row count differs from trace")
        payload_bytes = sum(int(row["tcp_payload_length"]) for row in rows)
        direction_counts = {"client_to_gs27": directions.count(1),
                            "gs27_to_client": directions.count(-1)}
        expected_counts = manifest.get("direction_counts", {})
        if (direction_counts["client_to_gs27"] != expected_counts.get("client_to_gs27")
                or direction_counts["gs27_to_client"] != expected_counts.get(
                    "gs27_to_client")):
            failures.append("trace direction counts differ from extraction manifest")
        readiness_resources = (visits[0].get(
            "resource_timing_at_readiness", {}).get("resources", [])
            if visits else [])
        end_resources = (visits[0].get(
            "resource_timing_at_window_end", {}).get("resources", [])
            if visits else [])
        target_paths, _path_failures = (target_circuit_paths(visits[0])
                                        if visits else ([], []))
        metrics = {
            "event_count": len(times),
            "tcp_payload_bytes": payload_bytes,
            "window_duration_seconds": duration,
            "events_per_second": len(times) / duration if duration else None,
            "client_to_gs27_events": direction_counts["client_to_gs27"],
            "gs27_to_client_events": direction_counts["gs27_to_client"],
            "client_to_gs27_share": (direction_counts["client_to_gs27"] / len(times)
                                      if times else None),
            "resource_origin_count": len(manifest.get("resource_origins", [])),
            "resource_timing_entry_count": (visits[0].get(
                "resource_timing_entry_count") if visits else None),
            "resource_timing_readiness_count": len(readiness_resources),
            "resource_timing_window_end_count": len(end_resources),
            "resource_timing_after_readiness_count": (
                len(end_resources) - len(readiness_resources)),
            "resource_timing_window_end_unique_keys": len({
                item.get("resource_key") for item in end_resources
                if item.get("resource_key")}),
            "page_content_character_count": (visits[0].get(
                "page_content_character_count") if visits else None),
            "profile_bins": PROFILE_BINS,
        }
        artifacts = {
            "pcap": {"path": str(pcap_path), "sha256": hashes["pcap"]},
            "trace": {"path": str(trace_path), "sha256": hashes["trace"]},
            "packet_audit": {"path": str(packet_audit_path),
                             "sha256": hashes["packet_audit"]},
            "manifest": {"path": str(manifest_path), "sha256": sha256_file(manifest_path)},
        }
    except (KeyError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if isinstance(exc, KeyError) and exc.args == ("trace_path",):
            statuses = [item.get("status") for item in
                        summary.get("trace_extractions", [])
                        if item.get("status")]
            extraction_status = extraction.get("status")
            if extraction_status is None and statuses:
                extraction_status = ",".join(statuses)
            failures.append(
                "trace extraction produced no trace_path (status: {})".format(
                    extraction_status or "unknown"))
        else:
            failures.append("artifact audit failed: {}: {}".format(
                type(exc).__name__, exc))
        metrics = None
        artifacts = None
        profiles = None
        manifest = {}
        interface = None
        protocol = protocol or {}

    return {
        "run_id": summary.get("run_id", run_dir.name),
        "run_dir": str(run_dir),
        "topology_container_ids": sorted(set(
            str(value) for value in summary.get(
                "starrynet_container_ids", {}).values() if value)),
        "capture_phase_seconds": (summary.get(
            "capture_phase_gate_by_visit", {}).get("1", {}).get(
                "actual_capture_start_seconds")),
        "passed": not failures,
        "failures": failures,
        "interface": interface,
        "protocol": protocol,
        "same_target_tor_circuit_reused_across_visits": circuit_reuse_observed,
        "target_circuit_ids": (visits[0].get("target_circuit_ids", []) if visits else []),
        "target_circuit_paths": target_paths,
        "metrics": metrics,
        "artifacts": artifacts,
        "direction_profiles": profiles,
    }


def summarize_metrics(runs):
    names = ("event_count", "tcp_payload_bytes", "window_duration_seconds", "events_per_second")
    summary = {}
    for name in names:
        values = [run["metrics"][name] for run in runs if run.get("metrics")]
        if not values:
            continue
        mean = statistics.mean(values)
        sd = statistics.stdev(values) if len(values) > 1 else 0.0
        summary[name] = {
            "values": values,
            "mean": mean,
            "sample_sd": sd,
            "cv": sd / mean if mean else None,
            "min": min(values),
            "max": max(values),
            "range_over_mean": (max(values) - min(values)) / mean if mean else None,
        }
    shares = [run["metrics"]["client_to_gs27_share"] for run in runs if run.get("metrics")]
    if shares:
        summary["client_to_gs27_share"] = {
            "values": shares,
            "mean": statistics.mean(shares),
            "range_percentage_points": (max(shares) - min(shares)) * 100,
            "min": min(shares),
            "max": max(shares),
        }
    return summary


def compare_profiles(runs):
    comparisons = []
    for left, right in itertools.combinations(runs, 2):
        left_profiles = left.get("direction_profiles")
        right_profiles = right.get("direction_profiles")
        result = {"run_a": left["run_id"], "run_b": right["run_id"]}
        for direction, name in ((1, "client_to_gs27"), (-1, "gs27_to_client")):
            if left_profiles is None or right_profiles is None:
                corr = None
            else:
                corr = pairwise_pearson(left_profiles[direction], right_profiles[direction])
            result[name + "_pearson_r"] = corr
        comparisons.append(result)
    return comparisons


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", action="append", required=True,
                        help="one completed run directory; provide at least three")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    if len(args.run_dir) < 3:
        parser.error("at least three --run-dir values are required")

    runs = [audit_one(path) for path in args.run_dir]
    protocol_ids = {run.get("protocol", {}).get("protocol_id") for run in runs}
    if (any(protocol_id in MATCHED_PHASE_PROTOCOL_IDS for protocol_id in protocol_ids)
            and len(runs) != 3
            and not (protocol_ids.issubset(set(E_BROWSER_PROTOCOL_IDS))
                     and len(protocol_ids) == 1 and len(runs) >= 3)):
        parser.error("matched-phase protocols require three runs; E browser groups allow three or more")
    run_pass = all(run["passed"] for run in runs)
    protocols = [run.get("protocol") for run in runs]
    def acquisition_protocol_signature(item):
        signature = dict(item or {})
        if signature.get("protocol_id") in MATCHED_PHASE_PROTOCOL_IDS:
            source_hashes = dict(signature.get("source_sha256", {}))
            source_hashes.pop("repeatability_auditor", None)
            signature["source_sha256"] = source_hashes
        if signature.get("protocol_id") in E_BROWSER_PROTOCOL_IDS:
            # Independent sample IDs differ by repetition; the page-level
            # capture protocol remains comparable after removing that ID.
            signature.pop("sample_id", None)
        return signature

    protocol_signatures = [acquisition_protocol_signature(item)
                           for item in protocols]
    protocol_agreement = (bool(protocol_signatures)
                          and all(item == protocol_signatures[0]
                                  for item in protocol_signatures))
    auditor_hashes = [protocol.get("source_sha256", {}).get(
        "repeatability_auditor") if isinstance(protocol, dict) else None
        for protocol in protocols]
    auditor_hash_agreement = (bool(auditor_hashes)
                              and all(value == auditor_hashes[0]
                                      for value in auditor_hashes))
    interfaces = [run.get("interface") for run in runs]
    interface_agreement = bool(interfaces) and all(item == interfaces[0] for item in interfaces)
    matched_phase_repeat = (bool(protocols)
                            and protocols[0].get("protocol_id")
                                in MATCHED_PHASE_PROTOCOL_IDS)
    run_ids = [run.get("run_id") for run in runs]
    container_ids = [container_id for run in runs
                     for container_id in run.get("topology_container_ids", [])]
    independent_topologies = (
        len(set(run_ids)) == len(runs)
        and len(container_ids) == len(set(container_ids))
        and all(run.get("topology_container_ids") for run in runs)
    ) if matched_phase_repeat else None
    protocol_reproducible = (run_pass and protocol_agreement and interface_agreement
                             and (independent_topologies is not False))
    circuit_reuse_values = [run.get(
        "same_target_tor_circuit_reused_across_visits") for run in runs]
    circuit_reuse_observed = (all(value is True for value in circuit_reuse_values)
                              if protocols and protocols[0].get("protocol_id") in
                              ("starrynet-tor-site-window-v3",
                               "starrynet-tor-site-window-v4",
                               "starrynet-tor-site-window-v5",
                               "starrynet-tor-site-window-v6",
                               "starrynet-tor-site-window-v7",
                               "starrynet-tor-site-window-v8",
                               "starrynet-tor-site-window-v9",
                               "starrynet-tor-site-window-v10",
                               "starrynet-tor-site-window-v11",
                               "starrynet-tor-site-window-v12",
                               "starrynet-tor-site-window-v13",
                               "starrynet-tor-site-window-v14",
                               "starrynet-tor-site-window-v15",
                               "starrynet-tor-site-window-v17-phase-resource-observability",
                               "starrynet-tor-site-window-v18-phase-resource-route-settled") else None)

    metrics = summarize_metrics([run for run in runs if run.get("metrics")])
    profile_correlations = compare_profiles(runs)
    cv_checks = {}
    for name in ("event_count", "tcp_payload_bytes", "window_duration_seconds"):
        cv = metrics.get(name, {}).get("cv")
        cv_checks[name] = cv is not None and cv <= CV_LIMIT
    share_range = metrics.get("client_to_gs27_share", {}).get("range_percentage_points")
    direction_share_check = (share_range is not None
                              and share_range <= DIRECTION_SHARE_RANGE_LIMIT * 100)
    correlations = [comparison.get(key) for comparison in profile_correlations
                    for key in ("client_to_gs27_pearson_r", "gs27_to_client_pearson_r")]
    profile_correlation_check = bool(correlations) and all(
        value is not None and value >= PROFILE_CORRELATION_FLOOR for value in correlations)
    profile_stable = (protocol_reproducible and all(cv_checks.values())
                      and direction_share_check and profile_correlation_check)
    if profile_stable:
        status = "profile_stable_in_{}_run_check".format(len(runs))
    elif protocol_reproducible:
        status = "capture_protocol_reproducible_profile_varies"
    else:
        status = "capture_protocol_or_run_gates_failed"

    result = {
        "schema_version": 1,
        "status": status,
        "run_count": len(runs),
        "capture_protocol_reproducible": protocol_reproducible,
        "profile_stable_in_run_set": profile_stable,
        "profile_stable_in_three_run_check": (
            profile_stable if len(runs) == 3 else None),
        "protocol_metadata_agrees": protocol_agreement,
        "protocol_metadata_comparison_excludes": (
            ["source_sha256.repeatability_auditor"]
            if matched_phase_repeat else []),
        "repeatability_auditor_hashes_agree": auditor_hash_agreement,
        "repeatability_auditor_hashes_by_run": auditor_hashes,
        "capture_interface_agrees": interface_agreement,
        "same_target_tor_circuit_reused_across_visits": circuit_reuse_observed,
        "independent_dynamic_topologies": independent_topologies,
        "matched_capture_phase_seconds_by_run": [
            run.get("capture_phase_seconds") for run in runs],
        "target_circuit_ids_by_visit": [run.get("target_circuit_ids", []) for run in runs],
        "target_circuit_paths_by_run": [run.get("target_circuit_paths", [])
                                         for run in runs],
        "resource_timing_diagnostics_by_run": [
            {"run_id": run.get("run_id"), "readiness_entries": (
                run.get("metrics") or {}).get("resource_timing_readiness_count"),
             "window_end_entries": (run.get("metrics") or {}).get(
                "resource_timing_window_end_count"),
             "entries_after_readiness": (run.get("metrics") or {}).get(
                "resource_timing_after_readiness_count"),
             "window_end_unique_keys": (run.get("metrics") or {}).get(
                "resource_timing_window_end_unique_keys")}
            for run in runs],
        "run_gates_passed": run_pass,
        "criteria": {
            "event_count_cv_max": CV_LIMIT,
            "tcp_payload_bytes_cv_max": CV_LIMIT,
            "window_duration_cv_max": CV_LIMIT,
            "client_to_gs27_share_range_percentage_points_max":
                DIRECTION_SHARE_RANGE_LIMIT * 100,
            "directional_50_bin_pairwise_pearson_r_min": PROFILE_CORRELATION_FLOOR,
            "profile_bins": PROFILE_BINS,
            "checks": {
                **cv_checks,
                "client_to_gs27_share_range": direction_share_check,
                "directional_profile_correlations": profile_correlation_check,
            },
        },
        "protocol_id": protocols[0].get("protocol_id") if protocols else None,
        "runs": [{key: value for key, value in run.items()
                  if key != "direction_profiles"} for run in runs],
        "metrics": metrics,
        "directional_profile_correlations": profile_correlations,
        "limitations": [
            "{} visits are an engineering repeatability screen, not a population estimate.".format(
                len(runs)),
            "For v3, visits share one StarryNet topology and Tor process; independent network-session variability is not estimated.",
            "Matched-phase observations use new StarryNet topologies and Tor sessions; circuit-path and resource-timing records are diagnostic covariates, not causal proof.",
            "Site content and third-party resources can still vary between visits.",
            "The trace is the encrypted WebTunnel carrier between GS26 and GS27, not origin TCP traffic.",
            "No scientific-fidelity claim is made by this audit.",
        ],
    }

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "repeatability.json"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    report_lines = [
        "# Website trace repeatability audit",
        "",
        "- Status: `{}`".format(status),
        "- Runs: {}".format(len(runs)),
        "- Capture protocol reproducible: `{}`".format(protocol_reproducible),
        "- Profile stable across this run set: `{}`".format(profile_stable),
        "- Run gates passed: `{}`".format(run_pass),
        "- Protocol metadata agrees (excluding the repeatability-auditor hash only): `{}`".format(
            protocol_agreement),
        "- Repeatability-auditor source hashes agree: `{}` ({})".format(
            auditor_hash_agreement, auditor_hashes),
        "- Capture interface agrees: `{}` ({})".format(
            interface_agreement, interfaces[0] if interfaces else "missing"),
        "- Independent dynamic topologies: `{}`".format(independent_topologies),
        "- Matched capture phases (s): `{}`".format(
            [run.get("capture_phase_seconds") for run in runs]),
        "- Same Tor target circuit observed across visits: `{}`".format(
            "not applicable (one visit per topology)" if matched_phase_repeat
            else circuit_reuse_observed),
        "",
        "## Per-run results",
        "",
        "| Run | Gate | Phase (s) | Events | TCP payload bytes | Window (s) | C→GS27 share | Origins |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for run in runs:
        values = run.get("metrics") or {}
        share = values.get("client_to_gs27_share")
        report_lines.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            run["run_id"], "PASS" if run["passed"] else "FAIL",
            "{:.3f}".format(run["capture_phase_seconds"])
            if isinstance(run.get("capture_phase_seconds"), (int, float)) else "—",
            values.get("event_count", "—"), values.get("tcp_payload_bytes", "—"),
            "{:.3f}".format(values["window_duration_seconds"])
            if "window_duration_seconds" in values else "—",
            "{:.3f}".format(share) if share is not None else "—",
            values.get("resource_origin_count", "—")))
        for failure in run.get("failures", []):
            report_lines.append("  - `{}`: {}".format(run["run_id"], failure))
    report_lines.extend(["", "## Diagnostic covariates", "",
                         "| Run | Resources at readiness | At window end | Added after readiness | Unique keys at end | Target Tor relay fingerprints |",
                         "|---|---:|---:|---:|---:|---|"])
    for run in runs:
        values = run.get("metrics") or {}
        paths = "; ".join("{}: {}".format(
            item.get("circuit_id"), ">".join(item.get("relay_fingerprints", [])))
            for item in run.get("target_circuit_paths", [])) or "unavailable"
        report_lines.append("| {} | {} | {} | {} | {} | {} |".format(
            run.get("run_id", "unknown"),
            values.get("resource_timing_readiness_count", "—"),
            values.get("resource_timing_window_end_count", "—"),
            values.get("resource_timing_after_readiness_count", "—"),
            values.get("resource_timing_window_end_unique_keys", "—"),
            paths))
    report_lines.extend(["", "## Variation summary", "",
                         "| Measure | Mean | Sample SD | CV or range |",
                         "|---|---:|---:|---:|"])
    for name, item in metrics.items():
        if name == "client_to_gs27_share":
            report_lines.append("| Client→GS27 share | {:.3f} | — | range {:.2f} pp |".format(
                item["mean"], item["range_percentage_points"]))
        else:
            report_lines.append("| {} | {:.3f} | {:.3f} | CV {:.3f} |".format(
                name, item["mean"], item["sample_sd"], item["cv"] or 0.0))
    report_lines.extend(["", "## Directional profile correlations", "",
                         "| Run pair | Client→GS27 r | GS27→client r |",
                         "|---|---:|---:|"])
    for item in profile_correlations:
        report_lines.append("| {} / {} | {} | {} |".format(
            item["run_a"], item["run_b"],
            "{:.3f}".format(item["client_to_gs27_pearson_r"])
            if item["client_to_gs27_pearson_r"] is not None else "undefined",
            "{:.3f}".format(item["gs27_to_client_pearson_r"])
            if item["gs27_to_client_pearson_r"] is not None else "undefined"))
    report_lines.extend(["", "## Gates and limitations", "",
                         "The predeclared exploratory band is event-count, payload-byte, and window-duration CV ≤ 20%; direction-share range ≤ 10 percentage points; and both directional 50-bin profile correlations ≥ 0.80 for every pair.", "",
                         "The machine-readable report records artifact hashes and per-run failures. Three runs do not estimate population-level variation or establish scientific fidelity.", ""])
    report_path = output_dir / "REPEATABILITY.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    print(json.dumps({
        "status": status,
        "capture_protocol_reproducible": protocol_reproducible,
        "profile_stable_in_three_run_check": profile_stable,
        "repeatability_json": str(json_path),
        "report": str(report_path),
    }, indent=2, sort_keys=True))
    return 0 if protocol_reproducible else 2


if __name__ == "__main__":
    sys.exit(main())
