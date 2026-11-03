#!/usr/bin/env python3
"""Run V3 fixed-object GRE/NAT checks on dynamic StarryNet paths."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import p0_smoke
import p1_http_smoke
import satellite_wf_v3 as v3
import satellite_wf_v3_fixed_object as fixed
import satellite_wf_v3_route_nat as route_nat

DYNAMIC_ARTIFACTS = (ROOT / "artifacts" / "reports" /
                     "satellite_wf_v3_20261021" / "dynamic_network_acceptance")
CONFIG_SECONDS = 100
BROWSER_TOPOLOGY_SECONDS = 300
BROWSER_CAPTURE_SECONDS = 180
BROWSER_SIMULATION_START_UTC = "2022-01-01T01:02:00Z"
BROWSER_EXPECTED_FIRST_TOPOLOGY_EVENT_SECONDS = 272
BROWSER_PAGE_LOAD_TIMEOUT_SECONDS = 60
BROWSER_PAGE_CONTENT_TIMEOUT_SECONDS = 120
BROWSER_CAPTURE_SETTLE_SECONDS = 2
BROWSER_CAPTURE_SETUP_SECONDS = 10
BROWSER_CAPTURE_SAFETY_SECONDS = 5
CAPTURE_FILTER = "tcp port 18080 or icmp"
CAPTURE_LABELS = ("gs26-wf-gre0", "gs27-wf-gre0", "gs27-b27-default",
                  "gs26-gre-outer", "gs27-gre-outer")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def parse_topology_events(path):
    events = []
    current = None
    section = None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == "time" and words[1].endswith(":"):
            if current is not None and (current["added_links"] or current["removed_links"]):
                events.append(current)
            current = {"logical_second": int(words[1][:-1]),
                       "added_links": [], "removed_links": []}
            section = None
        elif current is not None and words and words[0] in ("add:", "del:"):
            section = "added_links" if words[0] == "add:" else "removed_links"
        elif current is not None and section and words and "-" in words[0]:
            current[section].append(words[0])
    if current is not None and (current["added_links"] or current["removed_links"]):
        events.append(current)
    return events


def scenario_window(scenario_id, events, duration=CONFIG_SECONDS,
                    browser_capture_seconds=None):
    if not events:
        raise RuntimeError("generated topology contains no ground-station handover")
    first = events[0]["logical_second"]
    if scenario_id == "dynamic_no_handover":
        if (browser_capture_seconds is not None
                and first != BROWSER_EXPECTED_FIRST_TOPOLOGY_EVENT_SECONDS):
            raise RuntimeError("generated browser topology differs from the frozen first-event second")
        end = first - 8
        if browser_capture_seconds is None:
            start = first - 38
        else:
            # Reserve capture setup, helper settle, and a margin before the
            # first topology event after the fixed browser window.
            required_window = (browser_capture_seconds
                               + BROWSER_CAPTURE_SETUP_SECONDS
                               + BROWSER_CAPTURE_SETTLE_SECONDS
                               + BROWSER_CAPTURE_SAFETY_SECONDS)
            start = end - required_window
        transfers = [start + 5, start + 15, start + 25]
    elif scenario_id == "dynamic_handover":
        start, end = first - 12, first + 22
        transfers = [first - 8, first + 8, first + 18]
    else:
        raise ValueError("unsupported dynamic scenario: " + str(scenario_id))
    if start < 3 or end >= duration or end <= start:
        raise RuntimeError("first handover cannot support the requested capture window")
    if (scenario_id == "dynamic_no_handover"
            and browser_capture_seconds is not None
            and end - start < (
                browser_capture_seconds + BROWSER_CAPTURE_SETUP_SECONDS
                + BROWSER_CAPTURE_SETTLE_SECONDS
                + BROWSER_CAPTURE_SAFETY_SECONDS)):
        raise RuntimeError("no-handover interval is shorter than the frozen Browser/Tor window")
    return {"first_topology_handover_logical_second": first,
            "capture_window_logical_seconds": [start, end],
            "transfer_logical_seconds": transfers}


def read_clock(path):
    if not Path(path).exists():
        return []
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return records


def verify_route_state(state_path):
    result = fixed.run_command(
        [sys.executable, ROOT / "tools" / "satellite_wf_v3_route_nat.py",
         "verify", "--state", state_path], timeout=60, check=False)
    try:
        verification = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("route/NAT verifier returned invalid JSON: {}".format(
            (result.stderr or result.stdout).strip())) from exc
    verification["command_returncode"] = result.returncode
    return verification


def one_ping(client_id, endpoint_ip):
    started = time.monotonic()
    result = fixed.run_command(
        ["docker", "exec", client_id, "ping", "-n", "-c", "1", "-W", "1",
         "-I", "10.255.253.1", endpoint_ip], timeout=4, check=False)
    finished = time.monotonic()
    reply = re.search(r"time[=<]([0-9.]+)\s*ms", result.stdout)
    return {"started_monotonic": started, "finished_monotonic": finished,
            "returncode": result.returncode,
            "passed": result.returncode == 0 and reply is not None,
            "rtt_ms": float(reply.group(1)) if reply else None,
            "output": (result.stdout + result.stderr).strip()}


def measure_handover_interruption(ping_samples, topology_event_monotonic,
                                  route_change_monotonic=None):
    """Measure loss as first failed probe start through first recovery probe."""
    ordered = sorted(ping_samples, key=lambda item: item["started_monotonic"])
    index = 0
    while index < len(ordered):
        if ordered[index].get("passed"):
            index += 1
            continue
        first_failure = ordered[index]
        end = index
        while end + 1 < len(ordered) and not ordered[end + 1].get("passed"):
            end += 1
        recovery = next((item for item in ordered[end + 1:]
                         if item.get("passed")), None)
        if recovery is not None:
            failure_start = first_failure["started_monotonic"]
            recovery_end = recovery["finished_monotonic"]
            event_in_interval = (
                topology_event_monotonic is not None
                and failure_start <= topology_event_monotonic <= recovery_end)
            retarget_in_interval = (
                route_change_monotonic is not None
                and failure_start <= route_change_monotonic <= recovery_end)
            if event_in_interval or retarget_in_interval:
                return {
                    "outage_start_monotonic": failure_start,
                    "route_recovered_monotonic": recovery_end,
                    "interruption_ms": max(0.0, (recovery_end - failure_start) * 1000),
                    "interruption_measurement": (
                        "first failed one-second ICMP probe start through first later "
                        "successful probe completion"),
                    "probe_failures_in_outage": end - index + 1,
                    "outage_spans_topology_event": bool(event_in_interval),
                    "outage_spans_gre_retarget": bool(retarget_in_interval),
                }
        index = end + 1

    post_event_success = [item for item in ordered
                          if item.get("passed")
                          and topology_event_monotonic is not None
                          and item["finished_monotonic"] >= topology_event_monotonic]
    if post_event_success and not any(
            not item.get("passed") and topology_event_monotonic is not None
            and item["finished_monotonic"] >= topology_event_monotonic
            for item in ordered):
        return {
            "outage_start_monotonic": topology_event_monotonic,
            "route_recovered_monotonic": post_event_success[0]["finished_monotonic"],
            "interruption_ms": 0.0,
            "interruption_measurement": (
                "no failed ICMP probe observed from topology event through first later "
                "successful probe; one-second probe resolution"),
            "probe_failures_in_outage": 0,
            "outage_spans_topology_event": False,
            "outage_spans_gre_retarget": False,
        }
    return {
        "outage_start_monotonic": None,
        "route_recovered_monotonic": None,
        "interruption_ms": None,
        "interruption_measurement": "no event-linked ICMP loss and recovery interval found",
        "probe_failures_in_outage": 0,
        "outage_spans_topology_event": False,
        "outage_spans_gre_retarget": False,
    }


def qdisc_snapshot(client_id, egress_id):
    records = {}
    for label, container in (("GS26", client_id), ("GS27", egress_id)):
        output = fixed.docker_exec(container, "tc", "-s", "qdisc", "show")
        drops = [int(value) for value in re.findall(r"\bdropped\s+(\d+)\b", output)]
        records[label] = {"output": output, "drop_counters": drops,
                          "all_observed_drop_counters_zero": all(value == 0 for value in drops)}
    return records


def analyze_dynamic_capture(capture, run):
    if capture.get("capture_kind") == "gre_outer":
        return fixed.analyze_outer_capture(capture, run)
    if capture["label"] == "gs27-b27-default":
        expected_ips, expected_source = ["9.27.27.10", "9.27.27.20"], "9.27.27.10"
    else:
        expected_ips, expected_source = ["10.255.253.1", "9.27.27.20"], "10.255.253.1"
    return fixed.analyze_capture(capture, run, expected_ips, expected_source, "9.27.27.20")


def analyze_browser_capture(capture, run):
    """Copy and hash a V3 browser capture without HTTP payload assumptions."""
    if capture.get("capture_kind") == "gre_outer":
        return fixed.analyze_outer_capture(capture, run)
    local_pcap = Path(run) / "captures" / (capture["label"] + ".pcap")
    local_pcap.parent.mkdir(parents=True, exist_ok=True)
    fixed.run_command(["docker", "cp", "{}:{}".format(
        capture["container"], capture["pcap"]), local_pcap], timeout=120)
    tcpdump_log = fixed.docker_exec(
        capture["container"], "sh", "-lc", "cat " + shlex.quote(capture["log"]))
    (local_pcap.parent / (capture["label"] + ".tcpdump.log")).write_text(
        tcpdump_log + "\n", encoding="utf-8")
    rows = fixed.tshark_fields(
        local_pcap, "frame.len", "ip.src", "ip.dst", display_filter="ip")
    packets = [row.split("|") for row in rows if row.strip()]
    counts = fixed._tcpdump_counts(tcpdump_log)
    endpoints = {address for row in packets for address in row[1:3] if address}
    directions = {
        "client_to_network": any(row[1] == "10.255.253.1" for row in packets),
        "network_to_client": any(row[2] == "10.255.253.1" for row in packets),
    }
    return {
        "label": capture["label"],
        "interface": capture["interface"],
        "pcap": str(local_pcap),
        "pcap_bytes": local_pcap.stat().st_size,
        "pcap_sha256": v3.sha256_file(local_pcap),
        "ip_packet_count": len(packets),
        "observed_ip_addresses": sorted(endpoints),
        "client_flow_directions": directions,
        "bidirectional_client_flow_seen": all(directions.values()),
        "tcpdump_counters": counts,
        "kernel_dropped_packets": counts.get("dropped_by_kernel"),
        "zero_kernel_drops": counts.get("dropped_by_kernel") == 0,
        "capture_counters_consistent": (
            counts.get("captured") is not None
            and counts.get("received_by_filter") is not None
            and counts["captured"] == counts["received_by_filter"]),
    }


def finalize_capture_artifacts(route_state, captures, run, summary, analyzer,
                               logical_start, callback_started):
    """Check route/NAT immediately after capture, before expensive PCAP analysis."""
    verification_started = time.monotonic()
    verification_started_utc = utc_now()
    try:
        verification = verify_route_state(route_state)
        verification_finished = time.monotonic()
        verification.update({
            "verification_started_utc": verification_started_utc,
            "verification_started_monotonic": verification_started,
            "verification_finished_monotonic": verification_finished,
            "verification_logical_second_estimate": round(
                logical_start + verification_finished - callback_started, 3),
            "capture_end_logical_second_estimate": summary.get(
                "time_boundaries", {}).get(
                    "capture_end_logical_second_estimate"),
        })
        summary["handover_verification"] = verification
    except Exception as exc:
        verification_finished = time.monotonic()
        summary.setdefault("route_nat_verification_errors", []).append(str(exc))
        summary["handover_verification"] = {
            "status": "error",
            "errors": [str(exc)],
            "verification_started_monotonic": verification_started,
            "verification_finished_monotonic": verification_finished,
            "verification_logical_second_estimate": round(
                logical_start + verification_finished - callback_started, 3),
            "capture_end_logical_second_estimate": summary.get(
                "time_boundaries", {}).get(
                    "capture_end_logical_second_estimate"),
        }
    for capture in captures:
        try:
            summary.setdefault("captures", []).append(analyzer(capture, run))
        except Exception as exc:
            summary.setdefault("capture_analysis_errors", []).append(
                "{}: {}".format(capture.get("label"), exc))


def kernel_capture_drop_gate(captures):
    """Require every capture point and use the kernel's drop counter as the gate."""
    by_label = {item.get("label"): item for item in captures}
    return (set(CAPTURE_LABELS).issubset(by_label)
            and all(by_label[label].get("zero_kernel_drops") is True
                    for label in CAPTURE_LABELS))


def make_capture_callback(scenario_id, window, run, client_id, egress_id,
                          endpoint, remote_dir, route_state, captures, summary,
                          browser_session=None):
    def capture_window(logical_start):
        callback_started = time.monotonic()
        browser_capture_filter = "ip" if browser_session is not None else CAPTURE_FILTER
        capture_specs = [
            (client_id, "gs26-wf-gre0", "wf-gre0", browser_capture_filter, "http"),
            (egress_id, "gs27-wf-gre0", "wf-gre0", browser_capture_filter, "http"),
            (egress_id, "gs27-b27-default", "B27-default", browser_capture_filter, "http"),
            (client_id, "gs26-gre-outer", "any", "ip proto 47", "gre_outer"),
            (egress_id, "gs27-gre-outer", "any", "ip proto 47", "gre_outer"),
        ]
        route_samples, ping_samples, qdisc_samples = [], [], []
        visit_threads, visit_lock, visit_errors = [], threading.Lock(), []
        visits, scheduled_visits = [], set()
        topology_event_monotonic = None
        route_change_monotonic = None
        stable_route_signature = None
        stable_route_samples = 0
        last_route_nat_verification_monotonic = float("-inf")
        deadline = callback_started + (
            window["capture_window_logical_seconds"][1] - logical_start
            + (5 if browser_session is not None else 0))
        try:
            for container in (client_id, egress_id):
                fixed.run_command(["docker", "exec", container, "mkdir", "-p", remote_dir])
            for container, label, interface, capture_filter, capture_kind in capture_specs:
                captures.append(fixed.start_capture(
                    container, label, interface, remote_dir,
                    capture_filter=capture_filter, capture_kind=capture_kind))
            raw_start = time.monotonic()
            raw_start_utc = utc_now()
            summary["time_boundaries"] = {
                "capture_callback_logical_second": logical_start,
                "capture_callback_start_monotonic": callback_started,
                "clock_anchor_utc": utc_now(),
                "clock_anchor_monotonic": callback_started,
                "raw_capture_start_monotonic": raw_start,
                "raw_capture_start_utc": raw_start_utc,
                "planned_capture_window_logical_seconds": window[
                    "capture_window_logical_seconds"]}
            initial_verify = verify_route_state(route_state)
            summary["initial_route_nat_verification"] = initial_verify
            if initial_verify.get("status") != "passed":
                raise RuntimeError("initial GRE/NAT verification failed in the dynamic capture window")
            if browser_session is not None:
                browser_session.release_capture_gate(
                    raw_start, raw_start_utc, logical_start, callback_started)

            first_handover = window["first_topology_handover_logical_second"]
            visit_targets = (window["transfer_logical_seconds"]
                             if browser_session is None else [])
            next_probe = raw_start
            next_qdisc = raw_start
            first_route_sample = True
            while time.monotonic() < deadline:
                now = time.monotonic()
                logical_now = logical_start + (now - callback_started)
                if browser_session is not None:
                    browser_session.service_capture_control(
                        captures, summary, run, logical_now)
                for visit_index, target_second in enumerate(visit_targets, 1):
                    if target_second <= logical_now and visit_index not in scheduled_visits:
                        scheduled_visits.add(visit_index)

                        def fetch(index=visit_index, scheduled_second=target_second):
                            try:
                                result = fixed.fetch_object(
                                    client_id, endpoint, remote_dir, run, index,
                                    fixed.EXPECTED_OBJECT_SHA256,
                                    max_time_seconds=12)
                                result["planned_logical_second"] = scheduled_second
                                result["started_monotonic"] = time.monotonic() - result[
                                    "duration_seconds"]
                                with visit_lock:
                                    visits.append(result)
                            except BaseException as exc:
                                with visit_lock:
                                    visit_errors.append("GET {}: {}".format(index, exc))

                        thread = threading.Thread(target=fetch)
                        thread.start()
                        visit_threads.append(thread)

                if now >= next_probe:
                    sample = {"logical_second_estimate": round(logical_now, 3),
                              "sample_monotonic": now}
                    before_endpoints = dict(summary.get("current_gre_outer_endpoints", {}))
                    try:
                        if scenario_id == "dynamic_handover":
                            retarget = route_nat.retarget_dynamic_gre(
                                route_state, logical_second=round(logical_now, 3))
                            sample["retarget"] = retarget
                            selected = retarget.get("routes")
                            if retarget.get("changed"):
                                route_change_monotonic = retarget["monotonic_seconds"]
                                summary["route_change_monotonic"] = route_change_monotonic
                                summary["current_gre_outer_endpoints"] = retarget["current"]
                                summary.setdefault("gre_outer_endpoint_changes", []).append(retarget)
                                stable_route_signature = None
                                stable_route_samples = 0
                        else:
                            selected = route_nat._selected_outer_endpoint_routes(
                                client_id, egress_id)
                            current = json.loads(Path(route_state).read_text(
                                encoding="utf-8")).get("gre_outer_endpoints_current", {})
                            if (selected["client"] != current.get("client")
                                    or selected["egress"] != current.get("egress")):
                                summary.setdefault("unexpected_route_source_changes", []).append({
                                    "logical_second_estimate": round(logical_now, 3),
                                    "selected": selected})
                        sample["selected_routes"] = selected
                        sample["tunnel_endpoints_client"] = route_nat._tunnel_outer_endpoints(
                            client_id)
                        sample["tunnel_endpoints_egress"] = route_nat._tunnel_outer_endpoints(
                            egress_id)
                        sample["client_endpoint_route"] = route_nat._route(
                            client_id, endpoint["address"])
                        sample["egress_endpoint_route"] = route_nat._route(
                            egress_id, endpoint["address"])
                        current_endpoints = json.loads(Path(route_state).read_text(
                            encoding="utf-8")).get("gre_outer_endpoints_current", {})
                        summary["current_gre_outer_endpoints"] = current_endpoints
                        if (scenario_id == "dynamic_handover" and before_endpoints
                                and current_endpoints != before_endpoints):
                            route_change_monotonic = route_change_monotonic or now
                        if scenario_id == "dynamic_handover":
                            endpoints_match = bool(
                                selected.get("client") == current_endpoints.get("client")
                                and selected.get("egress") == current_endpoints.get("egress"))
                            if endpoints_match:
                                route_signature = (
                                    selected.get("client"), selected.get("egress"),
                                    selected.get("client_underlay_route", {}).get("dev"),
                                    selected.get("client_underlay_route", {}).get("src"),
                                    selected.get("egress_underlay_route", {}).get("dev"),
                                    selected.get("egress_underlay_route", {}).get("src"))
                                if route_signature == stable_route_signature:
                                    stable_route_samples += 1
                                else:
                                    stable_route_signature = route_signature
                                    stable_route_samples = 1
                            else:
                                stable_route_signature = None
                                stable_route_samples = 0
                            if (route_change_monotonic is not None
                                    and stable_route_samples >= 2
                                    and now - last_route_nat_verification_monotonic >= 2.0):
                                verification = verify_route_state(route_state)
                                verification_record = {
                                    "logical_second_estimate": round(logical_now, 3),
                                    "monotonic_seconds": time.monotonic(),
                                    "route_signature": list(stable_route_signature),
                                    "verification": verification}
                                sample["route_nat_verification"] = verification_record
                                summary.setdefault("route_nat_reverifications", []).append(
                                    verification_record)
                                last_route_nat_verification_monotonic = time.monotonic()
                    except Exception as exc:
                        sample["route_error"] = str(exc)
                        selected = None
                        if scenario_id == "dynamic_handover":
                            stable_route_signature = None
                            stable_route_samples = 0
                    if browser_session is None:
                        try:
                            sample["ping"] = one_ping(client_id, endpoint["address"])
                            ping_samples.append(sample["ping"])
                        except Exception as exc:
                            sample["ping_error"] = str(exc)
                    if first_route_sample or logical_now >= first_handover - 2 or now >= next_qdisc:
                        try:
                            qdisc = qdisc_snapshot(client_id, egress_id)
                            sample["qdisc"] = qdisc
                            qdisc_samples.append({"logical_second_estimate": round(logical_now, 3),
                                                  "samples": qdisc})
                        except Exception as exc:
                            sample["qdisc_error"] = str(exc)
                        next_qdisc = now + 5
                    if selected is not None:
                        sample["satellite_route_checks"] = {
                            "gs26_uses_satellite": str(selected[
                                "client_underlay_route"].get("dev", "")).startswith("B26-eth"),
                            "gs27_uses_satellite": str(selected[
                                "egress_underlay_route"].get("dev", "")).startswith("B27-eth"),
                                "gs26_gre_peer_uses_satellite": str(selected[
                                    "client_peer_route"].get("dev", "")).startswith("B26-eth"),
                                "gs27_gre_peer_uses_satellite": str(selected[
                                    "egress_peer_route"].get("dev", "")).startswith("B27-eth"),
                            "client_object_uses_gre": sample.get(
                                "client_endpoint_route", {}).get("dev") == "wf-gre0",
                            "egress_object_uses_b27_default": sample.get(
                                "egress_endpoint_route", {}).get("dev") == "B27-default"}
                    route_samples.append(sample)
                    first_route_sample = False
                    next_probe = now + 1.0
                time.sleep(0.05)

            raw_end = time.monotonic()
            summary["time_boundaries"].update({
                "raw_capture_end_monotonic": raw_end,
                "raw_capture_end_utc": utc_now(),
                "capture_end_logical_second_estimate": round(
                    logical_start + raw_end - callback_started, 3)})
        except BaseException as exc:
            summary.setdefault("errors", []).append("capture callback: " + str(exc))
            summary.setdefault("tracebacks", []).append(traceback.format_exc())
        finally:
            if browser_session is not None and not browser_session.capture_stop_acknowledged:
                summary.setdefault("errors", []).append(
                    "Browser/Tor did not complete the capture stop handshake inside the V3 window")
            for capture in captures:
                try:
                    fixed.stop_capture(capture)
                except Exception as exc:
                    summary.setdefault("errors", []).append("stop capture: " + str(exc))
            for thread in visit_threads:
                thread.join(25)
                if thread.is_alive():
                    visit_errors.append("fixed-object GET worker did not finish within 25 seconds")
            with visit_lock:
                if browser_session is None:
                    summary["visits"] = sorted(visits, key=lambda item: item["index"])
                summary.setdefault("errors", []).extend(visit_errors)
            summary["route_samples"] = route_samples
            summary["ping_samples"] = ping_samples
            summary["qdisc_samples"] = qdisc_samples
            analyzer = (analyze_dynamic_capture if browser_session is None
                        else analyze_browser_capture)
            finalize_capture_artifacts(
                route_state, captures, run, summary, analyzer,
                logical_start, callback_started)
            fixed.write_json(run / "summary.json", summary)

    return capture_window


def route_change_summary(samples, scenario_id):
    signatures = []
    for sample in samples:
        selected = sample.get("selected_routes") or {}
        client_route = selected.get("client_underlay_route") or {}
        egress_route = selected.get("egress_underlay_route") or {}
        signature = (client_route.get("dev"), client_route.get("src"),
                     egress_route.get("dev"), egress_route.get("src"))
        if signature != (None, None, None, None) and (not signatures or signature != signatures[-1]):
            signatures.append(signature)
    return signatures


def write_report(run, summary):
    scenario = summary.get("scenario_id")
    window = summary.get("planned_window", {})
    lines = ["# V3 动态 GRE/NAT 固定对象验收", "",
             "- Run ID: `{}`".format(summary.get("run_id")),
             "- 场景: `{}`".format(scenario),
             "- 状态: `{}`".format(summary.get("status")),
             "- 首次计划切换: 仿真秒 `{}`".format(
                 window.get("first_topology_handover_logical_second")),
             "- 抓包窗口: `{}`".format(window.get("capture_window_logical_seconds")),
             "- 工程网络验收通过: `{}`".format(
                 summary.get("engineering_network_acceptance_passed")),
             "- 清理恢复通过: `{}`".format(summary.get("cleanup_verified")),
             "- 科学保真: `false`", "- 训练准入: `false`", "",
             "## 固定对象传输", ""]
    for visit in summary.get("visits", []):
        lines.append("- GET {}: HTTP `{}`, {} bytes, SHA-256 `{}`, hash通过 `{}`".format(
            visit.get("index"), visit.get("curl_metrics", {}).get("http_code"),
            visit.get("bytes"), visit.get("local_sha256"),
            visit.get("object_matches_expected")))
    lines += ["", "## 动态路径与切换记录", ""]
    lines.append("- 路由样本数: `{}`".format(len(summary.get("route_samples", []))))
    lines.append("- GRE 外层地址变化: `{}`".format(
        summary.get("gre_outer_endpoint_changes", [])))
    lines.append("- Ping 探测样本数: `{}`".format(len(summary.get("ping_samples", []))))
    lines.append("- 切换中断/恢复: `{}`".format(summary.get("handover_record")))
    lines += ["", "## 验收门槛", ""]
    for key, value in summary.get("checks", {}).items():
        lines.append("- {}: `{}`".format(key, value))
    for capture in summary.get("captures", []):
        lines.append("- `{}` / `{}`: packets {}, GET {}, HTTP 200 {}, drops {}, SHA-256 `{}`".format(
            capture.get("label"), capture.get("interface"),
            capture.get("gre_outer_packet_count", capture.get("tcp_packet_count")),
            capture.get("fixed_object_get_count"), capture.get("http_200_count"),
            capture.get("kernel_dropped_packets"), capture.get("pcap_sha256")))
    if summary.get("capture_counter_discrepancies"):
        lines += ["", "## tcpdump 计数诊断", "",
                  "以下 captured 与 received-by-filter 计数不相等；内核 dropped 计数单独作为丢包验收门槛。"]
        lines.extend("- `{}`: `{}`".format(item.get("label"),
                                           item.get("tcpdump_counters"))
                     for item in summary["capture_counter_discrepancies"])
    if summary.get("errors"):
        lines += ["", "## 错误", ""]
        lines.extend("- {}".format(item) for item in summary["errors"])
    if summary.get("capture_analysis_errors"):
        lines += ["", "## 抓包分析错误", ""]
        lines.extend("- {}".format(item) for item in summary["capture_analysis_errors"])
    (Path(run) / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_scenario(scenario_id, browser_session=None, preflight_result=None,
                 topology_duration_seconds=None, simulation_start_utc=None):
    preflight_result = preflight_result or fixed.preflight()
    before = preflight_result["docker_inventory"]
    duration_seconds = topology_duration_seconds or CONFIG_SECONDS
    simulation_start_utc = (simulation_start_utc
                            or "2022-01-01T01:00:00Z")
    extra_sources = [Path(__file__)]
    if browser_session is not None:
        extra_sources.extend(browser_session.source_paths)
    run, fixture, topology_config, manifest = fixed.prepare_run(
        preflight_result, artifact_root=DYNAMIC_ARTIFACTS,
        scenario_id=scenario_id, extra_sources=extra_sources,
        duration_seconds=duration_seconds,
        simulation_start_utc=simulation_start_utc)
    if browser_session is not None:
        manifest["stage"] = "v3_browser_tor_sample"
        manifest["capture"] = {
            "filter": "ip",
            "client": "GS26 wf-gre0",
            "egress": "GS27 wf-gre0 and B27-default",
            "outer_gre_filter": "ip proto 47",
            "trace_scope": "all client IPv4 packets during navigation markers",
        }
        manifest["browser_proxy_environment"] = "unset"
        manifest["tor_https_proxy_path"] = (
            "GS26 wf-gre0 -> GS27 B27-default -> host GS_27 gateway -> 127.0.0.1:17897")
        fixed.write_json(run / "manifest.json", manifest)
    endpoint = manifest["endpoint"]
    run_id = manifest["run_id"]
    server_name = "wf-v3-object-{}".format(run_id.replace("_", "").lower())
    remote_dir = "/tmp/wf-v3-dynamic-{}".format(run_id.lower().replace("_", "-"))
    endpoint_ip = endpoint["address"]
    summary = {"run_id": run_id, "protocol_id": manifest["protocol_id"],
               "scenario_id": scenario_id, "status": "running",
               "started_monotonic": time.monotonic(),
               "engineering_network_acceptance_passed": False,
               "scientific_fidelity_verified": False,
               "training_data_eligible": False,
               "cleanup_verified": False,
               "runtime_config_sha256": manifest["runtime_config_sha256"],
               "fixed_object": manifest["fixed_object"], "endpoint": endpoint,
               "visits": [], "captures": [], "checks": {}, "errors": []}
    fixed.write_json(run / "summary.json", summary)
    fixed.print_phase("{} artifacts: {}".format(scenario_id, run))

    from starrynet.sn_synchronizer import StarryNet
    from starrynet.sn_thread import WORKER_ERRORS
    profile = v3.starrynet_link_profile(v3.load_json(v3.DEFAULT_CONFIG),
                                        "engineering_baseline")
    sn = None
    client_id = egress_id = None
    server_created = False
    allow_topology_cleanup = True
    route_state = run / "route_nat_state.json"
    captures = []
    failure = None
    try:
        sn = StarryNet(str(topology_config), p0_smoke.GS, 1, [[1, 27]],
                       local=True, argv=[], link_profile=profile)
        sn.container_sysctls = ["net.ipv6.conf.all.disable_ipv6=1",
                                "net.ipv6.conf.default.disable_ipv6=1"]
        WORKER_ERRORS.clear()
        if browser_session is not None:
            browser_session.mark_topology_started()
        sn.create_nodes()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet node worker failed: {}".format(WORKER_ERRORS))
        summary["ipv6_sysctls"] = fixed.verify_ipv6_sysctls(sn.container_id_list)
        sn.create_links()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet link worker failed: {}".format(WORKER_ERRORS))
        if len(sn.container_id_list) != 27:
            raise RuntimeError("expected 27 StarryNet node containers")
        client_id = sn.container_id_list[25]
        egress_id = sn.container_id_list[26]
        p1_http_smoke.disable_management_interfaces(sn)
        sn.run_routing_deamon()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet routing worker failed: {}".format(WORKER_ERRORS))
        topology_dir = Path(sn.configuration_file_path) / sn.file_path.lstrip("./")
        topology_summary = p0_smoke.topology_report(
            run, topology_dir, expected_matrix_count=duration_seconds)
        events = parse_topology_events(topology_dir / "Topo_leo_change.txt")
        window = scenario_window(
            scenario_id, events, duration=duration_seconds,
            browser_capture_seconds=(BROWSER_CAPTURE_SECONDS
                                     if browser_session is not None else None))
        summary["topology"] = topology_summary
        summary["topology_events"] = events
        summary["planned_window"] = window
        manifest["validation_window"] = window
        manifest["topology"].update({
            "mode": "dynamic link scheduler; route-aware GRE retarget enabled",
            "duration_seconds": duration_seconds,
            "simulation_start_utc": simulation_start_utc,
        })
        write_json(run / "manifest.json", manifest)
        fixed.write_json(run / "summary.json", summary)

        run_cmd = fixed.run_command
        if browser_session is None:
            run_cmd(["docker", "run", "-d", "--name", server_name,
                 "--network", endpoint["network"], "--ip", endpoint_ip,
                 "--label", "starrynet.v3.acceptance={}".format(run_id),
                 "--entrypoint", "sh", endpoint["image"], "-lc",
                 "mkdir -p /tmp/v3-object && sleep 86400"], timeout=45)
            server_created = True
            run_cmd(["docker", "cp", fixture,
                 "{}:/tmp/v3-object/{}".format(server_name, endpoint["object_name"])],
                timeout=60)
            server_command = ("cd /tmp/v3-object && exec python3 -m http.server "
                          "--bind 0.0.0.0 {}".format(endpoint["port"]))
            run_cmd(["docker", "exec", "-d", server_name, "sh", "-lc", server_command],
                timeout=20)
            deadline = time.monotonic() + 15
            ready = False
            while time.monotonic() < deadline:
                probe = run_cmd(["docker", "exec", server_name, "curl", "--noproxy", "*",
                             "-sS", "-I", "--connect-timeout", "1", "--max-time", "2",
                             "-o", "/dev/null", "-w", "%{http_code}",
                             "http://127.0.0.1:{}/{}".format(
                                 endpoint["port"], endpoint["object_name"])],
                            timeout=5, check=False)
                if probe.returncode == 0 and probe.stdout.strip() == "200":
                    ready = True
                    break
                time.sleep(0.25)
            if not ready:
                raise RuntimeError("fixed-object endpoint did not become ready")

        installed = route_nat.install(
            client_id, egress_id, route_state,
            iptables_deb=run / "tooling" / route_nat.DEFAULT_IPTABLES_DEB.name,
            libnfnetlink_deb=run / "tooling" / route_nat.DEFAULT_LIBNFNETLINK_DEB.name)
        summary["gre_outer_endpoints_initial"] = installed["gre_outer_endpoints"]
        summary["gre_outer_endpoints_current"] = installed["gre_outer_endpoints_current"]
        if verify_route_state(route_state).get("status") != "passed":
            raise RuntimeError("initial GRE/NAT route verification failed")
        proxy_env = fixed.docker_exec(client_id, "sh", "-lc", "env")
        proxy_keys = sorted(set(line.split("=", 1)[0] for line in proxy_env.splitlines()
                                if "=" in line and line.split("=", 1)[0] in fixed.PROXY_KEYS))
        summary["checks"]["proxy_environment_unset"] = not proxy_keys
        summary["proxy_environment_keys_present"] = proxy_keys
        if proxy_keys:
            raise RuntimeError("proxy environment is set in the GS26 client")

        if browser_session is not None:
            browser_session.prepare(run, manifest, client_id, egress_id,
                                    route_state, summary)

        capture_callback = make_capture_callback(
            scenario_id, window, run, client_id, egress_id, endpoint,
            remote_dir, route_state, captures, summary,
            browser_session=browser_session)
        sn.schedule_callback(window["capture_window_logical_seconds"][0], capture_callback)
        fixed.print_phase("{} dynamic scheduler starting; first handover at simulation second {}".format(
            scenario_id, window["first_topology_handover_logical_second"]))
        WORKER_ERRORS.clear()
        sn.start_emulation()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet scheduler worker failed: {}".format(WORKER_ERRORS))
        if browser_session is not None:
            browser_summary = browser_session.finish(run, summary)
            summary["browser_tor"]["helper_summary"] = browser_summary
            summary["visits"] = browser_summary.get("visits", [])
        clock_path = topology_dir / "simulation_clock.jsonl"
        summary["simulation_clock"] = read_clock(clock_path)
        if clock_path.exists():
            shutil.copy2(clock_path, run / "simulation_clock.jsonl")
        clock_events = [row for row in summary["simulation_clock"]
                        if row.get("event") == "topology_change_applied"]
        summary["observed_topology_events"] = clock_events

        captures_by_label = {item.get("label"): item for item in summary.get("captures", [])}
        expected_gets = len(window["transfer_logical_seconds"])
        http_capture_labels = ("gs26-wf-gre0", "gs27-wf-gre0", "gs27-b27-default")
        if browser_session is None:
            capture_http_passed = all(
                captures_by_label.get(label, {}).get("fixed_object_get_count") == expected_gets
                and captures_by_label.get(label, {}).get("http_200_count") == expected_gets
                for label in http_capture_labels)
        else:
            browser_visit = next(iter(summary.get("visits", [])), {})
            capture_http_passed = bool(
                summary.get("browser_tor", {}).get("passed") is True
                and browser_visit.get("target_stream_succeeded") is True
                and browser_visit.get("page_loaded") is True
                and browser_visit.get("http_200_confirmed") is True
                and all(captures_by_label.get(label, {}).get("ip_packet_count", 0) > 0
                        for label in http_capture_labels))
        zero_capture_drops = kernel_capture_drop_gate(summary.get("captures", []))
        summary["capture_counter_discrepancies"] = [
            {"label": item.get("label"),
             "tcpdump_counters": item.get("tcpdump_counters")}
            for item in summary.get("captures", [])
            if item.get("capture_counters_consistent") is not True]
        valid_samples = [sample for sample in summary.get("route_samples", [])
                         if sample.get("selected_routes")]
        satellite_routes_passed = bool(valid_samples) and all(
            all(sample.get("satellite_route_checks", {}).values())
            for sample in valid_samples)
        qdisc_drops_zero = bool(summary.get("qdisc_samples")) and all(
            node.get("all_observed_drop_counters_zero") is True
            for sample in summary["qdisc_samples"]
            for node in sample.get("samples", {}).values())
        event_seconds = [row["logical_second"] for row in events]
        start_second, end_second = window["capture_window_logical_seconds"]
        events_in_window = [second for second in event_seconds
                            if start_second <= second <= end_second]
        observed_events_in_window = [row for row in clock_events
                                     if start_second <= row.get(
                                         "logical_time_seconds", -1) <= end_second]
        visits = summary.get("visits", [])
        if browser_session is None:
            transfer_integrity = len(visits) == expected_gets and all(
                item.get("object_matches_expected") is True for item in visits)
        else:
            transfer_integrity = capture_http_passed
        route_signatures = route_change_summary(valid_samples, scenario_id)
        gre_history = summary.get("gre_outer_endpoint_changes", [])
        outer_pairs = set()
        for label in ("gs26-gre-outer", "gs27-gre-outer"):
            capture = captures_by_label.get(label, {})
            outer_pairs.update(tuple(pair) for pair in capture.get(
                "gre_outer_endpoint_pairs", []))
        endpoint_sequence = [summary.get("gre_outer_endpoints_initial", {})]
        endpoint_sequence.extend(item.get("current", {}) for item in gre_history)
        expected_outer_pairs = set()
        for pair in endpoint_sequence:
            if pair.get("client") and pair.get("egress"):
                expected_outer_pairs.add((pair["client"], pair["egress"]))
                expected_outer_pairs.add((pair["egress"], pair["client"]))
        outer_endpoint_path_passed = bool(expected_outer_pairs) and expected_outer_pairs.issubset(
            outer_pairs)
        handover_event_monotonic = None
        if observed_events_in_window:
            event_monos = [row.get("monotonic_seconds") for row in observed_events_in_window
                           if isinstance(row.get("monotonic_seconds"), (int, float))]
            handover_event_monotonic = min(event_monos) if event_monos else None
            summary["time_boundaries"]["topology_handover_monotonic"] = handover_event_monotonic
        ping_passes = [item for item in summary.get("ping_samples", []) if item.get("passed")]
        ping_failures = [item for item in summary.get("ping_samples", []) if not item.get("passed")]
        handover_record = None
        if scenario_id == "dynamic_handover":
            transition = gre_history[0] if gre_history else None
            post_event_success = [item for item in ping_passes
                                 if handover_event_monotonic is not None
                                 and item["finished_monotonic"] >= handover_event_monotonic]
            post_event_visit = any(
                item.get("object_matches_expected") is True
                and item.get("started_monotonic", 0) >= (handover_event_monotonic or 0)
                for item in visits)
            after_route_event_failures = [item for item in ping_failures
                                          if handover_event_monotonic is not None
                                          and item["started_monotonic"] >= handover_event_monotonic]
            prior_success = [item for item in ping_passes
                             if handover_event_monotonic is not None
                             and item["finished_monotonic"] <= handover_event_monotonic]
            recovery_ping = post_event_success[0] if post_event_success else None
            interruption = measure_handover_interruption(
                summary.get("ping_samples", []), handover_event_monotonic,
                route_change_monotonic=summary.get("route_change_monotonic"))
            handover_record = {
                "occurred": bool(observed_events_in_window and transition),
                "topology_event_monotonic": handover_event_monotonic,
                "route_retarget": transition,
                "pre_handover_last_success_monotonic": (
                    prior_success[-1]["finished_monotonic"] if prior_success else None),
                **interruption,
                "route_recovered": bool(recovery_ping and post_event_visit),
                "post_handover_successful_get": post_event_visit,
                "probe_failures_after_topology_event": len(after_route_event_failures),
            }
        summary["handover_record"] = handover_record

        checks = summary["checks"]
        route_verified_during_capture = (
            any(item.get("verification", {}).get("status") == "passed"
                for item in summary.get("route_nat_reverifications", []))
            if scenario_id == "dynamic_handover"
            else summary.get("initial_route_nat_verification", {}).get("status") == "passed")
        checks.update({
            "topology_scheduler_clock_recorded": bool(summary.get("simulation_clock")),
            "capture_window_has_expected_topology_events": (
                bool(observed_events_in_window) if scenario_id == "dynamic_handover"
                else not events_in_window and not observed_events_in_window),
            "dynamic_route_samples_use_satellite_interfaces": satellite_routes_passed,
            ("fixed_object_transfers_match_frozen_hash" if browser_session is None
             else "browser_target_stream_page_and_capture_passed"): transfer_integrity,
            ("all_capture_points_saw_each_http_200" if browser_session is None
             else "all_v3_capture_points_contain_navigation_traffic"): capture_http_passed,
            "all_kernel_capture_drop_counters_zero": zero_capture_drops,
            "observed_qdisc_drop_counters_zero": qdisc_drops_zero,
            "continuous_gre_outer_capture_present": bool(
                captures_by_label.get("gs26-gre-outer", {}).get("gre_outer_packet_count", 0)
                and captures_by_label.get("gs27-gre-outer", {}).get("gre_outer_packet_count", 0)
                and outer_endpoint_path_passed),
            "route_state_verified_during_capture": bool(route_verified_during_capture),
            "route_state_verified_after_capture": (
                summary.get("handover_verification", {}).get("status") == "passed"),
        })
        if scenario_id == "dynamic_no_handover":
            checks["no_route_or_gre_endpoint_handover_during_capture"] = (
                len(route_signatures) <= 1
                and not summary.get("unexpected_route_source_changes")
                and not gre_history)
        else:
            checks["handover_route_and_gre_endpoint_changed"] = bool(
                len(route_signatures) > 1 and gre_history
                and summary.get("route_change_monotonic"))
            checks["handover_route_recovered_with_fixed_object"] = bool(
                handover_record and handover_record.get("route_recovered"))
            checks["handover_interruption_recovery_recorded"] = bool(
                handover_record and isinstance(
                    handover_record.get("interruption_ms"), (int, float))
                and handover_record.get("route_recovered_monotonic") is not None)
        summary["engineering_network_acceptance_passed"] = all(checks.values())
        if not summary["engineering_network_acceptance_passed"]:
            raise RuntimeError("one or more {} acceptance gates failed".format(scenario_id))
    except BaseException as exc:
        failure = exc
        summary.setdefault("errors", []).append(str(exc))
        summary.setdefault("tracebacks", []).append(traceback.format_exc())
        fixed.print_phase("{} stopped: {}".format(scenario_id, exc))
    finally:
        if browser_session is not None:
            try:
                browser_cleanup_errors = browser_session.cleanup()
                if browser_cleanup_errors:
                    allow_topology_cleanup = False
                    summary.setdefault("errors", []).extend(browser_cleanup_errors)
            except Exception as exc:
                allow_topology_cleanup = False
                summary.setdefault("errors", []).append(
                    "Browser/Tor cleanup: " + str(exc))
        if any(not capture.get("stopped") for capture in captures):
            time.sleep(0.5)
            for capture in captures:
                try:
                    fixed.stop_capture(capture)
                except Exception as exc:
                    summary.setdefault("errors", []).append("stop capture: " + str(exc))
        if server_created:
            removed = fixed.run_command(["docker", "rm", "-f", server_name],
                                        timeout=30, check=False)
            summary["object_server_removed"] = removed.returncode == 0
            if removed.returncode:
                allow_topology_cleanup = False
                summary.setdefault("errors", []).append(
                    "remove fixed-object server: " + removed.stderr.strip())
        if route_state.exists():
            try:
                state = json.loads(route_state.read_text(encoding="utf-8"))
                cleanup_errors = route_nat.cleanup_state(state)
                if cleanup_errors:
                    allow_topology_cleanup = False
                    summary["route_nat_cleanup_errors"] = cleanup_errors
                else:
                    state["installed"] = False
                    route_nat._save_state(route_state, state)
                    summary["route_nat_restored"] = True
            except Exception as exc:
                allow_topology_cleanup = False
                summary.setdefault("errors", []).append("route/NAT cleanup: " + str(exc))
        if sn is not None and allow_topology_cleanup:
            try:
                sn.stop_emulation()
                after = fixed.wait_for_inventory(before)
                summary["docker_inventory_restored"] = True
                summary["docker_inventory_after"] = after
                summary["cleanup_verified"] = bool(
                    summary.get("route_nat_restored", not route_state.exists())
                    and summary.get("object_server_removed", True))
            except Exception as exc:
                summary["cleanup_verified"] = False
                summary.setdefault("errors", []).append("StarryNet cleanup: " + str(exc))
        elif sn is None:
            try:
                after = p0_smoke.inventory()
                summary["docker_inventory_restored"] = all(
                    set(after[key]) == set(before[key]) for key in before)
                summary["cleanup_verified"] = summary["docker_inventory_restored"]
            except Exception as exc:
                summary.setdefault("errors", []).append("inventory check: " + str(exc))
        summary["status"] = (
            "passed" if (failure is None and not summary.get("errors")
                         and summary.get("engineering_network_acceptance_passed")
                         and summary.get("cleanup_verified")) else "failed")
        summary["completed_utc"] = utc_now()
        summary["elapsed_seconds"] = round(
            time.monotonic() - float(summary.get("started_monotonic", time.monotonic())), 3)
        fixed.write_json(run / "summary.json", summary)
        if browser_session is None:
            write_report(run, summary)
        else:
            browser_session.write_report(run, summary)
        fixed.print_phase("{}; report: {}".format(summary["status"], run / "REPORT.md"))
    return {"scenario_id": scenario_id, "run_id": run_id,
            "status": summary["status"], "report": str(run / "REPORT.md"),
            "summary": str(run / "summary.json"),
            "cleanup_verified": summary.get("cleanup_verified")}


def latest_scenario_result(scenario_id, current_results):
    current = next((item for item in reversed(current_results)
                    if item["scenario_id"] == scenario_id), None)
    if current is not None:
        return current
    for path in sorted(DYNAMIC_ARTIFACTS.glob("*/summary.json"), reverse=True):
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if summary.get("scenario_id") == scenario_id:
            return {"scenario_id": scenario_id,
                    "run_id": path.parent.name,
                    "status": summary.get("status", "unknown"),
                    "report": str(path.parent / "REPORT.md"),
                    "summary": str(path),
                    "cleanup_verified": summary.get("cleanup_verified")}
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("plan", help="show the frozen dynamic validation windows")
    sub.add_parser("preflight", help="check runtime prerequisites without changing Docker")
    run_parser = sub.add_parser("run", help="run dynamic no-handover then handover acceptance")
    run_parser.add_argument("--apply", action="store_true",
                            help="acknowledge isolated StarryNet/Docker network changes")
    run_parser.add_argument("--scenario", choices=("all", "dynamic_no_handover",
                                                     "dynamic_handover"), default="all")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("a command is required: plan, preflight, or run")
    if args.command == "plan":
        config = v3.load_json(v3.DEFAULT_CONFIG)
        print(json.dumps({"scenarios": [item for item in config["scenarios"]
                                         if item["id"] in ("dynamic_no_handover",
                                                           "dynamic_handover")],
                          "topology_duration_seconds": CONFIG_SECONDS,
                          "first_handover": "read from generated Topo_leo_change.txt",
                          "scientific_fidelity_verified": False}, indent=2))
        return 0
    if args.command == "preflight":
        print(json.dumps(fixed.preflight(), indent=2, sort_keys=True))
        return 0
    if not args.apply:
        parser.error("run requires --apply")
    lock = (ROOT / ".p0.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("another local StarryNet experiment is running")
    scenarios = (["dynamic_no_handover", "dynamic_handover"] if args.scenario == "all"
                 else [args.scenario])
    results = []
    for scenario_id in scenarios:
        result = run_scenario(scenario_id)
        results.append(result)
        DYNAMIC_ARTIFACTS.mkdir(parents=True, exist_ok=True)
        latest_results = [latest_scenario_result(item, results)
                          for item in ("dynamic_no_handover", "dynamic_handover")]
        latest_results = [item for item in latest_results if item is not None]
        write_json(DYNAMIC_ARTIFACTS / "dynamic_acceptance_summary.json",
                   {"protocol_id": "starrynet-browser-tor-route-nat-v3",
                    "results": latest_results,
                    "scenarios_run": scenarios,
                    "requested_scenarios_passed": all(
                        item["status"] == "passed" for item in results),
                    "all_passed": (
                        {item["scenario_id"] for item in latest_results}
                        == {"dynamic_no_handover", "dynamic_handover"}
                        and all(item["status"] == "passed" for item in latest_results)),
                    "scientific_fidelity_verified": False,
                    "training_data_eligible": False})
        if result["status"] != "passed":
            break
    return 0 if len(results) == len(scenarios) and all(
        item["status"] == "passed" for item in results) else 2


if __name__ == "__main__":
    sys.exit(main())
