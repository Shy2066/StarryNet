#!/usr/bin/env python3
"""Run one header-only V3 GRE/NAT-to-host-relay diagnostic, with no sample."""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import satellite_wf_v3_browser_tor_collector as collector
import satellite_wf_v3_dynamic_fixed_object as dynamic
import run_e_browser_pilot_v2 as proxy_runtime


READINESS_DIR = (ROOT / "artifacts/reports/satellite_wf_v3_20261021/"
                 "matched_class_x3_readiness_20261022")
PILOT_PLAN = READINESS_DIR / "pilot_plan.json"
PILOT_AUDIT = READINESS_DIR / "plan_audit_revision7.json"
DIAG_PLAN = READINESS_DIR / "r002_proxy_path_diagnosis_plan_20261022.json"
DIAG_ROOT = ROOT / "artifacts/reports/satellite_wf_v3_20261021/proxy_path_diagnosis"
DIAG_RELAY = ROOT / "tools/satellite_wf_v3_diagnostic_relay.py"
PROBE_PORT = 17897
MAX_PROBES = 1
CAPTURE_SECONDS = 18
CAPTURE_SNAPLEN = 96


class DiagnosticBoundary(Exception):
    """Expected stop after the probe, before any Browser/Tor helper can start."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_plan(plan_path=DIAG_PLAN):
    plan_path = Path(plan_path).resolve()
    errors = []
    if not plan_path.is_file():
        return {"passed": False, "errors": ["diagnosis plan is missing"],
                "plan": str(plan_path)}
    plan = read_json(plan_path)
    pilot = read_json(PILOT_PLAN)
    pilot_audit = read_json(PILOT_AUDIT)
    if plan.get("plan_id") not in (
            "v3-r002-proxy-path-diagnosis-20261022",
            "v3-r002-proxy-path-diagnosis-20261022-r2",
            "v3-r002-proxy-path-diagnosis-20261022-r3",
            "v3-r002-proxy-path-diagnosis-20261022-r4"):
        errors.append("unexpected diagnosis plan id")
    if plan.get("status") != "diagnostic_only":
        errors.append("diagnosis plan status must be diagnostic_only")
    parent = plan.get("parent_pilot_plan", {})
    if (parent.get("plan_id") != pilot.get("plan_id")
            or parent.get("revision") != pilot.get("revision")
            or parent.get("plan_status") != pilot.get("plan_status")
            or parent.get("sha256") != sha256_file(PILOT_PLAN)):
        errors.append("diagnosis plan parent reference does not match current stopped pilot plan")
    if pilot.get("revision") != 7 or pilot.get(
            "plan_status") != "stopped_after_r002_gate_failure":
        errors.append("expected revision 7 pilot stop state is not present")
    if pilot_audit.get("manual_execution_ready") is not False:
        errors.append("revision 7 pilot audit no longer records the stop gate")
    scope = plan.get("scope", {})
    if scope.get("topology_scenario") != "dynamic_no_handover":
        errors.append("diagnosis scenario must match R002")
    if scope.get("probe_count_max") != MAX_PROBES:
        errors.append("diagnosis must allow exactly one in-topology probe")
    if scope.get("probe_target") != "https://example.com/":
        errors.append("diagnosis target changed")
    if (scope.get("snaplen_bytes") != CAPTURE_SNAPLEN
            or scope.get("capture_payload") is not False
            or scope.get("capture_format") != "tcpdump textual packet headers"):
        errors.append("diagnostic observation must be header-only")
    if scope.get("capture_interfaces") != [
            "GS26:wf-gre0", "GS27:wf-gre0", "GS27:B27-default"]:
        errors.append("diagnostic observation points changed")
    artifact_root = (ROOT / plan.get("artifacts", {}).get("root", "")).resolve()
    bounded_root = (ROOT / "artifacts/reports/satellite_wf_v3_20261021/"
                    "proxy_path_diagnosis").resolve()
    if os.path.commonpath([str(artifact_root), str(bounded_root)]) != str(bounded_root):
        errors.append("diagnostic artifact root is outside its bounded directory")
    if plan.get("plan_id", "").endswith("-r2") and artifact_root == DIAG_ROOT.resolve():
        errors.append("revision 2 must preserve revision 1 diagnostic artifacts")
    if (plan.get("plan_id", "").endswith("-r3")
            and artifact_root == (ROOT / "artifacts/reports/satellite_wf_v3_20261021/"
                                 "proxy_path_diagnosis/revision2").resolve()):
        errors.append("revision 3 must preserve earlier diagnostic artifacts")
    fixed_port = scope.get("fixed_relay_port")
    if fixed_port is not None and not (1024 <= int(fixed_port) <= 65535):
        errors.append("fixed relay port is outside the allowed user-port range")
    if plan.get("plan_id", "").endswith("-r3") and scope.get(
            "capture_filter") != "tcp-syn-synack-only":
        errors.append("revision 3 must observe only TCP SYN/SYN-ACK headers")
    if plan.get("plan_id", "").endswith("-r4"):
        forward = scope.get("user_proxy_forward", {})
        if (forward.get("server_endpoint") != "127.0.0.1:17897"
                or forward.get("user_computer_endpoint") != "127.0.0.1:7897"
                or forward.get("authorization") != "user_attested_approved"):
            errors.append("revision 4 must record the approved user proxy forward endpoints")
    implementation = plan.get("implementation", {})
    for name, path in (("diagnosis_runner", Path(__file__).resolve()),
                       ("diagnostic_relay", DIAG_RELAY)):
        row = implementation.get(name, {})
        if (row.get("path") != str(path)
                or row.get("sha256") != sha256_file(path)):
            errors.append("diagnostic implementation hash mismatch: " + name)
    prohibitions = plan.get("prohibitions", {})
    required_prohibitions = (
        "browser_tor_helper", "site_navigation", "class_sample",
        "sample_manifest", "sample_attempt_ledger_write", "training",
        "class_expansion", "r002_sample_retry", "r003_sample")
    for item in required_prohibitions:
        if prohibitions.get(item) is not True:
            errors.append("required prohibition is not enabled: " + item)
    return {
        "schema_version": 1,
        "observed_utc": utc_now(),
        "plan_id": plan.get("plan_id"),
        "plan_sha256": sha256_file(plan_path),
        "parent_pilot_plan_sha256": sha256_file(PILOT_PLAN),
        "parent_pilot_status": pilot.get("plan_status"),
        "parent_pilot_manual_execution_ready": pilot_audit.get(
            "manual_execution_ready"),
        "passed": not errors,
        "errors": errors,
    }


def _acquire_locks():
    handles = []
    try:
        for path in (ROOT / ".p0.lock", READINESS_DIR / "collector.lock"):
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a+")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                handle.close()
                raise RuntimeError("another StarryNet/V3 experiment holds "
                                   "the serial-run lock")
            handles.append(handle)
        return handles
    except BaseException:
        _release_locks(handles)
        raise


def _release_locks(handles):
    for handle in reversed(handles):
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _tcpdump_processes(session, port, diag_dir, scope):
    diag_dir.mkdir(parents=True, exist_ok=True)
    points = [
        ("gs26-wf-gre0", session.client_id, "wf-gre0"),
        ("gs27-wf-gre0", session.egress_id, "wf-gre0"),
        ("gs27-b27-default", session.egress_id, "B27-default"),
    ]
    started = []
    packet_filter = "tcp and host {} and port {}".format(
        session.host_gateway, port)
    if scope.get("capture_filter") == "tcp-syn-synack-only":
        packet_filter += " and (tcp[tcpflags] & tcp-syn != 0)"
    try:
        for label, container, interface in points:
            output_path = diag_dir / (label + ".txt")
            output = output_path.open("w", encoding="utf-8")
            command = [
                "docker", "exec", container, "timeout",
                str(CAPTURE_SECONDS), "tcpdump", "-n", "-l", "-tttt",
                "-vv", "-s", str(int(scope.get("snaplen_bytes", CAPTURE_SNAPLEN))),
                "-i", interface,
                packet_filter,
            ]
            process = subprocess.Popen(
                command, stdout=output, stderr=subprocess.STDOUT,
                universal_newlines=True)
            started.append({"label": label, "container": container,
                            "interface": interface, "path": output_path,
                            "output": output, "process": process})
            time.sleep(0.35)
            if process.poll() is not None:
                output.flush()
                raise RuntimeError("packet observer failed to start on {}: {}".format(
                    label, output_path.read_text(encoding="utf-8")))
    except BaseException:
        _finish_tcpdump_processes(started)
        raise
    return started


def _finish_tcpdump_processes(processes):
    errors = []
    for item in processes:
        process = item["process"]
        try:
            process.wait(timeout=CAPTURE_SECONDS + 5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            errors.append("packet observer timeout: " + item["label"])
        finally:
            item["output"].flush()
            item["output"].close()
        # GNU timeout returns 124 after the intended 18-second observation.
        if process.returncode not in (0, 124):
            errors.append("packet observer exit {}: {}".format(
                process.returncode, item["label"]))
    return errors


def _events_from_relay(path):
    events = []
    if not Path(path).is_file():
        return events
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and item.get("event"):
            events.append(item)
    return events


def _packet_observations(diag_dir):
    observations = {}
    for label in ("gs26-wf-gre0", "gs27-wf-gre0", "gs27-b27-default"):
        path = Path(diag_dir) / (label + ".txt")
        text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        observations[label] = {
            "path": str(path),
            "file_exists": path.is_file(),
            "tcp_flags_decoded": "Flags [" in text,
            "syn_seen": "Flags [S]" in text,
            "syn_ack_seen": "Flags [S.]" in text or "Flags [S,S.]" in text,
            "reset_seen": "Flags [R" in text,
            "packet_lines": sum(1 for line in text.splitlines()
                                if " IP " in line or " IP6 " in line),
            "tcpdump_output": text,
        }
    return observations


def _first_missing_segment(observations, relay_events, probe):
    if probe.get("passed") is True and probe.get("target_http_status") == "200":
        return "path_operational_during_diagnosis_original_R002_cause_not_reproduced"
    a = observations["gs26-wf-gre0"]
    b = observations["gs27-wf-gre0"]
    c = observations["gs27-b27-default"]
    event_names = [item.get("event") for item in relay_events]
    if not any(row["file_exists"] for row in observations.values()):
        return "unresolved_observer_output_missing"
    if any(row["packet_lines"] and not row["tcp_flags_decoded"]
           for row in observations.values()):
        return "unresolved_tcp_flags_truncated_by_capture_snaplen"
    if not a["syn_seen"]:
        return "no_client_SYN_observed_on_GS26_wf-gre0"
    if not b["syn_seen"]:
        return "first_gap_between_GS26_wf-gre0_and_GS27_wf-gre0"
    if not c["syn_seen"]:
        return "first_gap_between_GS27_wf-gre0_and_B27-default"
    if "client_accepted" not in event_names:
        return "first_gap_after_B27-default_before_host_relay_accept"
    if "upstream_connected" not in event_names:
        return "relay_to_127.0.0.1_17897_upstream_connect_failed_or_timed_out"
    return "relay_upstream_connected_but_HTTPS_CONNECT_response_path_not_proven"


def _write_diagnostic_report(run_dir, summary):
    run_dir = Path(run_dir)
    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = read_json(manifest_path)
        manifest["stage"] = "v3_proxy_path_diagnosis"
        manifest["diagnostic_only"] = True
        manifest["sample_manifest_created"] = False
        manifest["sample_attempt_ledger_write"] = False
        manifest["training_started"] = False
        manifest["browser_tor_collection_started"] = False
        manifest["capture"] = {
            "format": "tcpdump textual packet headers",
            "interfaces": ["GS26:wf-gre0", "GS27:wf-gre0",
                           "GS27:B27-default"],
            "snaplen_bytes": CAPTURE_SNAPLEN,
            "application_payload_captured": False,
        }
        write_json(manifest_path, manifest)
    (run_dir / "DIAGNOSIS_REPORT.md").write_text(
        "# V3 R002 proxy-path diagnosis\n\n"
        "This run is diagnostic only. The expected stop occurs immediately "
        "before Browser/Tor helper startup. It creates no class sample and "
        "does not write the pilot attempt ledger.\n\n"
        "- Network run: `{}`\n"
        "- Raw dynamic controller status: `{}` (the controlled early stop is "
        "recorded in `diagnosis_summary.json`)\n"
        "- Topology CONNECT: `{}`\n"
        "- Browser/Tor helper started: `false`\n"
        "- Sample manifest created: `false`\n"
        "- Training started: `false`\n".format(
            summary.get("run_id"), summary.get("status"),
            summary.get("proxy_path", {}).get(
                "gre_nat_https_connect_probe", {}).get("passed")),
        encoding="utf-8")


def _run_diagnostic(plan_path=DIAG_PLAN):
    plan = read_json(plan_path)
    diag_root = (ROOT / plan.get("artifacts", {}).get("root", "")).resolve()
    audit = audit_plan(plan_path)
    audit_path = READINESS_DIR / (Path(plan_path).stem + "_audit.json")
    write_json(audit_path, audit)
    if audit.get("passed") is not True:
        raise RuntimeError("diagnosis plan audit failed: "
                           + "; ".join(audit.get("errors", [])))
    if not os.environ.get("TMUX"):
        raise RuntimeError("run this bounded diagnosis inside tmux session starrynet")
    if not str(Path(sys.prefix)).endswith("/envs/starrynet"):
        raise RuntimeError("diagnosis must run in conda environment starrynet")
    if collector.active_v3_collectors():
        raise RuntimeError("an official V3 collection process is active")
    if diag_root.exists() and any(diag_root.iterdir()):
        raise RuntimeError("diagnosis artifact root already has data; refusing overwrite")
    diag_root.mkdir(parents=True, exist_ok=True)

    lock_handles = _acquire_locks()
    ledger_path = READINESS_DIR / "attempt_ledger.jsonl"
    ledger_sha_before = sha256_file(ledger_path)
    try:
        host_preflight_path = diag_root / "host_proxy_preflight.json"
        host_preflight = collector.proxy_preflight(
            collector.DEFAULT_V2_CONFIG, host_preflight_path)
        if host_preflight.get("passed") is not True:
            write_json(diag_root / "diagnosis_summary.json", {
                "schema_version": 1,
                "diagnosis_status": "stopped_host_preflight_failed",
                "diagnostic_topology_started": False,
                "host_proxy_preflight": host_preflight,
                "sample_created": False,
            })
            return 3

        preflight_result = dynamic.fixed.preflight()
        if (preflight_result.get("status") != "preflight_passed"
                and preflight_result.get("passed") is not True):
            write_json(diag_root / "diagnosis_summary.json", {
                "schema_version": 1,
                "diagnosis_status": "stopped_runtime_preflight_failed",
                "diagnostic_topology_started": False,
                "host_proxy_preflight": host_preflight,
                "runtime_preflight": preflight_result,
                "sample_created": False,
            })
            return 3

        pilot = read_json(PILOT_PLAN)
        config = proxy_runtime.read_json(collector.DEFAULT_V2_CONFIG)
        planned_run = {"sample_id": "v3-path-diagnosis-r002-20261022"}
        scope = plan.get("scope", {})
        session = collector.BrowserTorSession(
            pilot, planned_run, config, collector.DEFAULT_V2_CONFIG)
        fixed_port = scope.get("fixed_relay_port")
        if fixed_port is not None:
            session._free_gateway_port = lambda _gateway: int(fixed_port)
        existing_helper = collector.v2_runner.docker(
            "inspect", session.name, check=False, timeout=10)
        if existing_helper.returncode == 0:
            raise RuntimeError("diagnostic helper container name already exists; "
                               "refusing to remove or reuse it")
        session.runtime_inputs = collector.runtime_asset_snapshot(
            config, collector.DEFAULT_V2_CONFIG)
        session.source_paths.extend([Path(__file__).resolve(), DIAG_RELAY])
        session.diagnostic_observers = []
        session.diagnostic_observer_errors = []
        session.diagnostic_probe_count = 0
        session.diagnostic_dir = None

        def stop_before_helper():
            raise DiagnosticBoundary(
                "expected diagnostic boundary: stopped before Browser/Tor helper")
        session._start_browser_helper = stop_before_helper

        def diagnostic_report(run_dir, summary):
            _write_diagnostic_report(run_dir, summary)
        session.write_report = diagnostic_report

        original_start_relay = collector.v2_runner.start_host_relay

        def start_diagnostic_relay(_script, run_dir, listen, upstream):
            return original_start_relay(DIAG_RELAY, run_dir, listen, upstream)
        collector.v2_runner.start_host_relay = start_diagnostic_relay

        original_run_command = dynamic.fixed.run_command

        def observed_run_command(args, timeout=60, check=True):
            args = [str(item) for item in args]
            is_probe = ("curl" in args and "--proxy" in args
                        and any(item.startswith("https://example.com/")
                                for item in args))
            if not is_probe:
                return original_run_command(args, timeout=timeout, check=check)
            session.diagnostic_probe_count += 1
            if session.diagnostic_probe_count > MAX_PROBES:
                raise RuntimeError("diagnosis probe limit exceeded")
            port_text = args[args.index("--proxy") + 1].rsplit(":", 1)[1]
            port = int(port_text)
            session.diagnostic_dir = Path(session.run_dir) / "diagnostics"
            session.diagnostic_observers = _tcpdump_processes(
                session, port, session.diagnostic_dir, scope)
            try:
                return original_run_command(args, timeout=timeout, check=check)
            finally:
                session.diagnostic_observer_errors.extend(
                    _finish_tcpdump_processes(session.diagnostic_observers))
                session.diagnostic_observers = []

        dynamic.fixed.run_command = observed_run_command
        old_artifact_root = dynamic.DYNAMIC_ARTIFACTS
        dynamic.DYNAMIC_ARTIFACTS = diag_root
        try:
            result = dynamic.run_scenario(
                "dynamic_no_handover", browser_session=session,
                preflight_result=preflight_result,
                topology_duration_seconds=dynamic.BROWSER_TOPOLOGY_SECONDS,
                simulation_start_utc=dynamic.BROWSER_SIMULATION_START_UTC)
        finally:
            dynamic.fixed.run_command = original_run_command
            collector.v2_runner.start_host_relay = original_start_relay
            dynamic.DYNAMIC_ARTIFACTS = old_artifact_root

        raw = read_json(result["summary"])
        run_dir = Path(result["summary"]).resolve().parent
        probe = raw.get("proxy_path", {}).get("gre_nat_https_connect_probe", {})
        relay_log = run_dir / "logs/host-relay.log"
        relay_events = _events_from_relay(relay_log)
        observers = _packet_observations(run_dir / "diagnostics")
        stop_marker = any(
            "expected diagnostic boundary" in str(item)
            for item in raw.get("errors", []))
        helper_started = bool(raw.get("browser_tor", {}).get(
            "helper_summary_path") or raw.get("browser_tor", {}).get(
                "helper_exit_code") is not None)
        cleanup = {
            "top_level_cleanup_verified": raw.get("cleanup_verified") is True,
            "route_nat_restored": raw.get("route_nat_restored") is True,
            "docker_inventory_restored": raw.get("docker_inventory_restored") is True,
            "host_relay_cleanup_verified": raw.get("browser_tor", {}).get(
                "host_relay_cleanup_verified") is True,
            "observer_errors": session.diagnostic_observer_errors,
        }
        first_missing = _first_missing_segment(observers, relay_events, probe)
        diag_status = (
            "path_probe_passed_stopped_before_helper"
            if (probe.get("passed") is True and stop_marker
                and session.diagnostic_probe_count == MAX_PROBES
                and all(row.get("file_exists") is True
                        for row in observers.values())
                and not cleanup["observer_errors"]
                and all(
                value is True for key, value in cleanup.items()
                if key != "observer_errors")
                and not helper_started
                and not (run_dir / "sample_manifest.json").exists()
                and not raw.get("captures")
                and not raw.get("visits")
                and ledger_sha_before == sha256_file(ledger_path))
            else "probe_failed_or_diagnostic_incomplete")
        diagnostic_summary = {
            "schema_version": 1,
            "diagnostic_plan_id": read_json(plan_path).get("plan_id"),
            "diagnosis_status": diag_status,
            "first_missing_segment_interpretation": first_missing,
            "run_id": raw.get("run_id"),
            "raw_dynamic_status": raw.get("status"),
            "raw_summary_path": str(Path(result["summary"]).resolve()),
            "topology_probe_count": session.diagnostic_probe_count,
            "topology_connect_probe": probe,
            "packet_observations": {
                key: {subkey: value for subkey, value in row.items()
                      if subkey != "tcpdump_output"}
                for key, row in observers.items()},
            "packet_observation_paths": {
                key: row["path"] for key, row in observers.items()},
            "relay_log": str(relay_log),
            "relay_events": relay_events,
            "browser_tor_helper_started": helper_started,
            "sample_manifest_created": (run_dir / "sample_manifest.json").exists(),
            "captures_created": len(raw.get("captures", [])),
            "visits_created": len(raw.get("visits", [])),
            "cleanup": cleanup,
            "attempt_ledger_sha256_before": ledger_sha_before,
            "attempt_ledger_sha256_after": sha256_file(ledger_path),
            "official_attempt_ledger_unchanged": (
                ledger_sha_before == sha256_file(ledger_path)),
            "training_started": False,
            "scientific_fidelity_verified": False,
        }
        diag_summary_path = run_dir / "diagnosis_summary.json"
        write_json(diag_summary_path, diagnostic_summary)
        artifact_paths = [
            host_preflight_path,
            Path(result["summary"]).resolve(),
            run_dir / "manifest.json",
            run_dir / "DIAGNOSIS_REPORT.md",
            relay_log,
            run_dir / "logs/host-relay.ready.json",
            diag_summary_path,
        ] + [Path(row["path"]) for row in observers.values()]
        hashes = {}
        for path in artifact_paths:
            if path.is_file():
                hashes[str(path.resolve())] = sha256_file(path)
        write_json(run_dir / "diagnosis_artifact_hashes.json", {
            "schema_version": 1,
            "hashed_utc": utc_now(),
            "hashes": hashes,
        })
        return 0 if diag_status == "path_probe_passed_stopped_before_helper" else 2
    finally:
        _release_locks(lock_handles)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    audit = sub.add_parser("audit", help="offline audit the separate diagnosis plan")
    audit.add_argument("--plan", default=str(DIAG_PLAN))
    run = sub.add_parser("run", help="run one diagnostic probe, without a sample")
    run.add_argument("--plan", default=str(DIAG_PLAN))
    run.add_argument("--apply", action="store_true",
                     help="acknowledge the bounded diagnostic topology run")
    args = parser.parse_args(argv)
    if args.command == "audit":
        result = audit_plan(args.plan)
        audit_path = READINESS_DIR / (Path(args.plan).stem + "_audit.json")
        write_json(audit_path, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("passed") else 2
    if args.command == "run":
        if not args.apply:
            parser.error("run requires --apply")
        return _run_diagnostic(args.plan)
    parser.error("a command is required: audit or run")


if __name__ == "__main__":
    sys.exit(main())
