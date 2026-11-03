#!/usr/bin/env python3
"""Collect class-2 V3 samples with exact circuit snapshots and Python 3.6 support.

The command has separate offline audit and host-proxy preflight modes. The
``run`` command rechecks the host proxy before it creates any topology, then
starts exactly one independent browser/Tor process and one dynamic no-handover
StarryNet scenario.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import run_e_browser_pilot_v2 as proxy_runtime
import satellite_wf_v3 as v3
import satellite_wf_v3_dynamic_fixed_object as dynamic
import satellite_wf_v3_pilot_plan_circuit_snapshot_py36compat_20261026 as pilot_plan
import satellite_wf_v3_route_nat as route_nat
import satellite_wf_v3_trace_extractor as trace_extractor
import tor_browser_starrynet_smoke_v2 as v2_runner

DEFAULT_PLAN = ROOT / "artifacts/reports/satellite_wf_v3_20261021/"
DEFAULT_PLAN /= "matched_class_x3_readiness_20261022/pilot_plan_class2_x3_circuit_snapshot_py36compat_20261026.json"
DEFAULT_V2_CONFIG = ROOT / "artifacts/e_browser_tor_pilot_v2_2_runtime_rebase_20261026/"
DEFAULT_V2_CONFIG /= "protocol/runtime_config.json"
DEFAULT_V2_FREEZE = ROOT / "artifacts/e_browser_tor_pilot_v2_2_runtime_rebase_20261026/"
DEFAULT_V2_FREEZE /= "protocol/freeze_hashes.json"
READINESS_DIR = ROOT / "artifacts/reports/satellite_wf_v3_20261021/"
READINESS_DIR /= "matched_class_x3_readiness_20261022"
ATTEMPT_LEDGER = READINESS_DIR / "attempt_ledger.jsonl"
ATTEMPT_LEDGER_CORRECTIONS = READINESS_DIR / "attempt_ledger_corrections.jsonl"
CONNECT_PORT = 17897
CAPTURE_SECONDS = dynamic.BROWSER_CAPTURE_SECONDS
CAPTURE_LABELS = (
    "gs26-wf-gre0", "gs27-wf-gre0", "gs27-b27-default",
    "gs26-gre-outer", "gs27-gre-outer")
RUN_STATE = {"topology_started": False}


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds")


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


def file_ref(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": sha256_file(path)}


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def active_v3_collectors():
    result = subprocess.run(["ps", "-eo", "pid=,args="],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=10)
    if result.returncode:
        raise RuntimeError("cannot inspect current processes: " + result.stderr.strip())
    matches = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        if pid == os.getpid():
            continue
        command = fields[1]
        if ("satellite_wf_v3_browser_tor_collector.py run" in command
                or "satellite_wf_v3_dynamic_fixed_object.py run" in command):
            matches.append(line.strip()[:500])
    return matches


def normalize_doctor(doctor):
    resources = doctor.get("starrynet_resources", {})
    return {
        "implementation": "tools/run_e_browser_pilot_v2.py::doctor",
        "python": doctor.get("python"),
        "passed": doctor.get("passed") is True,
        "tmux_starrynet": doctor.get("tmux_starrynet") is True,
        "active_collection_processes": doctor.get("active_collection_processes", []),
        "docker": doctor.get("docker", {}),
        "starrynet_resources_clean": resources.get("clean") is True,
        "helper_image_matches": doctor.get("helper_image", {}).get("matches") is True,
        "errors": doctor.get("errors", []),
    }


def proxy_preflight(config_path=DEFAULT_V2_CONFIG, output_path=None):
    """Run the host doctor followed by three sequential real HTTPS CONNECTs."""
    config_path = Path(config_path).resolve()
    config = proxy_runtime.read_json(config_path)
    doctor_raw = proxy_runtime.doctor(config, check_network=False)
    doctor = normalize_doctor(doctor_raw)
    active_v3 = active_v3_collectors()
    if active_v3:
        doctor["active_v3_collectors"] = active_v3
        doctor["passed"] = False
        doctor.setdefault("errors", []).append("a V3 collector is already active")
    probes = []
    if doctor["passed"]:
        for index in range(1, 4):
            probe = proxy_runtime.https_proxy_probe(CONNECT_PORT)
            probe["index"] = index
            probes.append(probe)
            if not (probe.get("https_connect_passed") is True
                    and probe.get("listener_reachable") is True
                    and probe.get("target_http_status") == 200):
                break
    passed = (doctor["passed"] is True and len(probes) == 3
              and all(item.get("https_connect_passed") is True
                      and item.get("listener_reachable") is True
                      and item.get("target_http_status") == 200
                      for item in probes))
    snapshot = {
        "schema_version": 1,
        "observed_utc": utc_now(),
        "check_scope": "read_only_host_runtime_and_proxy_preflight",
        "runtime_config": file_ref(config_path),
        "runtime_doctor": doctor,
        "https_connect_probe": {
            "implementation": "tools/run_e_browser_pilot_v2.py::https_proxy_probe",
            "proxy": "127.0.0.1:{}".format(CONNECT_PORT),
            "target": "https://example.com/",
            "required_status": 200,
            "sequence": probes,
            "consecutive_count": len(probes),
            "all_passed": len(probes) == 3 and all(
                item.get("https_connect_passed") is True
                and item.get("target_http_status") == 200 for item in probes),
        },
        "passed": passed,
        "interpretation": {
            "host_proxy_readiness_passed": passed,
            "v3_collector_readiness_proven": False,
            "topology_started": False,
            "browser_tor_collection_started": False,
        },
    }
    if output_path:
        write_json(output_path, snapshot)
    return snapshot


def runtime_asset_snapshot(config, config_path=DEFAULT_V2_CONFIG,
                           verify_image=True):
    required = ("browser_dir", "expert_bundle", "bridge_file", "geckodriver",
                "python_site_packages")
    missing = [key for key in required
               if not config.get(key) or not Path(config[key]).exists()]
    if missing:
        raise RuntimeError("V3 Browser/Tor runtime assets are missing: "
                           + ", ".join(missing))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}",
                        str(config.get("helper_image_id", ""))):
        raise RuntimeError("runtime config must pin the helper Docker image ID")
    bridge_lines = [line.strip() for line in Path(config["bridge_file"])
                    .read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    bridge_lines = [line[7:] if line.startswith("Bridge ") else line
                    for line in bridge_lines]
    if not bridge_lines or any(not line.startswith("webtunnel ")
                               for line in bridge_lines):
        raise RuntimeError("frozen bridge input must contain WebTunnel lines")
    asset_names = {
        "browser_dir": "browser_directory",
        "expert_bundle": "expert_bundle",
        "bridge_file": "webtunnel_bridge_file",
        "geckodriver": "geckodriver",
        "python_site_packages": "browser_helper_packages",
    }
    freeze = load_json(DEFAULT_V2_FREEZE)
    frozen_hashes = freeze.get("hashes", {})
    if freeze.get("helper_image_id") != config.get("helper_image_id"):
        raise RuntimeError("V2.2 runtime freeze helper image ID differs from runtime config")
    actual_assets = {key: proxy_runtime.sha256_path(config[key])
                     for key in required}
    for key, frozen_name in asset_names.items():
        expected = frozen_hashes.get(frozen_name, {}).get("sha256")
        if not expected or actual_assets.get(key) != expected:
            raise RuntimeError("V2 frozen Browser/Tor runtime asset changed: " + key)
    hashes = {
        "runtime_freeze": file_ref(DEFAULT_V2_FREEZE),
        "runtime_config": file_ref(config_path),
        "browser_tree_sha256": actual_assets["browser_dir"],
        "expert_bundle_tree_sha256": actual_assets["expert_bundle"],
        "bridge_file_sha256": actual_assets["bridge_file"],
        "geckodriver_sha256": actual_assets["geckodriver"],
        "python_site_packages_tree_sha256": actual_assets[
            "python_site_packages"],
        "helper_image": config["helper_image"],
        "helper_image_id": config["helper_image_id"],
        "bridge_line_count": len(bridge_lines),
    }
    if verify_image:
        observed = dynamic.fixed.run_command([
            "docker", "image", "inspect", config["helper_image"], "--format",
            "{{.Id}}"], timeout=15).stdout.strip()
        hashes["observed_helper_image_id"] = observed
        hashes["helper_image_id_matches"] = (
            observed == config["helper_image_id"])
        if not hashes["helper_image_id_matches"]:
            raise RuntimeError("pinned Browser helper image is unavailable or changed")
    return hashes


def offline_audit(plan_path=DEFAULT_PLAN, v2_config_path=DEFAULT_V2_CONFIG):
    plan_path = Path(plan_path).resolve()
    config_path = Path(v2_config_path).resolve()
    config = load_json(v3.DEFAULT_CONFIG)
    errors = list(v3.validate_config(config))
    try:
        route_nat.validate_runtime_config()
    except Exception as exc:
        errors.append("GRE/NAT runtime config validation failed: " + str(exc))
    plan_result = pilot_plan.audit_plan(plan_path)
    if not plan_result.get("plan_valid"):
        errors.extend("pilot plan: " + item for item in plan_result.get("errors", []))
    current_plan = load_json(plan_path)
    collector = current_plan.get("collector_gate", {})
    try:
        runtime_config = proxy_runtime.read_json(config_path)
        runtime_assets = runtime_asset_snapshot(
            runtime_config, config_path, verify_image=False)
        expected_assets = current_plan.get(
            "browser_runtime_assets_contract", {}).get("asset_hashes", {})
        actual_asset_map = {
            "browser_directory": runtime_assets.get("browser_tree_sha256"),
            "expert_bundle": runtime_assets.get("expert_bundle_tree_sha256"),
            "webtunnel_bridge_file": runtime_assets.get("bridge_file_sha256"),
            "geckodriver": runtime_assets.get("geckodriver_sha256"),
            "browser_helper_packages": runtime_assets.get(
                "python_site_packages_tree_sha256"),
        }
        if expected_assets != actual_asset_map:
            errors.append("Browser/Tor mounted runtime assets differ from the frozen plan")
    except Exception as exc:
        runtime_assets = {}
        errors.append("Browser/Tor runtime asset audit failed: " + str(exc))
    expected_sources = {
        "v3_collector": ("v3_collector", ROOT / "tools/satellite_wf_v3_browser_tor_collector_circuit_snapshot_py36compat_20261026.py"),
        "v3_dynamic_network_controller": ("v3_dynamic_network_controller", ROOT / "tools/satellite_wf_v3_dynamic_fixed_object.py"),
        "v3_route_nat": ("v3_route_nat", ROOT / "tools/satellite_wf_v3_route_nat.py"),
        "v3_browser_helper": ("browser_helper", ROOT / "tools/tor_browser_site_smoke_circuit_snapshot_20261026.py"),
        "p0_topology_audit": ("p0_topology_audit", ROOT / "tools/p0_smoke.py"),
        "v2_host_proxy_relay": ("v2_host_proxy_relay", ROOT / "tools/tor_browser_starrynet_smoke_v2.py"),
        "v3_trace_extractor": ("trace_extractor", ROOT / "tools/satellite_wf_v3_trace_extractor.py"),
    }
    source_hashes = {}
    for name, (frozen_name, path) in expected_sources.items():
        source_hashes[name] = file_ref(path)
        frozen = current_plan.get("frozen_inputs", {}).get(frozen_name, {})
        if frozen.get("path") != str(path.relative_to(ROOT)):
            errors.append("pilot plan does not freeze " + name)
        elif frozen.get("sha256") != source_hashes[name]["sha256"]:
            errors.append("pilot plan source hash changed for " + name)
    runtime_config_ref = {"path": str(config_path)}
    if not config_path.is_file():
        errors.append("V2 runtime config is missing")
    else:
        runtime_config_ref["sha256"] = sha256_file(config_path)
    return {
        "audit_time_utc": utc_now(),
        "plan": plan_result,
        "runtime_config_status": config.get("runtime_status"),
        "network": {
            "mode": config.get("network", {}).get("mode"),
            "capture_interface": config.get("network", {}).get("capture_interface"),
            "egress_interface": config.get("network", {}).get("egress_interface"),
            "browser_proxy_environment": config.get("network", {}).get(
                "browser_proxy_environment"),
            "route_nat_module": "integrated",
        },
        "collector_gate": collector,
        "frozen_sources": source_hashes,
        "runtime_assets_config": runtime_config_ref,
        "runtime_assets_verified": bool(runtime_assets),
        "runtime_asset_hashes": runtime_assets,
        "collector_path_exists": expected_sources["v3_collector"][1].is_file(),
        "gre_nat_path_wired_to_collector": (
            "browser_session.prepare" in
            expected_sources["v3_dynamic_network_controller"][1].read_text(
                encoding="utf-8")
            and "route_nat.install(" in
            expected_sources["v3_dynamic_network_controller"][1].read_text(
                encoding="utf-8")),
        "proxy_readiness_requires_three_live_http_200_connects": True,
        "topology_started": False,
        "collection_started": False,
        "training_started": False,
        "passed": not errors,
        "errors": errors,
    }


class BrowserTorSession(object):
    def __init__(self, plan, planned_run, runtime_config,
                 runtime_config_path=DEFAULT_V2_CONFIG):
        self.plan = plan
        self.planned_run = planned_run
        self.runtime_config = runtime_config
        self.runtime_config_path = Path(runtime_config_path).resolve()
        self.name = "v3-browser-{}".format(
            self.planned_run["sample_id"].lower().replace("_", "-")[-48:])
        self.run_dir = None
        self.client_id = None
        self.egress_id = None
        self.control_dir = None
        self.helper_process_exit = None
        self.host_relay = None
        self.host_relay_port = None
        self.host_gateway = None
        self.capture_stop_acknowledged = False
        self.capture_start_acknowledged = False
        self.capture_start_request_id = None
        self.capture_stop_request_id = None
        self.capture_start_request = None
        self.capture_stop_request = None
        self.capture_started_monotonic = None
        self.capture_started_utc = None
        self.capture_stopped_monotonic = None
        self.capture_stopped_utc = None
        self.callback_started_monotonic = None
        self.callback_start_logical = None
        self.browser_summary = None
        self.runtime_inputs = None
        self.network_summary = None
        self.source_paths = [
            Path(__file__).resolve(),
            ROOT / "tools/tor_browser_site_smoke_circuit_snapshot_20261026.py",
            ROOT / "tools/tor_browser_starrynet_smoke_v2.py",
            ROOT / "tools/satellite_wf_v3_trace_extractor.py",
        ]

    def prepare(self, run_dir, run_manifest, client_id, egress_id,
                route_state, network_summary):
        self.run_dir = Path(run_dir).resolve()
        self.network_summary = network_summary
        self.client_id = str(client_id)
        self.egress_id = str(egress_id)
        self.control_dir = self.run_dir / "browser_tor" / "capture_control"
        self.control_dir.mkdir(parents=True, exist_ok=False)
        if self.runtime_inputs is None:
            self.runtime_inputs = runtime_asset_snapshot(
                self.runtime_config, self.runtime_config_path)
        self.runtime_inputs["helper_image"] = self.runtime_config.get("helper_image")

        docker_network = json.loads(v2_runner.docker(
            "network", "inspect", "GS_27").stdout)[0]
        self.host_gateway = v2_runner.get_bridge_gateway(docker_network)
        proxy_route_override = route_nat.ensure_client_host_route_via_gre(
            route_state, self.host_gateway)
        proxy_client_route = route_nat._route(self.client_id, self.host_gateway)
        proxy_egress_route = route_nat._route(self.egress_id, self.host_gateway)
        network_summary["proxy_path"] = {
            "host_proxy": "127.0.0.1:{}".format(CONNECT_PORT),
            "host_gateway": self.host_gateway,
            "tor_https_proxy_endpoint": "{}:{}".format(
                self.host_gateway, self.host_relay_port if self.host_relay_port else "pending"),
            "gs26_route_before_override": proxy_route_override.get("before"),
            "gs26_route": proxy_client_route,
            "gs27_route": proxy_egress_route,
            "proxy_gateway_route_override": proxy_route_override,
            "browser_proxy_environment": "unset",
            "tor_https_proxy_over_v3_gre_nat": True,
        }
        if proxy_client_route.get("dev") != "wf-gre0":
            raise RuntimeError("host proxy endpoint does not route through GS26 wf-gre0: {}".format(
                proxy_client_route.get("raw", proxy_client_route)))
        if proxy_egress_route.get("dev") != "B27-default":
            raise RuntimeError("host proxy endpoint does not exit through GS27 B27-default: {}".format(
                proxy_egress_route.get("raw", proxy_egress_route)))
        self.host_relay_port = self._free_gateway_port(self.host_gateway)
        logs_dir = self.run_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        relay_script = ROOT / "tools/tor_browser_starrynet_smoke_v2.py"
        self.host_relay = v2_runner.start_host_relay(
            relay_script, self.run_dir,
            "{}:{}".format(self.host_gateway, self.host_relay_port),
            "127.0.0.1:{}".format(CONNECT_PORT))
        network_summary["proxy_path"]["tor_https_proxy_endpoint"] = "{}:{}".format(
            self.host_gateway, self.host_relay_port)
        route_probe = dynamic.fixed.run_command([
            "docker", "exec", self.client_id,
            "env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "ALL_PROXY",
            "-u", "http_proxy", "-u", "https_proxy", "-u", "all_proxy",
            "-u", "NO_PROXY", "-u", "no_proxy",
            "curl", "--silent", "--show-error", "--connect-timeout", "5",
            "--max-time", "15", "--proxy",
            "http://{}:{}".format(self.host_gateway, self.host_relay_port),
            "--output", "/dev/null", "--write-out", "%{http_code}",
            "https://example.com/"], timeout=20, check=False)
        network_summary["proxy_path"]["gre_nat_https_connect_probe"] = {
            "returncode": route_probe.returncode,
            "target_http_status": route_probe.stdout.strip(),
            "error": route_probe.stderr.strip(),
            "passed": route_probe.returncode == 0
            and route_probe.stdout.strip() == "200",
        }
        if network_summary["proxy_path"]["gre_nat_https_connect_probe"]["passed"] is not True:
            raise RuntimeError("HTTPS CONNECT through V3 GRE/NAT to the host proxy failed")

        self._start_browser_helper()
        ready_path = self.control_dir / "tor_ready.json"
        deadline = time.monotonic() + min(
            360, int(self.runtime_config.get("collector_timeout_seconds", 1200)))
        while time.monotonic() < deadline:
            if ready_path.is_file():
                ready = load_json(ready_path)
                check = ready.get("tor_check", {})
                if (ready.get("ok") is True
                        and check.get("tor_check_passed") is True
                        and check.get("check_streams_closed_before_capture") is True):
                    network_summary["browser_tor_ready_before_topology_window"] = {
                        "passed": True,
                        "observed_utc": ready.get("observed_utc"),
                        "observed_monotonic": ready.get("observed_monotonic"),
                        "check_stream_ids": check.get("check_stream_ids", []),
                    }
                    run_manifest["stage"] = "v3_browser_tor_sample"
                    run_manifest["collector_sources"] = {
                        str(path.relative_to(ROOT)): sha256_file(path)
                        for path in self.source_paths}
                    run_manifest["browser_runtime_inputs"] = self.runtime_inputs
                    run_manifest["planned_sample"] = self.planned_run
                    run_manifest["route_nat_state_path"] = str(route_state)
                    write_json(self.run_dir / "manifest.json", run_manifest)
                    dynamic.fixed.write_json(
                        self.run_dir / "summary.json", network_summary)
                    return
                raise RuntimeError("Tor check failed before the V3 capture gate")
            state = v2_runner.docker(
                "inspect", "--format", "{{.State.Running}}", self.name,
                check=False, timeout=10)
            if state.returncode == 0 and state.stdout.strip().lower() != "true":
                logs = v2_runner.docker("logs", self.name, check=False).stdout
                raise RuntimeError("Browser/Tor helper exited before Tor readiness: "
                                   + logs[-1000:])
            time.sleep(0.2)
        raise TimeoutError("Tor Browser did not pass its pre-capture check")

    @staticmethod
    def _free_gateway_port(gateway):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((gateway, 0))
            return listener.getsockname()[1]

    def _start_browser_helper(self):
        config = self.runtime_config
        uid, gid = os.getuid(), os.getgid()
        browser_helper = ROOT / "tools/tor_browser_site_smoke_circuit_snapshot_20261026.py"
        container_control_dir = "/out/browser_tor/capture_control"
        browser_command = [
            "docker", "run", "-d", "--name", self.name,
            "--network", "container:" + self.client_id,
            "--user", "{}:{}".format(uid, gid),
            "-e", "HOME=/tmp/tor-browser-home", "-e", "TMPDIR=/tmp",
            "-e", "PYTHONPATH=/opt/py312site",
            "-e", "HTTP_PROXY=", "-e", "HTTPS_PROXY=", "-e", "ALL_PROXY=",
            "-e", "http_proxy=", "-e", "https_proxy=", "-e", "all_proxy=",
            "-e", "NO_PROXY=", "-e", "no_proxy=",
            "-v", str(Path(config["browser_dir"]).resolve()) + ":/opt/tor-browser:ro",
            "-v", str(Path(config["expert_bundle"]).resolve()) + ":/opt/expert-bundle:ro",
            "-v", str(Path(config["bridge_file"]).resolve()) + ":/opt/webtunnel-bridges.txt:ro",
            "-v", str(Path(config["geckodriver"]).resolve()) + ":/usr/local/bin/geckodriver:ro",
            "-v", str(Path(config["python_site_packages"]).resolve()) + ":/opt/py312site:ro",
            "-v", str(browser_helper.resolve()) + ":/opt/tor_browser_site_smoke.py:ro",
            "-v", str(self.run_dir) + ":/out:rw",
            "--entrypoint", "python3.11", config["helper_image"],
            "/opt/tor_browser_site_smoke.py",
            "--browser-dir", "/opt/tor-browser",
            "--expert-bundle", "/opt/expert-bundle",
            "--bridge-file", "/opt/webtunnel-bridges.txt",
            "--geckodriver", "/usr/local/bin/geckodriver",
            "--output-root", "/out/browser_runs",
            "--capture-control-dir", container_control_dir,
            "--capture-ack-timeout", "90",
            "--label", str(self.planned_run["class_id"]),
            "--url", self.planned_run["requested_url"],
            "--visits", "1", "--bootstrap-timeout", "300",
            "--page-load-timeout", str(dynamic.BROWSER_PAGE_LOAD_TIMEOUT_SECONDS),
            "--page-content-timeout", str(dynamic.BROWSER_PAGE_CONTENT_TIMEOUT_SECONDS),
            "--resource-idle-seconds", "4", "--capture-settle-seconds",
            str(dynamic.BROWSER_CAPTURE_SETTLE_SECONDS),
            "--fixed-window-seconds", str(CAPTURE_SECONDS),
            "--direct-network", "--https-proxy", "{}:{}".format(
                self.host_gateway, self.host_relay_port),
            "--wait-for-capture-gate", "--capture-gate-timeout", "900",
        ]
        result = dynamic.fixed.run_command(browser_command, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError("could not start V3 Browser/Tor helper: "
                               + (result.stderr or result.stdout).strip())

    def release_capture_gate(self, raw_start, raw_start_utc,
                             logical_start, callback_started):
        self.capture_started_monotonic = raw_start
        self.capture_started_utc = raw_start_utc
        self.callback_start_logical = logical_start
        self.callback_started_monotonic = callback_started
        write_json(self.control_dir / "capture_release.json", {
            "ok": True,
            "released_utc": utc_now(),
            "released_monotonic": time.monotonic(),
            "raw_capture_start_utc": raw_start_utc,
            "raw_capture_start_monotonic": raw_start,
            "logical_capture_start": logical_start,
        })

    @staticmethod
    def mark_topology_started():
        RUN_STATE["topology_started"] = True

    def service_capture_control(self, captures, summary, run_dir, logical_now):
        for phase in ("start", "stop"):
            request_path = self.control_dir / "capture_{}_request.json".format(phase)
            ack_path = self.control_dir / "capture_{}_ack.json".format(phase)
            if not request_path.is_file() or ack_path.is_file():
                continue
            request = load_json(request_path)
            request_id = request.get("request_id")
            if not request_id:
                raise RuntimeError("capture {} request omitted request_id".format(phase))
            if phase == "start":
                if self.capture_start_request_id not in (None, request_id):
                    raise RuntimeError("V3 capture start request ID changed")
                self.capture_start_request_id = request_id
                self.capture_start_request = request
                self.capture_start_acknowledged = True
                response = {
                    "ok": True, "request_id": request_id,
                    "phase": phase, "logical_second": logical_now,
                    "capture_interfaces": CAPTURE_LABELS,
                    "captures_already_live": all(
                        not item.get("stopped") for item in captures),
                }
                if response["captures_already_live"] is not True:
                    response.update({"ok": False,
                                     "error": "one or more V3 capture processes are not live"})
                write_json(ack_path, response)
            else:
                if self.capture_start_acknowledged is not True:
                    raise RuntimeError("capture stop arrived before acknowledged capture start")
                if self.capture_stop_request_id not in (None, request_id):
                    raise RuntimeError("V3 capture stop request ID changed")
                self.capture_stop_request_id = request_id
                self.capture_stop_request = request
                errors = []
                for capture in captures:
                    try:
                        dynamic.fixed.stop_capture(capture)
                    except Exception as exc:
                        errors.append("{}: {}".format(capture.get("label"), exc))
                self.capture_stopped_monotonic = time.monotonic()
                self.capture_stopped_utc = utc_now()
                self.capture_stop_acknowledged = not errors
                response = {
                    "ok": not errors, "request_id": request_id,
                    "phase": phase,
                    "capture_end_utc": self.capture_stopped_utc,
                    "capture_end_monotonic": self.capture_stopped_monotonic,
                    "logical_second": logical_now,
                    "errors": errors,
                }
                write_json(ack_path, response)
                summary["time_boundaries"].update({
                    "raw_capture_end_monotonic": self.capture_stopped_monotonic,
                    "raw_capture_end_utc": self.capture_stopped_utc,
                    "capture_end_logical_second_estimate": logical_now,
                })
                summary["browser_capture_control"] = {
                    "start_request": self.capture_start_request,
                    "start_ack": load_json(self.control_dir / "capture_start_ack.json"),
                    "stop_request": self.capture_stop_request,
                    "stop_ack": response,
                }

    def finish(self, run_dir, network_summary):
        if self.name is None:
            raise RuntimeError("Browser/Tor session was not started")
        if not self.capture_stop_acknowledged:
            raise RuntimeError("Browser/Tor helper did not complete the capture stop handshake")
        result = v2_runner.docker("wait", self.name, check=False, timeout=90)
        if result.returncode:
            raise RuntimeError("Browser/Tor helper did not exit cleanly: "
                               + result.stderr.strip())
        try:
            self.helper_process_exit = int(result.stdout.strip())
        except ValueError:
            self.helper_process_exit = None
        logs = v2_runner.docker("logs", self.name, check=False).stdout
        (Path(run_dir) / "logs" / "browser-tor-helper.log").write_text(
            logs, encoding="utf-8")
        summaries = sorted((Path(run_dir) / "browser_runs").glob("*/summary.json"))
        if len(summaries) != 1:
            raise RuntimeError("expected exactly one Browser/Tor helper summary")
        self.browser_summary = load_json(summaries[0])
        if self.helper_process_exit != 0:
            network_summary.setdefault("errors", []).append(
                "Browser/Tor helper exited with code {}".format(
                    self.helper_process_exit))
        summary_copy = Path(run_dir) / "browser_tor" / "browser_summary.json"
        write_json(summary_copy, self.browser_summary)
        visits = self.browser_summary.get("visits", [])
        visit = visits[0] if len(visits) == 1 else {}
        capture_window = visit.get("capture_window", {})
        nav_start = capture_window.get("navigation_started", {})
        nav_end = capture_window.get("navigation_completed", {})
        boundaries = network_summary.get("time_boundaries", {})
        if all(nav_start.get(field) is not None for field in ("utc", "monotonic")) and all(
                nav_end.get(field) is not None for field in ("utc", "monotonic")):
            boundaries.update({
                "navigation_start_utc": nav_start["utc"],
                "navigation_start_monotonic": nav_start["monotonic"],
                "navigation_complete_utc": nav_end["utc"],
                "navigation_complete_monotonic": nav_end["monotonic"],
                "topology_start_seconds": self.callback_start_logical,
                "topology_end_seconds": (
                    self.callback_start_logical
                    + self.capture_stopped_monotonic
                    - self.callback_started_monotonic),
            })
        network_summary["time_boundaries"] = boundaries
        boundaries.update({
            "raw_capture_start_monotonic": self.capture_started_monotonic,
            "raw_capture_start_utc": self.capture_started_utc,
            "raw_capture_end_monotonic": self.capture_stopped_monotonic,
            "raw_capture_end_utc": self.capture_stopped_utc,
        })
        network_summary["browser_tor"] = {
            "passed": self.browser_summary.get("passed") is True,
            "helper_exit_code": self.helper_process_exit,
            "helper_summary_path": str(summary_copy),
            "transport": self.browser_summary.get("transport"),
            "browser_proxy_environment": self.browser_summary.get(
                "browser_proxy_environment"),
            "tor_https_proxy_endpoint": self.browser_summary.get(
                "tor_https_proxy_endpoint"),
            "browser_version": self.browser_summary.get("tor_browser_version"),
            "tor_version": self.browser_summary.get("tor_version"),
            "browser_tree_sha256": self.runtime_inputs.get(
                "browser_tree_sha256"),
            "tor_binary_sha256": sha256_file(
                Path(self.runtime_config["expert_bundle"]) / "tor/tor"),
            "browser_helper_source_sha256": sha256_file(
                ROOT / "tools/tor_browser_site_smoke_circuit_snapshot_20261026.py"),
            "helper_image_id": self.runtime_inputs.get("helper_image_id"),
            "cleanup_verified": (self.browser_summary.get("cleanup_verified") is True
                                 and self.helper_process_exit == 0),
        }
        return self.browser_summary

    def cleanup(self):
        errors = []
        if self.name:
            result = v2_runner.docker("rm", "-f", self.name,
                                      check=False, timeout=30)
            if result.returncode:
                inspect = v2_runner.docker("inspect", self.name,
                                           check=False, timeout=10)
                if inspect.returncode == 0:
                    errors.append("Browser/Tor helper container remains")
        if self.host_relay:
            if not v2_runner.stop_host_relay(self.host_relay):
                errors.append("host proxy relay process remains")
            self.host_relay = None
        if self.network_summary is not None:
            browser = self.network_summary.setdefault("browser_tor", {})
            browser["host_relay_cleanup_verified"] = not errors
            browser["cleanup_verified"] = (
                browser.get("cleanup_verified") is True and not errors)
            self.network_summary["browser_tor_cleanup_errors"] = list(errors)
        return errors

    def write_report(self, run_dir, summary):
        lines = [
            "# V3 Browser/Tor matched-class sample run",
            "",
            "- Sample ID: `{}`".format(self.planned_run.get("sample_id")),
            "- Network status: `{}`".format(summary.get("status")),
            "- Engineering GRE/NAT acceptance: `{}`".format(
                summary.get("engineering_network_acceptance_passed")),
            "- Candidate training sample: `false`",
            "- Scientific fidelity verified: `false`",
            "",
            "## V3 route and capture gates",
            "",
        ]
        lines.extend("- {}: `{}`".format(key, value)
                     for key, value in summary.get("checks", {}).items())
        lines.extend(["", "## Browser/Tor", "",
                      "- Helper status: `{}`".format(
                          summary.get("browser_tor", {}).get("passed")),
                      "- Capture control stop acknowledged: `{}`".format(
                          self.capture_stop_acknowledged),
                      "- Browser proxy environment: `{}`".format(
                          summary.get("browser_tor", {}).get(
                              "browser_proxy_environment")),
                      "- Tor upstream proxy route: GS26 `wf-gre0` -> GS27 `B27-default` -> host proxy",
                      ""])
        if summary.get("errors"):
            lines.extend(["## Errors", ""])
            lines.extend("- {}".format(item) for item in summary["errors"])
        (Path(run_dir) / "REPORT.md").write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8")


def sample_from_summary(plan, planned_run, run_dir, network_summary,
                        source_audit_path):
    run_dir = Path(run_dir).resolve()
    browser = network_summary.get("browser_tor", {})
    visits = network_summary.get("visits", [])
    visit = visits[0] if len(visits) == 1 else {}
    page = {
        "requested_url": planned_run["requested_url"],
        "final_url": visit.get("final_url"),
        "http_status": visit.get("http_status"),
        "canonical_url": "",
        "access_challenge_detected": bool(
            visit.get("access_challenge_indicators")),
        "access_challenge_indicators": visit.get(
            "access_challenge_indicators", []),
        "title": visit.get("title"),
        "document_domain": visit.get("document_domain"),
    }
    if page["final_url"]:
        try:
            page["canonical_url"] = v3.normalize_site_url(page["final_url"])
        except ValueError:
            pass
    site_stream_events = visit.get("capture_window", {}).get(
        "site_stream_events", [])
    target_domain = (urlsplit(planned_run["requested_url"]).hostname or "").lower()
    if target_domain.startswith("www."):
        target_domain = target_domain[4:]
    target_stream_ids = {item.get("id") for item in site_stream_events
                         if item.get("status") in ("NEW", "SENTCONNECT")
                         and item.get("address")
                         and (item["address"].lower().rstrip(".") == target_domain
                              or item["address"].lower().rstrip(".").endswith(
                                  "." + target_domain))}
    successful_streams = [item for item in site_stream_events
                          if item.get("id") in target_stream_ids
                          and item.get("status") == "SUCCEEDED"
                          and item.get("circuit_id")]
    target_stream = successful_streams[0] if successful_streams else {}
    target_circuit_id = target_stream.get("circuit_id")
    path_snapshots = visit.get("target_circuit_status_snapshots", [])
    built = next((item for item in path_snapshots
                  if item.get("circuit_id") == target_circuit_id
                  and item.get("status") == "BUILT"
                  and len(item.get("path", [])) == 3), {})
    hops = built.get("path", [])
    fingerprints = [str(item.get("fingerprint", "")).upper() for item in hops]
    route_samples = [item for item in network_summary.get("route_samples", [])
                     if item.get("selected_routes")]
    satellite_nodes = set()
    for sample in route_samples:
        for role in ("client_underlay_route", "egress_underlay_route"):
            device = sample.get("selected_routes", {}).get(role, {}).get("dev", "")
            match = re.fullmatch(r"B(?:26|27)-eth(\d+)", str(device))
            if match:
                satellite_nodes.add(int(match.group(1)))
    capture = network_summary.get("captures", [])
    capture_ok = (set(CAPTURE_LABELS).issubset(
        {item.get("label") for item in capture})
        and all(item.get("interface") == ("any" if item.get("capture_kind") == "gre_outer"
                                             else ("B27-default" if item.get("label") == "gs27-b27-default"
                                                   else "wf-gre0"))
                and item.get("zero_kernel_drops") is True for item in capture))
    packet_audit_result = trace_extractor.extract(
        run_dir / "captures/gs26-wf-gre0.pcap",
        _write_time_boundaries(run_dir, network_summary),
        "10.255.253.1", run_dir / "trace_audit")
    packet_audit = packet_audit_result["packet_audit_data"]
    route_verified = (network_summary.get("initial_route_nat_verification", {}).get(
        "status") == "passed"
        and network_summary.get("handover_verification", {}).get("status") == "passed")
    offloads_verified = network_summary.get(
        "initial_route_nat_verification", {}).get("checks", {}).get(
            "capture_offloads_disabled") is True
    topology_events_recorded = bool(network_summary.get("topology_events"))
    actual_tor_path = bool(
        target_stream.get("id") and target_stream.get("status") == "SUCCEEDED"
        and built.get("status") == "BUILT" and len(hops) == 3
        and len(set(fingerprints)) == 3
        and all(re.fullmatch(r"[0-9A-F]{40}", item) for item in fingerprints))
    nav_start = network_summary.get("time_boundaries", {}).get(
        "navigation_start_monotonic")
    nav_end = network_summary.get("time_boundaries", {}).get(
        "navigation_complete_monotonic")
    capture_start = network_summary.get("time_boundaries", {}).get(
        "raw_capture_start_monotonic")
    capture_end = network_summary.get("time_boundaries", {}).get(
        "raw_capture_end_monotonic")
    time_order = (all(isinstance(value, (int, float)) for value in
                      (capture_start, nav_start, nav_end, capture_end))
                  and capture_start <= nav_start < nav_end <= capture_end)
    clock_pair = (isinstance(network_summary.get("time_boundaries", {}).get(
        "clock_anchor_monotonic"), (int, float))
        and bool(network_summary.get("time_boundaries", {}).get("clock_anchor_utc")))
    gates = {
        "target_identity_verified": bool(page["final_url"] and page["canonical_url"]),
        "target_page_success_verified": bool(visit.get("passed")
                                               and page["http_status"] == 200),
        "access_challenge_absent": page["access_challenge_detected"] is False,
        "tor_target_stream_verified": bool(target_stream.get("status") == "SUCCEEDED"),
        "target_tor_circuit_three_hops_verified": actual_tor_path,
        "route_nat_verified": route_verified,
        "bidirectional_satellite_route_verified": bool(
            network_summary.get("checks", {}).get(
                "dynamic_route_samples_use_satellite_interfaces")),
        "capture_interface_verified": bool(capture_ok and all(
            item.get("label") != "gs26-wf-gre0"
            or item.get("interface") == "wf-gre0" for item in capture)),
        "capture_loss_zero": bool(capture_ok and all(
            item.get("zero_kernel_drops") is True for item in capture)),
        "offloads_disabled_verified": offloads_verified,
        "pcap_trace_audit_passed": packet_audit.get("passed") is True,
        "topology_events_recorded": topology_events_recorded,
        "actual_tor_path_recorded": actual_tor_path,
        "capture_window_order_verified": time_order,
        "clock_pair_verified": clock_pair,
        "cleanup_verified": network_summary.get("cleanup_verified") is True
        and browser.get("cleanup_verified", True) is True,
    }
    source_audit = load_json(source_audit_path)
    requested = planned_run["requested_url"]
    page_host = (urlsplit(requested).hostname or "").lower()
    sample_id = planned_run["sample_id"]
    session_id = planned_run["session_id"]
    sample = {
        "sample_id": sample_id,
        "class_id": str(planned_run["class_id"]),
        "site_url": requested,
        "source_domain": "E",
        "session_id": session_id,
        "split_group_id": session_id,
        "split": "pilot_only",
        "protocol_config_sha256": sha256_file(v3.DEFAULT_CONFIG),
        "class_mapping_sha256": source_audit.get("class_mapping_sha256"),
        "network_scenario_id": "dynamic_no_handover",
        "page_identity": page,
        "tor_path": {
            "target_stream_id": target_stream.get("id"),
            "stream_status": target_stream.get("status"),
            "circuit_id": target_circuit_id,
            "stream_circuit_id": target_stream.get("circuit_id"),
            "circuit_status": built.get("status"),
            "path_evidence_source": built.get("evidence_source"),
            "path_observed_utc": built.get("observed_utc"),
            "path_observed_monotonic": built.get("observed_monotonic"),
            "entry_fingerprint": hops[0].get("fingerprint") if len(hops) == 3 else None,
            "middle_fingerprint": hops[1].get("fingerprint") if len(hops) == 3 else None,
            "exit_fingerprint": hops[2].get("fingerprint") if len(hops) == 3 else None,
            "circuit_path": hops,
        },
        "network_path": {
            "capture_interface": "wf-gre0",
            "egress_interface": "B27-default",
            "route_snapshot_count": len(route_samples),
            "satellite_node_ids": sorted(satellite_nodes),
            "route_snapshots": route_samples,
            "proxy_endpoint_route": network_summary.get("proxy_path", {}),
        },
        "time_boundaries": network_summary.get("time_boundaries", {}),
        "browser_tor": {
            "browser_version": browser.get("browser_version"),
            "tor_version": browser.get("tor_version"),
            "browser_tree_sha256": browser.get("browser_tree_sha256"),
            "tor_binary_sha256": browser.get("tor_binary_sha256"),
            "helper_image_id": browser.get("helper_image_id"),
            "helper_source_sha256": browser.get("browser_helper_source_sha256"),
        },
        "handover": {
            "occurred": not bool(network_summary.get("checks", {}).get(
                "capture_window_has_expected_topology_events")),
            "route_recovered": None,
        },
        "gates": gates,
        "training_eligible": False,
        "pilot_only": True,
    }
    write_json(run_dir / "sample_manifest.json", sample)
    artifacts = []
    artifact_files = (
        ("trace", run_dir / "trace_audit/trace.tsv"),
        ("pcap", run_dir / "captures/gs26-wf-gre0.pcap"),
        ("sample_manifest", run_dir / "sample_manifest.json"),
        ("packet_audit", run_dir / "trace_audit/packet_audit.json"),
        ("topology_events", _write_topology_events(run_dir, network_summary)),
        ("route_events", _write_route_events(run_dir, network_summary)),
    )
    for kind, path in artifact_files:
        artifacts.append({"kind": kind, "path": str(path),
                          "sha256": sha256_file(path)})
    write_json(run_dir / "sample_artifacts.json", {
        "sample_id": sample_id, "artifacts": artifacts,
        "all_gates_passed": all(gates.values()),
        "training_eligible": False,
    })
    sample["artifact_index_path"] = str(run_dir / "sample_artifacts.json")
    sample["sample_status"] = "passed" if all(gates.values()) else "failed"
    sample["training_eligible"] = False
    write_json(run_dir / "sample_manifest.json", sample)
    # The separately hashed sample manifest artifact now binds its final bytes.
    for row in artifacts:
        if row["kind"] == "sample_manifest":
            row["sha256"] = sha256_file(run_dir / "sample_manifest.json")
    write_json(run_dir / "sample_artifacts.json", {
        "sample_id": sample_id, "artifacts": artifacts,
        "all_gates_passed": all(gates.values()),
        "training_eligible": False,
    })
    return sample


def _write_time_boundaries(run_dir, summary):
    path = Path(run_dir) / "time_boundaries.json"
    write_json(path, {"time_boundaries": summary.get("time_boundaries", {})})
    return path


def _write_topology_events(run_dir, summary):
    path = Path(run_dir) / "topology_events.json"
    write_json(path, {
        "planned": summary.get("topology_events", []),
        "observed": summary.get("observed_topology_events", []),
        "window": summary.get("planned_window", {}),
        "simulation_clock": summary.get("simulation_clock", []),
    })
    return path


def _write_route_events(run_dir, summary):
    path = Path(run_dir) / "route_events.jsonl"
    with path.open("w", encoding="utf-8") as stream:
        for row in summary.get("route_samples", []):
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    return path


def _read_attempt_ledger(path=ATTEMPT_LEDGER,
                         corrections_path=ATTEMPT_LEDGER_CORRECTIONS):
    records = []
    path = Path(path)
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    corrections_path = Path(corrections_path) if corrections_path else None
    corrections = {}
    if corrections_path and corrections_path.is_file():
        for line in corrections_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            correction = json.loads(line)
            if correction.get("event") != "classification_review":
                raise RuntimeError("unknown attempt-ledger correction event")
            attempt_id = correction.get("attempt_id")
            if not attempt_id or attempt_id in corrections:
                raise RuntimeError("attempt-ledger correction has a missing or duplicate attempt_id")
            corrections[attempt_id] = correction

    finished_ids = set(row.get("attempt_id") for row in records
                       if row.get("event") == "finished")
    if set(corrections) - finished_ids:
        raise RuntimeError("attempt-ledger correction references an unknown finished attempt")
    corrected = []
    for row in records:
        correction = corrections.get(row.get("attempt_id"))
        if row.get("event") == "finished" and correction:
            if (row.get("failure_class") != correction.get("recorded_failure_class")
                    or row.get("retry_consumed") != correction.get(
                        "recorded_retry_consumed")):
                raise RuntimeError("attempt-ledger correction does not match the recorded classification")
            corrected_class = correction.get("reviewed_failure_class")
            corrected_retry = correction.get("reviewed_retry_consumed")
            if corrected_class not in ("infrastructure", "sample_gate"):
                raise RuntimeError("attempt-ledger correction has an invalid failure class")
            if corrected_class == "infrastructure" and corrected_retry is not False:
                raise RuntimeError("infrastructure failures cannot consume the site retry")
            row = dict(row)
            row["recorded_failure_class"] = row.get("failure_class")
            row["recorded_retry_consumed"] = row.get("retry_consumed")
            row["failure_class"] = corrected_class
            row["retry_consumed"] = corrected_retry
            row["classification_review_id"] = correction.get("review_id")
            row["classification_review_reason"] = correction.get("reason")
        corrected.append(row)
    records = corrected
    return records


def _append_attempt_record(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


def _attempt_retry_policy(plan, index, plan_sha256, records, retry_limit):
    """Enforce sequential samples and one reviewed, re-frozen site retry."""
    runs = plan.get("runs", [])
    passed_ids = set(row.get("sample_id") for row in records
                     if row.get("event") == "finished"
                     and row.get("sample_status") == "passed")
    for prior in runs[:index - 1]:
        if prior.get("sample_id") not in passed_ids:
            raise RuntimeError("V3 runs are sequential; earlier samples must pass before the next index")
    planned = runs[index - 1]
    sample_id = planned.get("sample_id")
    sample_records = [row for row in records
                      if row.get("sample_id") == sample_id]
    started = set(row.get("attempt_id") for row in sample_records
                  if row.get("event") == "started")
    finished = set(row.get("attempt_id") for row in sample_records
                   if row.get("event") == "finished")
    if started - finished:
        raise RuntimeError("a prior collector attempt is unfinished; inspect its artifacts before continuing")
    attempts = [row for row in sample_records if row.get("event") == "finished"]
    if any(row.get("sample_status") == "passed" for row in attempts):
        raise RuntimeError("this planned sample already passed and cannot be collected again")
    retries_used = sum(1 for row in attempts if row.get("retry_consumed") is True)
    if retries_used >= retry_limit:
        raise RuntimeError("the frozen per-site retry limit is exhausted")
    if attempts and attempts[-1].get("plan_sha256") == plan_sha256:
        raise RuntimeError("a failed attempt requires a reviewed and re-frozen plan before retry")
    retry_reserved = any(row.get("failure_class") != "infrastructure"
                         for row in attempts)
    return len(attempts) + 1, retry_reserved


def _classify_attempt_failure(network_summary, exc, topology_started):
    if not topology_started:
        return "infrastructure"
    errors = []
    if isinstance(network_summary, dict):
        errors.extend(str(item).lower() for item in network_summary.get("errors", []))
        errors.extend(str(item).lower() for item in network_summary.get("tracebacks", []))
        # BrowserTorSession.cleanup adds relay-cleanup metadata even when the
        # helper was never launched. Do not treat that placeholder as evidence
        # that a sample capture started.
        browser = network_summary.get("browser_tor") or {}
        helper_observed = bool(
            browser.get("helper_summary_path")
            or browser.get("helper_exit_code") is not None
            or browser.get("passed") is not None
            or browser.get("browser_version")
            or browser.get("tor_version")
            or network_summary.get("visits"))
        # Failures before capture or an observed Browser/Tor helper run are
        # setup/network-infrastructure failures, not sample-data failures.
        if not network_summary.get("captures") and not helper_observed:
            return "infrastructure"
    errors.append(str(exc).lower())
    infra_markers = (
        "proxy endpoint does not route", "initial gre/nat", "route bypass",
        "docker inventory", "container cleanup", "live proxy preflight",
        "docker daemon", "topology scheduler worker failed",
        "p0_smoke.topology_report",
    )
    if any(marker in item for marker in infra_markers for item in errors):
        return "infrastructure"
    return "sample_gate"


def run_one(plan_path, index, v2_config_path=DEFAULT_V2_CONFIG):
    RUN_STATE["topology_started"] = False
    plan_path = Path(plan_path).resolve()
    plan = load_json(plan_path)
    audit = offline_audit(plan_path, v2_config_path)
    if audit.get("passed") is not True or not audit.get("plan", {}).get(
            "manual_execution_ready"):
        raise RuntimeError("V3 offline admission is not ready: "
                           + "; ".join(audit.get("errors", [])))
    if index not in (1, 2, 3):
        raise ValueError("run index must be 1, 2, or 3")
    planned_run = plan["runs"][index - 1]
    ledger_path = READINESS_DIR / "execution_ledger.jsonl"
    if ledger_path.is_file():
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if (record.get("sample_id") == planned_run["sample_id"]
                    and record.get("sample_status") == "passed"):
                raise RuntimeError("this planned sample already passed and cannot be collected again")
    lock_path = READINESS_DIR / "collector.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another V3 pilot collector holds the serial-run lock") from exc
        plan_sha256 = sha256_file(plan_path)
        v3_config = v3.load_json(v3.DEFAULT_CONFIG)
        retry_limit = int(v3_config.get("pilot", {}).get(
            "per_site_retry_limit", 0))
        attempt_number, retry_reserved = _attempt_retry_policy(
            plan, index, plan_sha256, _read_attempt_ledger(), retry_limit)
        snapshot_path = READINESS_DIR / "live_proxy_preflight_{}_{}.json".format(
            planned_run["sample_id"],
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ"))
        live = proxy_preflight(v2_config_path, snapshot_path)
        if live.get("passed") is not True:
            raise RuntimeError("live proxy preflight failed; topology was not started")
        config = proxy_runtime.read_json(v2_config_path)
        runtime_inputs = runtime_asset_snapshot(config, v2_config_path)
        session = BrowserTorSession(plan, planned_run, config, v2_config_path)
        existing = v2_runner.docker("inspect", session.name,
                                    check=False, timeout=10)
        if existing.returncode == 0:
            raise RuntimeError("a container already exists for this planned sample ID")
        session.runtime_inputs = runtime_inputs
        preflight_result = dynamic.fixed.preflight()
        attempt_id = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%dT%H%M%S_%fZ")
        attempt_started = {
            "event": "started", "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "sample_id": planned_run["sample_id"],
            "session_id": planned_run["session_id"],
            "run_index": index, "plan_sha256": plan_sha256,
            "retry_reserved": retry_reserved, "started_utc": utc_now(),
            "live_proxy_snapshot": str(snapshot_path),
        }
        _append_attempt_record(ATTEMPT_LEDGER, attempt_started)
        result = None
        network_summary = {}
        run_dir = None
        attempt_finalized = False
        try:
            result = dynamic.run_scenario(
                "dynamic_no_handover", browser_session=session,
                preflight_result=preflight_result,
                topology_duration_seconds=dynamic.BROWSER_TOPOLOGY_SECONDS,
                simulation_start_utc=dynamic.BROWSER_SIMULATION_START_UTC)
            run_dir = Path(result["summary"]).resolve().parent
            network_summary = load_json(result["summary"])
            sample = sample_from_summary(
                plan, planned_run, run_dir, network_summary,
                pilot_plan.DEFAULT_SOURCE_AUDIT)
            network_summary["sample_manifest_path"] = str(
                run_dir / "sample_manifest.json")
            network_summary["sample_status"] = sample["sample_status"]
            network_summary["sample_gates"] = sample["gates"]
            network_summary["training_eligible"] = False
            write_json(result["summary"], network_summary)
            session.write_report(run_dir, network_summary)
            sample_status = sample["sample_status"]
            failure_class = (None if sample_status == "passed" else
                             _classify_attempt_failure(
                                 network_summary, RuntimeError("sample gates failed"),
                                 RUN_STATE.get("topology_started") is True))
            retry_consumed = bool(retry_reserved and failure_class not in
                                  (None, "infrastructure"))
            finished = dict(attempt_started)
            finished.update({
                "event": "finished", "sample_status": sample_status,
                "failure_class": failure_class,
                "retry_consumed": retry_consumed,
                "network_run_id": network_summary.get("run_id"),
                "completed_utc": utc_now(),
                "cleanup_verified": network_summary.get("cleanup_verified"),
                "training_eligible": False,
            })
            _append_attempt_record(ATTEMPT_LEDGER, finished)
            attempt_finalized = True
            if sample_status == "passed":
                with ledger_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({
                        "sample_id": planned_run["sample_id"],
                        "session_id": planned_run["session_id"],
                        "run_index": index,
                        "sample_status": sample_status,
                        "network_run_id": network_summary.get("run_id"),
                        "completed_utc": utc_now(),
                        "live_proxy_snapshot": str(snapshot_path),
                        "cleanup_verified": network_summary.get("cleanup_verified"),
                        "training_eligible": False,
                    }, sort_keys=True) + "\n")
            return {"sample_id": planned_run["sample_id"],
                    "sample_status": sample_status,
                    "run_dir": str(run_dir),
                    "cleanup_verified": network_summary.get("cleanup_verified"),
                    "training_eligible": False}
        except BaseException as exc:
            if attempt_finalized:
                raise
            if result and result.get("summary"):
                summary_path = Path(result["summary"]).resolve()
                if summary_path.is_file():
                    network_summary = load_json(summary_path)
                    run_dir = summary_path.parent
            failure_class = _classify_attempt_failure(
                network_summary, exc,
                RUN_STATE.get("topology_started") is True)
            finished = dict(attempt_started)
            finished.update({
                "event": "finished", "sample_status": "failed",
                "failure_class": failure_class,
                "retry_consumed": bool(retry_reserved
                                        and failure_class != "infrastructure"),
                "network_run_id": network_summary.get("run_id"),
                "completed_utc": utc_now(),
                "run_dir": str(run_dir) if run_dir else None,
                "cleanup_verified": network_summary.get("cleanup_verified"),
                "error": str(exc), "training_eligible": False,
            })
            _append_attempt_record(ATTEMPT_LEDGER, finished)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    audit = sub.add_parser("audit", help="run offline V3 collector and provenance checks")
    audit.add_argument("--plan", default=str(DEFAULT_PLAN))
    audit.add_argument("--v2-runtime-config", default=str(DEFAULT_V2_CONFIG))
    preflight = sub.add_parser("proxy-preflight", help="doctor plus three live HTTPS CONNECT checks; never starts topology")
    preflight.add_argument("--v2-runtime-config", default=str(DEFAULT_V2_CONFIG))
    preflight.add_argument("--output")
    run = sub.add_parser("run", help="collect exactly one frozen run index")
    run.add_argument("--plan", default=str(DEFAULT_PLAN))
    run.add_argument("--run-index", type=int, choices=(1, 2, 3), required=True)
    run.add_argument("--v2-runtime-config", default=str(DEFAULT_V2_CONFIG))
    args = parser.parse_args(argv)
    if args.command == "audit":
        result = offline_audit(args.plan, args.v2_runtime_config)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("passed") else 2
    if args.command == "proxy-preflight":
        output = Path(args.output).resolve() if args.output else None
        result = proxy_preflight(args.v2_runtime_config, output)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("passed") else 3
    if args.command == "run":
        try:
            result = run_one(args.plan, args.run_index, args.v2_runtime_config)
        except Exception as exc:
            print(json.dumps({"status": "stopped", "reason": str(exc),
                              "topology_started": RUN_STATE["topology_started"]}, indent=2))
            return 3
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("sample_status") == "passed" else 4
    parser.error("a subcommand is required")


if __name__ == "__main__":
    sys.exit(main())
