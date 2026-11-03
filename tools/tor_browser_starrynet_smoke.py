#!/usr/bin/env python3
"""Run one Tor Browser visit through a temporary StarryNet path.

The Tor client shares GS26's network namespace. Its WebTunnel TCP stream is
forwarded over the emulated constellation to GS27, then through a host-bound
relay to the existing loopback HTTP proxy. It extracts one site-window trace
candidate for audit; it does not publish a dataset sample.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import re
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import traceback
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
REPO_TOOLS = ROOT / "tools"
DEFAULT_OUTPUT_ROOT = Path("/mnt/HDD4T/shy/satellite_wf_browser/tor_starrynet_site_smoke")
DEFAULT_HELPER_IMAGE = "constellation-p2-tor:0.4.9.11"
HTTP_PROXY_HOST = "127.0.0.1"
HTTP_PROXY_PORT = 17897
GS_CLIENT = 26
GS_EGRESS = 27
STARLINK_LOSS_SMOKE = 0
SATELLITE_BW_GBPS_SMOKE = 5
V26_ENTRY_FINGERPRINT = "F99CFE52EDFF8EAA332CD73C1E638035210C0336"
V26_MIDDLE_FINGERPRINT = "DBCBB4CEF0FC8E32BE674D4B19A964CB2981CF5D"
V26_EXIT_FINGERPRINT = "3C89C80E2699FB6358BBB64FDC9547AFCB5C03F7"
V27_BRIDGE_FINGERPRINT = V26_ENTRY_FINGERPRINT
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
E_BROWSER_V1_2_WARMUP_REDIRECT_POLICY = {
    "requested_url_must_be_https": True,
    "redirects_within_source_domain_host_family_allowed": True,
    "redirects_outside_source_domain_host_family_allowed": False,
    "retain_final_https_host_and_path_for_same_tab_refresh": True,
    "record_warmup_final_url": True,
}


def write_json(path, value):
    path = Path(path)
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds")


def parse_endpoint(value):
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError("endpoint must be IPv4-or-host:port")
    return host, int(port)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            upstream = socket.create_connection(self.server.upstream, timeout=20)
            self.request.settimeout(None)
            upstream.settimeout(None)
            active = [self.request, upstream]
            peer_by_socket = {self.request: upstream, upstream: self.request}
            while active:
                readable, _writable, _errors = select.select(active, [], [], 1.0)
                for source in readable:
                    data = source.recv(65536)
                    target = peer_by_socket[source]
                    if not data:
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        active.remove(source)
                    else:
                        target.sendall(data)
        except (OSError, ValueError) as exc:
            self.server.log("connection closed: " + type(exc).__name__)
        finally:
            for connection in (self.request, upstream):
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass


class ThreadedRelay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, upstream, ready_file):
        self.upstream = upstream
        self.ready_file = Path(ready_file)
        socketserver.ThreadingTCPServer.__init__(self, address, RelayHandler)

    def log(self, message):
        sys.stdout.write(message + "\n")
        sys.stdout.flush()


def relay_main(args):
    listen = parse_endpoint(args.listen)
    upstream = parse_endpoint(args.upstream)
    server = ThreadedRelay(listen, upstream, args.ready_file)
    server.ready_file.write_text(json.dumps({
        "pid": os.getpid(),
        "listen": "{}:{}".format(*server.server_address[:2]),
        "upstream": "{}:{}".format(*upstream),
    }) + "\n", encoding="utf-8")
    server.log("READY {}:{}".format(*server.server_address[:2]))
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


def docker(*args, **kwargs):
    timeout = kwargs.pop("timeout", 60)
    check = kwargs.pop("check", True)
    result = subprocess.run(["docker"] + [str(arg) for arg in args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("docker {} failed: {}".format(
            " ".join(str(arg) for arg in args),
            (result.stderr or result.stdout).strip()))
    return result


def docker_exec(cid, *args, **kwargs):
    result = docker("exec", cid, *args, **kwargs)
    return (result.stdout or "").strip()


OFFLOAD_FEATURES = {
    "tso": "tcp-segmentation-offload",
    "gso": "generic-segmentation-offload",
    "gro": "generic-receive-offload",
    "lro": "large-receive-offload",
    "tx-gso-list": "tx-gso-list",
}


def ethtool_path_in_container(cid):
    container_path = "/tmp/tor-site-smoke-ethtool"
    available = docker("exec", cid, "sh", "-c",
                       "test -x " + container_path, check=False, timeout=10)
    if available.returncode == 0:
        return container_path
    host_path = shutil.which("ethtool")
    if not host_path:
        raise RuntimeError("ethtool is unavailable on host and in container " + cid)
    docker("cp", host_path, cid + ":" + container_path, timeout=10)
    return container_path


def read_ethtool_features(cid, interface):
    tool_path = ethtool_path_in_container(cid)
    result = docker("exec", cid, tool_path, "-k", interface,
                    check=False, timeout=10)
    output = (result.stdout or "") + (result.stderr or "")
    features = {}
    for line in output.splitlines():
        match = re.match(r"\s*([a-z0-9-]+):\s+(on|off)(?:\s+\[([^]]+)\])?",
                         line, re.IGNORECASE)
        if match:
            features[match.group(1)] = {
                "state": match.group(2).lower(),
                "fixed": (match.group(3) or "").lower() == "fixed",
            }
    return {"returncode": result.returncode, "output": output.strip(),
            "features": features}


def audit_path_offloads(client_cid, peer_cid, client_interface,
                        peer_interface, mode, extra_endpoints=None):
    endpoints = [
        {"role": "GS26_capture_interface", "container_id": client_cid,
         "interface": client_interface},
        {"role": "next_hop_veth_peer", "container_id": peer_cid,
         "interface": peer_interface},
    ]
    endpoints.extend(extra_endpoints or [])
    records = []
    verification_errors = []
    for endpoint in endpoints:
        record = dict(endpoint)
        before = read_ethtool_features(endpoint["container_id"],
                                       endpoint["interface"])
        record["before"] = before
        if before["returncode"] != 0:
            verification_errors.append(
                "cannot read offload features on {} {}: {}".format(
                    endpoint["role"], endpoint["interface"], before["output"]))
            records.append(record)
            continue

        if mode == "disable_path":
            supported = []
            for short_name, feature_name in OFFLOAD_FEATURES.items():
                feature = before["features"].get(feature_name)
                if feature is None:
                    continue
                if feature["fixed"]:
                    if feature["state"] != "off":
                        verification_errors.append(
                            "{} is fixed on at {} {}".format(
                                feature_name, endpoint["role"], endpoint["interface"]))
                    continue
                if feature["state"] == "off":
                    continue
                supported.append(short_name)
            for short_name in supported:
                tool_path = ethtool_path_in_container(endpoint["container_id"])
                result = docker("exec", endpoint["container_id"], tool_path, "-K",
                                endpoint["interface"], short_name, "off",
                                check=False, timeout=10)
                record.setdefault("change_results", []).append({
                    "feature": short_name,
                    "returncode": result.returncode,
                    "output": ((result.stdout or "") + (result.stderr or "")).strip(),
                })
            after = read_ethtool_features(endpoint["container_id"],
                                          endpoint["interface"])
            record["after"] = after
            if after["returncode"] != 0:
                verification_errors.append(
                    "cannot verify offload features on {} {}: {}".format(
                        endpoint["role"], endpoint["interface"], after["output"]))
            for feature_name in OFFLOAD_FEATURES.values():
                state = after["features"].get(feature_name)
                if state is not None and state["state"] != "off":
                    verification_errors.append(
                        "{} remains {} at {} {}".format(
                            feature_name, state["state"], endpoint["role"],
                            endpoint["interface"]))
            for short_name in ("tso", "gso", "gro", "tx-gso-list"):
                feature_name = OFFLOAD_FEATURES[short_name]
                if feature_name not in after["features"]:
                    verification_errors.append(
                        "{} is not reported at {} {}".format(
                            feature_name, endpoint["role"], endpoint["interface"]))
        records.append(record)
    return {"mode": mode, "endpoints": records,
            "verified_disabled": mode == "disable_path" and not verification_errors,
            "errors": verification_errors}


def route_monitor_sample(client_cid, egress_cid, client_peer_ip, egress_peer_ip):
    sample = {}
    for name, cid, peer_ip, prefix in (
            ("client_to_egress", client_cid, egress_peer_ip, "B26-eth"),
            ("egress_to_client", egress_cid, client_peer_ip, "B27-eth")):
        try:
            route = docker_exec(cid, "ip", "route", "get", peer_ip,
                                timeout=5)
            device_match = re.search(r"\bdev\s+(\S+)", route)
            source_match = re.search(r"\bsrc\s+(\S+)", route)
            device = device_match.group(1) if device_match else None
            qdisc = None
            qdisc_error = None
            if device:
                try:
                    qdisc = docker_exec(cid, "tc", "qdisc", "show", "dev",
                                        device, timeout=5)
                except BaseException as exc:
                    qdisc_error = type(exc).__name__ + ": " + str(exc)[:200]
            sample[name] = {
                "route": route,
                "device": device,
                "source": source_match.group(1) if source_match else None,
                "satellite_route": bool(device and device.startswith(prefix)),
                "qdisc": qdisc,
                "qdisc_error": qdisc_error,
            }
        except BaseException as exc:
            sample[name] = {"route": None, "device": None,
                            "satellite_route": False,
                            "error": type(exc).__name__ + ": " + str(exc)[:300]}
    sample["sampled_utc"] = utc_now()
    sample["sampled_monotonic"] = time.monotonic()
    return sample


def route_monitor_worker(stop_event, samples_path, client_cid, egress_cid,
                         client_peer_ip, egress_peer_ip, interval_seconds=1.0):
    samples_path = Path(samples_path)
    samples_path.parent.mkdir(parents=True, exist_ok=True)
    next_sample = time.monotonic()
    with samples_path.open("a", encoding="utf-8") as stream:
        while not stop_event.is_set():
            sample = route_monitor_sample(client_cid, egress_cid,
                                          client_peer_ip, egress_peer_ip)
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()
            next_sample += interval_seconds
            stop_event.wait(max(0.0, next_sample - time.monotonic()))


def route_offload_endpoints(client_cid, egress_cid, container_ids, sample,
                            capture_interface):
    client_route = sample.get("client_to_egress", {})
    egress_route = sample.get("egress_to_client", {})
    client_device = client_route.get("device")
    egress_device = egress_route.get("device")
    if client_device != capture_interface:
        raise RuntimeError("active GS26 route {} differs from frozen capture interface {}".format(
            client_device, capture_interface))
    if client_route.get("satellite_route") is not True or egress_route.get(
            "satellite_route") is not True:
        raise RuntimeError("both ground-station routes must use satellite interfaces")

    def peer_for(device, local_node):
        match = re.fullmatch(r"B{}-eth(\d+)".format(local_node), device or "")
        if not match:
            raise RuntimeError("route device is not a GS{} satellite veth: {}".format(
                local_node, device))
        peer_node = int(match.group(1))
        if not 1 <= peer_node <= len(container_ids) - 2:
            raise RuntimeError("route device peer is outside the satellite container range")
        peer_cid = str(container_ids[peer_node - 1])
        peer_interface = "B{}-eth{}".format(peer_node, local_node)
        return peer_node, peer_cid, peer_interface

    client_peer_node, client_peer_cid, client_peer_interface = peer_for(
        client_device, GS_CLIENT)
    egress_peer_node, egress_peer_cid, egress_peer_interface = peer_for(
        egress_device, GS_EGRESS)
    egress_sender_interface = "B{}-eth{}".format(GS_EGRESS, egress_peer_node)
    return {
        "client_route_device": client_device,
        "egress_route_device": egress_device,
        "endpoints": audit_path_offloads(
            client_cid, client_peer_cid, client_device, client_peer_interface,
            "disable_path", extra_endpoints=[
                {"role": "GS27_return_sender_interface",
                 "container_id": egress_cid,
                 "interface": egress_sender_interface},
                {"role": "GS27_return_next_hop_veth_peer",
                 "container_id": egress_peer_cid,
                 "interface": egress_peer_interface},
            ]),
        "client_peer_node": client_peer_node,
        "egress_peer_node": egress_peer_node,
    }


def load_route_monitor_samples(samples_path):
    try:
        lines = Path(samples_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    samples = []
    for line in lines:
        try:
            sample = json.loads(line)
        except ValueError:
            continue
        if isinstance(sample, dict) and isinstance(
                sample.get("sampled_monotonic"), (int, float)):
            samples.append(sample)
    return samples


def route_monitor_stability(samples, start_monotonic, end_monotonic,
                            device_pair, stable_seconds):
    selected = [sample for sample in samples
                if start_monotonic <= sample.get("sampled_monotonic", -1)
                <= end_monotonic]
    times = [float(start_monotonic)] + [
        float(sample["sampled_monotonic"]) for sample in selected] + [
            float(end_monotonic)]
    max_gap = max((right - left for left, right in zip(times, times[1:])),
                  default=float("inf"))
    routes_match = bool(selected) and all(
        sample.get("client_to_egress", {}).get("satellite_route") is True
        and sample.get("egress_to_client", {}).get("satellite_route") is True
        and sample.get("client_to_egress", {}).get("device") == device_pair[0]
        and sample.get("egress_to_client", {}).get("device") == device_pair[1]
        for sample in selected)
    duration = end_monotonic - start_monotonic
    return {
        "passed": (routes_match and duration >= stable_seconds
                   and max_gap <= 2.5),
        "samples": selected,
        "duration_seconds": round(duration, 3),
        "maximum_sample_gap_seconds": max_gap,
        "maximum_sample_gap_limit_seconds": 2.5,
        "routes_match": routes_match,
    }


def wait_for_route_readiness(client_cid, egress_cid, container_ids,
                             client_peer_ip, egress_peer_ip,
                             capture_interface, stable_seconds,
                             timeout_seconds, route_samples_path):
    deadline = time.monotonic() + timeout_seconds
    audited_pair = None
    entry_offload_audit = None
    entry_audit_completed_monotonic = None
    entry_audit_completed_utc = None
    last_offload_audit_sample_monotonic = None
    route_attempts = []
    last_error = None
    while time.monotonic() < deadline:
        monitor_samples = load_route_monitor_samples(route_samples_path)
        sample = monitor_samples[-1] if monitor_samples else None
        if sample is None:
            last_error = "one-second route monitor has not produced a sample"
            time.sleep(0.25)
            continue
        client_route = sample.get("client_to_egress", {})
        egress_route = sample.get("egress_to_client", {})
        pair = (client_route.get("device"), egress_route.get("device"))
        candidate = (
            client_route.get("satellite_route") is True
            and egress_route.get("satellite_route") is True
            and pair[0] == capture_interface
            and pair[1] is not None)
        if not candidate:
            audited_pair = None
            entry_offload_audit = None
            entry_audit_completed_monotonic = None
            entry_audit_completed_utc = None
            last_error = "current routes are not both satellite routes on the frozen capture interface"
            last_offload_audit_sample_monotonic = None
            if (not route_attempts or route_attempts[-1].get(
                    "sampled_monotonic") != sample.get("sampled_monotonic")):
                route_attempts.append(sample)
        elif ((pair != audited_pair or entry_offload_audit is None or
               entry_offload_audit.get("endpoints", {}).get(
                   "verified_disabled") is not True)
              and sample.get("sampled_monotonic")
              != last_offload_audit_sample_monotonic):
            if (not route_attempts or route_attempts[-1].get(
                    "sampled_monotonic") != sample.get("sampled_monotonic")):
                route_attempts.append(sample)
            last_offload_audit_sample_monotonic = sample.get(
                "sampled_monotonic")
            try:
                entry_offload_audit = route_offload_endpoints(
                    client_cid, egress_cid, container_ids, sample,
                    capture_interface)
                if entry_offload_audit.get("endpoints", {}).get(
                        "verified_disabled") is True:
                    audited_pair = pair
                    entry_audit_completed_monotonic = time.monotonic()
                    entry_audit_completed_utc = utc_now()
                    last_error = None
                else:
                    audited_pair = None
                    entry_audit_completed_monotonic = None
                    entry_audit_completed_utc = None
                    last_error = "; ".join(entry_offload_audit.get(
                        "endpoints", {}).get("errors", [])) or "route offloads are not verified disabled"
            except BaseException as exc:
                audited_pair = None
                entry_offload_audit = {"endpoints": {
                    "verified_disabled": False, "errors": [last_error]}}
                entry_audit_completed_monotonic = None
                entry_audit_completed_utc = None
                last_error = type(exc).__name__ + ": " + str(exc)[:300]
        elif entry_audit_completed_monotonic is not None:
            initial_stability = route_monitor_stability(
                monitor_samples, entry_audit_completed_monotonic,
                sample["sampled_monotonic"], pair, stable_seconds)
            if initial_stability.get("passed"):
                try:
                    final_audit = route_offload_endpoints(
                        client_cid, egress_cid, container_ids, sample,
                        capture_interface)
                    final_sample = route_monitor_sample(
                        client_cid, egress_cid, client_peer_ip, egress_peer_ip)
                    final_pair = (
                        final_sample.get("client_to_egress", {}).get("device"),
                        final_sample.get("egress_to_client", {}).get("device"))
                    final_monitor_samples = load_route_monitor_samples(
                        route_samples_path)
                    final_stability = route_monitor_stability(
                        final_monitor_samples, entry_audit_completed_monotonic,
                        final_sample["sampled_monotonic"], pair, stable_seconds)
                    if (final_audit.get("endpoints", {}).get(
                            "verified_disabled") is True
                            and final_pair == pair
                            and final_sample.get("client_to_egress", {}).get(
                                "satellite_route") is True
                            and final_sample.get("egress_to_client", {}).get(
                                "satellite_route") is True
                            and final_stability.get("passed")):
                        attempts_hash = hashlib.sha256(json.dumps(
                            route_attempts, sort_keys=True).encode(
                                "utf-8")).hexdigest()
                        return {
                            "passed": True,
                            "stable_seconds_required": stable_seconds,
                            "stable_seconds_observed": final_stability[
                                "duration_seconds"],
                            "timeout_seconds": timeout_seconds,
                            "capture_interface": capture_interface,
                            "route_devices": {
                                "client_to_egress": pair[0],
                                "egress_to_client": pair[1],
                            },
                            "route_samples": final_stability["samples"],
                            "route_stability_start_monotonic":
                                entry_audit_completed_monotonic,
                            "route_stability_start_utc": entry_audit_completed_utc,
                            "route_stability_end_monotonic":
                                final_sample["sampled_monotonic"],
                            "route_stability_evidence_source":
                                "one_second_route_monitor_after_path_offload_audit",
                            "route_stability_maximum_sample_gap_seconds":
                                final_stability["maximum_sample_gap_seconds"],
                            "offload_audit_at_route_entry": entry_offload_audit,
                            "offload_audit_immediately_before_capture": final_audit,
                            "route_recheck_immediately_before_capture": final_sample,
                            "route_attempt_samples": route_attempts,
                            "attempt_count": len(route_attempts),
                            "attempt_sample_sha256": attempts_hash,
                        }
                    last_error = "route or offloads changed during final verification"
                    if final_pair != pair or final_sample.get(
                            "client_to_egress", {}).get("satellite_route") is not True or final_sample.get(
                                "egress_to_client", {}).get("satellite_route") is not True:
                        audited_pair = None
                        entry_offload_audit = None
                        entry_audit_completed_monotonic = None
                        entry_audit_completed_utc = None
                        last_offload_audit_sample_monotonic = None
                except BaseException as exc:
                    last_error = type(exc).__name__ + ": " + str(exc)[:300]
        time.sleep(0.25)
    return {
        "passed": False,
        "stable_seconds_required": stable_seconds,
        "timeout_seconds": timeout_seconds,
        "capture_interface": capture_interface,
        "attempt_count": len(route_attempts),
        "route_attempt_samples": route_attempts,
        "last_error": last_error,
        "last_route_sample": route_attempts[-1] if route_attempts else None,
        "attempt_sample_sha256": hashlib.sha256(
            json.dumps(route_attempts, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def check_route_monitor_windows(samples, browser_summary,
                                interval_seconds=1.0,
                                dynamic_start_monotonic=None):
    visits = browser_summary.get("visits", [])
    checks = []
    max_gap_limit = max(2.5, interval_seconds * 2.5)
    for visit_index, visit in enumerate(visits, 1):
        window = visit.get("capture_window", {})
        start = (window.get("start_ack") or {}).get("tcpdump_ready_monotonic")
        end = (window.get("stop_ack") or {}).get("tcpdump_stopped_monotonic")
        selected = [sample for sample in samples
                    if isinstance(start, (int, float))
                    and isinstance(end, (int, float))
                    and start <= sample.get("sampled_monotonic", -1) <= end]
        times = [float(start)] + [float(sample["sampled_monotonic"])
                                  for sample in selected] + [float(end)] \
            if isinstance(start, (int, float)) and isinstance(end, (int, float)) else []
        max_gap = max((right - left for left, right in zip(times, times[1:])),
                      default=None)
        routes_ok = bool(selected) and all(
            sample.get("client_to_egress", {}).get("satellite_route") is True
            and sample.get("egress_to_client", {}).get("satellite_route") is True
            for sample in selected)
        phase_samples = [float(sample["sampled_monotonic"])
                         - float(dynamic_start_monotonic)
                         for sample in selected
                         if isinstance(dynamic_start_monotonic, (int, float))
                         and isinstance(sample.get("sampled_monotonic"), (int, float))]
        qdisc_delays = {}
        for direction in ("client_to_egress", "egress_to_client"):
            values = []
            for sample in selected:
                qdisc = sample.get(direction, {}).get("qdisc") or ""
                match = re.search(r"\bdelay\s+([0-9]+(?:\.[0-9]+)?)ms\b", qdisc)
                if match:
                    values.append(float(match.group(1)))
            qdisc_delays[direction] = {
                "sample_count": len(values),
                "minimum_ms": min(values) if values else None,
                "maximum_ms": max(values) if values else None,
                "unique_values_ms": sorted(set(values)),
            }
        checks.append({
            "visit_index": visit_index,
            "capture_start_monotonic": start,
            "capture_stop_monotonic": end,
            "sample_count": len(selected),
            "topology_phase_seconds": ({
                "minimum": min(phase_samples),
                "maximum": max(phase_samples),
            } if phase_samples else None),
            "ground_station_qdisc_delay_ms": qdisc_delays,
            "maximum_sample_gap_seconds": max_gap,
            "maximum_sample_gap_limit_seconds": max_gap_limit,
            "both_directions_satellite_for_all_samples": routes_ok,
            "coverage_complete": (max_gap is not None and max_gap <= max_gap_limit),
            "passed": routes_ok and max_gap is not None and max_gap <= max_gap_limit,
        })
    return checks


def docker_inspect_json(cid):
    value = docker("inspect", cid).stdout
    data = json.loads(value)
    if not data:
        raise RuntimeError("docker inspect returned no container")
    return data[0]


def get_container_pid(cid):
    return int(docker("inspect", "--format", "{{.State.Pid}}", cid).stdout.strip())


def get_bridge_gateway(network):
    """Read the host-side bridge address even when Docker omits IPAM.Gateway."""
    for config in network.get("IPAM", {}).get("Config") or []:
        gateway = config.get("Gateway")
        if gateway:
            return gateway
    network_id = network.get("Id", "")
    if not network_id:
        raise RuntimeError("Docker network inspect omitted the network ID")
    bridge_name = "br-" + network_id[:12]
    result = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", bridge_name],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=10)
    if result.returncode:
        raise RuntimeError("could not read host bridge {}: {}".format(
            bridge_name, (result.stderr or result.stdout).strip()))
    match = re.search(r"\binet\s+(\d+(?:\.\d+){3})/", result.stdout)
    if not match:
        raise RuntimeError("host bridge {} has no IPv4 address".format(bridge_name))
    return match.group(1)


def wait_for_file_in_container(name, path, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = docker("inspect", "--format", "{{.State.Running}}", name,
                       check=False)
        if state.returncode or state.stdout.strip().lower() != "true":
            logs = docker("logs", name, check=False).stdout
            raise RuntimeError("relay helper exited: " + (logs or "").strip())
        ready = docker("exec", name, "cat", path, check=False)
        if ready.returncode == 0 and ready.stdout.strip():
            return json.loads(ready.stdout)
        time.sleep(0.2)
    logs = docker("logs", name, check=False).stdout
    raise RuntimeError("relay helper did not become ready: " + (logs or "").strip())


def start_helper_relay(name, node_cid, helper_image, script_path, listen,
                       upstream, ready_path, log_path, uid, gid):
    command = ["docker", "run", "-d", "--name", name,
               "--network", "container:" + node_cid,
               "--user", "{}:{}".format(uid, gid),
               "-e", "HOME=/tmp",
               "-v", str(script_path) + ":/opt/tor_browser_starrynet_smoke.py:ro",
               "--entrypoint", "python3.11", helper_image,
               "/opt/tor_browser_starrynet_smoke.py", "relay",
               "--listen", listen, "--upstream", upstream,
               "--ready-file", ready_path]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=60)
    if result.returncode:
        raise RuntimeError("could not start {}: {}".format(
            name, (result.stderr or result.stdout).strip()))
    Path(log_path).write_text("container={}\n{}\n".format(
        name, result.stdout.strip()), encoding="utf-8")
    ready = wait_for_file_in_container(name, ready_path)
    return {"name": name, "listen": listen, "upstream": upstream,
            "ready": ready}


def start_host_relay(script_path, run_dir, listen, upstream):
    ready_file = run_dir / "logs" / "host-relay.ready.json"
    log_file = (run_dir / "logs" / "host-relay.log").open("w")
    command = [sys.executable, str(script_path), "relay",
               "--listen", listen, "--upstream", upstream,
               "--ready-file", str(ready_file)]
    process = subprocess.Popen(command, stdout=log_file,
                               stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_file.flush()
            raise RuntimeError("host relay exited before ready; inspect {}".format(
                run_dir / "logs" / "host-relay.log"))
        if ready_file.is_file():
            return {"process": process, "log_file": log_file,
                    "listen": listen, "upstream": upstream}
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=5)
    log_file.close()
    raise RuntimeError("host relay startup timed out")


def stop_host_relay(relay):
    if not relay:
        return True
    process = relay.get("process")
    log_file = relay.get("log_file")
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if log_file is not None and not log_file.closed:
        log_file.flush()
        log_file.close()
    return process is None or process.poll() is not None


def stop_named_container(name):
    if not name:
        return True
    result = docker("rm", "-f", name, check=False, timeout=30)
    if result.returncode:
        inspect = docker("inspect", name, check=False)
        return bool(inspect.returncode)
    return True


def start_capture(cid, run_dir, port, peer_ip, interface, capture_id="client"):
    remote_dir = "/tmp/tor-site-smoke-" + run_dir.name
    remote_pcap = remote_dir + "/" + capture_id + ".pcap"
    remote_log = remote_dir + "/" + capture_id + ".tcpdump.log"
    remote_pid = remote_dir + "/" + capture_id + ".tcpdump.pid"
    docker_exec(cid, "sh", "-c", "mkdir -p {0}; rm -f {1} {2} {3}; "
                "tcpdump -i {4} -n -s 0 -U -w {1} 'host {5} and tcp port {6}' >{2} 2>&1 & "
                "echo $! >{3}".format(remote_dir, remote_pcap, remote_log,
                                      remote_pid, interface, peer_ip, port))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        size = docker_exec(cid, "sh", "-c", "wc -c < " + remote_pcap,
                           check=False)
        try:
            if int(size) >= 24:
                return {"cid": cid, "remote_dir": remote_dir,
                        "remote_pcap": remote_pcap, "remote_log": remote_log,
                        "remote_pid": remote_pid, "port": port,
                        "peer_ip": peer_ip, "interface": interface,
                        "capture_id": capture_id,
                        "ready_utc": utc_now(),
                        "ready_monotonic": time.monotonic()}
        except (TypeError, ValueError):
            pass
        time.sleep(0.2)
    detail = docker_exec(cid, "cat", remote_log, check=False)
    raise RuntimeError("tcpdump did not initialize: " + detail)


def capture_process_is_alive(capture):
    pidfile = capture["remote_pid"]
    state = docker_exec(
        capture["cid"], "sh", "-c",
        "pid=$(cat {0} 2>/dev/null); state=$(awk '{{print $3}}' "
        "/proc/$pid/stat 2>/dev/null || true); "
        "[ -n \"$pid\" ] && [ -n \"$state\" ] && "
        "[ \"$state\" != Z ] && echo alive || true".format(pidfile),
        check=False)
    return state.strip() == "alive"


def stop_capture(capture, destination, output_name=None, already_signalled=False):
    if not capture:
        return None
    cid = capture["cid"]
    pidfile = capture["remote_pid"]
    if not already_signalled:
        docker_exec(cid, "sh", "-c", "kill -INT $(cat {0}) 2>/dev/null || true".format(
            pidfile), check=False)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if not capture_process_is_alive(capture):
            break
        time.sleep(0.2)
    else:
        docker_exec(cid, "sh", "-c", "kill -TERM $(cat {0}) 2>/dev/null || true".format(
            pidfile), check=False)
        time.sleep(0.5)
    output_name = output_name or "client_satellite_path.pcap"
    local_pcap = destination / output_name
    docker("cp", cid + ":" + capture["remote_pcap"], local_pcap, timeout=120)
    log = docker_exec(cid, "cat", capture["remote_log"], check=False)
    capture_id = capture.get("capture_id", "client")
    if "_visit_" in capture_id:
        prefix, visit_index = capture_id.rsplit("_visit_", 1)
        log_name = "{}_visit_{}.tcpdump.log".format(
            "tcpdump" if prefix == "client" else "peer_tcpdump", visit_index)
    else:
        log_name = ("tcpdump.log" if capture_id == "client"
                    else "peer_tcpdump.log")
    (destination / log_name).write_text(log + "\n", encoding="utf-8")
    return local_pcap


def stop_capture_group(captures, destination):
    if isinstance(captures, dict):
        captures = [captures]
    captures = captures or []
    for capture in captures:
        docker_exec(capture["cid"], "sh", "-c",
                    "kill -INT $(cat {0}) 2>/dev/null || true".format(
                        capture["remote_pid"]), check=False)
    output_paths = {}
    for capture in captures:
        capture_id = capture.get("capture_id", "client")
        peer_capture = capture_id == "peer" or capture_id.startswith("peer_visit_")
        if "_visit_" in capture_id:
            visit_index = capture_id.rsplit("_visit_", 1)[1]
            output_name = ("next_hop_peer_visit_{}.pcap" if peer_capture
                           else "client_satellite_path_visit_{}.pcap").format(visit_index)
        else:
            visit_index = None
            output_name = ("next_hop_peer.pcap" if peer_capture
                           else "client_satellite_path.pcap")
        output_path = stop_capture(
            capture, destination, output_name=output_name, already_signalled=True)
        output_paths[capture_id] = output_path
        output_paths["peer" if peer_capture else "client"] = output_path
    return output_paths


def capture_control_request(control_dir, phase):
    request_path = control_dir / "capture_{}_request.json".format(phase)
    if not request_path.is_file():
        return None
    try:
        return json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def service_capture_control(control_dir, client_cid, run_dir, port, peer_ip,
                            interface, state, summary, summary_path,
                            peer_capture=None, route_readiness_context=None,
                            deferred_emulation_start=None,
                            emulation_start_after_warmup=None):
    """Handle the next start/stop request and acknowledge only after tcpdump is ready/stopped."""
    phase = state.get("phase")
    request = capture_control_request(control_dir, phase)
    if not request:
        return state
    request_id = request.get("request_id")
    handled_ids = state.setdefault("handled_request_ids", set())
    if not request_id or request_id in handled_ids:
        return state
    ack = {"request_id": request_id, "ok": False}
    try:
        visit_index = int(request.get("visit_index", 1))
        if visit_index < 1:
            raise ValueError("capture request has an invalid visit index")
        if phase == "warmup":
            if state.get("capture"):
                raise RuntimeError("warm-up route check cannot run during capture")
            if not route_readiness_context:
                raise RuntimeError("warm-up requires the route-readiness protocol")
            if visit_index == 1 and deferred_emulation_start:
                deferred_emulation_start()
            route_readiness = wait_for_route_readiness(
                client_cid, route_readiness_context["egress_cid"],
                route_readiness_context["container_ids"],
                route_readiness_context["client_peer_ip"],
                route_readiness_context["egress_peer_ip"],
                interface,
                route_readiness_context["stable_seconds"],
                route_readiness_context["timeout_seconds"],
                route_readiness_context["samples_path"])
            summary.setdefault("warmup_route_readiness_by_visit", {})[
                str(visit_index)] = route_readiness
            if visit_index == 1:
                summary["warmup_route_readiness"] = route_readiness
            if route_readiness.get("passed") is not True:
                raise RuntimeError("bidirectional satellite route was not ready for site warm-up: {}".format(
                    route_readiness.get("last_error", "readiness timeout")))
            ack.update({"ok": True, "route_ready_utc": utc_now(),
                        "route_ready_monotonic": time.monotonic(),
                        "visit_index": visit_index,
                        "route_readiness": route_readiness})
        elif phase == "start":
            if state.get("capture"):
                raise RuntimeError("capture is already active")
            if visit_index == 1 and emulation_start_after_warmup:
                emulation_start_after_warmup()
            phase_spec = (route_readiness_context or {}).get(
                "matched_dynamic_phase")
            route_readiness = None
            phase_route_check = None
            if route_readiness_context:
                route_readiness = wait_for_route_readiness(
                    client_cid, route_readiness_context["egress_cid"],
                    route_readiness_context["container_ids"],
                    route_readiness_context["client_peer_ip"],
                    route_readiness_context["egress_peer_ip"],
                    interface,
                    route_readiness_context["stable_seconds"],
                    route_readiness_context["timeout_seconds"],
                    route_readiness_context["samples_path"])
                summary.setdefault("route_readiness_by_visit", {})[
                    str(visit_index)] = route_readiness
                if route_readiness.get("passed") is not True:
                    raise RuntimeError("bidirectional satellite route did not become stable: {}".format(
                        route_readiness.get("last_error", "readiness timeout")))
            if phase_spec:
                dynamic_start = summary.get("dynamic_emulation_start", {}).get(
                    "started_monotonic")
                target_phase = phase_spec.get("target_capture_start_seconds")
                tolerance = phase_spec.get("tolerance_seconds")
                stable_seconds = route_readiness_context.get("stable_seconds")
                phase_route_reaudit = bool(
                    phase_spec and phase_spec.get(
                        "reaudit_active_route_before_phase_window"))
                phase_audit_lead = 10.0
                if (not isinstance(dynamic_start, (int, float))
                        or not isinstance(target_phase, (int, float))
                        or not isinstance(tolerance, (int, float))
                        or not isinstance(stable_seconds, (int, float))
                        or route_readiness is None):
                    raise RuntimeError("matched dynamic phase or route evidence is missing")
                target_monotonic = dynamic_start + target_phase
                if time.monotonic() > target_monotonic + tolerance:
                    raise RuntimeError(
                        "route-readiness verification finished after the matched capture phase")
                phase_check_start = target_monotonic - stable_seconds
                phase_audit_sample = None
                phase_audit = None
                phase_audit_completed = None
                if phase_route_reaudit:
                    phase_audit_start = phase_check_start - phase_audit_lead
                    if time.monotonic() > phase_audit_start:
                        raise RuntimeError(
                            "route-readiness verification finished after the phase-route offload-audit deadline")
                    if time.monotonic() < phase_audit_start:
                        time.sleep(phase_audit_start - time.monotonic())
                    phase_audit_sample = route_monitor_sample(
                        client_cid, route_readiness_context["egress_cid"],
                        route_readiness_context["client_peer_ip"],
                        route_readiness_context["egress_peer_ip"])
                    try:
                        phase_audit = route_offload_endpoints(
                            client_cid, route_readiness_context["egress_cid"],
                            route_readiness_context["container_ids"],
                            phase_audit_sample, interface)
                    except BaseException as exc:
                        phase_audit = {
                            "client_route_device": phase_audit_sample.get(
                                "client_to_egress", {}).get("device"),
                            "egress_route_device": phase_audit_sample.get(
                                "egress_to_client", {}).get("device"),
                            "endpoints": {
                                "verified_disabled": False,
                                "errors": [type(exc).__name__ + ": " + str(exc)[:300]],
                            },
                        }
                    phase_audit_completed = time.monotonic()
                    if phase_audit.get("endpoints", {}).get(
                            "verified_disabled") is not True:
                        summary.setdefault("capture_phase_gate_by_visit", {})[
                            str(visit_index)] = {
                                "target_capture_start_seconds": target_phase,
                                "tolerance_seconds": tolerance,
                                "phase_route_offload_audit": phase_audit,
                                "phase_route_audit_sample": phase_audit_sample,
                                "phase_route_offload_audit_completed_monotonic":
                                    phase_audit_completed,
                                "passed": False,
                            }
                        errors = phase_audit.get("endpoints", {}).get(
                            "errors", [])
                        raise RuntimeError(
                            "phase-aligned active-route offload audit did not pass: {}".format(
                                "; ".join(errors) or "verification returned false"))
                    if phase_audit_completed > phase_check_start:
                        summary.setdefault("capture_phase_gate_by_visit", {})[
                            str(visit_index)] = {
                                "target_capture_start_seconds": target_phase,
                                "tolerance_seconds": tolerance,
                                "phase_route_offload_audit": phase_audit,
                                "phase_route_audit_sample": phase_audit_sample,
                                "phase_route_offload_audit_completed_monotonic":
                                    phase_audit_completed,
                                "passed": False,
                            }
                        raise RuntimeError(
                            "phase-route offload audit completed after the five-second route window began")
                if time.monotonic() < target_monotonic:
                    time.sleep(target_monotonic - time.monotonic())
                phase_check_end = time.monotonic()
                route_devices = (
                    {
                        "client_to_egress": phase_audit_sample.get(
                            "client_to_egress", {}).get("device"),
                        "egress_to_client": phase_audit_sample.get(
                            "egress_to_client", {}).get("device"),
                    } if phase_route_reaudit else
                    route_readiness.get("route_devices", {}))
                device_pair = (route_devices.get("client_to_egress"),
                               route_devices.get("egress_to_client"))
                phase_samples = load_route_monitor_samples(
                    route_readiness_context["samples_path"])
                recent_stability = route_monitor_stability(
                    phase_samples, phase_check_start, phase_check_end,
                    device_pair, stable_seconds)
                recent_samples = recent_stability.get("samples", [])
                qdisc_ok = bool(recent_samples) and all(
                    sample.get(direction, {}).get("qdisc")
                    and sample.get(direction, {}).get("qdisc_error") is None
                    for sample in recent_samples
                    for direction in ("client_to_egress", "egress_to_client"))
                latest_age = (phase_check_end - recent_samples[-1].get(
                    "sampled_monotonic", -1) if recent_samples else None)
                phase_route_check = {
                    "phase_interval_start_monotonic": phase_check_start,
                    "phase_interval_end_monotonic": phase_check_end,
                    "stable_seconds_required": stable_seconds,
                    "route_devices": {
                        "client_to_egress": device_pair[0],
                        "egress_to_client": device_pair[1],
                    },
                    "sample_count": len(recent_samples),
                    "routes_match_audited_devices": recent_stability.get(
                        "routes_match") is True,
                    "maximum_sample_gap_seconds": recent_stability.get(
                        "maximum_sample_gap_seconds"),
                    "maximum_sample_gap_limit_seconds": recent_stability.get(
                        "maximum_sample_gap_limit_seconds"),
                    "qdisc_samples_complete": qdisc_ok,
                    "latest_sample_age_seconds": latest_age,
                    "route_offload_audit_reverified": (
                        phase_audit is not None
                        and phase_audit.get("endpoints", {}).get(
                            "verified_disabled") is True),
                    "route_offload_audit_completed_before_window": (
                        phase_audit_completed is not None
                        and phase_audit_completed <= phase_check_start),
                    "phase_route_offload_audit": phase_audit,
                    "phase_route_audit_sample": phase_audit_sample,
                    "phase_route_offload_audit_completed_monotonic":
                        phase_audit_completed,
                    "passed": (recent_stability.get("passed") is True
                               and qdisc_ok and latest_age is not None
                               and latest_age <= 2.5
                               and (not phase_route_reaudit or (
                                   phase_audit is not None
                                   and phase_audit.get("endpoints", {}).get(
                                       "verified_disabled") is True
                                   and phase_audit_completed is not None
                                   and phase_audit_completed <= phase_check_start))),
                }
                if phase_route_reaudit:
                    phase_route_check["phase_route_offload_audit_lead_seconds"] = (
                        phase_audit_lead)
                summary.setdefault("capture_phase_gate_by_visit", {})[
                    str(visit_index)] = {
                        "target_capture_start_seconds": target_phase,
                        "tolerance_seconds": tolerance,
                        "actual_capture_start_seconds": None,
                        "deviation_seconds": None,
                        "capture_started_monotonic": None,
                        "dynamic_start_monotonic": dynamic_start,
                        "phase_aligned_route_check": phase_route_check,
                        "passed": False,
                    }
                if not phase_route_check["passed"]:
                    raise RuntimeError(
                        "five-second phase-aligned route/qdisc evidence did not pass")
            state["capture"] = []
            state["capture"].append(start_capture(
                client_cid, run_dir, port, peer_ip, interface,
                capture_id="client_visit_{}".format(visit_index)))
            if peer_capture:
                peer_item = start_capture(
                    peer_capture["cid"], run_dir, port, peer_ip,
                    peer_capture["interface"],
                    capture_id="peer_visit_{}".format(visit_index))
                state["capture"].append(peer_item)
                summary["peer_capture_window"] = {
                    "interface": peer_capture["interface"],
                    "capture_started_utc": peer_item["ready_utc"],
                    "capture_started_monotonic": peer_item["ready_monotonic"],
                }
            phase_gate = None
            if phase_spec:
                dynamic_start = summary["dynamic_emulation_start"][
                    "started_monotonic"]
                capture_started_monotonic = state["capture"][0].get(
                    "ready_monotonic")
                actual_phase = capture_started_monotonic - dynamic_start
                target_phase = phase_spec["target_capture_start_seconds"]
                tolerance = phase_spec["tolerance_seconds"]
                phase_gate = {
                    "target_capture_start_seconds": target_phase,
                    "tolerance_seconds": tolerance,
                    "actual_capture_start_seconds": actual_phase,
                    "deviation_seconds": actual_phase - target_phase,
                    "capture_started_monotonic": capture_started_monotonic,
                    "dynamic_start_monotonic": dynamic_start,
                    "phase_aligned_route_check": phase_route_check,
                    "passed": (abs(actual_phase - target_phase) <= tolerance
                               and phase_route_check.get("passed") is True),
                }
                summary.setdefault("capture_phase_gate_by_visit", {})[
                    str(visit_index)] = phase_gate
                if not phase_gate["passed"]:
                    stop_capture_group(state["capture"], run_dir)
                    state["capture"] = []
                    raise RuntimeError(
                        "capture began outside the matched dynamic-phase tolerance: "
                        "{:.3f}s from target {:.3f}s (±{:.3f}s)".format(
                            actual_phase, target_phase, tolerance))
            summary["capture_started"] = True
            ack.update({"ok": True, "tcpdump_ready_utc": utc_now(),
                        "tcpdump_ready_monotonic": time.monotonic(),
                        "capture_interface": interface,
                        "visit_index": visit_index})
            if route_readiness is not None:
                ack["route_readiness"] = route_readiness
            if phase_gate is not None:
                ack["dynamic_phase_gate"] = phase_gate
            state["active_visit_index"] = visit_index
        elif phase == "stop":
            if not state.get("capture"):
                raise RuntimeError("capture stop requested without an active capture")
            output_paths = stop_capture_group(state["capture"], run_dir)
            state["capture"] = []
            visit_index = int(state.pop("active_visit_index", visit_index))
            client_path = output_paths.get("client_visit_{}".format(visit_index))
            peer_path = output_paths.get("peer_visit_{}".format(visit_index))
            state["pcap_path"] = client_path or output_paths.get("client")
            state["peer_pcap_path"] = peer_path or output_paths.get("peer")
            state.setdefault("pcap_paths_by_visit", {})[str(visit_index)] = {
                "client": str(state["pcap_path"]) if state.get("pcap_path") else None,
                "peer": str(state["peer_pcap_path"])
                    if state.get("peer_pcap_path") else None,
            }
            if state.get("peer_pcap_path"):
                summary["peer_capture_window"].update({
                    "pcap_path": str(state["peer_pcap_path"]),
                    "capture_stopped_utc": utc_now(),
                    "capture_stopped_monotonic": time.monotonic(),
                })
            ack.update({"ok": True, "tcpdump_stopped_utc": utc_now(),
                        "tcpdump_stopped_monotonic": time.monotonic()})
        else:
            raise ValueError("unsupported capture-control phase: " + str(phase))
    except BaseException as exc:
        ack["error"] = type(exc).__name__ + ": " + str(exc)[:400]
        summary["errors"].append("capture {}: {}".format(phase, ack["error"]))
    write_json(control_dir / "capture_{}_ack.json".format(phase), ack)
    state["last_request_id"] = request_id
    state["last_ack"] = ack
    handled_ids.add(request_id)
    if ack.get("ok"):
        if phase == "start":
            state["phase"] = "stop"
        elif phase == "stop":
            state["phase"] = (
                "warmup" if state.get("warmup_before_each_visit")
                and visit_index < state.get("visit_count", 0) else "start")
        else:
            state["phase"] = "start"
    summary["capture_control_last_ack"] = ack
    write_json(summary_path, summary)
    return state


def inspect_capture(pcap_path, port, peer_ip):
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return {"parsed": False, "reason": "host tcpdump unavailable"}
    result = subprocess.run([tcpdump, "-nn", "-tt", "-r", str(pcap_path),
                             "tcp port {}".format(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=120)
    lines = [line for line in result.stdout.splitlines()
             if " > " in line and ": " in line]
    outbound = 0
    inbound = 0
    peer = "{}.{}".format(peer_ip, port)
    for line in lines:
        try:
            source, destination = line.split(" > ", 1)
            destination = destination.split(": ", 1)[0]
            source = source.rsplit(" ", 1)[-1]
            if destination == peer:
                outbound += 1
            elif source == peer:
                inbound += 1
        except ValueError:
            continue
    return {"parsed": result.returncode == 0,
            "packet_count": len(lines),
            "client_to_egress_packets": outbound,
            "egress_to_client_packets": inbound,
            "bidirectional": outbound > 0 and inbound > 0,
            "tcpdump_exit_code": result.returncode,
            "pcap_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
            "stderr": (result.stderr or "")[-1000:]}


def wait_for_proxy_listener(host, port, timeout=10):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection((host, port), timeout=1)
            connection.close()
            return True
        except OSError as exc:
            last_error = str(exc)
            time.sleep(0.2)
    raise RuntimeError("host proxy {}:{} is unavailable: {}".format(
        host, port, last_error))


def run_pilot(args):
    selected_bridge_file = None
    selected_bridge_line = None
    observed_helper_image_id = None
    bridge_file_for_mount = Path(args.bridge_file).resolve()
    matched_single_visit = args.matched_dynamic_phase_seconds is not None
    if matched_single_visit:
        parsed_url = urlsplit(args.url)
        if args.protocol_id in E_BROWSER_PROTOCOL_IDS:
            expected_domain = ({
                E_BROWSER_V1_1_PROTOCOL_ID: E_BROWSER_V1_1_DOMAIN,
                E_BROWSER_V1_2_PROTOCOL_ID: E_BROWSER_V1_2_DOMAIN,
                E_BROWSER_V1_3_PROTOCOL_ID: E_BROWSER_V1_3_DOMAIN,
                E_BROWSER_V1_4_PROTOCOL_ID: E_BROWSER_V1_4_DOMAIN,
            }.get(args.protocol_id, "E_BROWSER_TOR"))
            if (parsed_url.scheme != "https" or not parsed_url.hostname
                    or parsed_url.username or parsed_url.password
                    or args.data_domain != expected_domain
                    or not args.page_id or not args.sample_id
                    or args.class_label not in {str(value) for value in range(5)}
                    or not args.source_domain or not args.source_rank
                    or not args.source_list_sha256
                    or not args.pilot_controller
                    or not re.fullmatch(r"[0-9a-f]{64}",
                                        args.source_list_sha256)):
                raise ValueError(
                    "E browser protocol requires an HTTPS target, page/sample IDs, "
                    "a pilot-local class label, source rank/domain, matching E domain "
                    "namespace, wrapper, and frozen source-list SHA-256")
            if args.protocol_id in (E_BROWSER_V1_2_PROTOCOL_ID,
                                    E_BROWSER_V1_3_PROTOCOL_ID,
                                    E_BROWSER_V1_4_PROTOCOL_ID):
                expected_image_id = args.expected_helper_image_id or ""
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id):
                    raise ValueError(
                        "E v1.2/v1.3/v1.4 requires the frozen helper Docker image ID")
                observed_helper_image_id = docker(
                    "image", "inspect", "--format", "{{.Id}}",
                    args.helper_image).stdout.strip()
                if observed_helper_image_id != expected_image_id:
                    raise RuntimeError(
                        "helper image ID differs from the frozen E browser image: "
                        + observed_helper_image_id)
        elif args.protocol_id is not None:
            raise ValueError("unsupported explicit protocol_id")
        if (args.visits != 1 or args.fixed_window_seconds != 85
                or args.route_ready_stable_seconds != 5
                or args.route_ready_timeout_seconds != 90
                or args.offload_mode != "disable_path"
                or args.capture_peer_veth
                or (args.protocol_id not in E_BROWSER_PROTOCOL_IDS
                    and args.url != "https://www.adobe.com/")
                or args.page_load_timeout != 240
                or args.page_content_timeout != 60
                or args.resource_idle_seconds != 4
                or args.capture_settle_seconds != 2
                or args.browser_timeout != 1200
                or args.warmup_settle_seconds != 25
                or not args.reuse_check_circuit
                or not args.reuse_target_page_between_visits
                or not args.warmup_site_visit
                or args.warmup_before_each_visit
                or (args.defer_emulation_until_warmup
                    == args.defer_emulation_until_after_warmup)
                or args.freeze_topology):
            raise ValueError(
                "matched dynamic-phase capture requires one 85-second visit, "
                "a warm-up page refresh and exactly one deferred dynamic-start policy, "
                "circuit reuse, and a five-second route gate")
        if args.matched_dynamic_phase_seconds <= args.route_ready_stable_seconds:
            raise ValueError(
                "matched capture phase must be later than the route-stability interval")
        if not 0.1 <= args.matched_dynamic_phase_tolerance_seconds <= 5:
            raise ValueError("matched dynamic-phase tolerance must be 0.1–5 seconds")
        if (args.matched_dynamic_phase_seconds != 120
                or args.matched_dynamic_phase_tolerance_seconds != 1.5):
            raise ValueError("matched-phase protocols fix capture at dynamic second 120 ± 1.5 seconds")
    if args.reaudit_active_route_before_phase_window and not (
            matched_single_visit
            and args.defer_emulation_until_after_warmup
            and args.enable_browser_cache_between_visits):
        raise ValueError(
            "phase-route offload re-audit is fixed to the post-warm-up cache-on matched-phase protocol")
    if args.pin_tor_path_diagnostic and not (
            matched_single_visit
            and args.defer_emulation_until_after_warmup
            and args.reaudit_active_route_before_phase_window
            and args.enable_browser_cache_between_visits):
        raise ValueError(
            "fixed Tor path diagnostic requires the V25 post-warm-up, cache-on, "
            "phase-route-reaudit protocol")
    if args.pin_tor_entry_bridge_diagnostic and not args.pin_tor_path_diagnostic:
        if (args.protocol_id not in E_BROWSER_ENTRY_ONLY_PROTOCOL_IDS
                or not matched_single_visit):
            raise ValueError(
                "entry-bridge-only control is reserved for entry-only E browser protocols")
    if args.protocol_id == E_BROWSER_PROTOCOL_ID and not (
            args.pin_tor_path_diagnostic
            and args.pin_tor_entry_bridge_diagnostic):
        raise ValueError("E browser v1 requires the frozen V27 path and bridge pins")
    if args.protocol_id in E_BROWSER_ENTRY_ONLY_PROTOCOL_IDS and (
            args.pin_tor_path_diagnostic
            or not args.pin_tor_entry_bridge_diagnostic):
        raise ValueError("entry-only E browser protocols pin only the configured bridge")
    if args.reuse_browser_profile_between_visits and (
            args.visits < 2 or not args.reuse_circuit_between_visits):
        raise ValueError("persistent-profile repeats require multiple visits and circuit reuse")
    if args.reuse_browser_process_between_visits and not (
            args.reuse_browser_profile_between_visits):
        raise ValueError("persistent browser-process repeats require a persistent profile")
    if args.route_ready_stable_seconds > 0:
        if args.route_ready_stable_seconds < 5:
            raise ValueError("route readiness requires at least five stable seconds")
        if args.route_ready_timeout_seconds < args.route_ready_stable_seconds:
            raise ValueError("route readiness timeout must cover the requested stable interval")
        if args.offload_mode != "disable_path":
            raise ValueError("route readiness requires --offload-mode disable_path")
        if ((args.visits != 3 and not matched_single_visit)
                or args.fixed_window_seconds is None):
            raise ValueError("route-ready repeatability requires three visits with a fixed window")
    if (args.warmup_site_visit or args.warmup_before_each_visit) and not (
            args.route_ready_stable_seconds >= 5
            and args.fixed_window_seconds is not None
            and ((args.visits == 3
                  and args.reuse_browser_profile_between_visits
                  and args.reuse_browser_process_between_visits)
                 or matched_single_visit)):
        raise ValueError("site warm-up requires route readiness and either three persistent-profile visits or one matched-phase visit")
    if args.reuse_target_page_between_visits and not (
            ((args.visits == 3 and args.fixed_window_seconds in (60, 85))
             or (matched_single_visit and args.visits == 1
                 and args.fixed_window_seconds == 85))
            and args.route_ready_stable_seconds >= 5
            and (matched_single_visit or (
                args.reuse_browser_profile_between_visits
                and args.reuse_browser_process_between_visits
                and args.reuse_circuit_between_visits))
            and args.reuse_check_circuit
            and args.warmup_site_visit and not args.warmup_before_each_visit):
        raise ValueError("target-page reuse requires either the three-visit refresh protocol or one matched-phase visit with an initial Tor check/warm-up")
    if args.defer_emulation_until_warmup and (
            args.freeze_topology or not args.reuse_target_page_between_visits
            or args.fixed_window_seconds != 85 or not args.warmup_site_visit
            or args.warmup_before_each_visit
            or (not matched_single_visit and args.visits != 3)):
        raise ValueError("deferred dynamic start requires an 85-second same-page refresh protocol")
    if args.defer_emulation_until_after_warmup and (
            not matched_single_visit or args.freeze_topology
            or not args.reuse_target_page_between_visits
            or args.fixed_window_seconds != 85 or not args.warmup_site_visit
            or args.warmup_before_each_visit
            or not args.enable_browser_cache_between_visits):
        raise ValueError("post-warm-up dynamic start requires the matched-phase cache-on refresh protocol")
    if args.enable_browser_cache_between_visits and not (
            (args.defer_emulation_until_warmup
             or args.defer_emulation_until_after_warmup)
            and args.reuse_target_page_between_visits
            and args.fixed_window_seconds == 85):
        raise ValueError("browser cache is restricted to deferred-start 85-second same-page refresh protocols")
    if not 0 <= args.warmup_settle_seconds <= 60:
        raise ValueError("warm-up settle interval must be between zero and 60 seconds")
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(REPO_TOOLS))
    import replay_trace_over_starrynet as replay
    from starrynet.sn_synchronizer import StarryNet

    output_root = Path(args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    run_start_monotonic = time.monotonic()
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%S_%fZ")
    run_dir = output_root / run_id
    run_dir.mkdir()
    (run_dir / "logs").mkdir()
    bridge_selection = None
    if args.pin_tor_entry_bridge_diagnostic:
        source_lines = bridge_file_for_mount.read_text(encoding="utf-8").splitlines()
        matching_lines = []
        for line in source_lines:
            fingerprints = re.findall(
                r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", line)
            if V27_BRIDGE_FINGERPRINT in [item.upper() for item in fingerprints]:
                matching_lines.append(line)
        if len(matching_lines) != 1:
            raise ValueError(
                "V27 requires exactly one source bridge line for the registered entry fingerprint")
        selected_bridge_line = matching_lines[0].rstrip() + "\n"
        bridge_selection = {
            "mode": "single_configured_webtunnel_bridge",
            "bridge_fingerprint": V27_BRIDGE_FINGERPRINT,
            "source_file_path": str(Path(args.bridge_file).resolve()),
            "source_file_sha256": sha256_file(Path(args.bridge_file).resolve()),
            "selected_file_sha256": hashlib.sha256(
                selected_bridge_line.encode("utf-8")).hexdigest(),
            "selected_line_count": 1,
            "selected_file_deleted_after_run": True,
        }
    capture_control_dir = run_dir / "capture_control"
    capture_control_dir.mkdir()
    script_path = Path(__file__).resolve()
    summary_path = run_dir / "summary.json"
    config = dict(replay.P2_CONFIG)
    config["Name"] = "tor-browser-site-smoke"
    config["Duration (s)"] = 7200
    config["satellite link bandwidth (\"X\" Gbps)"] = SATELLITE_BW_GBPS_SMOKE
    config["sat-ground bandwidth (\"X\" Gbps)"] = SATELLITE_BW_GBPS_SMOKE
    config["satellite link loss (\"X\"% )"] = STARLINK_LOSS_SMOKE
    config["sat-ground loss (\"X\"% )"] = STARLINK_LOSS_SMOKE
    config_path = run_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")

    protocol_paths = {
        "runner": script_path,
        "browser_visit_helper": ROOT / "tools" / "tor_browser_site_smoke.py",
        "trace_extractor": ROOT / "tools" / "extract_starrynet_site_trace.py",
        "repeatability_auditor": ROOT / "tools" / "audit_site_trace_repeatability.py",
        "replay_helper": Path(replay.__file__).resolve(),
    }
    if args.pilot_controller:
        protocol_paths["pilot_controller"] = Path(args.pilot_controller).resolve()
    collection_protocol = {
        "protocol_id": ("starrynet-tor-site-window-v27-cache-on-phase-route-reaudit-fixed-entry-middle-exit"
                        if matched_single_visit and args.pin_tor_entry_bridge_diagnostic
                        else "starrynet-tor-site-window-v26-cache-on-phase-route-reaudit-fixed-middle-exit"
                        if matched_single_visit and args.pin_tor_path_diagnostic
                        else "starrynet-tor-site-window-v25-cache-on-phase-route-reaudit"
                        if matched_single_visit and args.reaudit_active_route_before_phase_window
                        else "starrynet-tor-site-window-v23-cache-on-after-warmup-phase-matched"
                        if matched_single_visit and args.defer_emulation_until_after_warmup
                        else "starrynet-tor-site-window-v22-cache-on-matched-phase"
                        if matched_single_visit and args.enable_browser_cache_between_visits
                        else "starrynet-tor-site-window-v21-circuit-path-diagnostic"
                        if matched_single_visit
                        else "starrynet-tor-site-window-v18-phase-resource-route-settled"
                        if args.visits == 3 and args.fixed_window_seconds == 85
                        and args.route_ready_stable_seconds >= 5
                        and args.reuse_check_circuit
                        and args.reuse_circuit_between_visits
                        and args.reuse_browser_profile_between_visits
                        and args.reuse_browser_process_between_visits
                        and args.reuse_target_page_between_visits
                        and args.defer_emulation_until_warmup
                        and args.warmup_site_visit
                        and args.page_load_timeout == 240
                        and args.page_content_timeout == 60
                        and args.resource_idle_seconds == 4
                        and args.capture_settle_seconds == 2
                        and args.browser_timeout == 1200
                        and args.route_ready_timeout_seconds == 90
                        and args.warmup_settle_seconds == 25
                        and args.offload_mode == "disable_path"
                        and not args.enable_browser_cache_between_visits
                        else "starrynet-tor-site-window-v17-phase-resource-observability"
                        if args.visits == 3 and args.fixed_window_seconds == 85
                        and args.route_ready_stable_seconds >= 5
                        and args.reuse_check_circuit
                        and args.reuse_circuit_between_visits
                        and args.reuse_browser_profile_between_visits
                        and args.reuse_browser_process_between_visits
                        and args.reuse_target_page_between_visits
                        and args.defer_emulation_until_warmup
                        and args.warmup_site_visit
                        and args.page_load_timeout == 240
                        and args.page_content_timeout == 60
                        and args.resource_idle_seconds == 4
                        and args.capture_settle_seconds == 2
                        and args.browser_timeout == 1200
                        and args.route_ready_timeout_seconds == 90
                        and args.warmup_settle_seconds == 10
                        and args.offload_mode == "disable_path"
                        and not args.enable_browser_cache_between_visits
                        else "starrynet-tor-site-window-v15"
                        if args.enable_browser_cache_between_visits
                        else "starrynet-tor-site-window-v14"
                        if args.defer_emulation_until_warmup
                        else "starrynet-tor-site-window-v13"
                        if args.reuse_target_page_between_visits
                        and args.fixed_window_seconds == 60
                        else "starrynet-tor-site-window-v12"
                        if args.reuse_target_page_between_visits
                        and args.fixed_window_seconds == 85
                        else "starrynet-tor-site-window-v11"
                        if args.warmup_before_each_visit
                        and args.visits == 3 and args.reuse_browser_process_between_visits
                        and args.fixed_window_seconds is not None
                        and args.route_ready_stable_seconds >= 5
                        else "starrynet-tor-site-window-v10"
                        if args.warmup_site_visit
                        and args.visits == 3 and args.reuse_browser_process_between_visits
                        and args.fixed_window_seconds is not None
                        and args.route_ready_stable_seconds >= 5
                        else "starrynet-tor-site-window-v8"
                        if args.visits == 3 and args.reuse_browser_process_between_visits
                        and args.fixed_window_seconds is not None
                        and args.route_ready_stable_seconds >= 5
                        else "starrynet-tor-site-window-v5"
                        if args.visits > 1 and args.reuse_browser_process_between_visits
                        and args.fixed_window_seconds is None
                        else "starrynet-tor-site-window-v7"
                        if args.visits > 1 and args.reuse_browser_process_between_visits
                        and args.fixed_window_seconds is not None
                        else "starrynet-tor-site-window-v4"
                        if args.visits > 1 and args.reuse_browser_profile_between_visits
                        else "starrynet-tor-site-window-v3"
                        if args.visits > 1 and args.reuse_circuit_between_visits
                        else "starrynet-tor-site-window-v2"),
        "site_url": args.url,
        "one_fresh_browser_profile_per_visit":
            not args.reuse_browser_profile_between_visits,
        "persistent_browser_profile_for_all_visits":
            bool(args.reuse_browser_profile_between_visits),
        "single_browser_process_for_all_visits":
            bool(args.reuse_browser_process_between_visits or matched_single_visit),
        "cache_disabled_for_persistent_profile": bool(
            args.reuse_browser_profile_between_visits
            and not args.enable_browser_cache_between_visits),
        "cache_enabled_for_persistent_profile": bool(
            args.reuse_browser_profile_between_visits
            and args.enable_browser_cache_between_visits),
        "cache_mode": ("enabled_from_warmup_to_single_refresh"
                       if matched_single_visit and args.enable_browser_cache_between_visits
                       else "disabled_for_single_warmup_refresh"
                       if matched_single_visit
                       else "persistent_between_measured_visits"
                       if args.enable_browser_cache_between_visits
                       else "disabled_for_persistent_profile"
                       if args.reuse_browser_profile_between_visits
                       else "browser_default"),
        "visits_per_dynamic_topology": args.visits,
        "single_tor_process_for_all_visits": (
            args.visits > 1 or matched_single_visit),
        "reuse_tor_circuit_between_visits_requested":
            bool(args.reuse_circuit_between_visits),
        "starrynet_run_id": run_id if args.visits > 1 else None,
        "reuse_check_circuit_for_site_visit": bool(args.reuse_check_circuit),
        "target_circuit_path_fingerprints": (
            "CIRC_BUILT_path_for_each_measured_target_stream"
            if matched_single_visit else None),
        "tor_path_control": ({
            "mode": "pinned_bridge_entry_only_default_middle_exit",
            "entry_fingerprint": V27_BRIDGE_FINGERPRINT,
            "middle_exit_selection": "Tor default selection",
            "torrc_options": [],
        } if matched_single_visit
            and args.protocol_id in E_BROWSER_ENTRY_ONLY_PROTOCOL_IDS else {
            "mode": "fixed_middle_exit_diagnostic",
            "middle_fingerprint": V26_MIDDLE_FINGERPRINT,
            "exit_fingerprint": V26_EXIT_FINGERPRINT,
            "torrc_options": [
                "MiddleNodes ${}".format(V26_MIDDLE_FINGERPRINT),
                "ExitNodes ${}".format(V26_EXIT_FINGERPRINT),
            ],
            "expected_target_relay_fingerprints": [
                V26_ENTRY_FINGERPRINT,
                V26_MIDDLE_FINGERPRINT,
                V26_EXIT_FINGERPRINT,
            ],
            "entry_node_pinned": False,
        } if args.pin_tor_path_diagnostic else None),
        "bridge_selection": bridge_selection,
        "target_page_reused_between_measured_visits": bool(
            args.reuse_target_page_between_visits and args.visits > 1),
        "warmup_page_retained_for_measurement": bool(
            args.reuse_target_page_between_visits),
        "browser_cache_enabled_for_warmup_refresh": bool(
            matched_single_visit and args.enable_browser_cache_between_visits),
        "cache_disabled_for_warmup_refresh": bool(
            matched_single_visit and not args.enable_browser_cache_between_visits),
        "target_page_refresh_window_seconds": (
            args.fixed_window_seconds if args.reuse_target_page_between_visits else None),
        "tor_check_frequency": ("once_before_initial_site_warmup"
                                if args.reuse_target_page_between_visits
                                else "once_per_measured_visit"),
        "measured_site_navigation_action": ("same_tab_refresh"
                                            if args.reuse_target_page_between_visits
                                            else "navigate_to_requested_url"),
        "repeat_design": (
            "one_visit_per_independent_dynamic_topology_with_capture_phase_matched"
            if matched_single_visit else
            "same_dynamic_topology_tor_process_browser_profile_and_target_page_refreshes"
            if args.reuse_target_page_between_visits
            else "same_dynamic_topology_tor_process_browser_profile_and_browser_process"
            if args.visits > 1 and args.reuse_browser_process_between_visits
            else "same_dynamic_topology_and_tor_process_persistent_browser_profile"
            if args.visits > 1 and args.reuse_browser_profile_between_visits
            else "same_dynamic_topology_and_tor_process_fresh_profile_per_visit"
            if args.visits > 1 else "independent_dynamic_topology_per_run"),
        "topology_mode": "frozen_after_initial_route" if args.freeze_topology else "dynamic",
        "topology_phase_and_ground_station_qdisc_monitoring": True,
        "matched_dynamic_phase": ({
            "target_capture_start_seconds": args.matched_dynamic_phase_seconds,
            "tolerance_seconds": args.matched_dynamic_phase_tolerance_seconds,
            "phase_origin": "dynamic_emulation_start.started_monotonic",
            "gate": (
                "audit_current_route_before_phase_window_then_verify_phase_aligned_route_qdisc_monitor_gate"
                if args.reaudit_active_route_before_phase_window else
                "verify_route_and_offloads_then_phase_aligned_route_qdisc_monitor_gate"),
            "phase_route_offload_audit_lead_seconds": (
                10 if args.reaudit_active_route_before_phase_window else None),
        } if matched_single_visit else None),
        "browser_resource_timing_snapshots": (
            "at_visible_content_readiness_and_fixed_window_end"
            if args.fixed_window_seconds is not None else "disabled"),
        "dynamic_emulation_start_policy": (
            "after_uncaptured_site_warmup_before_measured_capture"
            if args.defer_emulation_until_after_warmup else
            "after_initial_tor_check_before_uncaptured_site_warmup"
            if args.defer_emulation_until_warmup else "at_initial_route_ready"),
        "initial_tor_check_topology_state": (
            "verified_initial_satellite_route_before_dynamic_updates"
            if (args.defer_emulation_until_warmup
                or args.defer_emulation_until_after_warmup)
            else "dynamic_updates_active"),
        "offload_mode": args.offload_mode,
        "capture_peer_veth": bool(args.capture_peer_veth),
        "timeouts_seconds": {
            "tor_bootstrap": args.bootstrap_timeout,
            "page_load": args.page_load_timeout,
            "page_content": args.page_content_timeout,
            "browser_wall_clock": args.browser_timeout,
        },
        "page_readiness": {
            "minimum_visible_body_characters": 40,
            "resource_timing_count_idle_seconds": args.resource_idle_seconds,
            "resource_timing_idle_required": args.fixed_window_seconds is None,
            "fixed_window_seconds_after_navigation_start": args.fixed_window_seconds,
            "capture_settle_seconds_after_readiness": args.capture_settle_seconds,
        },
        "route_readiness": {
            "stable_seconds_required": args.route_ready_stable_seconds,
            "wait_timeout_seconds": args.route_ready_timeout_seconds,
            "required_before_initial_tor_check": bool(
                args.warmup_site_visit or args.warmup_before_each_visit),
            "same_forward_and_return_route_devices_required":
                args.route_ready_stable_seconds > 0,
            "active_path_offloads_reverified_before_each_capture":
                args.route_ready_stable_seconds > 0,
            "frozen_client_capture_interface": None,
            "stability_evidence_source": (
                "phase_aligned_one_second_route_monitor_after_phase_path_offload_audit"
                if matched_single_visit and args.reaudit_active_route_before_phase_window else
                "phase_aligned_one_second_route_monitor_after_prior_path_offload_audit"
                if matched_single_visit else
                "one_second_route_monitor_after_path_offload_audit"
                if args.route_ready_stable_seconds > 0 else None),
        },
        "premeasurement_site_warmup": {
            "enabled": bool(args.warmup_site_visit or args.warmup_before_each_visit),
            "before_each_measured_visit": bool(args.warmup_before_each_visit),
            "site_url": args.url if (args.warmup_site_visit
                                      or args.warmup_before_each_visit) else None,
            "settle_seconds_after_page_ready": (
                args.warmup_settle_seconds if (args.warmup_site_visit
                                               or args.warmup_before_each_visit) else None),
            "captured_as_a_trace": False,
            "cookies_and_site_storage_cleared_after_warmup":
                bool(args.warmup_site_visit or args.warmup_before_each_visit),
            "browser_process_and_open_site_connections_retained": bool(
                args.warmup_site_visit or args.warmup_before_each_visit),
            "target_page_retained_after_warmup": bool(
                args.reuse_target_page_between_visits),
        },
        "runtime_inputs": {
            "browser_dir": str(Path(args.browser_dir).resolve()),
            "expert_bundle": str(Path(args.expert_bundle).resolve()),
            "bridge_file_name": Path(args.bridge_file).name,
            "geckodriver": str(Path(args.geckodriver).resolve()),
            "python_site_packages": str(Path(args.python_site_packages).resolve()),
            "helper_image": args.helper_image,
        },
        "topology_assumptions": {
            "constellation": "5x5 satellites, two ground stations",
            "client_ground_station": GS_CLIENT,
            "egress_ground_station": GS_EGRESS,
            "satellite_bandwidth_gbps": SATELLITE_BW_GBPS_SMOKE,
            "satellite_loss_percent": STARLINK_LOSS_SMOKE,
            "values_are_smoke_assumptions_not_tor_starlink_calibration": True,
        },
        "trace_contract": {
            "observation_point": "GS26 satellite-facing interface on route to GS27",
            "filter": "TCP stream to the per-run GS27 proxy relay port",
            "window": ("after Tor check, from immediately before target navigation for a fixed duration, then settle"
                       if args.fixed_window_seconds is not None else
                       "after Tor check, from immediately before target navigation through visible-content/resource-idle readiness and settle"),
            "fixed_window_seconds_after_navigation_start": args.fixed_window_seconds,
            "check_stream_handling": (
                "allow 3 seconds for natural closure, request CLOSESTREAM for remaining Tor-check streams, "
                "and verify terminal stream events before capture"
            ),
            "includes_ack_retransmissions_and_page_subresources": True,
            "excludes_tor_bootstrap_and_pre-navigation_check_streams": True,
            "direction_encoding": {"client_to_gs27": 1, "gs27_to_client": -1},
            "required_offloads_off": [
                "tcp-segmentation-offload", "generic-segmentation-offload",
                "generic-receive-offload", "large-receive-offload", "tx-gso-list",
            ],
            "offload_interfaces": [
                "GS26 capture veth and its satellite peer",
                "GS27 return-route veth and its satellite peer",
            ],
            "route_sampling": {
                "directions": ["GS26-to-GS27", "GS27-to-GS26"],
                "interval_seconds": 1.0,
                "capture_window_max_sample_gap_seconds": 2.5,
            },
            "warmup": {
                "site_navigation_captured": False,
                "captured_repeat_visits_excluded_from_warmup": True,
            },
            "dataset_sample_created": False,
        },
        "source_sha256": {
            name: sha256_file(path) for name, path in protocol_paths.items()
            if path.is_file()
        },
        "generated_starrynet_config_sha256": sha256_file(config_path),
    }
    if args.protocol_id:
        collection_protocol["protocol_id"] = args.protocol_id
        collection_protocol["data_domain"] = args.data_domain
        collection_protocol["page_id"] = args.page_id
        collection_protocol["class_label"] = str(args.class_label)
        collection_protocol["source_rank"] = args.source_rank
        collection_protocol["source_domain"] = args.source_domain
        collection_protocol["source_list_sha256"] = args.source_list_sha256
        if args.protocol_id in (E_BROWSER_V1_2_PROTOCOL_ID,
                                E_BROWSER_V1_3_PROTOCOL_ID,
                                E_BROWSER_V1_4_PROTOCOL_ID):
            collection_protocol["runtime_inputs"]["helper_image_id"] = (
                observed_helper_image_id)
            collection_protocol["warmup_redirect_policy"] = dict(
                E_BROWSER_V1_2_WARMUP_REDIRECT_POLICY)
    protocol_path = run_dir / "acquisition_protocol.json"
    write_json(protocol_path, collection_protocol)

    base_port = random.randint(43000, 47000)
    client_proxy_port = base_port
    gs_proxy_port = base_port + 1
    host_relay_port = base_port + 2
    summary = {
        "run_id": run_id,
        "acquisition_protocol_path": str(protocol_path),
        "acquisition_protocol": collection_protocol,
        "status": "running",
        "site_url": args.url,
        "data_domain": args.data_domain,
        "page_id": args.page_id,
        "sample_id": args.sample_id,
        "class_label": str(args.class_label),
        "source_rank": args.source_rank,
        "source_domain": args.source_domain,
        "site_host": urlsplit(args.url).hostname or "",
        "browser": "signed official Tor Browser mounted into a helper container",
        "tor_transport": "WebTunnel through three temporary TCP relays",
        "proxy_path": [
            "GS26 loopback -> GS27 ground-station IP via StarryNet route",
            "GS27 -> host GS_27 bridge gateway",
            "host loopback proxy 127.0.0.1:17897 -> existing Windows Clash/mihomo",
        ],
        "starrynet_topology": {
            "constellation": "5x5 satellites, two ground stations",
            "client_ground_station": GS_CLIENT,
            "egress_ground_station": GS_EGRESS,
            "satellite_bandwidth_gbps_assumption": SATELLITE_BW_GBPS_SMOKE,
            "satellite_loss_percent_assumption": STARLINK_LOSS_SMOKE,
            "sat_ground_loss_percent_assumption": STARLINK_LOSS_SMOKE,
            "parameters_are_smoke_assumptions_not_tor_starlink_calibration": True,
        },
        "network_capture": {
            "location": "GS26 network namespace, satellite-facing route interface",
            "filter": "GS27 proxy peer and TCP port {}".format(gs_proxy_port),
            "window": ("starts immediately before target navigation and ends at the fixed window plus settle"
                       if args.fixed_window_seconds is not None else
                       "starts after Tor check, immediately before target URL navigation; stops after page load and settle"),
            "includes_tor_bootstrap_and_tor_check": False,
            "packet_size_fidelity_verified": False,
        },
        "dataset_sample_created": False,
        "site_trace_extracted": False,
        "trace_extractions": [],
        "capture_pcaps_by_visit": {},
        "pcap_generated": False,
        "scientific_fidelity_verified": False,
        "cleanup_verified": False,
        "errors": [],
    }
    write_json(summary_path, summary)

    sn = None
    emulation_thread = None
    emulation_errors = []
    route_monitor_stop = None
    route_monitor_thread = None
    route_samples_path = None
    capture = None
    peer_capture_endpoint = None
    peer_pcap_path = None
    host_relay = None
    helper_names = []
    browser_name = "tor-site-browser-" + run_id.lower().replace("_", "-")
    resource_inventory_before = None
    cleanup_errors = []
    pcap_path = None
    route_readiness_context = None
    try:
        resource_inventory_before = replay.docker_inventory()
        summary["resource_inventory_before"] = resource_inventory_before
        if not replay.starrynet_resources_cleared(resource_inventory_before):
            raise RuntimeError("owned StarryNet resources already exist; refusing to replace them")
        wait_for_proxy_listener(HTTP_PROXY_HOST, HTTP_PROXY_PORT, timeout=5)

        summary["phase"] = "create_starrynet_topology"
        write_json(summary_path, summary)
        sn = StarryNet(str(config_path), replay.GS, 1, [[1, 27]], local=True, argv=[])
        sn.create_nodes()
        sn.create_links()
        sn.run_routing_deamon()
        client_cid = str(sn.container_id_list[GS_CLIENT - 1])
        egress_cid = str(sn.container_id_list[GS_EGRESS - 1])
        summary["starrynet_container_ids"] = {
            "client": client_cid,
            "egress": egress_cid,
        }
        client_details = docker_inspect_json(client_cid)
        egress_details = docker_inspect_json(egress_cid)
        client_pid = int(client_details["State"]["Pid"])
        egress_pid = int(egress_details["State"]["Pid"])
        summary["network_namespace_pids"] = {"client": client_pid, "egress": egress_pid}

        egress_network = docker("network", "inspect", "GS_27").stdout
        egress_network = json.loads(egress_network)[0]
        egress_host_ip = get_bridge_gateway(egress_network)
        egress_guest_ip = egress_details["NetworkSettings"]["Networks"]["GS_27"]["IPAddress"]
        summary["egress_endpoint"] = {
            "guest_ip": egress_guest_ip,
            "host_bridge_ip": egress_host_ip,
            "host_listener_scope": "bound only to the StarryNet GS_27 bridge address",
        }
        if not egress_host_ip or not egress_guest_ip:
            raise RuntimeError("could not identify the GS27 ground-station bridge endpoints")

        summary["phase"] = "initial_route_check"
        write_json(summary_path, summary)
        route_before = replay.wait_for_satellite_route(client_cid, egress_guest_ip, 90)
        summary["route_before"] = route_before
        summary["egress_to_host_route"] = docker_exec(
            egress_cid, "ip", "route", "get", egress_host_ip)
        if "B27-default" not in summary["egress_to_host_route"]:
            raise RuntimeError("GS27 host-proxy route does not use B27-default: " +
                               summary["egress_to_host_route"])

        def run_emulation():
            try:
                sn.start_emulation()
            except BaseException as exc:
                emulation_errors.append(type(exc).__name__ + ": " + str(exc)[:500])

        def start_dynamic_emulation():
            nonlocal emulation_thread
            if emulation_thread is not None:
                return
            started_monotonic = time.monotonic()
            emulation_thread = threading.Thread(
                target=run_emulation, name="tor-site-starrynet-emulation",
                daemon=True)
            emulation_thread.start()
            summary["topology_update_mode"] = "dynamic"
            summary["emulation_started"] = True
            start_trigger = (
                "initial_site_warmup_capture_control_request"
                if args.defer_emulation_until_warmup else
                "measured_capture_start_after_uncaptured_site_warmup"
                if args.defer_emulation_until_after_warmup else
                "initial_route_ready")
            summary["dynamic_emulation_start"] = {
                "trigger": start_trigger,
                "started_utc": utc_now(),
                "started_monotonic": started_monotonic,
            }
            write_json(summary_path, summary)

        def start_deferred_emulation_and_check_route():
            start_dynamic_emulation()
            route_after_start = replay.wait_for_satellite_route(
                client_cid, egress_guest_ip, 90)
            summary["route_during_emulation_before"] = route_after_start
            summary["route_after_deferred_emulation_start"] = route_after_start
            write_json(summary_path, summary)

        if args.freeze_topology:
            # Keep the initial StarryNet topology and OSPF route in place while
            # the browser runs. This isolates dynamic topology updates from
            # the same end-to-end Tor Browser and capture path.
            summary["topology_update_mode"] = "frozen_after_initial_route"
            summary["emulation_started"] = False
            route_before = replay.wait_for_satellite_route(
                client_cid, egress_guest_ip, 90)
            summary["route_during_emulation_before"] = route_before
        elif (args.defer_emulation_until_warmup
              or args.defer_emulation_until_after_warmup):
            summary["topology_update_mode"] = "dynamic"
            summary["emulation_started"] = False
            summary["dynamic_emulation_start_policy"] = (
                "after_initial_tor_check_before_uncaptured_site_warmup"
                if args.defer_emulation_until_warmup else
                "after_uncaptured_site_warmup_before_measured_capture")
            route_before = replay.wait_for_satellite_route(
                client_cid, egress_guest_ip, 90)
            summary["route_before_deferred_emulation_start"] = route_before
            summary["route_during_emulation_before"] = route_before
        else:
            start_dynamic_emulation()
            route_before = replay.wait_for_satellite_route(
                client_cid, egress_guest_ip, 90)
            summary["route_during_emulation_before"] = route_before
        route_text = route_before.get("route", "")
        route_source = re.search(r"\bsrc\s+(\S+)", route_text)
        route_device = re.search(r"\bdev\s+(\S+)", route_text)
        if not route_source or not route_device:
            raise RuntimeError("could not identify the client satellite route source and interface")
        client_guest_ip = route_source.group(1)
        capture_interface = route_device.group(1)
        interface_line = next((line for line in route_before.get("interfaces", "").splitlines()
                               if capture_interface in line), "")
        interface_mtu = re.search(r"\bmtu\s+(\d+)", interface_line)
        if not interface_mtu:
            raise RuntimeError("could not identify the satellite interface MTU")
        capture_mtu = int(interface_mtu.group(1))
        summary["network_capture"].update({
            "interface": capture_interface,
            "interface_mtu_bytes": capture_mtu,
            "client_ip": client_guest_ip,
            "peer_ip": egress_guest_ip,
        })
        collection_protocol["route_readiness"][
            "frozen_client_capture_interface"] = capture_interface
        write_json(protocol_path, collection_protocol)
        summary["acquisition_protocol"] = collection_protocol
        write_json(summary_path, summary)
        interface_match = re.fullmatch(r"B(\d+)-eth(\d+)", capture_interface)
        if interface_match:
            local_node = int(interface_match.group(1))
            peer_node = int(interface_match.group(2))
            if (local_node != GS_CLIENT
                    or not 1 <= peer_node <= len(sn.container_id_list) - 2):
                raise RuntimeError("cannot map capture interface peer to a StarryNet node")
            peer_cid = str(sn.container_id_list[peer_node - 1])
            peer_interface = "B{}-eth{}".format(peer_node, local_node)
            egress_return_route = docker_exec(
                egress_cid, "ip", "route", "get", client_guest_ip)
            summary["egress_to_client_route_before_capture"] = egress_return_route
            egress_device_match = re.search(r"\bdev\s+(\S+)", egress_return_route)
            egress_match = re.fullmatch(
                r"B(\d+)-eth(\d+)",
                egress_device_match.group(1) if egress_device_match else "")
            if (not egress_match or int(egress_match.group(1)) != GS_EGRESS
                    or not 1 <= int(egress_match.group(2))
                    <= len(sn.container_id_list) - 2):
                raise RuntimeError("GS27 return route does not use a GS27 satellite interface: "
                                   + egress_return_route)
            egress_peer_node = int(egress_match.group(2))
            if not 1 <= egress_peer_node <= len(sn.container_id_list) - 2:
                raise RuntimeError("cannot map GS27 return-route peer to a StarryNet node")
            egress_peer_cid = str(sn.container_id_list[egress_peer_node - 1])
            egress_peer_interface = "B{}-eth{}".format(
                egress_peer_node, GS_EGRESS)
            offload_extra_endpoints = [
                {"role": "GS27_return_sender_interface",
                 "container_id": egress_cid,
                 "interface": "B{}-eth{}".format(
                     egress_match.group(1), egress_peer_node)},
                {"role": "GS27_return_next_hop_veth_peer",
                 "container_id": egress_peer_cid,
                 "interface": egress_peer_interface},
            ]
            if args.capture_peer_veth:
                peer_capture_endpoint = {
                    "cid": peer_cid,
                    "interface": peer_interface,
                }
                summary["network_capture"].update({
                    "peer_capture_enabled": True,
                    "peer_interface": peer_interface,
                    "peer_capture_location": "next-hop satellite network namespace",
                })
            offload_audit = audit_path_offloads(
                client_cid, peer_cid, capture_interface, peer_interface,
                args.offload_mode, extra_endpoints=offload_extra_endpoints)
        else:
            if args.capture_peer_veth:
                raise RuntimeError("cannot identify the next-hop veth for peer capture")
            offload_audit = {
                "mode": args.offload_mode,
                "endpoints": [],
                "verified_disabled": False,
                "errors": ["capture interface name does not identify a StarryNet veth peer"],
            }
        summary["packetization_offload_audit"] = offload_audit
        summary["network_capture"]["path_packet_offloads_disabled_verified"] = bool(
            args.offload_mode == "disable_path"
            and offload_audit.get("verified_disabled"))
        if args.offload_mode == "disable_path" and not offload_audit.get(
                "verified_disabled"):
            raise RuntimeError("could not disable and verify path packet offloads: "
                               + "; ".join(offload_audit.get("errors", [])))
        write_json(summary_path, summary)

        host_endpoint = "{}:{}".format(egress_host_ip, host_relay_port)
        guest_endpoint = "{}:{}".format(egress_guest_ip, gs_proxy_port)
        client_endpoint = "127.0.0.1:{}".format(client_proxy_port)
        upstream_endpoint = "127.0.0.1:{}".format(HTTP_PROXY_PORT)

        host_relay = start_host_relay(script_path, run_dir,
                                      host_endpoint, upstream_endpoint)
        uid = os.getuid()
        gid = os.getgid()
        remote_name = "tor-site-egress-" + run_id.lower().replace("_", "-")
        local_name = "tor-site-client-" + run_id.lower().replace("_", "-")
        helper_names.extend([remote_name, local_name])
        summary["relays"] = {
            "host": {"listen": host_endpoint, "upstream": upstream_endpoint},
            "egress_ground_station": start_helper_relay(
                remote_name, egress_cid, args.helper_image, script_path,
                guest_endpoint, host_endpoint, "/tmp/tor-site-relay-ready.json",
                run_dir / "logs" / "gs27-relay-container.log", uid, gid),
            "client_loopback": start_helper_relay(
                local_name, client_cid, args.helper_image, script_path,
                client_endpoint, guest_endpoint, "/tmp/tor-site-relay-ready.json",
                run_dir / "logs" / "gs26-relay-container.log", uid, gid),
        }
        summary["phase"] = "start_capture"
        write_json(summary_path, summary)

        summary["phase"] = "capture_and_site_visit"
        route_samples_path = run_dir / "route_samples.jsonl"
        route_monitor_stop = threading.Event()
        route_monitor_thread = threading.Thread(
            target=route_monitor_worker,
            args=(route_monitor_stop, route_samples_path, client_cid, egress_cid,
                  client_guest_ip, egress_guest_ip),
            name="tor-site-bidirectional-route-monitor", daemon=True)
        route_monitor_thread.start()
        summary["route_monitor"] = {
            "sample_path": str(route_samples_path),
            "sample_interval_seconds": 1.0,
            "directions": ["client_to_egress", "egress_to_client"],
            "started_before_browser_container": True,
        }
        route_readiness_context = None
        if args.route_ready_stable_seconds > 0:
            route_readiness_context = {
                "egress_cid": egress_cid,
                "container_ids": [str(item) for item in sn.container_id_list],
                "client_peer_ip": client_guest_ip,
                "egress_peer_ip": egress_guest_ip,
                "stable_seconds": args.route_ready_stable_seconds,
                "timeout_seconds": args.route_ready_timeout_seconds,
                "samples_path": str(route_samples_path),
            }
            if matched_single_visit:
                route_readiness_context["matched_dynamic_phase"] = {
                    "target_capture_start_seconds":
                        args.matched_dynamic_phase_seconds,
                    "tolerance_seconds":
                        args.matched_dynamic_phase_tolerance_seconds,
                    "reaudit_active_route_before_phase_window":
                        args.reaudit_active_route_before_phase_window,
                }
            summary["route_readiness_protocol"] = {
                "stable_seconds_required": args.route_ready_stable_seconds,
                "wait_timeout_seconds": args.route_ready_timeout_seconds,
                "consecutive_route_devices_required": True,
                "both_directions_must_use_satellite_interfaces": True,
                "active_path_offloads_reverified_before_each_capture": True,
                "stability_evidence_source":
                    ("phase_aligned_one_second_route_monitor_after_phase_path_offload_audit"
                     if args.reaudit_active_route_before_phase_window else
                     "one_second_route_monitor_after_path_offload_audit"),
                "frozen_client_capture_interface": capture_interface,
            }
        write_json(summary_path, summary)
        if (args.warmup_site_visit or args.warmup_before_each_visit) \
                and route_readiness_context:
            summary["phase"] = "wait_route_before_tor_check"
            write_json(summary_path, summary)
            browser_start_route_readiness = wait_for_route_readiness(
                client_cid, route_readiness_context["egress_cid"],
                route_readiness_context["container_ids"],
                route_readiness_context["client_peer_ip"],
                route_readiness_context["egress_peer_ip"],
                capture_interface,
                route_readiness_context["stable_seconds"],
                route_readiness_context["timeout_seconds"],
                route_readiness_context["samples_path"])
            summary["route_readiness_before_tor_check"] = (
                browser_start_route_readiness)
            summary["route_readiness_before_tor_check_ack"] = {
                "ok": browser_start_route_readiness.get("passed") is True,
                "route_ready_utc": utc_now(),
                "route_ready_monotonic": time.monotonic(),
                "route_readiness": browser_start_route_readiness,
            }
            if browser_start_route_readiness.get("passed") is not True:
                raise RuntimeError(
                    "bidirectional satellite route was not ready before the initial Tor check: "
                    + str(browser_start_route_readiness.get(
                        "last_error", "readiness timeout")))
            write_json(summary_path, summary)
        if selected_bridge_line is not None:
            selected_bridge_file = run_dir / "private-v27-bridge.txt"
            selected_bridge_file.write_text(selected_bridge_line, encoding="utf-8")
            selected_bridge_file.chmod(0o600)
            bridge_file_for_mount = selected_bridge_file
        browser_command = [
            "docker", "run", "--name", browser_name,
            "--network", "container:" + client_cid,
            "--user", "{}:{}".format(uid, gid),
            "-e", "HOME=/tmp/tor-browser-home",
            "-e", "TMPDIR=/tmp",
            "-e", "PYTHONPATH=/opt/py312site",
            "-e", "HTTPS_PROXY=http://127.0.0.1:{}".format(client_proxy_port),
            "-e", "https_proxy=http://127.0.0.1:{}".format(client_proxy_port),
            "-e", "HTTP_PROXY=",
            "-e", "http_proxy=",
            "-e", "ALL_PROXY=",
            "-e", "all_proxy=",
            "-e", "NO_PROXY=",
            "-e", "no_proxy=",
            "-v", str(Path(args.browser_dir).resolve()) + ":/opt/tor-browser:ro",
            "-v", str(Path(args.expert_bundle).resolve()) + ":/opt/expert-bundle:ro",
            "-v", str(bridge_file_for_mount) + ":/opt/webtunnel-bridges.txt:ro",
            "-v", str(Path(args.geckodriver).resolve()) + ":/usr/local/bin/geckodriver:ro",
            "-v", str(Path(args.python_site_packages).resolve()) + ":/opt/py312site:ro",
            "-v", str((ROOT / "tools" / "tor_browser_site_smoke.py").resolve()) +
            ":/opt/tor_browser_site_smoke.py:ro",
            "-v", str(run_dir) + ":/out:rw",
            "--entrypoint", "python3.11", args.helper_image,
            "/opt/tor_browser_site_smoke.py",
            "--browser-dir", "/opt/tor-browser",
            "--expert-bundle", "/opt/expert-bundle",
            "--bridge-file", "/opt/webtunnel-bridges.txt",
            "--geckodriver", "/usr/local/bin/geckodriver",
            "--output-root", "/out/browser_runs",
            "--capture-control-dir", "/out/capture_control",
            "--label", "0", "--url", args.url, "--visits", str(args.visits),
            "--bootstrap-timeout", str(args.bootstrap_timeout),
            "--page-load-timeout", str(args.page_load_timeout),
            "--page-content-timeout", str(args.page_content_timeout),
            "--resource-idle-seconds", str(args.resource_idle_seconds),
            "--capture-settle-seconds", str(args.capture_settle_seconds),
        ]
        if route_readiness_context:
            browser_command.extend([
                "--capture-ack-timeout",
                str(max(60, args.route_ready_timeout_seconds + 60)),
            ])
        if args.fixed_window_seconds is not None:
            browser_command.extend(["--fixed-window-seconds",
                                    str(args.fixed_window_seconds)])
        if args.warmup_site_visit or args.warmup_before_each_visit:
            browser_command.extend([
                "--warmup-settle-seconds", str(args.warmup_settle_seconds),
            ])
            if args.warmup_site_visit:
                browser_command.append("--warmup-site-visit")
            if args.warmup_before_each_visit:
                browser_command.append("--warmup-before-each-visit")
        if args.reuse_target_page_between_visits:
            browser_command.append("--reuse-target-page-between-visits")
        if args.enable_browser_cache_between_visits:
            browser_command.append("--enable-browser-cache-between-visits")
        if args.pin_tor_path_diagnostic:
            browser_command.extend([
                "--pin-tor-middle-fingerprint", V26_MIDDLE_FINGERPRINT,
                "--pin-tor-exit-fingerprint", V26_EXIT_FINGERPRINT,
            ])
        if args.reuse_check_circuit:
            browser_command.append("--reuse-check-circuit-for-first-site")
        if args.reuse_circuit_between_visits:
            browser_command.append("--reuse-circuit-between-visits")
        if args.reuse_browser_profile_between_visits:
            browser_command.append("--reuse-browser-profile-between-visits")
        if args.reuse_browser_process_between_visits:
            browser_command.append("--reuse-browser-process-between-visits")
        browser_log = (run_dir / "logs" / "browser-container.log").open("w")
        summary["phase"] = "tor_browser_visit_running"
        write_json(summary_path, summary)
        try:
            browser_process = subprocess.Popen(browser_command, stdout=browser_log,
                                              stderr=subprocess.STDOUT)
            capture_control_state = {
                "phase": "warmup" if (args.warmup_site_visit
                                        or args.warmup_before_each_visit) else "start",
                "capture": capture,
                "warmup_before_each_visit": args.warmup_before_each_visit,
                "visit_count": args.visits,
            }
            browser_deadline = time.monotonic() + args.browser_timeout
            while browser_process.poll() is None and time.monotonic() < browser_deadline:
                capture_control_state = service_capture_control(
                    capture_control_dir, client_cid, run_dir, gs_proxy_port,
                    egress_guest_ip, capture_interface, capture_control_state,
                    summary, summary_path, peer_capture=peer_capture_endpoint,
                    route_readiness_context=route_readiness_context,
                    deferred_emulation_start=(
                        start_deferred_emulation_and_check_route
                        if args.defer_emulation_until_warmup else None),
                    emulation_start_after_warmup=(
                        start_deferred_emulation_and_check_route
                        if args.defer_emulation_until_after_warmup else None))
                capture = capture_control_state.get("capture")
                time.sleep(0.1)
            if browser_process.poll() is None:
                browser_process.terminate()
                try:
                    browser_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    browser_process.kill()
                    browser_process.wait(timeout=10)
                summary["errors"].append("browser helper exceeded its wall-clock timeout")
                browser_exit = browser_process.returncode
            else:
                browser_exit = browser_process.returncode
            # Process a stop request written just before the helper exited.
            capture_control_state = service_capture_control(
                capture_control_dir, client_cid, run_dir, gs_proxy_port,
                egress_guest_ip, capture_interface, capture_control_state,
                summary, summary_path, peer_capture=peer_capture_endpoint,
                route_readiness_context=route_readiness_context,
                deferred_emulation_start=(
                    start_deferred_emulation_and_check_route
                    if args.defer_emulation_until_warmup else None),
                emulation_start_after_warmup=(
                    start_deferred_emulation_and_check_route
                    if args.defer_emulation_until_after_warmup else None))
            capture = capture_control_state.get("capture")
            summary["capture_pcaps_by_visit"] = capture_control_state.get(
                "pcap_paths_by_visit", {})
            first_capture = summary["capture_pcaps_by_visit"].get("1", {})
            pcap_path = Path(first_capture["client"]) if first_capture.get("client") else None
            peer_pcap_path = capture_control_state.get("peer_pcap_path")
        finally:
            if route_monitor_stop is not None:
                route_monitor_stop.set()
            if route_monitor_thread is not None:
                route_monitor_thread.join(timeout=10)
            browser_log.flush()
            browser_log.close()
            stop_named_container(browser_name)
        summary["browser_container_exit_code"] = browser_exit

        browser_summaries = sorted((run_dir / "browser_runs").glob("*/summary.json"))
        if browser_summaries:
            browser_summary_path = browser_summaries[-1]
            summary["browser_summary_path"] = str(browser_summary_path)
            summary["browser_summary"] = json.loads(browser_summary_path.read_text(
                encoding="utf-8"))
        else:
            summary["errors"].append("Tor Browser helper did not write a summary")

        if route_samples_path and route_samples_path.is_file():
            route_samples = [json.loads(line) for line in
                             route_samples_path.read_text(encoding="utf-8").splitlines()
                             if line.strip()]
            route_monitor = summary.setdefault("route_monitor", {})
            route_monitor.update({
                "sample_count": len(route_samples),
                "sample_sha256": sha256_file(route_samples_path),
                "visit_windows": check_route_monitor_windows(
                    route_samples, summary.get("browser_summary", {}), 1.0,
                    (summary.get("dynamic_emulation_start") or {}).get(
                        "started_monotonic")),
            })
            route_monitor["all_capture_windows_passed"] = (
                len(route_monitor["visit_windows"]) == args.visits
                and all(item.get("passed") is True
                        for item in route_monitor["visit_windows"]))
            write_json(summary_path, summary)

        summary["route_after"] = replay.final_route_snapshot(
            client_cid, egress_guest_ip, timeout=30)
        if capture:
            output_paths = stop_capture_group(capture, run_dir)
            active_visit = str(capture[0].get("capture_id", "").rsplit(
                "_visit_", 1)[-1]) if "_visit_" in capture[0].get("capture_id", "") else "1"
            client_visit_path = output_paths.get("client_visit_{}".format(active_visit))
            pcap_path = client_visit_path or output_paths.get("client", pcap_path)
            peer_pcap_path = output_paths.get("peer", peer_pcap_path)
            summary.setdefault("capture_pcaps_by_visit", {})[active_visit] = {
                "client": str(pcap_path) if pcap_path else None,
                "peer": str(peer_pcap_path) if peer_pcap_path else None,
            }
            capture = None
        browser_summary = summary.get("browser_summary", {})
        visits = browser_summary.get("visits", [])
        trace_extractions = []
        capture_audits = {}
        extractor = ROOT / "tools" / "extract_starrynet_site_trace.py"
        for visit_index, visit in enumerate(visits, 1):
            visit_key = str(visit_index)
            capture_record = summary.get("capture_pcaps_by_visit", {}).get(visit_key, {})
            visit_pcap = Path(capture_record["client"]) if capture_record.get("client") else None
            if not visit_pcap or not visit_pcap.is_file():
                trace_extractions.append({"visit_index": visit_index,
                                          "status": "missing_capture"})
                continue
            pcap_hash = __import__("hashlib").sha256(visit_pcap.read_bytes()).hexdigest()
            pcap_validation = inspect_capture(visit_pcap, gs_proxy_port, egress_guest_ip)
            capture_record.update({"pcap_sha256": pcap_hash,
                                   "pcap_validation": pcap_validation})
            capture_audits[visit_key] = capture_record

            visit_window = visit.get("capture_window", {})
            capture_window = {
                "schema": "starrynet-site-capture-window-v1",
                "capture_interface": capture_interface,
                "capture_start_request": visit_window.get("start_request"),
                "capture_start_ack": visit_window.get("start_ack"),
                "site_navigation_started": visit_window.get("navigation_started"),
                "site_navigation_completed": visit_window.get("navigation_completed"),
                "capture_stop_request": visit_window.get("stop_request"),
                "capture_stop_ack": visit_window.get("stop_ack"),
            }
            capture_window_path = run_dir / "capture_window_visit_{}.json".format(visit_index)
            write_json(capture_window_path, capture_window)
            visit_summary = dict(browser_summary)
            visit_summary["visits"] = [visit]
            visit_summary["passed"] = bool(visit.get("passed"))
            visit_summary_path = run_dir / "browser_summary_visit_{}.json".format(visit_index)
            write_json(visit_summary_path, visit_summary)
            trace_dir = run_dir / "site_trace_visit_{}".format(visit_index)
            extraction = subprocess.run([
                sys.executable, str(extractor),
                "--pcap", str(visit_pcap),
                "--client-ip", client_guest_ip,
                "--peer-ip", egress_guest_ip,
                "--peer-port", str(gs_proxy_port),
                "--interface-mtu", str(capture_mtu),
                "--window-json", str(capture_window_path),
                "--site-summary", str(visit_summary_path),
                "--output-dir", str(trace_dir),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               universal_newlines=True, timeout=180)
            try:
                extraction_result = json.loads(extraction.stdout.strip().splitlines()[-1])
            except (IndexError, ValueError):
                extraction_result = {"stdout": extraction.stdout[-2000:]}
            extraction_result.update({"exit_code": extraction.returncode,
                                      "stderr": extraction.stderr[-2000:]})
            trace_extractions.append({"visit_index": visit_index,
                                      "source_pcap": str(visit_pcap),
                                      "pcap_sha256": pcap_hash,
                                      "pcap_validation": pcap_validation,
                                      "capture_window_path": str(capture_window_path),
                                      "browser_summary_path": str(visit_summary_path),
                                      "trace_extraction": extraction_result})
            if visit_index == 1:
                summary["capture_window_path"] = str(capture_window_path)
                summary["capture_window"] = {
                    "mode": visit_window.get("mode"),
                    "navigation_started": visit_window.get("navigation_started"),
                    "navigation_completed": visit_window.get("navigation_completed"),
                    "site_stream_domains": visit_window.get("site_stream_domains", []),
                    "tor_check_stream_seen": visit_window.get("tor_check_stream_seen"),
                }
                summary["pcap_path"] = str(visit_pcap)
                summary["pcap_sha256"] = pcap_hash
                summary["pcap_validation"] = pcap_validation
                summary["trace_extraction"] = extraction_result
            if (args.offload_mode == "disable_path"
                    and summary["network_capture"].get(
                        "path_packet_offloads_disabled_verified")
                    and extraction_result.get("ip_length_bytes", {}).get(
                        "over_interface_mtu_count") == 0):
                summary["network_capture"]["packet_size_fidelity_verified"] = True
        summary["capture_pcaps_by_visit"] = capture_audits
        summary["trace_extractions"] = trace_extractions
        summary["pcap_generated"] = len(capture_audits) == len(visits) == args.visits
        summary["site_trace_extracted"] = (
            len(trace_extractions) == args.visits
            and all(item.get("trace_extraction", {}).get("exit_code") == 0
                    and item.get("trace_extraction", {}).get(
                        "status") == "clean_site_window_candidate"
                    for item in trace_extractions))
        if peer_pcap_path:
            summary["peer_pcap_path"] = str(peer_pcap_path)
            summary["peer_pcap_sha256"] = __import__("hashlib").sha256(
                peer_pcap_path.read_bytes()).hexdigest()
            summary["peer_pcap_validation"] = inspect_capture(
                peer_pcap_path, gs_proxy_port, egress_guest_ip)
        if peer_pcap_path and summary.get("browser_summary_path"):
            peer_trace_dir = run_dir / "site_trace_peer"
            peer_capture_window = dict(capture_window)
            peer_capture_window["capture_interface"] = summary[
                "network_capture"]["peer_interface"]
            peer_capture_window_path = run_dir / "capture_window_peer.json"
            write_json(peer_capture_window_path, peer_capture_window)
            summary["peer_capture_window"]["capture_window_path"] = str(
                peer_capture_window_path)
            peer_extraction = subprocess.run([
                sys.executable, str(extractor),
                "--pcap", str(peer_pcap_path),
                "--client-ip", client_guest_ip,
                "--peer-ip", egress_guest_ip,
                "--peer-port", str(gs_proxy_port),
                "--interface-mtu", str(capture_mtu),
                "--window-json", str(peer_capture_window_path),
                "--site-summary", summary["browser_summary_path"],
                "--output-dir", str(peer_trace_dir),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               universal_newlines=True, timeout=180)
            try:
                peer_result = json.loads(peer_extraction.stdout.strip().splitlines()[-1])
            except (IndexError, ValueError):
                peer_result = {"stdout": peer_extraction.stdout[-2000:]}
            peer_result.update({
                "exit_code": peer_extraction.returncode,
                "stderr": peer_extraction.stderr[-2000:],
            })
            summary["peer_trace_extraction"] = peer_result
        if emulation_errors:
            summary["errors"].extend(["dynamic emulation: " + error
                                      for error in emulation_errors])
        summary["status"] = "site_visit_finished"
    except BaseException as exc:
        summary["status"] = "aborted"
        summary["errors"].append(type(exc).__name__ + ": " + str(exc)[:800])
        summary["traceback"] = traceback.format_exc()[-5000:]
    finally:
        if route_monitor_stop is not None:
            route_monitor_stop.set()
        if route_monitor_thread is not None:
            route_monitor_thread.join(timeout=10)
        if capture:
            try:
                output_paths = stop_capture_group(capture, run_dir)
                pcap_path = output_paths.get("client", pcap_path)
                peer_pcap_path = output_paths.get("peer", peer_pcap_path)
                summary["pcap_generated"] = bool(pcap_path)
                if pcap_path:
                    summary["pcap_sha256"] = __import__("hashlib").sha256(
                        pcap_path.read_bytes()).hexdigest()
                    summary["pcap_validation"] = inspect_capture(
                        pcap_path, gs_proxy_port, summary.get("egress_endpoint", {}).get(
                            "guest_ip", "0.0.0.0"))
                if peer_pcap_path:
                    summary["peer_pcap_path"] = str(peer_pcap_path)
                    summary["peer_pcap_sha256"] = __import__("hashlib").sha256(
                        peer_pcap_path.read_bytes()).hexdigest()
                    summary["peer_pcap_validation"] = inspect_capture(
                        peer_pcap_path, gs_proxy_port, summary.get(
                            "egress_endpoint", {}).get("guest_ip", "0.0.0.0"))
            except BaseException as exc:
                cleanup_errors.append("capture: {}: {}".format(type(exc).__name__, exc))
        stop_named_container(browser_name)
        if selected_bridge_file is not None:
            try:
                selected_bridge_file.unlink()
                summary["bridge_selection_file_deleted_verified"] = (
                    not selected_bridge_file.exists())
            except OSError as exc:
                cleanup_errors.append("remove private V27 bridge selection: {}".format(exc))
                summary["bridge_selection_file_deleted_verified"] = False
        for name in reversed(helper_names):
            try:
                if not stop_named_container(name):
                    cleanup_errors.append("helper container remained: " + name)
            except BaseException as exc:
                cleanup_errors.append("remove {}: {}".format(name, exc))
        if not stop_host_relay(host_relay):
            cleanup_errors.append("host relay process remained")
        if sn is not None:
            try:
                sn.stop_emulation()
            except BaseException as exc:
                cleanup_errors.append("StarryNet cleanup: {}: {}".format(
                    type(exc).__name__, exc))
        if emulation_thread is not None:
            emulation_thread.join(timeout=30)
            if emulation_thread.is_alive():
                cleanup_errors.append("StarryNet emulation thread remained alive")
        try:
            inventory_after = replay.docker_inventory()
            summary["resource_inventory_after"] = inventory_after
            summary["cleanup_verified"] = (
                replay.starrynet_resources_cleared(inventory_after)
                and not cleanup_errors)
        except BaseException as exc:
            cleanup_errors.append("inventory after cleanup: {}".format(exc))
            summary["cleanup_verified"] = False
        if cleanup_errors:
            summary["cleanup_errors"] = cleanup_errors
        if summary.get("status") == "aborted":
            summary["passed"] = False
        write_json(summary_path, summary)

        browser_summary = summary.get("browser_summary") or {}
        browser_visits = browser_summary.get("visits") or []
        browser_visit = browser_visits[0] if browser_visits else None
        route_before_emulation = summary.get(
            "route_during_emulation_before") or {}
        route_monitor_summary = summary.get("route_monitor") or {}
        route_ok = bool(route_before_emulation.get("satellite_route")
                        and route_monitor_summary.get(
                            "all_capture_windows_passed"))
        dynamic_ok = summary.get("topology_update_mode") == "dynamic"
        capture_audits = summary.get("capture_pcaps_by_visit", {})
        capture_ok = (len(capture_audits) == args.visits and all(
            item.get("pcap_validation", {}).get("parsed")
            and item.get("pcap_validation", {}).get("bidirectional")
            for item in capture_audits.values()))
        browser_visits = browser_summary.get("visits") or []
        tor_site_ok = (len(browser_visits) == args.visits
                       and all(visit.get("passed") is True for visit in browser_visits))
        trace_result = summary.get("trace_extraction", {})
        trace_items = summary.get("trace_extractions", [])
        summary["acceptance"] = {
            "Tor_browser_check_and_site_HTTP_200": tor_site_ok,
            "dynamic_topology_updates_enabled": dynamic_ok,
            "client_to_GS27_route_uses_satellite_interface": route_ok,
            "satellite_route_sampled_through_each_capture_window": bool(
                route_monitor_summary.get("all_capture_windows_passed")),
            "PCAP_has_bidirectional_proxy_stream": capture_ok,
            "site_capture_window_bracketed": (
                len(trace_items) == args.visits and all(
                    item.get("trace_extraction", {}).get(
                        "window_markers_verified") is True
                    for item in trace_items)),
            "timestamp_direction_trace_extracted": summary.get(
                "site_trace_extracted") is True,
            "zero_over_mtu_packets": (
                len(trace_items) == args.visits and all(
                    item.get("trace_extraction", {}).get(
                        "ip_length_bytes", {}).get("over_interface_mtu_count") == 0
                    for item in trace_items)),
            "resources_cleaned": summary.get("cleanup_verified") is True,
        }
        if route_readiness_context:
            readiness = summary.get("route_readiness_by_visit", {})
            summary["acceptance"]["route_ready_and_active_path_offloads_verified_before_each_capture"] = (
                len(readiness) == args.visits and all(
                    item.get("passed") is True for item in readiness.values()))
        if args.warmup_site_visit:
            site_warmup = browser_summary.get("site_warmup") or {}
            summary["acceptance"]["premeasurement_site_warmup_passed"] = (
                site_warmup.get("passed") is True
                and summary.get("warmup_route_readiness", {}).get(
                    "passed") is True)
        if args.warmup_before_each_visit:
            warmups = browser_summary.get("site_warmups") or []
            warmup_routes = summary.get("warmup_route_readiness_by_visit", {})
            summary["acceptance"]["premeasurement_site_warmup_passed"] = (
                len(warmups) == args.visits
                and all(item.get("passed") is True for item in warmups)
                and len(warmup_routes) == args.visits
                and all(item.get("passed") is True
                        for item in warmup_routes.values()))
        if args.warmup_site_visit or args.warmup_before_each_visit:
            initial_route_readiness = summary.get(
                "route_readiness_before_tor_check") or {}
            initial_route_ack = summary.get(
                "route_readiness_before_tor_check_ack") or {}
            summary["acceptance"]["route_ready_before_initial_tor_check"] = (
                initial_route_readiness.get("passed") is True
                and initial_route_ack.get("ok") is True)
        if matched_single_visit:
            summary["acceptance"]["browser_cache_configuration_matches_protocol"] = (
                browser_summary.get("browser_cache_enabled_between_visits")
                is args.enable_browser_cache_between_visits)
        if args.reuse_circuit_between_visits:
            summary["same_target_tor_circuit_reused_across_visits"] = bool(
                browser_summary.get("same_target_circuit_across_visits"))
            summary["acceptance"]["same_target_tor_circuit_reused_across_visits"] = (
                summary["same_target_tor_circuit_reused_across_visits"])
        if args.capture_peer_veth:
            summary["acceptance"]["peer_veth_pcap_captured"] = bool(
                summary.get("peer_pcap_validation", {}).get("parsed")
                and summary.get("peer_pcap_validation", {}).get("bidirectional")
                and summary.get("peer_trace_extraction", {}).get("exit_code") == 0)
        summary["passed"] = (all(summary["acceptance"].values())
                             and not summary.get("errors"))
        summary["dataset_sample_created"] = False
        summary["scientific_fidelity_verified"] = False
        capture_start = None
        if browser_visits:
            capture_start = (browser_visits[0].get("capture_window", {})
                             .get("start_ack", {}).get(
                                 "tcpdump_ready_monotonic"))
        events = {
            "initial_route_ready": (
                summary.get("route_readiness_before_tor_check_ack") or {}).get(
                    "route_ready_monotonic"),
            "initial_tor_check_started": (
                browser_summary.get("initial_tor_check") or {}).get(
                    "tor_check_started_monotonic"),
            "dynamic_emulation_started": (
                summary.get("dynamic_emulation_start") or {}).get(
                    "started_monotonic"),
            "site_warmup_completed": (
                browser_summary.get("site_warmup") or {}).get(
                    "completed_monotonic"),
            "measured_capture_started": capture_start,
        }
        timing = {"runner_started_monotonic": run_start_monotonic}
        for event_name, event_time in events.items():
            if isinstance(event_time, (int, float)):
                timing[event_name + "_seconds_from_runner_start"] = (
                    event_time - run_start_monotonic)
        finished_monotonic = time.monotonic()
        timing["runner_finished_monotonic"] = finished_monotonic
        timing["runner_wall_clock_seconds"] = (
            finished_monotonic - run_start_monotonic)
        summary["timing"] = timing
        write_json(summary_path, summary)
        if (args.visits == 3 and args.reuse_circuit_between_visits
                and summary.get("trace_extractions")):
            repeat_root = run_dir / "repeatability_runs"
            browser_summary = summary.get("browser_summary", {})
            for item in summary["trace_extractions"]:
                visit_index = item.get("visit_index")
                if visit_index not in (1, 2, 3):
                    continue
                visit = (browser_summary.get("visits", [])[visit_index - 1]
                         if len(browser_summary.get("visits", [])) >= visit_index
                         else {})
                visit_dir = repeat_root / "visit_{}".format(visit_index)
                visit_dir.mkdir(parents=True, exist_ok=True)
                visit_protocol_path = visit_dir / "acquisition_protocol.json"
                write_json(visit_protocol_path, collection_protocol)
                visit_browser = dict(browser_summary)
                visit_browser["visits"] = [visit] if visit else []
                visit_browser["passed"] = bool(visit.get("passed"))
                if collection_protocol.get("protocol_id") in (
                        "starrynet-tor-site-window-v11",
                        "starrynet-tor-site-window-v12",
                        "starrynet-tor-site-window-v13"):
                    warmups = browser_summary.get("site_warmups", [])
                    if collection_protocol.get("protocol_id") == \
                            "starrynet-tor-site-window-v11" and len(warmups) >= visit_index:
                        visit_browser["site_warmup"] = warmups[visit_index - 1]
                    elif collection_protocol.get("protocol_id") == \
                            "starrynet-tor-site-window-v12" or collection_protocol.get(
                                "protocol_id") == "starrynet-tor-site-window-v13":
                        visit_browser["site_warmup"] = browser_summary.get(
                            "site_warmup", {})
                package = json.loads(json.dumps(summary))
                package.update({
                    "run_id": "{}_visit_{}".format(run_id, visit_index),
                    "acquisition_protocol_path": str(visit_protocol_path),
                    "acquisition_protocol": collection_protocol,
                    "browser_summary": visit_browser,
                    "browser_summary_path": item.get("browser_summary_path"),
                    "trace_extraction": item.get("trace_extraction", {}),
                    "site_trace_extracted": (
                        item.get("trace_extraction", {}).get("exit_code") == 0
                        and item.get("trace_extraction", {}).get(
                            "status") == "clean_site_window_candidate"),
                    "pcap_path": item.get("source_pcap"),
                    "pcap_sha256": item.get("pcap_sha256"),
                    "pcap_validation": item.get("pcap_validation", {}),
                })
                if route_readiness_context:
                    package["route_readiness_by_visit"] = {
                        str(visit_index): summary.get(
                            "route_readiness_by_visit", {}).get(
                                str(visit_index), {})}
                if collection_protocol.get("protocol_id") == \
                        "starrynet-tor-site-window-v11" or collection_protocol.get(
                            "protocol_id") in ("starrynet-tor-site-window-v12",
                                                "starrynet-tor-site-window-v13"):
                    warmup_key = (str(visit_index) if collection_protocol.get(
                        "protocol_id") == "starrynet-tor-site-window-v11" else "1")
                    warmup_readiness = summary.get(
                        "warmup_route_readiness_by_visit", {}).get(warmup_key,
                            summary.get("warmup_route_readiness", {}))
                    package["warmup_route_readiness"] = warmup_readiness
                    package["warmup_route_readiness_by_visit"] = {
                        warmup_key: warmup_readiness}
                write_json(visit_dir / "summary.json", package)
            summary["repeatability_run_directories"] = [
                str(repeat_root / "visit_{}".format(index))
                for index in (1, 2, 3)]
            write_json(summary_path, summary)

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 2


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    relay = subparsers.add_parser("relay", help="run a temporary TCP forwarder")
    relay.add_argument("--listen", required=True)
    relay.add_argument("--upstream", required=True)
    relay.add_argument("--ready-file", required=True)

    run = subparsers.add_parser("run", help="capture one to three site visits in StarryNet")
    run.add_argument("--browser-dir", required=True)
    run.add_argument("--expert-bundle", required=True)
    run.add_argument("--bridge-file", required=True)
    run.add_argument("--geckodriver", required=True)
    run.add_argument("--python-site-packages", required=True)
    run.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    run.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE)
    run.add_argument("--expected-helper-image-id",
                     help="require an immutable Docker image ID for frozen protocols")
    run.add_argument("--url", default="https://www.adobe.com/")
    run.add_argument("--protocol-id",
                     help="explicit protocol version for an independently frozen collection")
    run.add_argument("--data-domain",
                     help="dataset namespace recorded in the run summary")
    run.add_argument("--page-id", help="frozen page identifier recorded in the run")
    run.add_argument("--sample-id", help="planned sample identifier recorded in the run")
    run.add_argument("--class-label", default="0",
                     help="explicit class label; defaults to legacy label 0")
    run.add_argument("--source-rank", type=int,
                     help="rank in the frozen source website list")
    run.add_argument("--source-domain",
                     help="domain string from the frozen source website list")
    run.add_argument("--source-list-sha256",
                     help="SHA-256 of the frozen source website list")
    run.add_argument("--pilot-controller",
                     help="collector wrapper path included in protocol provenance")
    run.add_argument("--bootstrap-timeout", type=int, default=300)
    run.add_argument("--page-load-timeout", type=int, default=240,
                     help="maximum seconds to wait for the target page to load")
    run.add_argument("--page-content-timeout", type=int, default=60,
                     help="maximum seconds to wait for visible content and resource-idle")
    run.add_argument("--resource-idle-seconds", type=float, default=4.0)
    run.add_argument("--capture-settle-seconds", type=float, default=2.0)
    run.add_argument("--browser-timeout", type=int, default=900)
    run.add_argument("--freeze-topology", action="store_true",
                     help="keep the initial StarryNet route without dynamic updates")
    run.add_argument("--offload-mode", choices=("observe", "disable_path"),
                     default="observe",
                     help="record path offloads or disable and verify TSO/GSO/GRO/LRO/tx-gso-list on both route directions")
    run.add_argument("--capture-peer-veth", action="store_true",
                     help="capture the same TCP window at the next-hop end of the client veth")
    run.add_argument("--reuse-check-circuit", action="store_true",
                     help="use the circuit verified by the Tor check for the site visit")
    run.add_argument("--visits", type=int, choices=(1, 2, 3), default=1,
                     help="number of sequential fresh-profile site visits in one topology")
    run.add_argument("--reuse-circuit-between-visits", action="store_true",
                     help="avoid NEWNYM between visits and measure same-session repeatability")
    run.add_argument("--reuse-browser-profile-between-visits", action="store_true",
                     help="reuse one writable Tor Browser profile across measured visits; cache policy is controlled separately")
    run.add_argument("--reuse-browser-process-between-visits", action="store_true",
                     help="keep one Tor Browser process open across all visits")
    run.add_argument("--fixed-window-seconds", type=int,
                     help="capture each visit for an exact interval from navigation start (30–300 seconds)")
    run.add_argument("--route-ready-stable-seconds", type=float, default=0.0,
                     help="wait for both satellite routes and the same route devices to remain stable before capture")
    run.add_argument("--route-ready-timeout-seconds", type=int, default=90,
                     help="maximum time to wait for the per-visit route-readiness gate")
    run.add_argument("--warmup-site-visit", action="store_true",
                     help="visit the target once without capture before measured access")
    run.add_argument("--warmup-before-each-visit", action="store_true",
                     help="perform the same uncaptured target warm-up before each measured visit")
    run.add_argument("--reuse-target-page-between-visits", action="store_true",
                     help="one Tor check and warm-up, then same-tab Adobe refresh captures, including a matched-phase single visit")
    run.add_argument("--defer-emulation-until-warmup", action="store_true",
                     help="start dynamic topology updates after the initial Tor check and before the uncaptured site warm-up")
    run.add_argument("--defer-emulation-until-after-warmup", action="store_true",
                     help="V23: finish the uncaptured warm-up before starting the matched dynamic phase")
    run.add_argument("--reaudit-active-route-before-phase-window", action="store_true",
                     help="V25: re-audit offloads on the route active before the five-second matched-phase gate")
    run.add_argument("--pin-tor-path-diagnostic", action="store_true",
                     help="V26 lab diagnostic: fix Tor MiddleNodes/ExitNodes to the first V25 target circuit")
    run.add_argument("--pin-tor-entry-bridge-diagnostic", action="store_true",
                     help="V27 lab diagnostic: use only the configured WebTunnel bridge matching the V26 entry hop")
    run.add_argument("--enable-browser-cache-between-visits", action="store_true",
                     help="retain HTTP cache from the uncaptured warm-up across same-tab refreshes, including matched-phase runs")
    run.add_argument("--warmup-settle-seconds", type=float, default=10.0,
                     help="keep the uncaptured warm-up page open after visible content is ready")
    run.add_argument("--matched-dynamic-phase-seconds", type=float,
                     help="matched-phase protocol: target dynamic-topology phase for the one measured capture")
    run.add_argument("--matched-dynamic-phase-tolerance-seconds", type=float,
                     default=1.5,
                     help="allowed deviation from the requested capture phase")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "relay":
        return relay_main(args)
    return run_pilot(args)


if __name__ == "__main__":
    sys.exit(main())
