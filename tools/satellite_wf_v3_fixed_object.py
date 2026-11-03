#!/usr/bin/env python3
"""Run the V3 static-path GRE/NAT acceptance with a frozen HTTP object."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import p0_smoke
import satellite_wf_v3 as v3
import satellite_wf_v3_route_nat as route_nat

ARTIFACTS = ROOT / "artifacts" / "reports" / "satellite_wf_v3_20261021" / "network_acceptance"
EXPECTED_OBJECT_SHA256 = "c8411639cfd76fea51e53e9fdbc6c8cc13224e48aee23b20312040c10072aeef"
CLIENT_NODE = 26
EGRESS_NODE = 27
CAPTURE_FILTER = "tcp port 18080"
PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
              "https_proxy", "all_proxy")


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def run_command(args, timeout=60, check=True):
    result = subprocess.run([str(value) for value in args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("command failed ({}): {}".format(
            result.returncode, (result.stderr or result.stdout).strip()))
    return result


def docker_exec(container, *args, timeout=60):
    result = run_command(["docker", "exec", str(container), *args], timeout=timeout)
    return result.stdout.strip()


def make_fixed_object():
    seed = b"StarryNet-P1-fixed-HTTP-object-v1:"
    blocks = []
    size = 0
    index = 0
    while size < 1024 * 1024:
        blocks.append(hashlib.sha256(seed + str(index).encode("ascii")).digest())
        size += 32
        index += 1
    return b"".join(blocks)[:1024 * 1024]


def image_id(image):
    return run_command(["docker", "image", "inspect", image, "--format",
                        "{{.Id}}"]).stdout.strip()


def verify_ipv6_sysctls(container_ids):
    if len(container_ids) != 27:
        raise RuntimeError("IPv6 policy verification requires all 27 StarryNet nodes")
    checked = {}
    for node_index, label in ((CLIENT_NODE, "GS26"), (EGRESS_NODE, "GS27")):
        container = container_ids[node_index - 1]
        values = {}
        for setting in ("net.ipv6.conf.all.disable_ipv6",
                        "net.ipv6.conf.default.disable_ipv6"):
            values[setting] = docker_exec(container, "sysctl", "-n", setting)
        if any(value != "1" for value in values.values()):
            raise RuntimeError("IPv6 sysctls were not applied to {}: {}".format(
                label, values))
        if docker_exec(container, "ip", "-6", "route", "show", "table", "main",
                       "default"):
            raise RuntimeError("{} has an IPv6 default-route bypass".format(label))
        checked[label] = values
    return checked


def preflight():
    if os.environ.get("CONDA_DEFAULT_ENV") != "starrynet":
        raise RuntimeError("run this acceptance in the starrynet conda environment")
    if not shutil.which("tshark"):
        raise RuntimeError("host tshark is required to audit the captured HTTP packets")
    config_errors = v3.validate_config(v3.load_json(v3.DEFAULT_CONFIG))
    if config_errors:
        raise RuntimeError("invalid V3 runtime config: " + "; ".join(config_errors))
    _config_path, config_hash = route_nat.validate_runtime_config()
    firewall_packages = route_nat.validate_iptables_packages()
    inventory = p0_smoke.preflight()
    endpoint = v3.load_json(v3.DEFAULT_CONFIG)["network"]["fixed_object_endpoint"]
    if image_id(endpoint["image"]) != image_id("lwsen/starlab_node:1.0"):
        raise RuntimeError("fixed-object endpoint image does not match the local StarryNet node image")
    generated = make_fixed_object()
    actual_hash = hashlib.sha256(generated).hexdigest()
    if len(generated) != endpoint["object_size_bytes"] or actual_hash != EXPECTED_OBJECT_SHA256:
        raise RuntimeError("frozen fixed-object bytes or hash changed")
    return {
        "status": "preflight_passed",
        "runtime_config_sha256": config_hash,
        "conda_environment": os.environ.get("CONDA_DEFAULT_ENV"),
        "tshark_version": run_command(["tshark", "--version"]).stdout.splitlines()[0],
        "starrynet_node_image_id": image_id("lwsen/starlab_node:1.0"),
        "docker_inventory": inventory,
        "fixed_object": {"bytes": len(generated), "sha256": actual_hash},
        "temporary_firewall_packages": firewall_packages,
        "fixed_object_endpoint": endpoint,
    }


def prepare_run(preflight_result, artifact_root=None, scenario_id="static_satellite_path",
                extra_sources=(), duration_seconds=100,
                simulation_start_utc="2022-01-01T01:00:00Z"):
    if not isinstance(duration_seconds, int) or duration_seconds < 100:
        raise ValueError("topology duration must be an integer of at least 100 seconds")
    try:
        datetime.strptime(simulation_start_utc, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        raise ValueError("simulation_start_utc must use YYYY-MM-DDTHH:MM:SSZ")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    artifact_root = Path(artifact_root or ARTIFACTS)
    run = artifact_root / run_id
    run.mkdir(parents=True, exist_ok=False)
    fixture = run / "fixture" / "fixed-object.bin"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(make_fixed_object())
    tooling_dir = run / "tooling"
    tooling_dir.mkdir()
    iptables_deb = tooling_dir / route_nat.DEFAULT_IPTABLES_DEB.name
    libnfnetlink_deb = tooling_dir / route_nat.DEFAULT_LIBNFNETLINK_DEB.name
    shutil.copy2(route_nat.DEFAULT_IPTABLES_DEB, iptables_deb)
    shutil.copy2(route_nat.DEFAULT_LIBNFNETLINK_DEB, libnfnetlink_deb)

    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    config.update({
        "Name": "v3-fixed-object" if scenario_id == "static_satellite_path"
        else "v3-{}".format(scenario_id),
        "# of orbit": 5,
        "# of satellites": 5,
        "GS number": 2,
        "Duration (s)": duration_seconds,
        "Simulation start UTC": simulation_start_utc,
        "update_time (s)": 10,
        "satellite link loss (\"X\"% )": 0,
        "sat-ground loss (\"X\"% )": 0,
        "remote_machine_IP": "",
        "remote_machine_username": "",
        "remote_machine_password": "",
    })
    config_path = run / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    sources = [ROOT / "tools" / "satellite_wf_v3_fixed_object.py",
               ROOT / "tools" / "satellite_wf_v3_route_nat.py",
               ROOT / "tools" / "satellite_wf_v3.py",
               ROOT / "tools" / "p0_smoke.py",
               ROOT / "tools" / "p1_http_smoke.py",
               *[Path(path).resolve() for path in extra_sources],
               *sorted((ROOT / "starrynet").glob("*.py"))]
    shutil.copytree(ROOT / "starrynet", run / "source" / "starrynet",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for path in sources[:5 + len(extra_sources)]:
        shutil.copy2(path, run / "source" / path.name)
    write_json(run / "preflight.json", preflight_result)
    manifest = {
        "protocol_id": "starrynet-browser-tor-route-nat-v3",
        "scenario_id": scenario_id,
        "stage": "fixed_object_transfer",
        "created_utc": now_utc(),
        "run_id": run_id,
        "source_commit": run_command(["git", "-C", ROOT, "rev-parse", "HEAD"]).stdout.strip(),
        "source_sha256": {str(path.relative_to(ROOT)):
                          hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sources},
        "runtime_config_sha256": hashlib.sha256(
            v3.DEFAULT_CONFIG.read_bytes()).hexdigest(),
        "topology_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "python": sys.version,
        "starrynet_node_image_id": preflight_result["starrynet_node_image_id"],
        "topology": {"satellites": 25, "ground_stations": [26, 27],
                     "mode": ("static initial links; dynamic scheduler not started"
                              if scenario_id == "static_satellite_path"
                              else "dynamic scheduler runs for the frozen topology duration"),
                     "duration_seconds": duration_seconds,
                     "simulation_start_utc": simulation_start_utc,
                     "ipv6_policy": "disable_all_and_default_at_container_creation"},
        "fixed_object": {"name": "fixed-object.bin", "bytes": len(fixture.read_bytes()),
                         "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                         "expected_sha256": EXPECTED_OBJECT_SHA256},
        "endpoint": preflight_result["fixed_object_endpoint"],
        "temporary_firewall_packages": preflight_result[
            "temporary_firewall_packages"],
        "capture": {"filter": CAPTURE_FILTER,
                    "gre_outer_filter": "ip proto 47 between route-selected GS26 and GS27 satellite source addresses",
                    "client": "GS26 wf-gre0",
                    "egress": "GS27 B27-default"},
        "proxy_environment_required": "unset",
        "scientific_fidelity_verified": False,
        "training_data_eligible": False,
    }
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
    return run, fixture, config_path, manifest


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def print_phase(message):
    print("[{}] {}".format(datetime.now(timezone.utc).strftime("%H:%M:%S UTC"), message),
          flush=True)


def start_capture(container, label, interface, remote_dir,
                  capture_filter=CAPTURE_FILTER, capture_kind="http"):
    pcap = remote_dir + "/" + label + ".pcap"
    pid = remote_dir + "/" + label + ".pid"
    log = remote_dir + "/" + label + ".tcpdump.log"
    command = ("tcpdump -B 8192 -i {interface} -nn -s 0 -U -w {pcap} '{filter}' "
               "> {log} 2>&1 & echo $! > {pid}; wait $!").format(
                   interface=shlex.quote(interface), pcap=shlex.quote(pcap),
                   filter=capture_filter, log=shlex.quote(log), pid=shlex.quote(pid))
    run_command(["docker", "exec", "-d", container, "sh", "-c", command], timeout=15)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            size = int(docker_exec(container, "sh", "-c",
                                   "wc -c < " + shlex.quote(pcap), timeout=5))
            if size >= 24:
                return {"container": str(container), "label": label,
                        "interface": interface, "pcap": pcap,
                        "pid": pid, "log": log, "capture_kind": capture_kind}
        except (RuntimeError, ValueError, subprocess.CalledProcessError):
            pass
        time.sleep(0.2)
    detail = docker_exec(container, "sh", "-c",
                         "cat " + shlex.quote(log) + " 2>/dev/null || true")
    raise RuntimeError("tcpdump failed to initialize on {}: {}".format(interface, detail))


def stop_capture(capture):
    if capture is None or capture.get("stopped"):
        return
    docker_exec(capture["container"], "sh", "-c",
                "kill -INT \"$(cat {})\" 2>/dev/null || true".format(
                    shlex.quote(capture["pid"])))
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        result = run_command(
            ["docker", "exec", capture["container"], "sh", "-c",
             "kill -0 \"$(cat {})\" 2>/dev/null".format(
                 shlex.quote(capture["pid"]))], timeout=5, check=False)
        if result.returncode != 0:
            time.sleep(0.25)
            size = int(docker_exec(
                capture["container"], "sh", "-c",
                "wc -c < " + shlex.quote(capture["pcap"]), timeout=5))
            if size >= 24:
                capture["stopped"] = True
                return
        time.sleep(0.2)
    raise RuntimeError("tcpdump did not exit and flush {}".format(capture["label"]))


def fetch_object(client_id, endpoint, remote_dir, run, index, expected_hash,
                 max_time_seconds=45):
    remote_file = "{}/download-{}.bin".format(remote_dir, index)
    url = "http://{}:{}/{}".format(endpoint["address"], endpoint["port"],
                                    endpoint["object_name"])
    metrics = "http_code=%{http_code}\\nsize_download=%{size_download}\\ntime_total=%{time_total}\\nremote_ip=%{remote_ip}"
    curl = ("env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY "
            "-u http_proxy -u https_proxy -u all_proxy "
            "curl --noproxy '*' --http1.1 --connect-timeout 5 --max-time {max_time} "
            "-sS -o {file} -w {metrics} {url}").format(
                file=shlex.quote(remote_file), metrics=shlex.quote(metrics),
                url=shlex.quote(url), max_time=int(max_time_seconds))
    started_utc = now_utc()
    started = time.monotonic()
    result = run_command(["docker", "exec", client_id, "sh", "-lc", curl],
                         timeout=int(max_time_seconds) + 10,
                         check=False)
    duration = time.monotonic() - started
    visit = {"index": index, "started_utc": started_utc,
             "duration_seconds": round(duration, 6), "curl_exit_code": result.returncode,
             "curl_stderr": result.stderr.strip()}
    if result.returncode:
        return visit
    metrics_found = dict(re.findall(
        r"^(http_code|size_download|time_total|remote_ip)=(.*)$",
        result.stdout.strip(), re.MULTILINE))
    remote_hash_info = docker_exec(client_id, "sh", "-lc",
        "sha256sum {} && wc -c < {}".format(shlex.quote(remote_file),
                                             shlex.quote(remote_file)))
    remote_fields = remote_hash_info.splitlines()
    if len(remote_fields) < 2:
        raise RuntimeError("could not read downloaded object metadata")
    remote_hash = remote_fields[0].split()[0]
    remote_size = int(remote_fields[1].strip())
    local_file = run / "downloads" / "download-{}.bin".format(index)
    local_file.parent.mkdir(parents=True, exist_ok=True)
    run_command(["docker", "cp", "{}:{}".format(client_id, remote_file), local_file],
                timeout=60)
    local_hash = hashlib.sha256(local_file.read_bytes()).hexdigest()
    visit.update({"curl_metrics": metrics_found, "remote_sha256": remote_hash,
                  "local_sha256": local_hash, "bytes": remote_size,
                  "object_matches_expected": (
                      metrics_found.get("http_code") == "200"
                      and metrics_found.get("size_download") == str(endpoint["object_size_bytes"])
                      and remote_size == endpoint["object_size_bytes"]
                      and remote_hash == expected_hash and local_hash == expected_hash)})
    return visit


def tshark_fields(pcap, *fields, display_filter=None):
    args = ["tshark", "-r", str(pcap), "-d", "tcp.port==18080,http"]
    if display_filter:
        args += ["-Y", display_filter]
    args += ["-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
    for field in fields:
        args += ["-e", field]
    return run_command(args, timeout=60).stdout.splitlines()


def _tcpdump_counts(log):
    patterns = {
        "captured": r"(\d+) packets captured",
        "received_by_filter": r"(\d+) packets received by filter",
        "dropped_by_kernel": r"(\d+) packets dropped by kernel",
    }
    counts = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, log)
        counts[key] = int(match.group(1)) if match else None
    return counts


def analyze_capture(capture, run, expected_ips, expected_request_source,
                    expected_request_destination):
    local_pcap = run / "captures" / (capture["label"] + ".pcap")
    local_pcap.parent.mkdir(parents=True, exist_ok=True)
    run_command(["docker", "cp", "{}:{}".format(capture["container"],
                                                    capture["pcap"]), local_pcap],
                timeout=60)
    tcpdump_log = docker_exec(capture["container"], "sh", "-lc",
                              "cat " + shlex.quote(capture["log"]))
    (run / "captures" / (capture["label"] + ".tcpdump.log")).write_text(
        tcpdump_log + "\n", encoding="utf-8")
    tcpdump_counts = _tcpdump_counts(tcpdump_log)
    request_rows = tshark_fields(local_pcap, "ip.src", "ip.dst",
                                 "http.request.method", "http.request.uri",
                                 display_filter="http.request.method == GET")
    response_rows = tshark_fields(local_pcap, "ip.src", "ip.dst",
                                  "http.response.code",
                                  display_filter="http.response.code == 200")
    flow_rows = tshark_fields(local_pcap, "ip.src", "ip.dst",
                              display_filter="tcp.port == 18080")
    requests = [row.split("|") for row in request_rows
                if len(row.split("|")) >= 4
                and row.split("|")[2] == "GET"
                and row.split("|")[3] == "/fixed-object.bin"]
    request_sources = [row[0] for row in requests]
    request_destinations = [row[1] for row in requests]
    directions = set()
    for row in flow_rows:
        fields = row.split("|")
        if len(fields) >= 2:
            directions.update(fields[:2])
    return {
        "label": capture["label"],
        "interface": capture["interface"],
        "pcap": str(local_pcap),
        "pcap_bytes": local_pcap.stat().st_size,
        "pcap_sha256": hashlib.sha256(local_pcap.read_bytes()).hexdigest(),
        "tcp_packet_count": len(flow_rows),
        "fixed_object_get_count": len(requests),
        "fixed_object_request_sources": sorted(set(request_sources)),
        "fixed_object_request_destinations": sorted(set(request_destinations)),
        "expected_request_source_seen": expected_request_source in request_sources,
        "expected_request_destination_seen": (
            expected_request_destination in request_destinations),
        "http_200_count": len(response_rows),
        "observed_ip_addresses": sorted(directions),
        "expected_endpoint_ips_present": set(expected_ips).issubset(directions),
        "tcpdump_counters": tcpdump_counts,
        "kernel_dropped_packets": tcpdump_counts.get("dropped_by_kernel"),
        "zero_kernel_drops": tcpdump_counts.get("dropped_by_kernel") == 0,
        "capture_counters_consistent": (
            tcpdump_counts.get("captured") is not None
            and tcpdump_counts.get("received_by_filter") is not None
            and tcpdump_counts["captured"] == tcpdump_counts["received_by_filter"]),
    }


def analyze_outer_capture(capture, run):
    local_pcap = run / "captures" / (capture["label"] + ".pcap")
    local_pcap.parent.mkdir(parents=True, exist_ok=True)
    run_command(["docker", "cp", "{}:{}".format(capture["container"],
                                                    capture["pcap"]), local_pcap],
                timeout=60)
    tcpdump_log = docker_exec(capture["container"], "sh", "-lc",
                              "cat " + shlex.quote(capture["log"]))
    (run / "captures" / (capture["label"] + ".tcpdump.log")).write_text(
        tcpdump_log + "\n", encoding="utf-8")
    rows = tshark_fields(local_pcap, "ip.src", "ip.dst", "ip.proto", "ip.ttl",
                         display_filter="ip.proto == 47")
    packets = [row.split("|") for row in rows if row.strip()]
    tcpdump_counts = _tcpdump_counts(tcpdump_log)
    endpoint_pairs = sorted(set((row[0], row[1]) for row in packets
                                if len(row) > 1))
    return {
        "label": capture["label"],
        "capture_kind": "gre_outer",
        "interface": capture["interface"],
        "pcap": str(local_pcap),
        "pcap_bytes": local_pcap.stat().st_size,
        "pcap_sha256": hashlib.sha256(local_pcap.read_bytes()).hexdigest(),
        "gre_outer_packet_count": len(packets),
        "gre_outer_sources": sorted(set(row[0] for row in packets if len(row) > 0)),
        "gre_outer_destinations": sorted(set(row[1] for row in packets if len(row) > 1)),
        "gre_outer_endpoint_pairs": [list(pair) for pair in endpoint_pairs],
        "tcpdump_counters": tcpdump_counts,
        "zero_kernel_drops": tcpdump_counts.get("dropped_by_kernel") == 0,
        "kernel_dropped_packets": tcpdump_counts.get("dropped_by_kernel"),
        "capture_counters_consistent": (
            tcpdump_counts.get("captured") is not None
            and tcpdump_counts.get("received_by_filter") is not None
            and tcpdump_counts["captured"] == tcpdump_counts["received_by_filter"]),
    }


def wait_for_inventory(before, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = p0_smoke.inventory()
        if all(set(last[key]) == set(before[key]) for key in before):
            return last
        time.sleep(2)
    raise RuntimeError("StarryNet cleanup did not restore Docker inventory: {}".format(last))


def write_report(run, summary):
    lines = [
        "# V3 GRE/NAT 固定对象网络验收",
        "",
        "- Run ID: `{}`".format(summary.get("run_id")),
        "- 状态: `{}`".format(summary.get("status")),
        "- 场景: `static_satellite_path`，只建立初始拓扑，不启动动态更新调度器",
        "- 固定对象: {} 字节，SHA-256 `{}`".format(
            summary.get("fixed_object", {}).get("bytes"),
            summary.get("fixed_object", {}).get("sha256")),
        "- 工程验收通过: `{}`".format(summary.get("engineering_network_acceptance_passed")),
        "- 清理恢复通过: `{}`".format(summary.get("cleanup_verified")),
        "- 科学保真或真实 Starlink 验证: `false`",
        "- 训练数据准入: `false`",
        "- 临时防火墙工具包: Ubuntu Xenial `iptables`，验收清理时从节点命名空间卸载",
        "",
        "## 固定对象传输",
        "",
        "- Endpoint: `{}` via `{}`".format(
            summary.get("endpoint", {}).get("address"),
            summary.get("endpoint", {}).get("interface")),
    ]
    gre_outer = summary.get("gre_outer_endpoints", {})
    if gre_outer:
        lines.append("- GRE outer endpoints: GS26 `{}` to GS27 `{}` (route-selected satellite interface addresses)".format(
            gre_outer.get("client"), gre_outer.get("egress")))
    for visit in summary.get("visits", []):
        lines.append("- GET {}: HTTP {}, {} bytes, SHA-256 `{}`, 通过 `{}`".format(
            visit.get("index"), visit.get("curl_metrics", {}).get("http_code"),
            visit.get("bytes"), visit.get("local_sha256"),
            visit.get("object_matches_expected")))
    icmp = summary.get("diagnostics", {}).get("fixed_endpoint_icmp_probe")
    if icmp is not None:
        lines += ["", "## 诊断探针", "",
                  "- ICMP ping passed: `{}` (informational; HTTP transfer is the acceptance gate)".format(
                      icmp.get("passed"))]
    lines += ["", "## 网络与抓包门槛", ""]
    for key, value in summary.get("checks", {}).items():
        lines.append("- {}: `{}`".format(key, value))
    for capture in summary.get("captures", []):
        if capture.get("capture_kind") == "gre_outer":
            lines.append("- `{}` / `{}`: {} GRE outer packets, tcpdump counters {}, sources {}, destinations {}, kernel drops {}, SHA-256 `{}`".format(
                capture.get("label"), capture.get("interface"),
                capture.get("gre_outer_packet_count"), capture.get("tcpdump_counters"),
                capture.get("gre_outer_sources"),
                capture.get("gre_outer_destinations"),
                capture.get("kernel_dropped_packets"), capture.get("pcap_sha256")))
        else:
            lines.append("- `{}` / `{}`: {} packets, GET {}, HTTP 200 {}, tcpdump counters {}, kernel drops {}, SHA-256 `{}`".format(
                capture.get("label"), capture.get("interface"),
                capture.get("tcp_packet_count"), capture.get("fixed_object_get_count"),
                capture.get("http_200_count"), capture.get("tcpdump_counters"),
                capture.get("kernel_dropped_packets"),
                capture.get("pcap_sha256")))
    for error in summary.get("capture_analysis_errors", []):
        lines.append("- capture diagnostic: {}".format(error))
    if summary.get("errors"):
        lines += ["", "## 错误", ""]
        lines.extend("- {}".format(item) for item in summary["errors"])
    (run / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_acceptance():
    preflight_result = preflight()
    before = preflight_result["docker_inventory"]
    run, fixture, topology_config, manifest = prepare_run(preflight_result)
    endpoint = manifest["endpoint"]
    run_id = manifest["run_id"]
    endpoint_ip = endpoint["address"]
    http_port = endpoint["port"]
    egress_server_name = "wf-v3-object-{}".format(
        datetime.now(timezone.utc).strftime("%H%M%S%f"))
    remote_dir = "/tmp/wf-v3-object-{}".format(run_id.lower().replace("_", "-"))
    started_monotonic = time.monotonic()
    summary = {"run_id": run_id, "started_utc": now_utc(), "status": "running",
               "engineering_network_acceptance_passed": False,
               "scientific_fidelity_verified": False,
               "training_data_eligible": False,
               "cleanup_verified": False,
               "runtime_config_sha256": manifest["runtime_config_sha256"],
               "fixed_object": manifest["fixed_object"],
               "endpoint": endpoint, "visits": [], "captures": [], "checks": {}}
    write_json(run / "summary.json", summary)
    print_phase("artifacts prepared at {}".format(run))
    print_phase("preflight passed; creating one isolated 25-satellite, 2-GS topology")

    from starrynet.sn_synchronizer import StarryNet
    from starrynet.sn_thread import WORKER_ERRORS
    profile = v3.starrynet_link_profile(
        v3.load_json(v3.DEFAULT_CONFIG), "engineering_baseline")
    sn = None
    client_id = None
    egress_id = None
    helper_created = False
    route_state = run / "route_nat_state.json"
    captures = []
    allow_topology_cleanup = True
    failure = None
    try:
        sn = StarryNet(str(topology_config), p0_smoke.GS, 1, [[1, 27]],
                       local=True, argv=[], link_profile=profile)
        sn.container_sysctls = [
            "net.ipv6.conf.all.disable_ipv6=1",
            "net.ipv6.conf.default.disable_ipv6=1"]
        WORKER_ERRORS.clear()
        sn.create_nodes()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet node worker failed: {}".format(WORKER_ERRORS))
        summary["ipv6_sysctls"] = verify_ipv6_sysctls(sn.container_id_list)
        write_json(run / "summary.json", summary)
        sn.create_links()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet link worker failed: {}".format(WORKER_ERRORS))
        if len(sn.container_id_list) != 27:
            raise RuntimeError("expected 27 StarryNet node containers")
        client_id = sn.container_id_list[CLIENT_NODE - 1]
        egress_id = sn.container_id_list[EGRESS_NODE - 1]
        sys.path.insert(0, str(ROOT / "tools"))
        import p1_http_smoke
        p1_http_smoke.disable_management_interfaces(sn)
        sn.run_routing_deamon()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet routing worker failed: {}".format(WORKER_ERRORS))
        summary["starrynet_containers"] = {"GS26": client_id, "GS27": egress_id}
        summary["topology_mode"] = "static; StarryNet dynamic scheduler not started"
        write_json(run / "summary.json", summary)
        print_phase("routing is active; provisioning the frozen object on GS_27/B27-default")

        run_command(["docker", "run", "-d", "--name", egress_server_name,
                     "--network", endpoint["network"], "--ip", endpoint_ip,
                     "--label", "starrynet.v3.acceptance={}".format(run_id),
                     "--entrypoint", "sh", endpoint["image"],
                     "-lc", "mkdir -p /tmp/v3-object && sleep 86400"],
                    timeout=45)
        helper_created = True
        run_command(["docker", "cp", fixture,
                     "{}:/tmp/v3-object/{}".format(egress_server_name,
                                                    endpoint["object_name"])], timeout=60)
        server_command = ("cd /tmp/v3-object && exec python3 -m http.server "
                          "--bind 0.0.0.0 {}".format(http_port))
        run_command(["docker", "exec", "-d", egress_server_name, "sh", "-lc",
                     server_command], timeout=20)
        deadline = time.monotonic() + 15
        ready = False
        last_probe = None
        while time.monotonic() < deadline:
            probe = run_command(["docker", "exec", egress_server_name, "curl",
                                 "--noproxy", "*", "-sS", "-I", "--connect-timeout",
                                 "1", "--max-time", "2", "-o", "/dev/null", "-w",
                                 "%{http_code}",
                                 "http://127.0.0.1:{}/{}".format(http_port,
                                     endpoint["object_name"])],
                                timeout=5, check=False)
            last_probe = {"returncode": probe.returncode,
                          "stdout": probe.stdout.strip(),
                          "stderr": probe.stderr.strip()}
            if probe.returncode == 0 and probe.stdout.strip() == "200":
                ready = True
                break
            time.sleep(0.25)
        write_json(run / "object_server_probe.json",
                   {"ready": ready, "last_probe": last_probe})
        if not ready:
            diagnostics = {}
            for label, command in (("python", ["python3", "--version"]),
                                   ("processes", ["sh", "-lc", "ps -ef"]),
                                   ("server_directory", ["sh", "-lc",
                                                          "ls -l /tmp/v3-object"])):
                result = run_command(["docker", "exec", egress_server_name] + command,
                                     timeout=8, check=False)
                diagnostics[label] = {"returncode": result.returncode,
                                      "stdout": result.stdout.strip(),
                                      "stderr": result.stderr.strip()}
            write_json(run / "object_server_diagnostics.json", diagnostics)
            raise RuntimeError("fixed-object endpoint did not become ready; see object_server_probe.json and object_server_diagnostics.json")

        print_phase("installing and verifying the reversible GRE/NAT path")
        installed = route_nat.install(
            client_id, egress_id, route_state,
            iptables_deb=run / "tooling" / route_nat.DEFAULT_IPTABLES_DEB.name,
            libnfnetlink_deb=run / "tooling" /
            route_nat.DEFAULT_LIBNFNETLINK_DEB.name)
        outer_endpoints = installed["gre_outer_endpoints"]
        summary["gre_outer_endpoints"] = outer_endpoints
        write_json(run / "route_nat_install.json", installed)
        verify = run_command([sys.executable, ROOT / "tools" / "satellite_wf_v3_route_nat.py",
                              "verify", "--state", route_state], timeout=60)
        verification = json.loads(verify.stdout)
        write_json(run / "route_nat_verify.json", verification)
        summary["route_nat_verification"] = verification
        if verification.get("status") != "passed":
            raise RuntimeError("GRE/NAT route verification failed")

        client_env = docker_exec(client_id, "sh", "-lc", "env")
        present_proxy_keys = sorted(set(
            line.split("=", 1)[0] for line in client_env.splitlines()
            if "=" in line and line.split("=", 1)[0] in PROXY_KEYS))
        summary["checks"]["proxy_environment_unset"] = not present_proxy_keys
        summary["proxy_environment_keys_present"] = present_proxy_keys
        if present_proxy_keys:
            raise RuntimeError("proxy environment variables are set in the GS26 client")

        print_phase("starting GRE and egress captures; fetching the same 1 MiB object three times")
        run_command(["docker", "exec", client_id, "mkdir", "-p", remote_dir])
        run_command(["docker", "exec", egress_id, "mkdir", "-p", remote_dir])
        captures.append(start_capture(client_id, "gs26-wf-gre0", "wf-gre0", remote_dir))
        captures.append(start_capture(egress_id, "gs27-wf-gre0", "wf-gre0", remote_dir))
        captures.append(start_capture(egress_id, "gs27-b27-default", "B27-default", remote_dir))
        route_checks = installed["route_checks"]
        outer_filter = "ip proto 47 and host {} and host {}".format(
            outer_endpoints["client"], outer_endpoints["egress"])
        captures.append(start_capture(
            client_id, "gs26-gre-outer", route_checks[
                "client_gre_outer_route_after_install"]["dev"], remote_dir,
            capture_filter=outer_filter, capture_kind="gre_outer"))
        captures.append(start_capture(
            egress_id, "gs27-gre-outer", route_checks[
                "egress_gre_outer_route_after_install"]["dev"], remote_dir,
            capture_filter=outer_filter, capture_kind="gre_outer"))
        ping = run_command(["docker", "exec", client_id, "ping", "-I", "10.255.253.1",
                            "-c", "4", "-W", "3", endpoint_ip], timeout=20, check=False)
        summary["diagnostics"] = {"fixed_endpoint_icmp_probe": {
            "passed": ping.returncode == 0,
            "exit_code": ping.returncode,
            "output": ping.stdout.strip(),
            "stderr": ping.stderr.strip()}}

        for index in range(1, 4):
            visit = fetch_object(client_id, endpoint, remote_dir, run, index,
                                 EXPECTED_OBJECT_SHA256)
            summary["visits"].append(visit)
            write_json(run / "summary.json", summary)
            if not visit.get("object_matches_expected"):
                raise RuntimeError("fixed-object transfer {} failed validation".format(index))

        time.sleep(1.0)
        for capture in captures:
            stop_capture(capture)
        for capture in captures:
            if capture.get("capture_kind") == "gre_outer":
                summary["captures"].append(analyze_outer_capture(capture, run))
                continue
            if capture["label"] == "gs27-b27-default":
                expected_ips = ["9.27.27.10", endpoint_ip]
                expected_request_source = "9.27.27.10"
            else:
                expected_ips = ["10.255.253.1", endpoint_ip]
                expected_request_source = "10.255.253.1"
            summary["captures"].append(analyze_capture(
                capture, run, expected_ips, expected_request_source, endpoint_ip))
        for capture in summary["captures"]:
            if capture.get("capture_kind") == "gre_outer":
                continue
            if (capture["fixed_object_get_count"] != 3
                    or capture["http_200_count"] != 3
                    or not capture["expected_request_source_seen"]
                    or not capture["expected_request_destination_seen"]
                    or not capture["expected_endpoint_ips_present"]
                    or not capture["zero_kernel_drops"]):
                raise RuntimeError("capture gate failed for {}".format(capture["label"]))
        outer_captures = {capture["label"]: capture
                          for capture in summary["captures"]
                          if capture.get("capture_kind") == "gre_outer"}
        client_outer = outer_captures["gs26-gre-outer"]
        egress_outer = outer_captures["gs27-gre-outer"]
        summary["checks"].update({
            "route_nat_checks_passed": verification.get("status") == "passed",
            "three_fixed_object_transfers_passed": len(summary["visits"]) == 3 and all(
                visit.get("object_matches_expected") for visit in summary["visits"]),
            "client_gre_capture_passed": summary["captures"][0]["expected_endpoint_ips_present"],
            "egress_gre_capture_passed": summary["captures"][1]["expected_endpoint_ips_present"],
            "egress_nat_capture_passed": (
                summary["captures"][2]["expected_endpoint_ips_present"]
                and summary["captures"][2]["expected_request_source_seen"]),
            "both_kernel_capture_drop_counts_zero": all(
                capture["zero_kernel_drops"] for capture in summary["captures"]),
            "gre_outer_leaves_client_satellite_interface": (
                client_outer["gre_outer_packet_count"] > 0
                and outer_endpoints["client"] in client_outer["gre_outer_sources"]
                and outer_endpoints["egress"] in client_outer["gre_outer_destinations"]),
            "gre_outer_reaches_egress_satellite_interface": (
                egress_outer["gre_outer_packet_count"] > 0
                and outer_endpoints["client"] in egress_outer["gre_outer_sources"]
                and outer_endpoints["egress"] in egress_outer["gre_outer_destinations"]),
        })
        summary["engineering_network_acceptance_passed"] = all(summary["checks"].values())
        if not summary["engineering_network_acceptance_passed"]:
            raise RuntimeError("one or more V3 fixed-object acceptance gates failed")
        print_phase("fixed-object and capture gates passed")
    except BaseException as exc:
        failure = exc
        summary["errors"] = [str(exc)]
        summary["traceback"] = traceback.format_exc()
        print_phase("acceptance stopped: {}".format(exc))
    finally:
        if any(not capture.get("stopped") for capture in captures):
            time.sleep(1.0)
        for capture in captures:
            try:
                stop_capture(capture)
            except Exception as exc:
                summary.setdefault("errors", []).append("stop capture: {}".format(exc))
        analyzed_labels = {item.get("label") for item in summary.get("captures", [])}
        for capture in captures:
            if capture.get("label") in analyzed_labels:
                continue
            try:
                if capture.get("capture_kind") == "gre_outer":
                    summary.setdefault("captures", []).append(
                        analyze_outer_capture(capture, run))
                    continue
                if capture["label"] == "gs27-b27-default":
                    expected_ips = ["9.27.27.10", endpoint_ip]
                    expected_request_source = "9.27.27.10"
                else:
                    expected_ips = ["10.255.253.1", endpoint_ip]
                    expected_request_source = "10.255.253.1"
                summary.setdefault("captures", []).append(analyze_capture(
                    capture, run, expected_ips, expected_request_source, endpoint_ip))
            except Exception as exc:
                summary.setdefault("capture_analysis_errors", []).append(
                    "{}: {}".format(capture.get("label"), exc))
        if helper_created:
            removed = run_command(["docker", "rm", "-f", egress_server_name],
                                  timeout=30, check=False)
            summary["object_server_removed"] = removed.returncode == 0
            if removed.returncode:
                allow_topology_cleanup = False
                summary.setdefault("errors", []).append(
                    "remove fixed-object server: {}".format(removed.stderr.strip()))
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
                summary.setdefault("errors", []).append("route/NAT cleanup: {}".format(exc))
        if sn is not None and allow_topology_cleanup:
            try:
                print_phase("removing the isolated StarryNet topology")
                sn.stop_emulation()
                after = wait_for_inventory(before)
                summary["docker_inventory_restored"] = True
                summary["docker_inventory_after"] = after
                route_restored = summary.get("route_nat_restored", not route_state.exists())
                server_removed = summary.get("object_server_removed", True)
                summary["cleanup_verified"] = bool(route_restored and server_removed)
            except Exception as exc:
                summary["cleanup_verified"] = False
                summary.setdefault("errors", []).append("StarryNet cleanup: {}".format(exc))
        elif sn is None:
            try:
                after = p0_smoke.inventory()
                summary["docker_inventory_restored"] = all(
                    set(after[key]) == set(before[key]) for key in before)
            except Exception as exc:
                summary.setdefault("errors", []).append("inventory check: {}".format(exc))
        summary["status"] = (
            "passed" if (failure is None and not summary.get("errors")
                         and summary.get("engineering_network_acceptance_passed")
                         and summary.get("cleanup_verified")) else "failed")
        summary["completed_utc"] = now_utc()
        summary["elapsed_seconds"] = round(time.monotonic() - started_monotonic, 3)
        write_json(run / "summary.json", summary)
        write_report(run, summary)
        print_phase("{}; report: {}".format(summary["status"], run / "REPORT.md"))
    return 0 if summary["status"] == "passed" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("plan", help="print the frozen static-path acceptance plan")
    sub.add_parser("preflight", help="check the host without changing Docker resources")
    run_parser = sub.add_parser("run", help="run the temporary GRE/NAT acceptance")
    run_parser.add_argument("--apply", action="store_true",
                            help="acknowledge temporary topology and namespace changes")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("a command is required: plan, preflight, or run")
    if args.command == "plan":
        config = v3.load_json(v3.DEFAULT_CONFIG)
        print(json.dumps({"scenario_id": "static_satellite_path",
                          "endpoint": config["network"]["fixed_object_endpoint"],
                          "object_bytes": 1048576,
                          "object_sha256": EXPECTED_OBJECT_SHA256,
                          "transfers": 3,
                          "capture_interfaces": ["GS26:wf-gre0", "GS27:wf-gre0",
                                                 "GS27:B27-default"],
                          "scheduler": "not started; topology remains static",
                          "scientific_fidelity_verified": False}, indent=2))
        return 0
    if args.command == "preflight":
        print(json.dumps(preflight(), indent=2, sort_keys=True))
        return 0
    if not args.apply:
        parser.error("run requires --apply")
    lock = (ROOT / ".p0.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("another local StarryNet experiment is running")
    return run_acceptance()


if __name__ == "__main__":
    sys.exit(main())
