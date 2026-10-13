#!/usr/bin/env python3
"""Run one controlled Tor circuit over the StarryNet GS26 satellite access path."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from p0_smoke import GS, command, inventory, preflight as p0_preflight, topology_report
from p1_http_smoke import disable_management_interfaces, tshark_output

TOR_IMAGE = "constellation-p2-tor:0.4.9.11-chutney"
BASE_TOR_IMAGE = "constellation-p2-tor:0.4.9.11"
P2_OWNER_LABEL = "com.starrynet.p2.owner"
P2_OWNER_VALUE = "p2-tor-smoke"
CLIENT_NODE = 26
GATEWAY_NODE = 27
GUARD_IP = "9.27.27.11"
RELAY_IPS = ["9.27.27.{0}".format(last) for last in range(11, 17)]
SERVER_PORT = 18080
OBJECT_NAME = "fixed-page.html"
OBJECT_BYTES = (b"<!doctype html>\n"
                b"<html><head><meta charset=\"utf-8\"><title>StarryNet P2</title></head>\n"
                b"<body><h1>StarryNet controlled Tor smoke page</h1>\n"
                b"<p>fixture-version=p2-v1</p></body></html>\n")
REMOTE_ROOT = "/p2"
REMOTE_CLIENT_ROOT = REMOTE_ROOT + "/client"
REMOTE_SOURCE_ROOT = "/opt/p2-source"


def docker(*args, timeout=60, check=True):
    result = subprocess.run(["docker"] + [str(arg) for arg in args],
                            text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("docker {0} failed: {1}".format(
            " ".join(str(arg) for arg in args), result.stderr.strip()))
    return result


def docker_stream(*args, timeout):
    result = subprocess.run(["docker"] + [str(arg) for arg in args],
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError("docker {0} failed with exit {1}".format(
            " ".join(str(arg) for arg in args), result.returncode))


def docker_exec(cid, *args, timeout=60, check=True):
    result = docker("exec", cid, *args, timeout=timeout, check=check)
    if check:
        return result.stdout.strip()
    return result


def docker_exec_stdin(cid, data, *args, timeout=60):
    result = subprocess.run(["docker", "exec", "-i", cid]
                            + [str(arg) for arg in args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError("docker exec stdin failed: "
                           + result.stderr.decode(errors="replace").strip())
    return result.stdout.decode(errors="replace").strip()


def docker_output_bytes(cid, *args, timeout=120):
    result = subprocess.run(["docker", "exec", cid]
                            + [str(arg) for arg in args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError("docker exec output failed: "
                           + result.stderr.decode(errors="replace").strip())
    return result.stdout


def capture_inventory():
    return inventory()


def docker_network_details():
    ids = command("docker", "network", "ls", "-q").split()
    return json.loads(command("docker", "network", "inspect", *ids)) if ids else []


def choose_p2_subnet(details):
    occupied = []
    for detail in details:
        for config in detail.get("IPAM", {}).get("Config") or []:
            raw = config.get("Subnet")
            if raw:
                occupied.append(ipaddress.ip_network(raw, strict=False))
    for third in range(240, 256):
        candidate = ipaddress.ip_network("172.29.{0}.0/24".format(third))
        if not any(candidate.overlaps(network) for network in occupied):
            return candidate
    raise RuntimeError("No free subnet in the reserved P2 range 172.29.240.0/20")


def check_image():
    image_id = command("docker", "image", "inspect", TOR_IMAGE,
                       "--format", "{{.Id}}")
    inspect = docker("run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sh",
        TOR_IMAGE, "-c", "tor --version; python3 -c 'import stem; print(\"Stem\", stem.__version__)'; tcpdump --version | head -n 1; ip -Version; iptables --version; test -x /opt/chutney/chutney; cat /etc/p2-tor-packages.txt; sha256sum -c /etc/p2-chutney-source.sha256 >/dev/null",
        timeout=90)
    if inspect.returncode:
        raise RuntimeError("P2 Tor image capability check failed: "
                           + inspect.stderr.strip())
    return {"image": TOR_IMAGE, "image_id": image_id,
            "capability_check": inspect.stdout.strip()}


def preflight():
    before = p0_preflight()
    if not shutil.which("tshark"):
        raise RuntimeError("Host tshark is required to validate both PCAP files")
    existing = docker("ps", "-aq", "--filter",
                       "label={0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE)).stdout.split()
    if existing:
        raise RuntimeError("Existing P2 containers found: " + str(existing))
    existing_networks = docker("network", "ls", "-q", "--filter",
        "label={0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE)).stdout.split()
    if existing_networks:
        raise RuntimeError("Existing P2 networks found: " + str(existing_networks))
    image = check_image()
    subnet = choose_p2_subnet(docker_network_details())
    return {"preflight_passed": True, "inventory": before,
            "tor_image": image, "private_subnet": str(subnet),
            "satellite_gateway_endpoint": "GS27/GS_27 network, " + GUARD_IP,
            "client_endpoint": "GS26, with the P1 proven B26-eth* route"}


def topology_handover_seconds(path, ground_station_index=26):
    import numpy as np
    matrices = [np.loadtxt(p, delimiter=",") for p in sorted(
        path.glob("delay/*.txt"), key=lambda p: int(p.stem))]
    attached = [tuple(np.flatnonzero(matrix[ground_station_index, :25]))
                for matrix in matrices]
    return [second for second, (previous, current) in enumerate(
        zip(attached, attached[1:]), start=2) if previous != current]


def make_fixture(run):
    fixture = run / "fixture" / OBJECT_NAME
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_bytes(OBJECT_BYTES)
    return fixture


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def freeze_source(run):
    source_files = [*sorted((ROOT / "starrynet").glob("*.py")),
                    ROOT / "tools" / "p0_smoke.py",
                    ROOT / "tools" / "p1_http_smoke.py",
                    Path(__file__).resolve(),
                    *sorted((ROOT / "tools" / "p2_tor").rglob("*"))]
    hashes = {}
    for source in source_files:
        if not source.is_file() or "__pycache__" in source.parts or source.suffix == ".pyc":
            continue
        hashes[str(source.relative_to(ROOT))] = hashlib.sha256(
            source.read_bytes()).hexdigest()
    shutil.copytree(ROOT / "starrynet", run / "source" / "starrynet",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (run / "source" / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "tools" / "p0_smoke.py", run / "source" / "tools" / "p0_smoke.py")
    shutil.copy2(ROOT / "tools" / "p1_http_smoke.py", run / "source" / "tools" / "p1_http_smoke.py")
    shutil.copy2(Path(__file__).resolve(), run / "source" / "tools" / "p2_tor_smoke.py")
    shutil.copytree(ROOT / "tools" / "p2_tor",
                    run / "source" / "tools" / "p2_tor",
                    ignore=shutil.ignore_patterns("__pycache__"))
    config = json.loads((ROOT / "config.json").read_text())
    config.update({"Name": "p2-tor", "# of orbit": 5,
                   "# of satellites": 5, "GS number": 2,
                   "Duration (s)": 100, "update_time (s)": 10,
                   "remote_machine_IP": "", "remote_machine_username": "",
                   "remote_machine_password": ""})
    (run / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    return hashes


def load_frozen_helpers(run):
    source_tools = run / "source" / "tools"
    p0_spec = importlib.util.spec_from_file_location(
        "p0_smoke_frozen", source_tools / "p0_smoke.py")
    frozen_p0 = importlib.util.module_from_spec(p0_spec)
    p0_spec.loader.exec_module(frozen_p0)
    sys.modules["p0_smoke"] = frozen_p0
    p1_spec = importlib.util.spec_from_file_location(
        "p1_http_smoke_frozen", source_tools / "p1_http_smoke.py")
    frozen_p1 = importlib.util.module_from_spec(p1_spec)
    p1_spec.loader.exec_module(frozen_p1)
    globals()["GS"] = frozen_p0.GS
    globals()["command"] = frozen_p0.command
    globals()["inventory"] = frozen_p0.inventory
    globals()["topology_report"] = frozen_p0.topology_report
    globals()["disable_management_interfaces"] = frozen_p1.disable_management_interfaces
    globals()["tshark_output"] = frozen_p1.tshark_output


def current_route(cid, target):
    route = docker_exec(cid, "ip", "route", "get", target)
    if not re.search(r"\bdev B26-eth\d+\b", route):
        raise RuntimeError("GS26 traffic to the Guard is not routed over a "
                           "satellite interface: " + route)
    return route


def interface_for_address(cid, address):
    output = docker_exec(cid, "ip", "-o", "-4", "address", "show")
    match = re.search(r"^\d+:\s+(\S+)\s+inet\s+"
                      + re.escape(address) + r"/\d+\b",
                      output, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find interface for {0}: {1}".format(
            address, output))
    return match.group(1).split("@", 1)[0]


def start_capture(cid, label, capture_filter, interface):
    pcap = REMOTE_ROOT + "/" + label + ".pcap"
    pid = REMOTE_ROOT + "/" + label + ".tcpdump.pid"
    log = REMOTE_ROOT + "/" + label + ".tcpdump.log"
    shell = ("tcpdump -i {interface} -n -s 0 -U -w {pcap} {filter} "
             "> {log} 2>&1 & echo $! > {pid}; wait $!").format(
                 interface=shlex_quote(interface), pcap=shlex_quote(pcap),
                 filter=shlex_quote(capture_filter), log=shlex_quote(log),
                 pid=shlex_quote(pid))
    docker("exec", "-d", cid, "sh", "-c", shell, timeout=15)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            size = int(docker_exec(cid, "sh", "-c",
                "wc -c < " + shlex_quote(pcap), timeout=5))
            if size >= 24:
                return {"cid": cid, "label": label, "pcap": pcap,
                        "pid": pid, "log": log}
        except (RuntimeError, ValueError):
            pass
        time.sleep(0.2)
    detail = docker_exec(cid, "cat", log, check=False).stdout.strip()
    raise RuntimeError("tcpdump did not start for {0}: {1}".format(label, detail))


def restrict_relay_egress(cid, server_ip):
    commands = [
        ["iptables", "-F", "OUTPUT"],
        ["iptables", "-P", "OUTPUT", "DROP"],
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
         "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    for address in RELAY_IPS:
        commands.append(["iptables", "-A", "OUTPUT", "-d",
                         address + "/32", "-j", "ACCEPT"])
    commands.append(["iptables", "-A", "OUTPUT", "-d", server_ip,
        "-p", "tcp", "--dport", str(SERVER_PORT), "-j", "ACCEPT"])
    for command_args in commands:
        docker_exec(cid, *command_args, timeout=10)
    return docker_exec(cid, "iptables", "-S", "OUTPUT")


def configure_relay_aliases(cid):
    addresses = docker_exec(cid, "ip", "-o", "-4", "address", "show")
    match = re.search(r"^\d+:\s+(\S+)\s+inet\s+"
                      + re.escape(GUARD_IP) + r"/\d+\b",
                      addresses, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find the GS27 interface carrying "
                           + GUARD_IP + ": " + addresses)
    interface = match.group(1).split("@", 1)[0]
    aliases = []
    for address in RELAY_IPS:
        if address == GUARD_IP:
            continue
        docker_exec(cid, "ip", "address", "add", address + "/24",
                    "dev", interface, timeout=10)
        aliases.append(address)
    observed = docker_exec(cid, "ip", "-o", "-4", "address", "show", "dev",
                           interface)
    if not all(re.search(r"\binet\s+" + re.escape(address) + r"/24\b",
                         observed) for address in RELAY_IPS):
        raise RuntimeError("GS27 relay IP aliases did not all attach to "
                           + interface + ": " + observed)
    return {"interface": interface, "primary": GUARD_IP,
            "aliases": aliases, "observed_addresses": observed}


def shlex_quote(text):
    import shlex
    return shlex.quote(str(text))


def stop_capture(capture):
    if capture is None:
        return
    docker_exec(capture["cid"], "sh", "-c",
        "kill -INT \"$(cat {0})\"".format(shlex_quote(capture["pid"])),
        timeout=10, check=False)
    deadline = time.monotonic() + 12
    prior = None
    stable = 0
    while time.monotonic() < deadline:
        try:
            size = int(docker_exec(capture["cid"], "sh", "-c",
                "wc -c < " + shlex_quote(capture["pcap"]), timeout=5))
        except (RuntimeError, ValueError):
            break
        if size == prior and size >= 24:
            stable += 1
            if stable >= 2:
                break
        else:
            stable = 0
            prior = size
        time.sleep(0.25)


class VisitScheduler:
    def __init__(self, client_cid, run, anchor, route_target):
        self.client_cid = client_cid
        self.run = run
        self.anchor = anchor
        self.route_target = route_target
        self.events = []
        self.lock = threading.Lock()

    def launch(self, scheduled_second, label):
        stamp = datetime.now(timezone.utc).isoformat()
        elapsed = round(time.monotonic() - self.anchor, 3)
        route = docker_exec(self.client_cid, "ip", "route", "get",
                            self.route_target)
        result = docker("exec", "-d", self.client_cid, "python3",
            REMOTE_SOURCE_ROOT + "/client_agent.py", "visit",
            "--socket", REMOTE_CLIENT_ROOT + "/agent.sock",
            "--label", label, timeout=15, check=False)
        event = {"scheduled_second": int(scheduled_second), "label": label,
                 "wall_utc": stamp, "wall_seconds_from_emulation_start": elapsed,
                 "route_to_guard": route, "launch_returncode": result.returncode,
                 "launch_stdout": result.stdout.strip(),
                 "launch_stderr": result.stderr.strip()}
        with self.lock:
            self.events.append(event)
        if result.returncode:
            raise RuntimeError("Could not launch Tor visit: " + result.stderr.strip())


def wait_for_visit(client_cid, label, timeout=90):
    result_path = REMOTE_CLIENT_ROOT + "/" + label + ".json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = docker_exec(client_cid, "cat", result_path,
                             timeout=5, check=False)
        if result.returncode == 0 and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        time.sleep(0.5)
    raise RuntimeError("Tor visit did not finish within {0}s: {1}".format(
        timeout, label))


def verify_visit(visit, expected_hash, expected_size, expected_path):
    actual = []
    for item in visit.get("actual_path", []):
        if isinstance(item, (list, tuple)) and item:
            fingerprint = item[0]
        elif isinstance(item, dict):
            fingerprint = item.get("fingerprint", "")
        else:
            fingerprint = str(item).split("~", 1)[0]
        actual.append(str(fingerprint).lstrip("$").upper())
    metrics = visit.get("curl_metrics", {})
    exact_path = actual == [fp.upper() for fp in expected_path]
    return {
        **visit,
        "object_matches_expected": bool(
            visit.get("ok") and visit.get("object_bytes") == expected_size
            and visit.get("object_sha256") == expected_hash
            and metrics.get("http_code") == "200"
            and int(float(metrics.get("size_download", "0") or 0)) == expected_size),
        "controlled_path_matches": exact_path,
        "route_uses_satellite_interface": bool(re.search(
            r"\bdev B26-eth\d+\b", visit.get("route_to_guard", ""))),
    }


def analyze_client_capture(pcap, guard_ip, guard_or_port):
    fields = tshark_output("-r", pcap, "-Y", "tcp", "-T", "fields",
        "-E", "separator=|", "-e", "frame.time_epoch", "-e", "ip.src",
        "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "tcp.len")
    rows = []
    for line in fields.splitlines():
        values = (line.split("|") + [""] * 6)[:6]
        try:
            rows.append({"time": float(values[0]), "src": values[1],
                         "dst": values[2], "sport": int(values[3]),
                         "dport": int(values[4]), "payload": int(values[5] or 0)})
        except ValueError:
            continue
    selected = [row for row in rows if row["sport"] == guard_or_port
                or row["dport"] == guard_or_port]
    raw = pcap.read_bytes()
    positive = [row for row in selected if row["payload"] > 0]
    return {"endpoint": "GS26 satellite-side capture", "pcap": str(pcap),
            "pcap_bytes": pcap.stat().st_size,
            "guard_ip": guard_ip, "guard_or_port": guard_or_port,
            "guard_tcp_packet_count": len(selected),
            "guard_tcp_payload_packet_count": len(positive),
            "guard_tcp_payload_bytes": sum(row["payload"] for row in positive),
            "first_packet_epoch": min((row["time"] for row in selected), default=None),
            "last_packet_epoch": max((row["time"] for row in selected), default=None),
            "peer_addresses": sorted({x for row in selected for x in
                                      (row["src"], row["dst"]) if x}),
            "guard_address_seen": any(guard_ip in (row["src"], row["dst"])
                                      for row in selected),
            "http_object_request_visible": b"GET /" + OBJECT_NAME.encode() in raw,
            "http_200_response_visible": b"200 OK" in raw}


def analyze_server_capture(pcap):
    request_rows = tshark_output("-r", pcap, "-d",
        "tcp.port=={0},http".format(SERVER_PORT), "-Y",
        "http.request && http.request.uri==\"/{0}\"".format(OBJECT_NAME),
        "-T", "fields", "-e", "frame.number").splitlines()
    response_rows = tshark_output("-r", pcap, "-d",
        "tcp.port=={0},http".format(SERVER_PORT), "-Y",
        "http.response.code==200", "-T", "fields", "-e", "frame.number").splitlines()
    raw_gets = tshark_output("-r", pcap, "-Y",
        "tcp.dstport=={0} && tcp.payload contains \"GET /{1}\"".format(
            SERVER_PORT, OBJECT_NAME), "-T", "fields", "-e", "frame.number").splitlines()
    raw_ok = tshark_output("-r", pcap, "-Y",
        "tcp.srcport=={0} && tcp.payload contains \"200 OK\"".format(
            SERVER_PORT), "-T", "fields", "-e", "frame.number").splitlines()
    frames = tshark_output("-r", pcap, "-T", "fields", "-e", "frame.number").splitlines()
    raw = pcap.read_bytes()
    return {"endpoint": "Tor Exit to fixed page server", "pcap": str(pcap),
            "pcap_bytes": pcap.stat().st_size, "packet_count": len(frames),
            "decoded_get_count": len(request_rows),
            "raw_get_header_count": len(raw_gets),
            "get_count": max(len(request_rows), len(raw_gets)),
            "decoded_http_200_count": len(response_rows),
            "raw_http_200_header_count": len(raw_ok),
            "http_200_count": max(len(response_rows), len(raw_ok)),
            "fixed_page_request_visible": b"GET /" + OBJECT_NAME.encode() in raw,
            "http_200_response_visible": b"200 OK" in raw}


def analyze_server_log(path):
    if not path.is_file():
        return {"available": False, "successful_get_count": 0}
    text = path.read_text(errors="replace")
    lines = [line for line in text.splitlines()
             if "GET /{0} HTTP/".format(OBJECT_NAME) in line]
    successful = [line for line in lines if re.search(r"\" 200 ", line)]
    return {"available": True, "get_count": len(lines),
            "successful_get_count": len(successful),
            "log_file": str(path)}


def copy_remote_file(cid, source, target):
    exists = docker_exec(cid, "test", "-f", source, timeout=10, check=False)
    if exists.returncode:
        return False
    destination = Path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(docker_output_bytes(cid, "cat", source))
    return True


def save_runtime_artifacts(run, relay_cid, client_cid, server_cid):
    copied = []
    source_root = run / "source"
    chutney_archive = docker_output_bytes(relay_cid, "tar", "-C", "/opt",
        "-czf", "-", "chutney", timeout=120)
    chutney_target = source_root / "chutney.tar.gz"
    chutney_target.write_bytes(chutney_archive)
    copied.append("source/chutney.tar.gz")
    for cid, source, target in (
        (relay_cid, "/etc/p2-tor-packages.txt", run / "source" / "p2-tor-packages.txt"),
        (relay_cid, "/etc/p2-chutney-source.sha256", run / "source" / "p2-chutney-source.sha256"),
        (relay_cid, "/p2/chutney-setup.log", run / "logs" / "chutney-setup.log"),
        (relay_cid, "/p2/relay-artifacts.tar.gz", run / "configs" / "tor-relays.tar.gz"),
        (client_cid, "/p2/client/torrc", run / "configs" / "tor-client.torrc"),
        (client_cid, "/p2/client/notice.log", run / "logs" / "tor-client-notice.log"),
        (client_cid, "/p2/client/tor-process.log", run / "logs" / "tor-client-process.log"),
        (client_cid, "/p2/client/agent.log", run / "logs" / "tor-client-agent.log"),
        (client_cid, "/p2/client/controller_events.jsonl", run / "logs" / "tor-controller-events.jsonl"),
        (client_cid, "/p2/client/circuit_initial.json", run / "logs" / "circuit-initial.json"),
        (client_cid, "/p2/client.tcpdump.log", run / "logs" / "client-tcpdump.log"),
        (server_cid, "/p2/exit-server.tcpdump.log", run / "logs" / "exit-server-tcpdump.log"),
        (server_cid, "/p2/http-server.log", run / "logs" / "http-server.log"),
    ):
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        if copy_remote_file(cid, source, target):
            copied.append(str(Path(target).relative_to(run)))
    for label in ("stable", "before_handover", "after_handover"):
        for suffix, folder in ((".html", "downloads"), (".curl.txt", "logs"),
                               (".json", "logs")):
            source = REMOTE_CLIENT_ROOT + "/" + label + suffix
            target = run / folder / (label + suffix)
            target.parent.mkdir(parents=True, exist_ok=True)
            if copy_remote_file(client_cid, source, target):
                copied.append(str(target.relative_to(run)))
    return copied


def cleanup_helpers():
    containers = docker("ps", "-aq", "--filter",
        "label={0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE)).stdout.split()
    if containers:
        docker("rm", "-f", *containers, timeout=90)
    networks = docker("network", "ls", "-q", "--filter",
        "label={0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE)).stdout.split()
    for network in networks:
        docker("network", "rm", network, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?",
                        choices=["plan", "preflight", "build-image", "run"],
                        default="plan")
    args = parser.parse_args()
    lock = (ROOT / ".p0.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("Another local StarryNet experiment is running")

    if args.mode == "plan":
        print(json.dumps({"experiment": "P2 controlled Tor smoke",
            "route": ["GS26", "satellite B26-eth*", "GS27 gateway",
                      "Tor Guard", "Tor Middle", "Tor Exit", "fixed page server"],
            "satellite_impairment_scope": "GS26 satellite access segment",
            "visits": ["stable baseline", "before first GS27 handover",
                       "after first GS27 handover"],
            "artifacts": ["summary.json", "frozen source", "Tor configs/logs",
                          "client and exit/server PCAP", "three fixed-page downloads"],
            "image": TOR_IMAGE}, indent=2))
        return
    if args.mode == "build-image":
        docker_stream("build", "--pull", "--build-arg", "TOR_PACKAGE_VERSION=0.4.9.11-0+deb12u1",
            "--build-arg", "STEM_PACKAGE_VERSION=1.8.1-2.1", "-t", BASE_TOR_IMAGE,
            "-f", "tools/p2_tor/Dockerfile", "tools/p2_tor", timeout=3600)
        docker_stream("build", "--build-arg", "TOR_BASE_IMAGE=" + BASE_TOR_IMAGE,
            "-t", TOR_IMAGE, "-f", "tools/p2_tor/Dockerfile.chutney",
            "tools/p2_tor", timeout=1800)
        print(json.dumps(check_image(), indent=2))
        return

    ready = preflight()
    if args.mode == "preflight":
        print(json.dumps(ready, indent=2))
        return

    before_inventory = ready["inventory"]
    private_subnet = ipaddress.ip_network(ready["private_subnet"])
    run = ROOT / "artifacts" / "p2_tor" / datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S_%fZ")
    run.mkdir(parents=True)
    fixture = make_fixture(run)
    source_hashes = freeze_source(run)
    load_frozen_helpers(run)
    config = json.loads((run / "config.json").read_text())
    run_config_sha256 = hashlib.sha256((run / "config.json").read_bytes()).hexdigest()
    manifest = {
        "experiment": "P2_StarryNet_Controlled_Tor_Circuit_Smoke",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": command("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        "source_sha256": source_hashes,
        "run_config_sha256": run_config_sha256,
        "python": sys.version,
        "tor_image": ready["tor_image"],
        "private_network": {"subnet": str(private_subnet), "internal": True},
        "ground_stations": GS,
        "simulation_seconds": 100,
        "object": {"name": OBJECT_NAME, "bytes": len(OBJECT_BYTES),
                   "sha256": hashlib.sha256(OBJECT_BYTES).hexdigest()},
        "client": {"node": CLIENT_NODE, "guard_ip": GUARD_IP},
        "gateway": {"node": GATEWAY_NODE, "docker_network": "GS_27"},
        "exit_server": {"ip": str(private_subnet.network_address + 50),
                        "port": SERVER_PORT},
        "visits": ["stable", "before_handover", "after_handover"],
        "capture": {"client": "tcp host 9.27.27.11 and tcp port <Guard ORPort>",
                    "exit_server": "tcp port 18080"},
        "tshark_version": tshark_output("--version").splitlines()[0],
    }
    write_json(run / "manifest.json", manifest)
    print("Output: {0}".format(run), flush=True)

    sys.path.insert(0, str(run / "source"))
    from starrynet.sn_thread import WORKER_ERRORS
    WORKER_ERRORS.clear()
    sn = None
    client_cid = relay_cid = server_cid = None
    captures = []
    failure = None
    started = time.monotonic()
    summary = {"mode": "run", "p2_completed": False,
        "circuit_established": False, "stable_content_verified": False,
        "controlled_circuit_path_verified": False,
        "dual_endpoint_capture_passed": False,
        "satellite_path_proven": False, "cleanup_verified": False,
        "scientific_fidelity_verified": False, "visits": [], "captures": [],
        "resource_inventory_before": before_inventory}
    try:
        from starrynet.sn_synchronizer import StarryNet
        sn = StarryNet(str(run / "config.json"), GS, 1, [[1, 27]],
                       local=True, argv=[])
        topology_path = run / sn.file_path
        summary["topology"] = topology_report(run, topology_path)
        handovers = topology_handover_seconds(topology_path)
        if not handovers:
            raise RuntimeError("No GS26 satellite handover exists in this topology")
        handover = handovers[0]
        before_visit_second = handover - 18
        after_visit_second = handover + 22
        if before_visit_second < 15 or after_visit_second > 95:
            raise RuntimeError("First handover leaves no safe before/after visit window")
        summary.update({"handover_ground_station": GATEWAY_NODE,
                        "gs27_handover_second": handover,
                        "scheduled_dynamic_visits": [before_visit_second,
                                                      after_visit_second]})
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet initialization worker failed: "
                               + str(WORKER_ERRORS))

        for action in (sn.create_nodes, sn.create_links):
            action()
            if WORKER_ERRORS:
                raise RuntimeError("StarryNet worker failed: " + str(WORKER_ERRORS))
        if len(sn.container_id_list) != 27:
            raise RuntimeError("Expected 27 StarryNet containers")
        disable_management_interfaces(sn)
        sn.run_routing_deamon()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet routing worker failed: " + str(WORKER_ERRORS))
        client_cid = sn.container_id_list[CLIENT_NODE - 1]
        gateway_cid = sn.container_id_list[GATEWAY_NODE - 1]
        summary["route_before_helpers"] = current_route(client_cid, GUARD_IP)
        summary["gateway_snapshot_before"] = {
            "interfaces": docker_exec(gateway_cid, "ip", "-o", "address"),
            "routes": docker_exec(gateway_cid, "ip", "route"),
            "route_to_guard": docker_exec(gateway_cid, "ip", "route", "get",
                                            GUARD_IP),
            "route_to_client": docker_exec(gateway_cid, "ip", "route", "get",
                                             "9.26.26.10")}

        name_suffix = run.name[-12:].lower()
        p2_network = "p2-tor-" + name_suffix
        subnet = str(private_subnet)
        docker("network", "create", "--driver", "bridge", "--internal",
            "--subnet", subnet, "--label",
            "{0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE), p2_network)
        network_ip = lambda host: str(private_subnet.network_address + host)
        docker("run", "-d", "--name", "p2-tor-page-" + name_suffix,
            "--label", "{0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE),
            "--network", p2_network, "--ip", network_ip(50), "--read-only",
            "--tmpfs", "/p2:rw,nosuid,nodev,size=32m", "--cap-drop", "ALL",
            "--cap-add", "NET_RAW",
            "--security-opt", "no-new-privileges", TOR_IMAGE)
        server_cid = command("docker", "ps", "-q", "--filter",
            "name=p2-tor-page-" + name_suffix).splitlines()[0]
        docker_exec(server_cid, "mkdir", "-p", "/p2/www")
        docker_exec_stdin(server_cid, fixture.read_bytes(), "python3", "-c",
            "import pathlib,sys; pathlib.Path('/p2/www/{0}').write_bytes("
            "sys.stdin.buffer.read())".format(OBJECT_NAME))
        server_script = ("python3 -m http.server --bind 0.0.0.0 {port} "
                         "--directory /p2/www > /p2/http-server.log 2>&1 & "
                         "echo $! > /p2/http-server.pid; wait $!").format(
                             port=SERVER_PORT)
        docker("exec", "-d", server_cid, "sh", "-c", server_script)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            ready_check = docker_exec(server_cid, "curl", "--noproxy", "*",
                "-sS", "-I", "--connect-timeout", "1", "--max-time", "2",
                "-o", "/dev/null", "-w", "%{http_code}",
                "http://127.0.0.1:{0}/{1}".format(SERVER_PORT, OBJECT_NAME),
                timeout=5, check=False)
            if ready_check.returncode == 0 and ready_check.stdout.strip() == "200":
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Fixed page HTTP server did not become ready")

        relay_source = run / "source" / "tools" / "p2_tor"
        docker("run", "-d", "--name", "p2-tor-relay-" + name_suffix,
            "--label", "{0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE),
            "--network", "GS_27", "--ip", GUARD_IP, "--read-only",
            "--tmpfs", "/p2:rw,nosuid,nodev,size=512m", "--cap-drop", "ALL",
            "--cap-add", "NET_ADMIN",
            "--mount", "type=bind,source={0},target={1},readonly".format(
                str(relay_source), REMOTE_SOURCE_ROOT),
            "--mount", "type=bind,source={0},target=/opt/chutney/networks/p2-smoke,readonly".format(
                str(relay_source / "networks" / "p2-smoke")),
            "--security-opt", "no-new-privileges", TOR_IMAGE)
        relay_cid = command("docker", "ps", "-q", "--filter",
            "name=p2-tor-relay-" + name_suffix).splitlines()[0]
        docker("network", "connect", "--ip", network_ip(10), p2_network, relay_cid)
        summary["relay_addresses"] = configure_relay_aliases(relay_cid)
        summary["relay_egress_firewall"] = {
            "rules": restrict_relay_egress(relay_cid, network_ip(50)),
            "allowed_new_destinations": [
                {"ips": RELAY_IPS,
                 "scope": "private Tor relay and directory authority traffic"},
                {"ip": network_ip(50), "tcp_port": SERVER_PORT,
                 "scope": "fixed page server"}],
            "default_output_policy": "DROP"}
        relay_helper = REMOTE_SOURCE_ROOT + "/relay_net.py"
        relay_args = ["python3", relay_helper, "--listen-ip", GUARD_IP,
                      "--server-ip", network_ip(50), "--server-port",
                      str(SERVER_PORT)]
        config_result = docker_exec(relay_cid, *relay_args, "configure", timeout=180)
        network_result = docker_exec(relay_cid, *relay_args, "start", timeout=120)
        bootstrap_result = docker_exec(relay_cid, *relay_args, "wait", timeout=260)
        relay_nodes = json.loads(docker_exec(relay_cid, *relay_args, "metadata"))
        role_nodes = {item["role"]: item for item in relay_nodes}
        for required_role in ("authority", "guard", "middle", "exit"):
            if required_role not in role_nodes:
                raise RuntimeError("Missing Chutney Tor role: " + required_role)
            if not role_nodes[required_role].get("fingerprint"):
                raise RuntimeError("Missing Tor identity for role: " + required_role)
        advertised_nodes = [item for item in relay_nodes
                            if item["role"] in ("authority", "guard", "middle", "exit")]
        advertised_addresses = [item.get("advertised_address")
                                for item in advertised_nodes]
        if (None in advertised_addresses
                or set(advertised_addresses) != set(RELAY_IPS)
                or len(advertised_addresses) != len(set(advertised_addresses))):
            raise RuntimeError("Chutney relay identities do not advertise the "
                               "six configured GS27 addresses: "
                               + str(advertised_addresses))
        path = [role_nodes[role]["fingerprint"]
                for role in ("guard", "middle", "exit")]
        summary["tor_network_setup"] = {"configure": json.loads(config_result),
            "start": json.loads(network_result),
            "bootstrap": json.loads(bootstrap_result),
            "nodes": relay_nodes, "controlled_path_fingerprints": path,
            "controlled_path_nicknames": [role_nodes[r]["nickname"]
                                           for r in ("guard", "middle", "exit")]}
        torrc_lines = [
            "DataDirectory {0}/data".format(REMOTE_CLIENT_ROOT),
            "RunAsDaemon 0", "ClientOnly 1", "TestingTorNetwork 1",
            "SocksPort 127.0.0.1:9050", "ControlPort 127.0.0.1:9051",
            "ControlSocket {0}/control".format(REMOTE_CLIENT_ROOT),
            "CookieAuthentication 1",
            "PidFile {0}/tor.pid".format(REMOTE_CLIENT_ROOT),
            "Log notice file {0}/notice.log".format(REMOTE_CLIENT_ROOT),
            "UseEntryGuards 1", "EntryNodes ${0}".format(path[0]),
            "ExitNodes ${0}".format(path[2]), "StrictNodes 1",
            "CircuitBuildTimeout 90",
        ]
        for authority in [item for item in relay_nodes
                          if item["role"] == "authority"]:
            if not authority.get("authority_v3_identity"):
                raise RuntimeError("Missing v3 identity for " + authority["nickname"])
            torrc_lines.append("DirAuthority {nick} orport={orport} no-v2 "
                "v3ident={v3} {ip}:{dirport} {fp}".format(
                    nick=authority["nickname"], orport=authority["or_port"],
                    v3=authority["authority_v3_identity"],
                    ip=authority["advertised_address"],
                    dirport=authority["dir_port"], fp=authority["fingerprint"]))
        torrc = "\n".join(torrc_lines) + "\n"
        torrc_local = run / "configs" / "tor-client.torrc"
        torrc_local.parent.mkdir(parents=True, exist_ok=True)
        torrc_local.write_text(torrc)

        docker("run", "-d", "--name", "p2-tor-client-" + name_suffix,
            "--label", "{0}={1}".format(P2_OWNER_LABEL, P2_OWNER_VALUE),
            "--network", "container:" + client_cid, "--read-only",
            "--tmpfs", "/p2:rw,nosuid,nodev,size=128m", "--cap-drop", "ALL",
            "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges",
            "--mount", "type=bind,source={0},target={1},readonly".format(
                str(run / "source" / "tools" / "p2_tor"), REMOTE_SOURCE_ROOT),
            TOR_IMAGE)
        client_cid = command("docker", "ps", "-q", "--filter",
            "name=p2-tor-client-" + name_suffix).splitlines()[0]
        docker_exec(client_cid, "mkdir", "-p", REMOTE_CLIENT_ROOT)
        docker_exec(client_cid, "mkdir", "-p",
                    REMOTE_CLIENT_ROOT + "/data")
        docker_exec(client_cid, "chmod", "700", REMOTE_CLIENT_ROOT,
                    REMOTE_CLIENT_ROOT + "/data")
        docker_exec_stdin(client_cid, torrc.encode("utf-8"), "sh", "-c",
            "cat > " + shlex_quote(REMOTE_CLIENT_ROOT + "/torrc"))
        tor_shell = "exec tor -f {0} >>{1}/tor-process.log 2>&1".format(
            shlex_quote(REMOTE_CLIENT_ROOT + "/torrc"),
            shlex_quote(REMOTE_CLIENT_ROOT))
        docker("exec", "-d", client_cid, "sh", "-c", tor_shell, timeout=15)
        agent_command = ["python3", REMOTE_SOURCE_ROOT + "/client_agent.py", "serve",
            "--root", REMOTE_CLIENT_ROOT, "--guard-ip", GUARD_IP,
            "--server-ip", network_ip(50), "--server-port", str(SERVER_PORT),
            "--object-name", OBJECT_NAME, "--path", ",".join(path),
            "--ready-file", REMOTE_CLIENT_ROOT + "/ready.json"]
        agent_shell = "exec {0} >>{1}/agent.log 2>&1".format(
            " ".join(shlex_quote(part) for part in agent_command),
            shlex_quote(REMOTE_CLIENT_ROOT))
        docker("exec", "-d", client_cid, "sh", "-c", agent_shell, timeout=15)
        ready_deadline = time.monotonic() + 240
        initial_circuit = None
        while time.monotonic() < ready_deadline:
            status = docker_exec(client_cid, "cat", REMOTE_CLIENT_ROOT + "/ready.json",
                                 timeout=5, check=False)
            if status.returncode == 0 and status.stdout.strip():
                initial_circuit = json.loads(status.stdout)
                break
            tor_log = docker_exec(client_cid, "cat",
                REMOTE_CLIENT_ROOT + "/tor-process.log", timeout=5,
                check=False).stdout
            fatal_tor_markers = ("Failed to parse/validate config",
                                 "Reading config failed--see warnings above",
                                 "Address already in use")
            if any(marker in tor_log for marker in fatal_tor_markers):
                raise RuntimeError("Tor client exited before building a "
                                   "circuit: " + tor_log[-3000:])
            agent_log = docker_exec(client_cid, "cat",
                REMOTE_CLIENT_ROOT + "/agent.log", timeout=5,
                check=False).stdout
            if "Traceback (most recent call last)" in agent_log:
                raise RuntimeError("Tor controller agent exited before "
                                   "building a circuit: " + agent_log[-3000:])
            time.sleep(1)
        if initial_circuit is None:
            notice = docker_exec(client_cid, "cat", REMOTE_CLIENT_ROOT + "/notice.log",
                                 timeout=5, check=False)
            raise RuntimeError("Controlled Tor client did not build a circuit: "
                               + notice.stdout[-4000:])
        summary["circuit_established"] = True
        summary["initial_circuit"] = initial_circuit

        guard = role_nodes["guard"]
        summary["client_route_before_capture"] = current_route(client_cid, GUARD_IP)
        route_device = re.search(r"\bdev\s+(B26-eth\d+)\b",
                                 summary["client_route_before_capture"])
        if not route_device:
            raise RuntimeError("Could not select the client satellite capture "
                               "interface from its route: "
                               + summary["client_route_before_capture"])
        client_capture_interface = route_device.group(1)
        server_capture_interface = interface_for_address(
            server_cid, network_ip(50))
        summary["capture_interfaces"] = {
            "client": client_capture_interface,
            "exit_server": server_capture_interface}
        client_capture_filter = "host {0} and tcp port {1}".format(
            GUARD_IP, guard["or_port"])
        captures.append(start_capture(client_cid, "client",
            client_capture_filter, client_capture_interface))
        captures.append(start_capture(server_cid, "exit-server", "tcp port {0}".format(
            SERVER_PORT), server_capture_interface))

        page_hash = manifest["object"]["sha256"]
        stable_visit = json.loads(docker_exec(client_cid, "python3",
            REMOTE_SOURCE_ROOT + "/client_agent.py", "visit", "--socket",
            REMOTE_CLIENT_ROOT + "/agent.sock", "--label", "stable", timeout=90))
        stable_visit = verify_visit(stable_visit, page_hash, len(OBJECT_BYTES), path)
        summary["visits"].append({"scheduled_phase": "stable",
                                   **stable_visit})
        summary["stable_content_verified"] = stable_visit["object_matches_expected"]
        summary["controlled_circuit_path_verified"] = stable_visit[
            "controlled_path_matches"]

        visitor = VisitScheduler(client_cid, run, time.monotonic(), GUARD_IP)
        sn.schedule_callback(before_visit_second,
            lambda second=before_visit_second: visitor.launch(second, "before_handover"))
        sn.schedule_callback(after_visit_second,
            lambda second=after_visit_second: visitor.launch(second, "after_handover"))
        for second in (15, before_visit_second, after_visit_second, 95):
            sn.set_ping(CLIENT_NODE, GATEWAY_NODE, second)
            sn.check_routing_table(CLIENT_NODE, second)
            sn.check_routing_table(GATEWAY_NODE, second)
        from p0_smoke import snapshot
        snapshot(sn, run, "before")
        emulation_start = time.monotonic()
        visitor.anchor = emulation_start
        sn.start_emulation()
        if WORKER_ERRORS:
            raise RuntimeError("StarryNet emulation worker failed: " + str(WORKER_ERRORS))
        summary["scheduled_visit_events"] = sorted(visitor.events,
            key=lambda item: item["scheduled_second"])
        before_result = wait_for_visit(client_cid, "before_handover")
        after_result = wait_for_visit(client_cid, "after_handover")
        summary["visits"].extend([
            {"scheduled_phase": "before_handover",
             "scheduled_second": before_visit_second,
             **verify_visit(before_result, page_hash, len(OBJECT_BYTES), path)},
            {"scheduled_phase": "after_handover",
             "scheduled_second": after_visit_second,
             **verify_visit(after_result, page_hash, len(OBJECT_BYTES), path)},
        ])
        snapshot(sn, run, "after")
        summary["gs26_route_after"] = current_route(client_cid, GUARD_IP)
        summary["gateway_route_to_guard_after"] = docker_exec(
            gateway_cid, "ip", "route", "get", GUARD_IP)
        summary["gateway_route_to_client_after"] = docker_exec(
            gateway_cid, "ip", "route", "get", "9.26.26.10")
        summary["route_files"] = sorted(p.name for p in topology_path.glob("route-*.txt"))
        summary["ping_files"] = sorted(p.name for p in topology_path.glob("ping-26-27_*.txt"))
        client_routes_proven = all(
            visit.get("route_uses_satellite_interface")
            for visit in summary["visits"])
        gateway_routes_proven = all(re.search(r"\bdev B27-eth\d+\b", route)
            for route in (summary["gateway_snapshot_before"]["route_to_client"],
                          summary["gateway_route_to_client_after"]))
        gateway_local_guard_proven = all(re.search(r"\bdev B27-default\b", route)
            for route in (summary["gateway_snapshot_before"]["route_to_guard"],
                          summary["gateway_route_to_guard_after"]))
        summary["satellite_path_proven"] = bool(
            client_routes_proven and gateway_routes_proven
            and gateway_local_guard_proven)
    except BaseException as exc:
        failure = exc
        summary["error"] = str(exc)
    finally:
        for capture in captures:
            try:
                stop_capture(capture)
                destination = run / "captures" / (capture["label"] + ".pcap")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(docker_output_bytes(
                    capture["cid"], "cat", capture["pcap"], timeout=120))
            except Exception as exc:
                summary.setdefault("capture_errors", []).append(
                    {"label": capture["label"], "error": str(exc)})
                if failure is None:
                    failure = exc
                    summary["error"] = str(exc)

        try:
            if client_cid:
                docker_exec(client_cid, "python3", REMOTE_SOURCE_ROOT + "/client_agent.py",
                    "stop", "--socket", REMOTE_CLIENT_ROOT + "/agent.sock",
                    timeout=10, check=False)
                docker_exec(client_cid, "sh", "-c",
                    "test -s {0}/tor.pid && kill -TERM \"$(cat {0}/tor.pid)\" || true".format(
                        shlex_quote(REMOTE_CLIENT_ROOT)), timeout=10, check=False)
            if relay_cid:
                relay_stop = ["python3", REMOTE_SOURCE_ROOT + "/relay_net.py", "--listen-ip",
                    GUARD_IP, "--server-ip", str(private_subnet.network_address + 50),
                    "--server-port", str(SERVER_PORT), "stop"]
                docker_exec(relay_cid, *relay_stop, timeout=60, check=False)
                archive = ["python3", REMOTE_SOURCE_ROOT + "/relay_net.py", "--listen-ip",
                    GUARD_IP, "--server-ip", str(private_subnet.network_address + 50),
                    "--server-port", str(SERVER_PORT), "--network-file",
                    REMOTE_SOURCE_ROOT + "/networks/p2-smoke", "archive", "--archive",
                    REMOTE_ROOT + "/relay-artifacts.tar.gz"]
                docker_exec(relay_cid, *archive, timeout=60, check=False)
            if relay_cid and client_cid and server_cid:
                summary["artifacts_copied"] = save_runtime_artifacts(
                    run, relay_cid, client_cid, server_cid)
        except Exception as exc:
            summary["artifact_error"] = str(exc)
            if failure is None:
                failure = exc
                summary["error"] = str(exc)

        client_pcap = run / "captures" / "client.pcap"
        server_pcap = run / "captures" / "exit-server.pcap"
        if client_pcap.exists() and server_pcap.exists() and "tor_network_setup" in summary:
            try:
                guard_or_port = role_nodes["guard"]["or_port"]
                summary["captures"] = [
                    analyze_client_capture(client_pcap, GUARD_IP, guard_or_port),
                    analyze_server_capture(server_pcap),
                ]
                client_result, server_result = summary["captures"]
                summary["server_application_log"] = analyze_server_log(
                    run / "logs" / "http-server.log")
                summary["dual_endpoint_capture_passed"] = bool(
                    client_result["pcap_bytes"] > 24
                    and client_result["guard_tcp_payload_bytes"] > 0
                    and client_result["guard_address_seen"]
                    and not client_result["http_object_request_visible"]
                    and not client_result["http_200_response_visible"]
                    and server_result["pcap_bytes"] > 24
                    and server_result["get_count"] >= sum(
                        bool(item.get("object_matches_expected"))
                        for item in summary["visits"])
                    and server_result["http_200_count"] >= sum(
                        bool(item.get("object_matches_expected"))
                        for item in summary["visits"])
                    and summary["server_application_log"].get(
                        "successful_get_count", 0) >= sum(
                        bool(item.get("object_matches_expected"))
                        for item in summary["visits"])
                    and summary["stable_content_verified"]
                    and server_result["fixed_page_request_visible"]
                    and server_result["http_200_response_visible"])
            except Exception as exc:
                summary["capture_analysis_error"] = str(exc)
                if failure is None:
                    failure = exc
                    summary["error"] = str(exc)
        summary["dual_endpoint_capture_passed"] = bool(
            summary.get("dual_endpoint_capture_passed", False))

        try:
            cleanup_helpers()
        except Exception as exc:
            summary["helper_cleanup_error"] = str(exc)
            if failure is None:
                failure = exc
                summary["error"] = str(exc)
        try:
            from starrynet.sn_orchestrater import sn_stop_emulation
            sn_stop_emulation()
            summary["resource_inventory_after"] = capture_inventory()
            summary["cleanup_verified"] = (
                summary["resource_inventory_before"] == summary["resource_inventory_after"])
            if not summary["cleanup_verified"] and failure is None:
                failure = RuntimeError("Docker inventory differs from the startup baseline")
                summary["error"] = str(failure)
        except Exception as exc:
            summary["cleanup_error"] = str(exc)
            if failure is None:
                failure = exc
                summary["error"] = str(exc)

        summary["stable_content_verified"] = bool(summary.get("stable_content_verified"))
        summary["satellite_path_proven"] = bool(summary.get("satellite_path_proven"))
        summary["dual_endpoint_capture_passed"] = bool(
            summary.get("dual_endpoint_capture_passed"))
        summary["handover_visits_recorded"] = all(
            any(item.get("scheduled_phase") == phase for item in summary["visits"])
            for phase in ("before_handover", "after_handover"))
        summary["payload_integrity_passed"] = bool(
            summary.get("stable_content_verified"))
        summary["p2_completed"] = bool(
            summary.get("circuit_established")
            and summary.get("controlled_circuit_path_verified")
            and summary.get("stable_content_verified")
            and summary.get("dual_endpoint_capture_passed")
            and summary.get("satellite_path_proven")
            and summary.get("cleanup_verified")
            and summary.get("handover_visits_recorded"))
        summary["wall_seconds"] = round(time.monotonic() - started, 3)
        write_json(run / "summary.json", summary)
        print(json.dumps(summary, indent=2), flush=True)
    if failure is not None:
        raise failure
    if not summary["p2_completed"]:
        raise RuntimeError("P2 completion gates failed; inspect summary.json")


if __name__ == "__main__":
    main()
