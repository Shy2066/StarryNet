#!/usr/bin/env python3
"""Plan, install, verify, or remove the reversible V3 GRE and GS27 NAT path.

Install changes routes and firewall rules only inside the two supplied,
temporary StarryNet containers. It is deliberately never run by the collector.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time


CLIENT_IF = "wf-gre0"
EGRESS_IF = "wf-gre0"
CLIENT_GRE = "10.255.253.1/30"
EGRESS_GRE = "10.255.253.2/30"
CLIENT_PEER = "10.255.253.2"
EGRESS_PEER = "10.255.253.1"
GRE_KEY = "1398228531"
FWD_CHAIN = "WFV3_FWD"
NAT_CHAIN = "WFV3_NAT"
DEFAULT_CONFIG = (Path(__file__).resolve().parents[1] / "protocols" /
                  "satellite_wf_v3" / "runtime_config.json")
TEMP_ETHTOOL = "/tmp/starrynet-v3-ethtool"
TEMP_IPTABLES_DEB = "/tmp/starrynet-v3-iptables.deb"
TEMP_LIBNFNETLINK_DEB = "/tmp/starrynet-v3-libnfnetlink0.deb"
DEFAULT_IPTABLES_DEB = (Path(__file__).resolve().parent / "vendor" /
                        "satellite_wf_v3" /
                        "iptables_1.6.0-2ubuntu3_amd64.deb")
DEFAULT_LIBNFNETLINK_DEB = (Path(__file__).resolve().parent / "vendor" /
                            "satellite_wf_v3" /
                            "libnfnetlink0_1.0.1-3_amd64.deb")
EXPECTED_IPTABLES_SHA256 = "d2cafb4f1860435ce69a4971e3af5f4bb20753054020f32e1b767e4ba79c0831"
EXPECTED_LIBNFNETLINK_SHA256 = "fbaf9b8914a607e2a07e5525c6c9c0ecb71d70236f54ad185f4cc81b4541f6ba"


def docker_exec(container, command, check=True):
    result = subprocess.run(["docker", "exec", container, "sh", "-lc", command],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    if check and result.returncode:
        raise RuntimeError("container command failed: {}".format(
            (result.stderr or result.stdout).strip()))
    return result


def validate_runtime_config(config_path=DEFAULT_CONFIG):
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("runtime config must be a JSON object")
    network = config.get("network", {})
    if not isinstance(network, dict):
        raise ValueError("runtime config network section must be an object")
    expected = {
        "mode": "gre_route_nat",
        "client_underlay_address": "9.26.26.10",
        "egress_underlay_address": "9.27.27.10",
        "tunnel_interface": CLIENT_IF,
        "capture_interface": CLIENT_IF,
        "tunnel_key": int(GRE_KEY),
        "client_tunnel_address": CLIENT_GRE,
        "egress_tunnel_address": EGRESS_GRE,
        "egress_interface": "B27-default",
        "browser_proxy_environment": "unset",
        "client_ipv6_policy": "disable_in_isolated_namespace",
        "fixed_object_endpoint": {
            "network": "GS_27",
            "interface": "B27-default",
            "address": "9.27.27.20",
            "port": 18080,
            "object_name": "fixed-object.bin",
            "object_size_bytes": 1048576,
            "image": "lwsen/starlab_node:1.0",
        },
    }
    if config.get("protocol_id") != "starrynet-browser-tor-route-nat-v3":
        raise ValueError("runtime config protocol_id does not match route/NAT tool")
    mismatches = [key for key, value in expected.items()
                  if network.get(key) != value]
    if mismatches:
        raise ValueError("runtime config disagrees with route/NAT tool: " +
                         ", ".join(mismatches))
    client_network = ipaddress.IPv4Interface(CLIENT_GRE).network
    if client_network != ipaddress.IPv4Interface(EGRESS_GRE).network:
        raise ValueError("client and egress GRE addresses are not in the same subnet")
    digest = hashlib.sha256(config_path.read_bytes()).hexdigest()
    return config_path, digest


def validate_iptables_packages(iptables_deb=DEFAULT_IPTABLES_DEB,
                               libnfnetlink_deb=DEFAULT_LIBNFNETLINK_DEB):
    packages = (
        ("iptables", Path(iptables_deb), "iptables", "1.6.0-2ubuntu3",
         EXPECTED_IPTABLES_SHA256),
        ("libnfnetlink0", Path(libnfnetlink_deb), "libnfnetlink0", "1.0.1-3",
         EXPECTED_LIBNFNETLINK_SHA256),
    )
    result = {}
    for key, path, expected_name, expected_version, expected_hash in packages:
        path = path.resolve()
        if not path.is_file():
            raise ValueError("required pinned {} package is missing: {}".format(
                key, path))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_hash:
            raise ValueError("pinned {} package SHA-256 mismatch".format(key))
        fields = {}
        for field in ("Package", "Version"):
            output = subprocess.run(["dpkg-deb", "-f", str(path), field],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True)
            if output.returncode:
                raise ValueError("cannot inspect {} package metadata: {}".format(
                    key, (output.stderr or output.stdout).strip()))
            fields[field] = output.stdout.strip()
        if fields != {"Package": expected_name, "Version": expected_version}:
            raise ValueError("pinned {} package identity mismatch: {}".format(
                key, fields))
        result[key] = {"path": str(path), "package": expected_name,
                       "version": expected_version, "sha256": digest}
    return result


def _container_id(value):
    if not re.match(r"^[0-9a-f]{12,64}$", value or ""):
        raise ValueError("container IDs must be hexadecimal Docker IDs")
    return value


def _assert_starrynet_container(container):
    result = subprocess.run(
        ["docker", "inspect", "--format",
         '{{ index .Config.Labels "com.docker.swarm.service.name" }}', container],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        raise RuntimeError("cannot inspect Docker container {}: {}".format(
            container, (result.stderr or result.stdout).strip()))
    if result.stdout.strip() != "constellation-test":
        raise RuntimeError(
            "refusing to alter a container outside the StarryNet constellation-test service")


def _one_ipv4(container, interface):
    rows = docker_exec(container, "ip -4 addr show dev {}".format(interface)).stdout.splitlines()
    values = []
    for row in rows:
        match = re.match(r"\s*inet\s+([0-9.]+)/[0-9]+(?:\s|$)", row)
        if match:
            values.append(match.group(1))
    if len(values) != 1:
        raise RuntimeError("expected exactly one IPv4 address on {}".format(interface))
    return values[0]


def _route(container, destination):
    output = docker_exec(container, "ip -4 route get {}".format(destination)).stdout
    rows = [row.strip() for row in output.splitlines() if row.strip()]
    if not rows:
        raise RuntimeError("no route to {}".format(destination))
    tokens = shlex.split(rows[0])
    attributes = {"via", "dev", "src", "table", "metric", "uid", "mark",
                  "iif", "oif", "tos", "ipproto", "sport", "dport"}
    route = {"raw": rows[0]}
    for index, token in enumerate(tokens[:-1]):
        if token in attributes:
            route[token] = tokens[index + 1]
    if not route.get("dev"):
        raise RuntimeError("could not parse route to {}: {}".format(
            destination, rows[0]))
    return route


def _tunnel_outer_endpoints(container):
    output = docker_exec(container, "ip tunnel show wf-gre0").stdout.strip()
    tokens = shlex.split(output)
    values = {}
    for index, token in enumerate(tokens[:-1]):
        if token in ("local", "remote"):
            values[token] = tokens[index + 1]
    if "local" not in values or "remote" not in values:
        raise RuntimeError("could not parse wf-gre0 outer endpoints: {}".format(output))
    return values


def _selected_outer_endpoint_routes(client_id, egress_id):
    client_underlay = _route(client_id, "9.27.27.10")
    egress_underlay = _route(egress_id, "9.26.26.10")
    if not str(client_underlay.get("dev", "")).startswith("B26-eth"):
        raise RuntimeError("GS26 route to GS27 does not use a satellite interface")
    if not str(egress_underlay.get("dev", "")).startswith("B27-eth"):
        raise RuntimeError("GS27 route to GS26 does not use a satellite interface")
    client_source = str(ipaddress.IPv4Address(client_underlay.get("src", "")))
    egress_source = str(ipaddress.IPv4Address(egress_underlay.get("src", "")))
    if client_source == egress_source:
        raise RuntimeError("GS26 and GS27 satellite route sources are not distinct")
    client_peer_route = _route(client_id, egress_source)
    egress_peer_route = _route(egress_id, client_source)
    if not str(client_peer_route.get("dev", "")).startswith("B26-eth"):
        raise RuntimeError("GS26 has no satellite route to the selected GS27 endpoint")
    if not str(egress_peer_route.get("dev", "")).startswith("B27-eth"):
        raise RuntimeError("GS27 has no satellite route to the selected GS26 endpoint")
    return {
        "client": client_source,
        "egress": egress_source,
        "selection": "source address from route to the peer ground-station address",
        "client_underlay_route": client_underlay,
        "egress_underlay_route": egress_underlay,
        "client_peer_route": client_peer_route,
        "egress_peer_route": egress_peer_route,
    }


def _change_gre_outer_endpoints(container, local_address, remote_address):
    docker_exec(container,
                "ip tunnel change wf-gre0 mode gre local {} remote {} key {} ttl 64".format(
                    ipaddress.IPv4Address(local_address),
                    ipaddress.IPv4Address(remote_address), GRE_KEY))


def retarget_dynamic_gre(state_path, logical_second=None):
    """Follow route-selected satellite addresses after a StarryNet GSL handover."""
    state_path = Path(state_path).resolve()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("installed") is not True:
        raise RuntimeError("cannot retarget GRE endpoints before route/NAT install")
    client_id = _container_id(state["client_container_id"])
    egress_id = _container_id(state["egress_container_id"])
    _assert_starrynet_container(client_id)
    _assert_starrynet_container(egress_id)
    selected = _selected_outer_endpoint_routes(client_id, egress_id)
    target = {key: selected[key] for key in ("client", "egress", "selection")}
    current = state.get("gre_outer_endpoints_current", state["gre_outer_endpoints"])
    current = {key: current[key] for key in ("client", "egress", "selection")}
    if target["client"] == current["client"] and target["egress"] == current["egress"]:
        return {"changed": False, "current": current, "routes": selected}

    changed = []
    try:
        _change_gre_outer_endpoints(egress_id, target["egress"], target["client"])
        changed.append((egress_id, current["egress"], current["client"]))
        _change_gre_outer_endpoints(client_id, target["client"], target["egress"])
        changed.append((client_id, current["client"], current["egress"]))
        if (_tunnel_outer_endpoints(client_id) != {
                "local": target["client"], "remote": target["egress"]}
                or _tunnel_outer_endpoints(egress_id) != {
                    "local": target["egress"], "remote": target["client"]}):
            raise RuntimeError("GRE tunnel endpoints did not match the new satellite routes")
        # `ip tunnel change` may re-enable segmentation/coalescing offloads on
        # the GRE device. Reapply the capture contract after every dynamic rebind.
        state["dynamic_gre_offloads_current"] = {
            "logical_second": logical_second,
            "client": _disable_offloads(
                client_id, "wf-gre0", state=state, state_path=state_path),
            "egress": _disable_offloads(
                egress_id, "wf-gre0", state=state, state_path=state_path)}
        client_route = _route(client_id, target["egress"])
        egress_route = _route(egress_id, target["client"])
        if (not str(client_route.get("dev", "")).startswith("B26-eth")
                or not str(egress_route.get("dev", "")).startswith("B27-eth")):
            raise RuntimeError("retargeted GRE outer route bypasses a satellite interface")
    except BaseException as exc:
        rollback_errors = []
        for container, local_address, remote_address in reversed(changed):
            try:
                _change_gre_outer_endpoints(container, local_address, remote_address)
                _disable_offloads(container, "wf-gre0", state=state,
                                  state_path=state_path)
            except Exception as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            raise RuntimeError("GRE retarget failed and rollback was incomplete: {}".format(
                "; ".join(rollback_errors))) from exc
        raise

    event = {"logical_second": logical_second,
             "monotonic_seconds": time.monotonic(),
             "previous": current, "current": target,
             "routes": selected}
    state["gre_outer_endpoints_current"] = target
    state.setdefault("dynamic_gre_endpoint_history", []).append(event)
    state["dynamic_gre_offloads_current"]["monotonic_seconds"] = event[
        "monotonic_seconds"]
    _save_state(state_path, state)
    return {"changed": True, **event}


def _exact_ipv4_host_routes(container, address):
    address = ipaddress.IPv4Address(address)
    lines = docker_exec(container, "ip -4 route show table main").stdout.splitlines()
    matches = []
    for line in lines:
        tokens = shlex.split(line)
        if not tokens or tokens[0] == "default":
            continue
        destination = tokens[0]
        try:
            network = ipaddress.ip_network(
                destination if "/" in destination else destination + "/32",
                strict=False)
        except ValueError:
            continue
        if (network.version == 4 and network.prefixlen == 32
                and network.network_address == address):
            matches.append(line)
    return matches


def build_plan(client_id, egress_id, client_underlay, egress_underlay):
    _container_id(client_id)
    _container_id(egress_id)
    client_underlay = str(ipaddress.IPv4Address(client_underlay))
    egress_underlay = str(ipaddress.IPv4Address(egress_underlay))
    return {
        "client": {"container_id": client_id,
                   "underlay_address": client_underlay,
                   "tunnel_interface": CLIENT_IF,
                   "tunnel_address": CLIENT_GRE,
                   "tunnel_outer_source": "source selected by the GS26 satellite route",
                   "tunnel_outer_peer": "source selected by the GS27 satellite route",
                   "default_route": "via {} dev {}".format(CLIENT_PEER, CLIENT_IF),
                   "fixed_object_endpoint_route": "via {} dev {}".format(
                       CLIENT_PEER, CLIENT_IF),
                   "capture_interface": CLIENT_IF},
        "egress": {"container_id": egress_id,
                   "underlay_address": egress_underlay,
                   "tunnel_interface": EGRESS_IF,
                   "tunnel_address": EGRESS_GRE,
                   "tunnel_outer_source": "source selected by the GS27 satellite route",
                   "tunnel_outer_peer": "source selected by the GS26 satellite route",
                   "uplink_interface": "B27-default",
                   "fixed_object_endpoint": "9.27.27.20:18080",
                   "forwarding": True,
                   "source_nat": "10.255.253.0/30"},
        "gre_key": GRE_KEY,
        "required_gates": [
            "GS26 route to GS27 underlay remains on a B26-eth satellite interface",
            "GS27 route to GS26 underlay remains on a B27-eth satellite interface",
            "public client routes use wf-gre0; GRE outer endpoints use route-selected satellite source addresses",
            "discovered GS27 host-side proxy gateway route uses wf-gre0",
            "fixed-object endpoint route uses wf-gre0",
            "fixed-object endpoint route uses B27-default",
            "GS26 IPv6 is disabled and has no default-route bypass",
            "no HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, or proxy application relay",
            "GRE capture offloads are disabled and verified"],
        "mutations": [
            "create point-to-point GRE interfaces in temporary GS26 and GS27 namespaces",
            "enable IPv4 forwarding and owned forwarding/NAT chains in GS27",
            "replace the GS26 main-table default route with the GRE route",
            "override the fixed-object endpoint with a reversible GS26 /32 GRE route",
            "save prior routes and sysctls to a state file for cleanup"],
        "scientific_fidelity_verified": False}


def _save_namespace_state(client_id, egress_id):
    def rp_filter_values(container):
        command = ("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do "
                   "printf '%s=' \"$f\"; cat \"$f\"; done")
        return docker_exec(container, command).stdout.splitlines()
    return {
        "client": {
            "default_routes": docker_exec(
                client_id, "ip -4 route show table main default").stdout.splitlines(),
            "ipv6_default_routes": docker_exec(
                client_id, "ip -6 route show table main default").stdout.splitlines(),
            "ipv6_disable_all": docker_exec(
                client_id, "sysctl -n net.ipv6.conf.all.disable_ipv6").stdout.strip(),
            "ipv6_disable_default": docker_exec(
                client_id, "sysctl -n net.ipv6.conf.default.disable_ipv6").stdout.strip(),
            "rp_filter": rp_filter_values(client_id)},
        "egress": {
            "default_routes": docker_exec(
                egress_id, "ip -4 route show table main default").stdout.splitlines(),
            "ipv6_default_routes": docker_exec(
                egress_id, "ip -6 route show table main default").stdout.splitlines(),
            "ip_forward": docker_exec(
                egress_id, "sysctl -n net.ipv4.ip_forward").stdout.strip(),
            "rp_filter": rp_filter_values(egress_id)}}


def _set_rp_filter(container, rows, value):
    for row in rows:
        path = row.split("=", 1)[0]
        name = Path(path).parent.name
        if not re.match(r"^[A-Za-z0-9_.-]+$", name):
            raise RuntimeError("unsafe rp_filter interface name")
        docker_exec(container, "sysctl -q -w net.ipv4.conf.{}.rp_filter={}".format(
            name, value))


def _disable_offloads(container, interface, state=None, state_path=None):
    features = (("tcp-segmentation-offload", "tso"),
                ("generic-segmentation-offload", "gso"),
                ("generic-receive-offload", "gro"),
                ("large-receive-offload", "lro"))
    rows = _ethtool(container, ["-k", interface], state=state,
                    state_path=state_path).stdout.splitlines()
    observed = {}
    for feature, option in features:
        line = next((item for item in rows if item.strip().startswith(feature + ":")), None)
        if line is None:
            observed[feature] = "unavailable"
            continue
        if "[fixed]" in line:
            observed[feature] = line.strip()
            if re.search(r":\s+on(?:\s|$)", line):
                raise RuntimeError("{} is fixed on for {}".format(feature, interface))
            continue
        _ethtool(container, ["-K", interface, option, "off"], state=state,
                 state_path=state_path)
        after = _ethtool(container, ["-k", interface], state=state,
                         state_path=state_path).stdout.splitlines()
        checked = next((item for item in after
                        if item.strip().startswith(feature + ":")), "")
        observed[feature] = checked.strip()
        if not re.search(r":\s+off(?:\s|$)", checked):
            raise RuntimeError("could not disable {} on {}".format(feature, interface))
    return observed


def _offloads_disabled(container, interface):
    features = ("tcp-segmentation-offload", "generic-segmentation-offload",
                "generic-receive-offload", "large-receive-offload")
    rows = _ethtool(container, ["-k", interface]).stdout.splitlines()
    states = {}
    for feature in features:
        line = next((item for item in rows
                     if item.strip().startswith(feature + ":")), None)
        if line is None:
            states[feature] = None
        else:
            states[feature] = bool(re.search(r":\s+off(?:\s|$)", line))
    return states


def _iptables(container, args, check=True):
    return docker_exec(container, "iptables " + " ".join(
        shlex.quote(value) for value in args), check=check)


def _save_state(state_path, state):
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    os.chmod(str(state_path), 0o600)


def _ethtool_path(container, state=None, state_path=None):
    native = docker_exec(container, "command -v ethtool", check=False)
    if native.returncode == 0 and native.stdout.strip():
        return "ethtool"
    copied = docker_exec(container, "test -x {}".format(TEMP_ETHTOOL), check=False)
    if copied.returncode == 0:
        return TEMP_ETHTOOL
    host_ethtool = shutil.which("ethtool")
    if not host_ethtool:
        raise RuntimeError("ethtool is missing in the node image and on the host")
    if state is not None:
        helpers = state.setdefault("temporary_ethtool_helpers", [])
        if container not in helpers:
            helpers.append(container)
            if state_path is not None:
                _save_state(state_path, state)
    result = subprocess.run(["docker", "cp", host_ethtool,
                             "{}:{}".format(container, TEMP_ETHTOOL)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    if result.returncode:
        raise RuntimeError("could not stage temporary ethtool in {}: {}".format(
            container, (result.stderr or result.stdout).strip()))
    docker_exec(container, "chmod 0755 {}".format(TEMP_ETHTOOL))
    version = docker_exec(container, "{} --version".format(TEMP_ETHTOOL),
                          check=False)
    if version.returncode:
        docker_exec(container, "rm -f {}".format(TEMP_ETHTOOL), check=False)
        raise RuntimeError("host ethtool cannot run in the node image: {}".format(
            (version.stderr or version.stdout).strip()))
    return TEMP_ETHTOOL


def _ethtool(container, args, check=True, state=None, state_path=None):
    command = " ".join([shlex.quote(_ethtool_path(container, state, state_path))] +
                       [shlex.quote(value) for value in args])
    return docker_exec(container, command, check=check)


def _ensure_iptables(container, iptables_deb, libnfnetlink_deb):
    native = docker_exec(container, "iptables --version", check=False)
    if native.returncode == 0:
        return {"installed_by_v3": False,
                "native_version": native.stdout.strip()}
    packages = validate_iptables_packages(iptables_deb, libnfnetlink_deb)
    for package, destination in ((packages["libnfnetlink0"], TEMP_LIBNFNETLINK_DEB),
                                (packages["iptables"], TEMP_IPTABLES_DEB)):
        result = subprocess.run(["docker", "cp", package["path"],
                                 "{}:{}".format(container, destination)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        if result.returncode:
            raise RuntimeError("could not stage {} in {}: {}".format(
                package["package"], container,
                (result.stderr or result.stdout).strip()))
    docker_exec(container, "dpkg -i {} {}".format(
        shlex.quote(TEMP_LIBNFNETLINK_DEB), shlex.quote(TEMP_IPTABLES_DEB)))
    version = docker_exec(container, "iptables --version")
    docker_exec(container, "iptables -t nat -S")
    return {"installed_by_v3": True, "version": version.stdout.strip(),
            "packages": packages}


def _remove_temporary_iptables(container):
    for package in ("iptables", "libnfnetlink0"):
        status = docker_exec(container,
                             "dpkg-query -W -f='${{db:Status-Status}}' {} 2>/dev/null".format(
                                 package), check=False)
        if status.returncode == 0 and status.stdout.strip() in (
                "installed", "unpacked", "half-configured", "half-installed"):
            docker_exec(container, "dpkg -r {}".format(package))
    docker_exec(container, "rm -f {} {}".format(
        shlex.quote(TEMP_IPTABLES_DEB), shlex.quote(TEMP_LIBNFNETLINK_DEB)),
        check=False)


def _install_iptables(egress_id, state, state_path):
    for table, chain in (("filter", FWD_CHAIN), ("nat", NAT_CHAIN)):
        result = docker_exec(egress_id, "iptables -t {} -S {}".format(
            table, chain), check=False)
        if result.returncode == 0:
            raise RuntimeError("owned firewall chain already exists; refusing duplicate setup")
    _iptables(egress_id, ["-N", FWD_CHAIN])
    state["mutations"]["forward_chain_created"] = True
    _save_state(state_path, state)
    _iptables(egress_id, ["-A", FWD_CHAIN, "-i", EGRESS_IF,
                          "-o", "B27-default", "-j", "ACCEPT"])
    _iptables(egress_id, ["-A", FWD_CHAIN, "-i", "B27-default", "-o", EGRESS_IF,
                          "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                          "-j", "ACCEPT"])
    _iptables(egress_id, ["-I", "FORWARD", "1", "-j", FWD_CHAIN])
    state["mutations"]["forward_hook_inserted"] = True
    _save_state(state_path, state)
    _iptables(egress_id, ["-t", "nat", "-N", NAT_CHAIN])
    state["mutations"]["nat_chain_created"] = True
    _save_state(state_path, state)
    _iptables(egress_id, ["-t", "nat", "-A", NAT_CHAIN, "-s",
                          "10.255.253.0/30", "-o", "B27-default", "-j", "MASQUERADE"])
    _iptables(egress_id, ["-t", "nat", "-A", "POSTROUTING", "-j", NAT_CHAIN])
    state["mutations"]["nat_hook_inserted"] = True
    _save_state(state_path, state)


def _restore_routes(container, routes, family=4):
    docker_exec(container, "ip -{} route flush table main default".format(family),
                check=True)
    for route in routes:
        tokens = shlex.split(route)
        if tokens and tokens[0] == "default":
            command = "ip -{} route replace ".format(family) + " ".join(
                shlex.quote(token) for token in tokens)
            docker_exec(container, command)


def _restore_ipv4_host_routes(container, address, routes):
    destination = "{}/32".format(ipaddress.IPv4Address(address))
    result = docker_exec(container, "ip -4 route del {}".format(destination),
                         check=False)
    message = (result.stderr or result.stdout).lower()
    if (result.returncode and "no such process" not in message
            and "no such file or directory" not in message
            and "not found" not in message):
        raise RuntimeError("remove temporary endpoint route failed: {}".format(
            (result.stderr or result.stdout).strip()))
    for route in routes:
        tokens = shlex.split(route)
        if not tokens:
            continue
        command = "ip -4 route replace " + " ".join(
            shlex.quote(token) for token in tokens)
        docker_exec(container, command)


def ensure_client_host_route_via_gre(state_path, address):
    """Pin a discovered host-side endpoint to the GS26 GRE route reversibly."""
    address = str(ipaddress.IPv4Address(address))
    state_path = Path(state_path).resolve()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if (state.get("schema_version") != 1
            or state.get("protocol_id") != "starrynet-browser-tor-route-nat-v3"
            or state.get("installed") is not True):
        raise RuntimeError("cannot add a host route without an installed V3 GRE/NAT state")
    client_id = _container_id(state["client_container_id"])
    _assert_starrynet_container(client_id)
    overrides = state.setdefault("client_host_route_overrides", {})
    existing = overrides.get(address)
    if existing is not None:
        current = _route(client_id, address)
        if (current.get("dev") != "wf-gre0"
                or current.get("via") != CLIENT_PEER):
            raise RuntimeError("recorded host route override is no longer on wf-gre0: {}".format(
                current.get("raw", current)))
        return {"address": address,
                "before": existing.get("before_route"),
                "route": current,
                "changed": existing.get("changed") is True}

    before_route = _route(client_id, address)
    before_host_routes = _exact_ipv4_host_routes(client_id, address)
    override = {"before_route": before_route,
                "before_host_routes": before_host_routes,
                "changed": False,
                "route_after": None}
    overrides[address] = override
    state.setdefault("mutations", {}).setdefault(
        "client_host_route_overrides", {})[address] = False
    state.setdefault("route_checks", {})[
        "client_host_route_before_override_{}".format(address)] = before_route
    _save_state(state_path, state)

    if (before_route.get("dev") != "wf-gre0"
            or before_route.get("via") != CLIENT_PEER):
        override["changed"] = True
        state["mutations"]["client_host_route_overrides"][address] = True
        _save_state(state_path, state)
        docker_exec(client_id,
                    "ip -4 route replace {}/32 via {} dev wf-gre0".format(
                        address, CLIENT_PEER))

    route_after = _route(client_id, address)
    override["route_after"] = route_after
    state["route_checks"][
        "client_host_route_after_override_{}".format(address)] = route_after
    _save_state(state_path, state)
    if (route_after.get("dev") != "wf-gre0"
            or route_after.get("via") != CLIENT_PEER):
        raise RuntimeError("host proxy endpoint route does not use wf-gre0: {}".format(
            route_after.get("raw", route_after)))
    return {"address": address, "before": before_route,
            "route": route_after, "changed": override["changed"]}


def _remove_iptables(egress_id, ownership):
    def optional(args):
        result = _iptables(egress_id, args, check=False)
        if result.returncode == 0:
            return
        message = (result.stderr or result.stdout).lower()
        if ("bad rule" in message
                or "no chain/target/match by that name" in message):
            return
        raise RuntimeError("iptables cleanup failed: {}".format(
            (result.stderr or result.stdout).strip()))

    if ownership.get("forward_hook_inserted"):
        optional(["-D", "FORWARD", "-j", FWD_CHAIN])
    if ownership.get("nat_hook_inserted"):
        optional(["-t", "nat", "-D", "POSTROUTING", "-j", NAT_CHAIN])
    if ownership.get("forward_chain_created"):
        optional(["-F", FWD_CHAIN])
        optional(["-X", FWD_CHAIN])
    if ownership.get("nat_chain_created"):
        optional(["-t", "nat", "-F", NAT_CHAIN])
        optional(["-t", "nat", "-X", NAT_CHAIN])


def cleanup_state(state):
    errors = []
    if (state.get("schema_version") != 1
            or state.get("protocol_id") != "starrynet-browser-tor-route-nat-v3"):
        return ["refusing cleanup because the state file is not a V3 route/NAT record"]
    client_id = state["client_container_id"]
    egress_id = state["egress_container_id"]
    try:
        _assert_starrynet_container(_container_id(client_id))
        _assert_starrynet_container(_container_id(egress_id))
    except (ValueError, RuntimeError) as exc:
        return ["refusing cleanup because the saved container identity is not verified: {}".format(
            exc)]
    mutations = state.get("mutations", {})
    if mutations.get("client_endpoint_host_route_changed"):
        try:
            endpoint = state["fixed_object_endpoint"]["address"]
            old_routes = state["before"]["client"][
                "fixed_object_endpoint_host_routes"]
            _restore_ipv4_host_routes(client_id, endpoint, old_routes)
            mutations["client_endpoint_host_route_changed"] = False
        except Exception as exc:
            errors.append("restore fixed-object endpoint route: " + str(exc))
    for address, override in state.get("client_host_route_overrides", {}).items():
        if not override.get("changed"):
            continue
        try:
            _restore_ipv4_host_routes(
                client_id, address, override.get("before_host_routes", []))
            override["changed"] = False
            mutations.setdefault("client_host_route_overrides", {})[address] = False
        except Exception as exc:
            errors.append("restore host endpoint route {}: {}".format(address, exc))
    for role, container, family, flag in (
            ("client", client_id, 4, "client_ipv4_routes_changed"),
            ("client", client_id, 6, "client_ipv6_routes_changed")):
        if not mutations.get(flag):
            continue
        try:
            key = "default_routes" if family == 4 else "ipv6_default_routes"
            _restore_routes(container, state["before"][role][key], family)
            mutations[flag] = False
        except Exception as exc:
            errors.append("restore routes {}: {}".format(container, exc))
    for container, flag in ((client_id, "client_tunnel_created"),
                            (egress_id, "egress_tunnel_created")):
        if mutations.get(flag):
            result = docker_exec(container, "ip tunnel del wf-gre0", check=False)
            message = (result.stderr or result.stdout).lower()
            if (result.returncode == 0 or "cannot find device" in message
                    or "no such device" in message):
                mutations[flag] = False
            else:
                errors.append("remove GRE tunnel {}: {}".format(
                    container, (result.stderr or result.stdout).strip()))
    firewall_ownership = {
        key: mutations.get(key, False)
        for key in ("forward_chain_created", "forward_hook_inserted",
                    "nat_chain_created", "nat_hook_inserted")}
    firewall_cleanup_failed = False
    if any(firewall_ownership.values()):
        try:
            _remove_iptables(egress_id, firewall_ownership)
            for key in firewall_ownership:
                mutations[key] = False
        except Exception as exc:
            firewall_cleanup_failed = True
            errors.append("remove firewall chains: " + str(exc))
    if ((mutations.get("iptables_package_install_started")
         or mutations.get("iptables_package_installed"))
            and not firewall_cleanup_failed):
        try:
            _remove_temporary_iptables(egress_id)
            mutations["iptables_package_install_started"] = False
            mutations["iptables_package_installed"] = False
        except Exception as exc:
            errors.append("remove temporary iptables from {}: {}".format(
                egress_id, exc))
    if mutations.get("ip_forward_changed"):
        try:
            docker_exec(egress_id, "sysctl -q -w net.ipv4.ip_forward={}".format(
                int(state["before"]["egress"]["ip_forward"])))
            mutations["ip_forward_changed"] = False
        except Exception as exc:
            errors.append("restore ip_forward: " + str(exc))
    if mutations.get("rp_filter_changed"):
        for role, container in (("client", client_id), ("egress", egress_id)):
            for row in state["before"][role]["rp_filter"]:
                try:
                    path, value = row.split("=", 1)
                    name = Path(path).parent.name
                    if not re.match(r"^[A-Za-z0-9_.-]+$", name):
                        raise ValueError("unsafe interface name")
                    docker_exec(container,
                                "sysctl -q -w net.ipv4.conf.{}.rp_filter={}".format(
                                    name, int(value)))
                except Exception as exc:
                    errors.append("restore rp_filter {}: {}".format(role, exc))
        if not errors:
            mutations["rp_filter_changed"] = False
    if mutations.get("client_ipv6_disabled"):
        try:
            before_client = state["before"]["client"]
            all_value = int(before_client["ipv6_disable_all"])
            default_value = int(before_client["ipv6_disable_default"])
            if all_value not in (0, 1) or default_value not in (0, 1):
                raise ValueError("saved IPv6 disable sysctl is not 0 or 1")
            docker_exec(client_id,
                        "sysctl -q -w net.ipv6.conf.default.disable_ipv6={}".format(
                            default_value))
            docker_exec(client_id,
                        "sysctl -q -w net.ipv6.conf.all.disable_ipv6={}".format(
                            all_value))
            mutations["client_ipv6_disabled"] = False
        except Exception as exc:
            errors.append("restore IPv6 state: " + str(exc))
    for container in state.get("temporary_ethtool_helpers", []):
        result = docker_exec(container, "rm -f {}".format(TEMP_ETHTOOL), check=False)
        if result.returncode:
            errors.append("remove temporary ethtool from {}: {}".format(
                container, (result.stderr or result.stdout).strip()))
    return errors


def install(client_id, egress_id, state_path, config_path=DEFAULT_CONFIG,
            iptables_deb=DEFAULT_IPTABLES_DEB,
            libnfnetlink_deb=DEFAULT_LIBNFNETLINK_DEB):
    client_id = _container_id(client_id)
    egress_id = _container_id(egress_id)
    config_path, config_sha256 = validate_runtime_config(config_path)
    runtime_config = json.loads(config_path.read_text(encoding="utf-8"))
    endpoint = runtime_config["network"]["fixed_object_endpoint"]
    endpoint_address = endpoint["address"]
    state_path = Path(state_path).resolve()
    if state_path.exists():
        raise RuntimeError("state file already exists; inspect or clean prior setup first")
    _assert_starrynet_container(client_id)
    _assert_starrynet_container(egress_id)
    if _one_ipv4(client_id, "B26-default") != "9.26.26.10":
        raise RuntimeError("GS26 B26-default address differs from the frozen endpoint")
    if _one_ipv4(egress_id, "B27-default") != "9.27.27.10":
        raise RuntimeError("GS27 B27-default address differs from the frozen endpoint")
    client_underlay = _route(client_id, "9.27.27.10")
    egress_underlay = _route(egress_id, "9.26.26.10")
    if not str(client_underlay.get("dev", "")).startswith("B26-eth"):
        raise RuntimeError("GS26 has no satellite route to GS27 underlay")
    if not str(egress_underlay.get("dev", "")).startswith("B27-eth"):
        raise RuntimeError("GS27 has no satellite route to GS26 underlay")
    client_gre_outer = str(ipaddress.IPv4Address(client_underlay.get("src", "")))
    egress_gre_outer = str(ipaddress.IPv4Address(egress_underlay.get("src", "")))
    if client_gre_outer == egress_gre_outer:
        raise RuntimeError("GS26 and GS27 satellite route sources are not distinct")
    client_gre_peer_route = _route(client_id, egress_gre_outer)
    egress_gre_peer_route = _route(egress_id, client_gre_outer)
    if not str(client_gre_peer_route.get("dev", "")).startswith("B26-eth"):
        raise RuntimeError("GS26 has no satellite route to the GS27 GRE outer endpoint")
    if not str(egress_gre_peer_route.get("dev", "")).startswith("B27-eth"):
        raise RuntimeError("GS27 has no satellite route to the GS26 GRE outer endpoint")
    egress_endpoint_before = _route(egress_id, endpoint_address)
    if egress_endpoint_before.get("dev") != "B27-default":
        raise RuntimeError("GS27 fixed-object endpoint route does not use B27-default")
    client_endpoint_before = _route(client_id, endpoint_address)
    for container in (client_id, egress_id):
        if docker_exec(container, "ip link show dev wf-gre0", check=False).returncode == 0:
            raise RuntimeError("wf-gre0 already exists; refusing to alter an existing tunnel")

    before = _save_namespace_state(client_id, egress_id)
    before["client"]["fixed_object_endpoint_host_routes"] = _exact_ipv4_host_routes(
        client_id, endpoint_address)
    state = {"schema_version": 1,
             "protocol_id": "starrynet-browser-tor-route-nat-v3",
             "runtime_config_path": str(config_path),
             "runtime_config_sha256": config_sha256,
             "client_container_id": client_id,
             "egress_container_id": egress_id,
             "fixed_object_endpoint": endpoint,
             "client_host_route_overrides": {},
             "gre_outer_endpoints": {
                 "client": client_gre_outer,
                 "egress": egress_gre_outer,
                 "selection": "source address from route to the peer ground-station address"},
             "gre_outer_endpoints_current": {
                 "client": client_gre_outer,
                 "egress": egress_gre_outer,
                 "selection": "source address from route to the peer ground-station address"},
             "before": before,
             "mutations": {
                 "rp_filter_changed": False,
                 "client_tunnel_created": False,
                 "egress_tunnel_created": False,
                 "ip_forward_changed": False,
                 "forward_chain_created": False,
                 "forward_hook_inserted": False,
                 "nat_chain_created": False,
                 "nat_hook_inserted": False,
                 "iptables_package_install_started": False,
                 "iptables_package_installed": False,
                 "client_ipv6_disabled": False,
                 "client_ipv4_routes_changed": False,
                 "client_endpoint_host_route_changed": False,
                 "client_host_route_overrides": {},
                 "client_ipv6_routes_changed": False},
             "installed": False}
    _save_state(state_path, state)
    try:
        state["mutations"]["rp_filter_changed"] = True
        _save_state(state_path, state)
        _set_rp_filter(client_id, before["client"]["rp_filter"], 0)
        _set_rp_filter(egress_id, before["egress"]["rp_filter"], 0)
        docker_exec(client_id,
                    "ip tunnel add wf-gre0 mode gre local {} remote {} key {} ttl 64".format(
                        client_gre_outer, egress_gre_outer, GRE_KEY))
        state["mutations"]["client_tunnel_created"] = True
        _save_state(state_path, state)
        docker_exec(egress_id,
                    "ip tunnel add wf-gre0 mode gre local {} remote {} key {} ttl 64".format(
                        egress_gre_outer, client_gre_outer, GRE_KEY))
        state["mutations"]["egress_tunnel_created"] = True
        _save_state(state_path, state)
        docker_exec(client_id, "ip address add {} peer {} dev wf-gre0".format(
            CLIENT_GRE, CLIENT_PEER))
        docker_exec(egress_id, "ip address add {} peer {} dev wf-gre0".format(
            EGRESS_GRE, EGRESS_PEER))
        docker_exec(client_id, "ip link set dev wf-gre0 up")
        docker_exec(egress_id, "ip link set dev wf-gre0 up")
        state["gre_offloads"] = {
            "client": _disable_offloads(client_id, "wf-gre0", state, state_path),
            "egress": _disable_offloads(egress_id, "wf-gre0", state, state_path)}
        docker_exec(egress_id, "sysctl -q -w net.ipv4.ip_forward=1")
        state["mutations"]["ip_forward_changed"] = True
        _save_state(state_path, state)
        native_iptables = docker_exec(
            egress_id, "iptables --version", check=False).returncode == 0
        state["mutations"]["iptables_package_install_started"] = not native_iptables
        _save_state(state_path, state)
        tooling = _ensure_iptables(egress_id, iptables_deb, libnfnetlink_deb)
        state["mutations"]["iptables_package_install_started"] = False
        state["mutations"]["iptables_package_installed"] = tooling["installed_by_v3"]
        state["temporary_iptables_tooling"] = tooling
        _save_state(state_path, state)
        _install_iptables(egress_id, state, state_path)
        ipv6_before = before["client"]
        needs_ipv6_change = (ipv6_before["ipv6_disable_all"] != "1"
                             or ipv6_before["ipv6_disable_default"] != "1")
        if needs_ipv6_change:
            state["mutations"]["client_ipv6_disabled"] = True
            _save_state(state_path, state)
            docker_exec(client_id,
                        "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1")
            docker_exec(client_id,
                        "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1")
        for setting in ("net.ipv6.conf.all.disable_ipv6",
                        "net.ipv6.conf.default.disable_ipv6"):
            if docker_exec(client_id, "sysctl -n {}".format(setting)).stdout.strip() != "1":
                raise RuntimeError("could not verify client IPv6 disable setting: " + setting)
        state["mutations"]["client_ipv4_routes_changed"] = True
        _save_state(state_path, state)
        docker_exec(client_id, "ip -4 route flush table main default")
        state["mutations"]["client_ipv6_routes_changed"] = True
        _save_state(state_path, state)
        docker_exec(client_id, "ip -6 route flush table main default")
        docker_exec(client_id, "ip -4 route add default via {} dev wf-gre0".format(
            CLIENT_PEER))
        state["mutations"]["client_endpoint_host_route_changed"] = True
        _save_state(state_path, state)
        docker_exec(client_id,
                    "ip -4 route replace {}/32 via {} dev wf-gre0".format(
                        endpoint_address, CLIENT_PEER))
        client_outer = _route(client_id, egress_gre_outer)
        client_public = _route(client_id, "1.1.1.1")
        client_endpoint = _route(client_id, endpoint_address)
        egress_outer = _route(egress_id, client_gre_outer)
        egress_endpoint_after = _route(egress_id, endpoint_address)
        client_tunnel_outer = _tunnel_outer_endpoints(client_id)
        egress_tunnel_outer = _tunnel_outer_endpoints(egress_id)
        if not str(client_outer.get("dev", "")).startswith("B26-eth"):
            raise RuntimeError("GRE outer route bypasses the dynamic satellite path")
        if not str(egress_outer.get("dev", "")).startswith("B27-eth"):
            raise RuntimeError("GS27 return route bypasses the dynamic satellite path")
        if client_public.get("dev") != "wf-gre0":
            raise RuntimeError("GS26 public route does not use the GRE tunnel")
        if client_endpoint.get("dev") != "wf-gre0":
            raise RuntimeError("GS26 fixed-object endpoint route does not use wf-gre0")
        if egress_endpoint_after.get("dev") != "B27-default":
            raise RuntimeError("GS27 fixed-object endpoint route does not use B27-default")
        state["route_checks"] = {
            "client_to_egress_underlay_before_install": client_underlay,
            "egress_to_client_underlay_before_install": egress_underlay,
            "client_to_egress_gre_outer_before_install": client_gre_peer_route,
            "egress_to_client_gre_outer_before_install": egress_gre_peer_route,
            "gre_outer_endpoints": state["gre_outer_endpoints"],
            "client_gre_outer_route_after_install": client_outer,
            "egress_gre_outer_route_after_install": egress_outer,
            "client_gre_tunnel_outer_after_install": client_tunnel_outer,
            "egress_gre_tunnel_outer_after_install": egress_tunnel_outer,
            "client_public_route_after_install": client_public,
            "client_fixed_object_route_before_install": client_endpoint_before,
            "client_fixed_object_route_after_install": client_endpoint,
            "egress_fixed_object_route_before_install": egress_endpoint_before,
            "egress_fixed_object_route_after_install": egress_endpoint_after}
        state["installed"] = True
        _save_state(state_path, state)
        return state
    except BaseException as exc:
        rollback_errors = cleanup_state(state)
        if rollback_errors:
            state["rollback_errors"] = rollback_errors
            state["installed"] = False
            _save_state(state_path, state)
            raise RuntimeError(
                "route/NAT setup failed and rollback is incomplete; inspect {}: {}".format(
                    state_path, "; ".join(rollback_errors))) from exc
        try:
            state_path.unlink()
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    plan = sub.add_parser("plan")
    plan.add_argument("--client-container", required=True)
    plan.add_argument("--egress-container", required=True)
    plan.add_argument("--client-underlay", default="9.26.26.10")
    plan.add_argument("--egress-underlay", default="9.27.27.10")
    plan.add_argument("--config", default=str(DEFAULT_CONFIG))
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--client-container", required=True)
    install_parser.add_argument("--egress-container", required=True)
    install_parser.add_argument("--state", required=True)
    install_parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    install_parser.add_argument("--apply", action="store_true",
                                help="acknowledge namespace route and firewall changes")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--state", required=True)
    verify_parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("--state", required=True)
    cleanup_parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            config_path, config_sha256 = validate_runtime_config(args.config)
            runtime_config = json.loads(config_path.read_text(encoding="utf-8"))
            result = build_plan(args.client_container, args.egress_container,
                                args.client_underlay, args.egress_underlay)
            result["status"] = "planned"
            result["runtime_config_path"] = str(config_path)
            result["runtime_config_sha256"] = config_sha256
            result["fixed_object_endpoint"] = runtime_config["network"]["fixed_object_endpoint"]
        elif args.command == "install":
            if not args.apply:
                raise ValueError("install requires --apply; run plan first")
            result = install(args.client_container, args.egress_container,
                             args.state, args.config)
        elif args.command == "verify":
            state = json.loads(Path(args.state).read_text(encoding="utf-8"))
            _config_path, config_sha256 = validate_runtime_config(args.config)
            runtime_config = json.loads(Path(args.config).read_text(encoding="utf-8"))
            endpoint = runtime_config["network"]["fixed_object_endpoint"]
            client_id = state["client_container_id"]
            egress_id = state["egress_container_id"]
            gre_outer = state.get("gre_outer_endpoints_current",
                                  state["gre_outer_endpoints"])
            client_gre_outer = str(ipaddress.IPv4Address(gre_outer["client"]))
            egress_gre_outer = str(ipaddress.IPv4Address(gre_outer["egress"]))
            client_underlay_route = _route(client_id, "9.27.27.10")
            egress_underlay_route = _route(egress_id, "9.26.26.10")
            client_route = _route(client_id, "1.1.1.1")
            client_endpoint_route = _route(client_id, endpoint["address"])
            client_host_route_results = {
                address: _route(client_id, address)
                for address, override in state.get(
                    "client_host_route_overrides", {}).items()
                if override.get("changed")}
            outer_route = _route(client_id, egress_gre_outer)
            egress_outer_route = _route(egress_id, client_gre_outer)
            client_tunnel_outer = _tunnel_outer_endpoints(client_id)
            egress_tunnel_outer = _tunnel_outer_endpoints(egress_id)
            egress_route = _route(egress_id, endpoint["address"])
            forward_rules = docker_exec(
                egress_id, "iptables -S {}".format(FWD_CHAIN)).stdout.splitlines()
            nat_rules = docker_exec(
                egress_id, "iptables -t nat -S {}".format(NAT_CHAIN)).stdout.splitlines()
            forward_hook = _iptables(
                egress_id, ["-C", "FORWARD", "-j", FWD_CHAIN], check=False)
            nat_hook = _iptables(
                egress_id, ["-t", "nat", "-C", "POSTROUTING", "-j", NAT_CHAIN],
                check=False)
            forwarding_enabled = docker_exec(
                egress_id, "sysctl -n net.ipv4.ip_forward").stdout.strip()
            client_offloads = _offloads_disabled(client_id, "wf-gre0")
            egress_offloads = _offloads_disabled(egress_id, "wf-gre0")
            ipv6_disable_all = docker_exec(
                client_id, "sysctl -n net.ipv6.conf.all.disable_ipv6").stdout.strip()
            ipv6_disable_default = docker_exec(
                client_id, "sysctl -n net.ipv6.conf.default.disable_ipv6").stdout.strip()
            checks = {
                "installed_state": state.get("installed") is True,
                "runtime_config_unchanged": (
                    state.get("runtime_config_sha256") == config_sha256),
                "fixed_object_endpoint_unchanged": (
                    state.get("fixed_object_endpoint") == endpoint),
                "client_default_uses_gre": client_route.get("dev") == "wf-gre0",
                "client_fixed_object_route_uses_gre": (
                    client_endpoint_route.get("dev") == "wf-gre0"),
                "client_host_proxy_gateway_routes_use_gre": all(
                    route.get("dev") == "wf-gre0"
                    and route.get("via") == CLIENT_PEER
                    for route in client_host_route_results.values()),
                "client_has_no_ipv6_default_bypass": (
                    ipv6_disable_all == "1" and ipv6_disable_default == "1"
                    and not docker_exec(
                        client_id, "ip -6 route show table main default").stdout.strip()),
                "gre_outer_uses_satellite": str(outer_route.get("dev", "")).startswith("B26-eth"),
                "egress_return_outer_uses_satellite": str(
                    egress_outer_route.get("dev", "")).startswith("B27-eth"),
                "gre_outer_endpoints_use_distinct_route_sources": (
                    client_gre_outer != egress_gre_outer),
                "gre_outer_endpoints_follow_current_satellite_routes": (
                    client_underlay_route.get("src") == client_gre_outer
                    and str(client_underlay_route.get("dev", "")).startswith("B26-eth")
                    and egress_underlay_route.get("src") == egress_gre_outer
                    and str(egress_underlay_route.get("dev", "")).startswith("B27-eth")),
                "client_gre_tunnel_uses_route_selected_endpoints": (
                    client_tunnel_outer.get("local") == client_gre_outer
                    and client_tunnel_outer.get("remote") == egress_gre_outer),
                "egress_gre_tunnel_uses_route_selected_endpoints": (
                    egress_tunnel_outer.get("local") == egress_gre_outer
                    and egress_tunnel_outer.get("remote") == client_gre_outer),
                "egress_fixed_object_route_uses_public_uplink": (
                    egress_route.get("dev") == "B27-default"),
                "egress_ipv4_forwarding_enabled": forwarding_enabled == "1",
                "forward_chain_accepts_gre_to_uplink": any(
                    "-i wf-gre0 -o B27-default -j ACCEPT" in rule
                    for rule in forward_rules),
                "forward_chain_allows_stateful_return": any(
                    "-i B27-default -o wf-gre0" in rule
                    and "--ctstate" in rule
                    and ("ESTABLISHED,RELATED" in rule
                         or "RELATED,ESTABLISHED" in rule)
                    for rule in forward_rules),
                "forward_chain_hooked": forward_hook.returncode == 0,
                "nat_chain_has_gre_masquerade": any(
                    "-s 10.255.253.0/30" in rule
                    and "-o B27-default" in rule and "-j MASQUERADE" in rule
                    for rule in nat_rules),
                "nat_chain_hooked": nat_hook.returncode == 0,
                "capture_offloads_disabled": (
                    all(value is True for value in client_offloads.values())
                    and all(value is True for value in egress_offloads.values()))}
            result = {"status": "passed" if all(checks.values()) else "failed",
                      "checks": checks,
                      "client_host_proxy_gateway_routes": client_host_route_results,
                      "firewall_rules": {"forward": forward_rules,
                                         "nat": nat_rules},
                      "scientific_fidelity_verified": False}
        elif args.command == "cleanup":
            if not args.apply:
                raise ValueError("cleanup requires --apply")
            state_path = Path(args.state)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            errors = cleanup_state(state)
            result = {"status": "cleaned" if not errors else "cleanup_failed",
                      "errors": errors}
            if not errors:
                state["installed"] = False
            _save_state(state_path, state)
        else:
            parser.print_help()
            return 0
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        result = {"status": "error", "errors": [str(exc)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in ("planned", "passed", "cleaned") else 2


if __name__ == "__main__":
    sys.exit(main())
