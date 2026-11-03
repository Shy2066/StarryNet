#!/usr/bin/env python3
"""Derive a navigation-bounded, all-flow V3 trace from a wf-gre0 PCAP.

The V2 extractor requires one peer address and port. V3 captures the complete
client-side GRE interface and narrows the derived trace with recorded page
navigation markers instead.
"""
import argparse
import calendar
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc_epoch(value):
    if not isinstance(value, str):
        raise ValueError("UTC marker must be a string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    else:
        text = re.sub(r"([+-][0-9]{2}):([0-9]{2})$", r"\1\2", text)
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(\d+))?([+-]\d{4})$", text)
    if not match:
        raise ValueError("UTC marker must be ISO-8601 with an explicit timezone")
    whole = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    epoch = float(calendar.timegm(whole.timetuple()))
    fraction = float("0." + match.group(2)) if match.group(2) else 0.0
    offset_text = match.group(3)
    sign = 1 if offset_text[0] == "+" else -1
    offset_seconds = sign * (
        int(offset_text[1:3]) * 3600 + int(offset_text[3:5]) * 60)
    return epoch + fraction - offset_seconds


def read_time_boundaries(value):
    if isinstance(value, dict) and isinstance(value.get("time_boundaries"), dict):
        value = value["time_boundaries"]
    required_utc = (
        "raw_capture_start_utc", "navigation_start_utc",
        "navigation_complete_utc", "raw_capture_end_utc",
    )
    required_monotonic = (
        "raw_capture_start_monotonic", "navigation_start_monotonic",
        "navigation_complete_monotonic", "raw_capture_end_monotonic",
    )
    missing = [key for key in required_utc + required_monotonic
               if key not in value]
    if missing:
        raise ValueError("time_boundaries is missing: " + ", ".join(missing))
    utc = {key: parse_utc_epoch(value[key]) for key in required_utc}
    monotonic = {}
    for key in required_monotonic:
        current = value[key]
        if (not isinstance(current, (int, float))
                or isinstance(current, bool)):
            raise ValueError(key + " must be numeric")
        monotonic[key] = float(current)
    if not (utc["raw_capture_start_utc"] <= utc["navigation_start_utc"]
            <= utc["navigation_complete_utc"] <= utc["raw_capture_end_utc"]):
        raise ValueError("UTC capture and navigation boundaries are out of order")
    if not (monotonic["raw_capture_start_monotonic"]
            <= monotonic["navigation_start_monotonic"]
            <= monotonic["navigation_complete_monotonic"]
            <= monotonic["raw_capture_end_monotonic"]):
        raise ValueError("monotonic capture and navigation boundaries are out of order")
    for key in ("clock_anchor_monotonic", "topology_start_seconds",
                "topology_end_seconds"):
        current = value.get(key)
        if (not isinstance(current, (int, float))
                or isinstance(current, bool)):
            raise ValueError(key + " must be numeric")
    parse_utc_epoch(value.get("clock_anchor_utc"))
    if value["topology_start_seconds"] > value["topology_end_seconds"]:
        raise ValueError("topology logical-time boundaries are out of order")
    return {"utc_epoch": utc, "monotonic": monotonic}


def extract_trace_rows(tshark_output, time_boundaries, client_ip):
    boundaries = read_time_boundaries(time_boundaries)
    client = str(ipaddress.ip_address(client_ip))
    start = boundaries["utc_epoch"]["navigation_start_utc"]
    end = boundaries["utc_epoch"]["navigation_complete_utc"]
    rows = []
    raw_ip_packets = 0
    outside_window_packets = 0
    unclassified_packets = 0
    for line_number, line in enumerate(tshark_output.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            raise ValueError("tshark row {} has fewer than four fields".format(
                line_number))
        try:
            epoch = float(fields[0])
            source = str(ipaddress.ip_address(fields[1]))
            destination = str(ipaddress.ip_address(fields[2]))
            packet_bytes = int(fields[3])
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid tshark packet row {}: {}".format(
                line_number, exc))
        if packet_bytes <= 0:
            raise ValueError("frame.len must be positive")
        raw_ip_packets += 1
        if epoch < start or epoch > end:
            outside_window_packets += 1
            continue
        if source == client:
            direction = 1
        elif destination == client:
            direction = -1
        else:
            unclassified_packets += 1
            continue
        rows.append((max(0.0, epoch - start), direction, packet_bytes))
    audit = {
        "raw_ip_packet_count": raw_ip_packets,
        "navigation_window_packet_count": len(rows) + unclassified_packets,
        "trace_row_count": len(rows),
        "outside_navigation_window_packet_count": outside_window_packets,
        "unclassified_navigation_window_packet_count": unclassified_packets,
        "direction_counts": {
            "client_to_network": sum(1 for row in rows if row[1] == 1),
            "network_to_client": sum(1 for row in rows if row[1] == -1),
        },
        "client_ip": client,
        "navigation_duration_seconds": end - start,
    }
    return rows, audit


def tshark_rows(pcap_path, tshark_path=None):
    binary = tshark_path or shutil.which("tshark")
    if not binary:
        raise RuntimeError("tshark executable was not found")
    command = [binary, "-r", str(pcap_path), "-Y", "ip", "-T", "fields",
               "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
               "-e", "frame.len"]
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode:
        raise RuntimeError("tshark failed: " + (result.stderr or result.stdout).strip())
    return result.stdout


def write_json(path, value):
    path = Path(path)
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    temporary.replace(path)


def extract(pcap_path, time_boundaries_path, client_ip, output_dir,
            tshark_path=None):
    pcap_path = Path(pcap_path).resolve()
    boundaries_path = Path(time_boundaries_path).resolve()
    output_dir = Path(output_dir).resolve()
    if not pcap_path.is_file():
        raise ValueError("PCAP does not exist: " + str(pcap_path))
    boundaries = json.loads(boundaries_path.read_text(encoding="utf-8"))
    rows, row_audit = extract_trace_rows(
        tshark_rows(pcap_path, tshark_path), boundaries, client_ip)
    output_dir.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / "trace.tsv"
    with trace_path.open("w", encoding="utf-8") as stream:
        stream.write("timestamp_s\tdirection\tpacket_size_bytes\n")
        for timestamp, direction, packet_bytes in rows:
            stream.write("{:.9f}\t{}\t{}\n".format(
                timestamp, direction, packet_bytes))
    passed = bool(rows and row_audit["unclassified_navigation_window_packet_count"] == 0)
    source_path = Path(__file__).resolve()
    packet_audit = dict(row_audit)
    packet_audit.update({
        "schema_version": 1,
        "passed": passed,
        "capture_packet_count": row_audit["raw_ip_packet_count"],
        "pcap_path": str(pcap_path),
        "pcap_sha256": sha256_file(pcap_path),
        "trace_path": str(trace_path),
        "trace_sha256": sha256_file(trace_path),
        "auditor_path": str(source_path),
        "auditor_sha256": sha256_file(source_path),
        "capture_interface_contract": "wf-gre0 all IPv4 flows; navigation-window filter",
        "errors": ([] if rows else ["no client packets found in navigation window"]),
    })
    if row_audit["unclassified_navigation_window_packet_count"]:
        packet_audit["errors"].append(
            "navigation-window packets did not use the frozen GS26 client IP")
    audit_path = output_dir / "packet_audit.json"
    write_json(audit_path, packet_audit)
    return {"passed": passed, "trace": str(trace_path),
            "packet_audit": str(audit_path), "packet_audit_data": packet_audit}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--time-boundaries", required=True,
                        help="JSON with V3 time_boundaries fields")
    parser.add_argument("--client-ip", required=True,
                        help="GS26 GRE client IPv4 address, normally 10.255.253.1")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--tshark", help="explicit tshark executable path")
    args = parser.parse_args(argv)
    try:
        result = extract(args.pcap, args.time_boundaries, args.client_ip,
                         args.output_dir, args.tshark)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result = {"passed": False, "errors": [str(exc)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") is True else 2


if __name__ == "__main__":
    sys.exit(main())
