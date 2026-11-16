#!/usr/bin/env python3
"""Generate auditable dynamic StarryNet replay traces (E_v4).

The command has two deliberately separate responsibilities.  ``plan`` and
``verify`` are offline and safe to run without Docker.  ``run`` is the only
subcommand that creates StarryNet resources.  It runs a pair of long-lived TCP/UDP
agents in GS26/GS27 and records the client-side observation trace.
"""

import argparse
import datetime as datetime_module
import fcntl
import gzip
import hashlib
import ipaddress
import itertools
import math
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict, deque

from research2_evidence import build_client_trace, verify_events


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_RE = re.compile(r"^(?P<class_id>[0-9]+)-(?P<repeat_id>[0-9]+)$")
SCHEMA_VERSION = 1
PLAN_VERSION = "e_replay_v4_plan_2"
AGENT_SOURCE = Path(__file__).with_name("e_replay_agent.py")
RUNTIME_SOURCE_FILES = (
    ROOT / "starrynet" / "sn_orchestrater.py",
    ROOT / "starrynet" / "sn_synchronizer.py",
    ROOT / "starrynet" / "sn_observer.py",
    ROOT / "starrynet" / "sn_thread.py",
    ROOT / "starrynet" / "sn_utils.py",
    ROOT / "starrynet" / "local.py",
    ROOT / "starrynet" / "resource_scope.py",
)
FROZEN_HELPER_FILES = (Path(__file__).with_name("research2_evidence.py"),)
DEFAULT_INPUT = ROOT / "dataset" / "tor_fiber"
# Keep generated artifacts and the finalized E dataset together on the
# requested large-volume mount.  The source F dataset remains in the repo.
DEFAULT_OUTPUT_ROOT = ROOT
DEFAULT_RUN_ROOT = ROOT / "artifacts" / "research2_tcp_drift" / "unbatched" / "runs"
DEFAULT_DATASET = ROOT / "artifacts" / "research2_tcp_drift" / "unbatched" / "dataset"
CLIENT_NODE = 26
REMOTE_NODE = 27
UDP_PORT = 19999
REMOTE_UDP_PORT = 20000
UDP_PORTS = (UDP_PORT, REMOTE_UDP_PORT)
PAYLOAD_BYTES = 512
TAIL_SECONDS = 0.5
TCP_COMPLETION_TIMEOUT_SECONDS = 120.0
TCP_CONNECT_TIMEOUT_SECONDS = 30.0
TCP_COORDINATOR_WAIT_SECONDS = 15.0
TCP_STATE_INTERVAL_SECONDS = 0.5
TIMESTAMP_TOLERANCE = 0.005
GUARD_SECONDS = 0.5
DISPATCH_LEAD_SECONDS = 0.5
WARMUP_SECONDS = 15.0
SESSION_TAIL_SECONDS = 60.0
SAMPLE_TIMEOUT_MARGIN_SECONDS = 15.0
SESSION_TIMEOUT_MARGIN_SECONDS = 15 * 60.0
ROUTE_ROLLOVER_TIMEOUT_SECONDS = 120.0
MAX_SESSION_SETUP_ATTEMPTS = 3
PILOT_IDS = {0, 18, 37, 56, 74}
PILOT_REPEATS = set(range(10))
GS = [[50.110924, 8.682127], [46.635700, 14.311817]]
P2_CONFIG = {
    "Name": "e-replay-v4",
    "Altitude (km)": 550,
    "Cycle (s)": 5731,
    "Inclination": 53,
    "Phase shift": 1,
    "# of orbit": 5,
    "# of satellites": 5,
    "Duration (s)": 9000,
    "update_time (s)": 10,
    "satellite link bandwidth (\"X\" Gbps)": 5,
    "sat-ground bandwidth (\"X\" Gbps)": 5,
    "satellite link loss (\"X\"% )": 1,
    "sat-ground loss (\"X\"% )": 1,
    "GS number": 2,
    "antenna number": 1,
    "antenna_inclination_angle": 25,
    "remote_machine_IP": "",
    "remote_machine_username": "",
    "remote_machine_password": "",
    "Satellite link": "grid",
    "IP version": "IPv4",
    "Intra-AS routing": "OSPF",
    "Inter-AS routing": "BGP",
    "Link policy": "LeastDelay",
    "Handover policy": "instant handover",
    "multi-machine (\"0\" for no, \"1\" for yes)": 0,
}


_ATTEMPT_FILE_CACHE = {}


class ReplayError(RuntimeError):
    pass


class SatelliteRouteUnavailable(ReplayError):
    """The current topology instance did not regain an endpoint route."""


def monotonic_ns():
    """Return monotonic nanoseconds on Python versions before 3.7 too.

    The StarryNet conda environment currently uses Python 3.6, where the
    stdlib does not yet expose ``time.monotonic_ns``.  The replay protocol
    only needs a shared monotonic reference; converting the available
    monotonic seconds to nanoseconds preserves that contract on old Python.
    """
    native = getattr(time, "monotonic_ns", None)
    if native is not None:
        return native()
    return int(time.monotonic() * 1000000000)


def utc_now():
    return datetime_module.datetime.now(datetime_module.timezone.utc).isoformat()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def gzip_artifact(path):
    """Losslessly gzip one closed artifact, hash both representations, then unlink raw."""
    path = Path(path)
    if not path.is_file():
        raise ReplayError("cannot compress missing artifact: " + str(path))
    target = path.with_name(path.name + ".gz")
    temporary = target.with_name(target.name + ".tmp-" + str(os.getpid()))
    if target.exists():
        raise ReplayError("refusing to overwrite compressed artifact: " + str(target))
    original_bytes = path.stat().st_size
    original_sha256 = sha256_file(path)
    try:
        with path.open("rb") as source, temporary.open("wb") as raw_output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as zipped:
                shutil.copyfileobj(source, zipped, 1024 * 1024)
            raw_output.flush()
            os.fsync(raw_output.fileno())
        os.replace(str(temporary), str(target))
        compressed_sha256 = sha256_file(target)
        compressed_bytes = target.stat().st_size
        # Verify the gzip stream and the complete original hash before deleting raw.
        digest = hashlib.sha256()
        with gzip.open(str(target), "rb") as restored:
            for block in iter(lambda: restored.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != original_sha256:
            target.unlink()
            raise ReplayError("gzip round-trip hash mismatch: " + str(path))
        path.unlink()
        return {"path": str(target), "compression": "gzip",
                "original_path": str(path), "original_bytes": original_bytes,
                "original_sha256": original_sha256,
                "compressed_bytes": compressed_bytes,
                "compressed_sha256": compressed_sha256}
    finally:
        if temporary.exists():
            temporary.unlink()


def write_gzip_jsonl(path, rows):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp-" + str(os.getpid()))
    digest = hashlib.sha256()
    count = 0
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                for row in rows:
                    payload = (json.dumps(row, sort_keys=True, separators=(",", ":"))
                               + "\n").encode("utf-8")
                    digest.update(payload)
                    zipped.write(payload)
                    count += 1
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(str(temporary), str(path))
        return {"path": str(path), "records": count,
                "uncompressed_sha256": digest.hexdigest(),
                "compressed_sha256": sha256_file(path),
                "compressed_bytes": path.stat().st_size}
    finally:
        if temporary.exists():
            temporary.unlink()


def open_text_artifact(path):
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(str(path), "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def compressed_pcap_info(path, expected):
    """Validate a compressed PCAP using a private temporary uncompressed copy."""
    path = Path(path)
    if not path.is_file() or sha256_file(path) != expected.get("compressed_sha256"):
        raise ReplayError("compressed PCAP missing or hash mismatch: " + str(path))
    handle = tempfile.NamedTemporaryFile(prefix="research2-pcap-", suffix=".pcap",
                                         delete=False)
    temporary = Path(handle.name)
    handle.close()
    digest = hashlib.sha256()
    try:
        with gzip.open(str(path), "rb") as source, temporary.open("wb") as output:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != expected.get("original_sha256"):
            raise ReplayError("decompressed PCAP hash mismatch: " + str(path))
        info = validate_pcap(temporary)
        if int(info.get("bytes", -1)) != int(expected.get("original_bytes", -2)):
            raise ReplayError("decompressed PCAP size mismatch: " + str(path))
        return info
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def read_agent_sample(log_path, sample_id, token):
    matches = []
    with open_text_artifact(log_path) as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise ReplayError("invalid agent JSONL at {0}:{1}: {2}".format(
                    log_path, line_number, exc))
            if row.get("type") == "sample_done" and row.get("sample_id") == sample_id:
                records = row.get("records") or []
                row_token = row.get("sample_token")
                if row_token is None and records:
                    row_token = records[0].get("sample_token")
                if row_token == token:
                    matches.append(row)
    if len(matches) != 1:
        raise ReplayError("expected one matching {0} sample row in {1}, found {2}".format(
            sample_id, log_path, len(matches)))
    return matches[0]


def iter_agent_samples(log_path):
    """Stream only completed sample rows from one compressed agent log."""
    with open_text_artifact(log_path) as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise ReplayError("invalid agent JSONL at {0}:{1}: {2}".format(
                    log_path, line_number, exc))
            if row.get("type") == "sample_done":
                yield row


def verify_gzip_jsonl_rows(path, expected_rows, metadata):
    """Check a compressed mapping line-by-line without trusting its manifest."""
    path = Path(path)
    if (not path.is_file()
            or sha256_file(path) != metadata.get("compressed_sha256")):
        raise ReplayError("trace mapping gzip file missing or hash mismatch")
    digest = hashlib.sha256()
    count = 0
    with gzip.open(str(path), "rt", encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise ReplayError("invalid trace mapping JSONL: " + str(exc))
            if count >= len(expected_rows) or row != expected_rows[count]:
                raise ReplayError("trace mapping row differs at sequence index "
                                  + str(count))
            digest.update((json.dumps(row, sort_keys=True, separators=(",", ":"))
                           + "\n").encode("utf-8"))
            count += 1
    if count != len(expected_rows) or count != metadata.get("records"):
        raise ReplayError("trace mapping row count differs from the verified events")
    if digest.hexdigest() != metadata.get("uncompressed_sha256"):
        raise ReplayError("trace mapping uncompressed hash mismatch")


def build_legacy_udp_trace(client_row):
    """Preserve the historical observed-UDP trace semantics.

    UDP records represent datagram sends/receives and have no TCP send-complete
    timestamp. This path deliberately does not claim exact source-event
    completion; strict two-endpoint event verification is a TCP protocol gate.
    """
    selected = []
    for record in client_row.get("records", []):
        if (record.get("action"), record.get("direction")) not in (
                ("send", 1), ("recv", -1)):
            continue
        observed_ns = record.get("observed_ns")
        if not isinstance(observed_ns, int) or observed_ns < 0:
            raise ValueError("UDP client record has invalid observed_ns")
        selected.append({"sequence": int(record["sequence"]),
                         "action": record["action"],
                         "direction": int(record["direction"]),
                         "selected_ns": observed_ns,
                         "scheduled_offset_ns": int(record["scheduled_offset_ns"])})
    selected.sort(key=lambda item: (item["selected_ns"], item["sequence"]))
    if not selected:
        return "", []
    first_ns = selected[0]["selected_ns"]
    lines, mapping = [], []
    for row in selected:
        timestamp = (row["selected_ns"] - first_ns) / 1e9
        lines.append("{0:.9f}\t{1}\n".format(timestamp, row["direction"]))
        mapping.append({"sequence": row["sequence"], "action": row["action"],
                        "direction": row["direction"],
                        "selected_ns": row["selected_ns"],
                        "timestamp": timestamp,
                        "scheduled_offset_ns": row["scheduled_offset_ns"]})
    return "".join(lines), mapping


def verify_tcp_sample_artifacts(manifest, evidence_row, client_row, remote_row):
    """Rebuild the trace from persisted two-endpoint application events."""
    sample_id = evidence_row["sample_id"]
    token = sample_token(sample_id)
    if (client_row.get("sample_id") != sample_id
            or remote_row.get("sample_id") != sample_id
            or client_row.get("sample_token") != token
            or remote_row.get("sample_token") != token):
        raise ReplayError("persisted endpoint sample identity/token mismatch: " + sample_id)
    sample = {key: evidence_row.get(key) for key in
              ("sample_id", "source_path", "source_sha256")}
    events, _source_info = load_sample_events(sample)
    speed = float(manifest.get("speed", 1.0))
    scheduled = [dict(event, offset_ns=int(round(event["offset_ns"] / speed)))
                 for event in events]
    checked = verify_events(scheduled, client_row, remote_row,
                            payload_bytes=PAYLOAD_BYTES)
    if (checked.get("sample_id") != sample_id
            or checked.get("sample_token") != token
            or checked.get("passed") is not True):
        raise ReplayError("persisted endpoint event stream failed strict verification: "
                          + sample_id + " " + "; ".join(checked.get("errors", [])))
    stored = evidence_row.get("event_verification") or {}
    for key in ("passed", "event_count", "client_record_count",
                "remote_record_count", "sample_id", "sample_token"):
        if stored.get(key) != checked.get(key):
            raise ReplayError("stored event verification differs at {0}: {1}".format(
                key, sample_id))
    trace_text, mapping_rows = build_client_trace(client_row)
    root = sample_root(manifest, sample_id)
    trace_path = root / "trace"
    if not trace_path.is_file() or trace_path.read_text(encoding="utf-8") != trace_text:
        raise ReplayError("client application event export differs from endpoint evidence: "
                          + sample_id)
    if sha256_file(trace_path) != evidence_row.get("trace_sha256"):
        raise ReplayError("client event trace SHA256 differs from persisted evidence: "
                          + sample_id)
    attempt_id = evidence_row.get("attempt_id")
    attempt_root = root / "attempts" / str(attempt_id)
    if Path(evidence_row.get("attempt_artifact_dir", "")).resolve() != attempt_root.resolve():
        raise ReplayError("attempt evidence path is not bound to the frozen sample root: "
                          + sample_id)
    mapping = evidence_row.get("trace_mapping") or {}
    mapping_path = attempt_root / "trace_mapping.jsonl.gz"
    if Path(mapping.get("path", "")).resolve() != mapping_path.resolve():
        raise ReplayError("trace mapping path is not bound to its attempt: " + sample_id)
    verify_gzip_jsonl_rows(mapping_path, mapping_rows, mapping)
    if (evidence_row.get("client_record_count") != len(client_row.get("records", []))
            or evidence_row.get("remote_record_count") != len(remote_row.get("records", []))):
        raise ReplayError("endpoint record count differs from persisted evidence: " + sample_id)


def verify_session_endpoint_logs(manifest, session_id, expected_rows):
    """Verify one session's gzip logs in a single streaming pass per endpoint."""
    session_dir = Path(manifest["run_dir"]) / "sessions" / session_id
    summary_path = session_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    readers = {}
    for role in ("client", "remote"):
        artifact = summary.get(role + "_agent_log") or {}
        path = Path(artifact.get("path", ""))
        expected_path = session_dir / (role + "_agent.jsonl.gz")
        if (path.resolve() != expected_path.resolve() or not path.is_file()
                or sha256_file(path) != artifact.get("compressed_sha256")):
            raise ReplayError("missing or mismatched compressed {0} agent log: {1}".format(
                role, session_id))
        readers[role] = iter_agent_samples(path)
    wanted = {row["sample_id"]: row for row in expected_rows}
    seen = set()
    for client_row, remote_row in itertools.zip_longest(
            readers["client"], readers["remote"]):
        if client_row is None or remote_row is None:
            raise ReplayError("client/remote agent logs contain different sample counts: "
                              + session_id)
        client_key = (client_row.get("sample_id"), client_row.get("sample_token"))
        remote_key = (remote_row.get("sample_id"), remote_row.get("sample_token"))
        if client_key != remote_key:
            raise ReplayError("client/remote agent log sample order differs: " + session_id)
        sample_id = client_row.get("sample_id")
        if sample_id in wanted:
            if sample_id in seen:
                raise ReplayError("duplicate completed sample row in agent log: " + sample_id)
            verify_tcp_sample_artifacts(manifest, wanted[sample_id], client_row, remote_row)
            seen.add(sample_id)
    if seen != set(wanted):
        raise ReplayError("session agent logs do not cover successful samples: "
                          + ",".join(sorted(set(wanted) - seen)))
    return summary


def runtime_source_hashes():
    paths = RUNTIME_SOURCE_FILES + FROZEN_HELPER_FILES
    return {str(path.relative_to(ROOT)): sha256_file(path) for path in paths}


def atomic_write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + str(os.getpid()))
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(str(temporary), str(path))


def parse_sample_id(path):
    match = SAMPLE_RE.fullmatch(Path(path).name)
    if not match:
        raise ReplayError("invalid sample filename: " + str(path))
    return int(match.group("class_id")), int(match.group("repeat_id"))


def read_trace(path, tolerance=TIMESTAMP_TOLERANCE):
    path = Path(path)
    class_id, repeat_id = parse_sample_id(path)
    timestamps = []
    directions = []
    small_reversals = []
    previous = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise ReplayError("blank line in {0}:{1}".format(path, line_number))
        fields = re.split(r"\s+", line.strip())
        if len(fields) != 2:
            raise ReplayError("expected timestamp + direction in {0}:{1}".format(
                path, line_number))
        try:
            timestamp = float(fields[0])
            direction = int(fields[1])
        except ValueError as exc:
            raise ReplayError("non-numeric event in {0}:{1}".format(
                path, line_number)) from exc
        if not (timestamp == timestamp and abs(timestamp) != float("inf")):
            raise ReplayError("non-finite timestamp in " + str(path))
        if direction not in (-1, 1):
            raise ReplayError("direction must be -1 or +1 in " + str(path))
        if previous is not None and timestamp < previous:
            backward = previous - timestamp
            if backward > tolerance:
                raise ReplayError(
                    "large timestamp reversal {0:.9g}s in {1}:{2}".format(
                        backward, path, line_number))
            small_reversals.append({"line": line_number, "backward_seconds": backward})
        timestamps.append(timestamp)
        directions.append(direction)
        previous = timestamp
    if not timestamps:
        raise ReplayError("empty trace: " + str(path))
    first = timestamps[0]
    scheduled = []
    last_offset = 0.0
    for sequence, (timestamp, direction) in enumerate(zip(timestamps, directions)):
        raw_offset = timestamp - first
        corrected = max(raw_offset, last_offset)
        scheduled.append({"sequence": sequence, "direction": direction,
                          "raw_timestamp": timestamp,
                          "raw_offset_seconds": raw_offset,
                          "offset_seconds": corrected,
                          "offset_ns": int(round(corrected * 1e9)),
                          "corrected": corrected != raw_offset})
        last_offset = corrected
    return {
        "sample_id": path.name,
        "class_id": class_id,
        "repeat_id": repeat_id,
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "events": scheduled,
        "event_count": len(scheduled),
        "duration_seconds": last_offset,
        "small_reversal_count": len(small_reversals),
        "small_reversals": small_reversals,
        "direction_counts": dict(Counter(directions)),
    }


def source_files(input_root):
    root = Path(input_root).resolve()
    if not root.is_dir():
        raise ReplayError("input directory does not exist: " + str(root))
    files = []
    for path in root.iterdir():
        if path.is_file():
            parse_sample_id(path)
            files.append(path)
    files.sort(key=lambda item: tuple(parse_sample_id(item)))
    if not files:
        raise ReplayError("input directory is empty: " + str(root))
    return files


def selected_files(files, pilot=False, max_samples=None):
    if pilot:
        files = [path for path in files
                 if parse_sample_id(path)[0] in PILOT_IDS and
                 parse_sample_id(path)[1] in PILOT_REPEATS]
    if max_samples is not None:
        if max_samples < 1:
            raise ReplayError("max_samples must be positive")
        files = files[:max_samples]
    return files


def balanced_order(files, seed):
    groups = defaultdict(list)
    for path in files:
        groups[parse_sample_id(path)[0]].append(path)
    rng = random.Random(seed)
    for values in groups.values():
        rng.shuffle(values)
    ordered = []
    class_ids = sorted(groups)
    for index in range(max(len(values) for values in groups.values())):
        for class_id in class_ids:
            values = groups[class_id]
            if index < len(values):
                ordered.append(values[index])
    return ordered


def dispatch_lead_seconds(event_count):
    # Sending the JSON event list through docker exec is normally sub-second;
    # reserve a bounded larger lead for unusually dense traces.
    return max(DISPATCH_LEAD_SECONDS, min(10.0, event_count * 0.00002))


def build_sessions(files, seed, session_seconds, speed, guard_seconds):
    ordered = balanced_order(files, seed)
    sessions = []
    current = None
    for path in ordered:
        info = read_trace(path)
        # Reserve the receive tail and the small future dispatch lead.  The
        # endpoint is deliberately single-sample at a time, so omitting these
        # terms would make planned starts drift later during a long session.
        dispatch_lead = dispatch_lead_seconds(info["event_count"])
        required = (info["duration_seconds"] / speed + TAIL_SECONDS
                    + guard_seconds + dispatch_lead)
        if required >= session_seconds - WARMUP_SECONDS - SESSION_TAIL_SECONDS:
            raise ReplayError("sample is longer than usable session: " + str(path))
        if current is None or current["cursor_seconds"] + required > (
                session_seconds - SESSION_TAIL_SECONDS):
            current = {"session_id": "session-{0:04d}".format(len(sessions) + 1),
                       "session_seconds": session_seconds,
                       "cursor_seconds": WARMUP_SECONDS,
                       "samples": []}
            sessions.append(current)
        start = current["cursor_seconds"]
        current["samples"].append({
            "sample_id": path.name,
            "source_path": str(path.resolve()),
            "class_id": info["class_id"],
            "repeat_id": info["repeat_id"],
            "start_second": round(start, 6),
            "duration_seconds": info["duration_seconds"] / speed,
            "source_duration_seconds": info["duration_seconds"],
            "dispatch_lead_seconds": dispatch_lead,
            "event_count": info["event_count"],
            "source_sha256": info["sha256"],
            "small_reversal_count": info["small_reversal_count"],
        })
        current["cursor_seconds"] = start + required
    for session in sessions:
        session["planned_sample_count"] = len(session["samples"])
        session["used_seconds"] = round(session["cursor_seconds"], 6)
        del session["cursor_seconds"]
    return sessions


def coverage_report(sessions):
    by_class = defaultdict(list)
    for session in sessions:
        for sample in session["samples"]:
            decile = min(9, int(sample["start_second"] / session["session_seconds"] * 10))
            by_class[sample["class_id"]].append(decile)
    result = {}
    for class_id, values in sorted(by_class.items()):
        counts = Counter(values)
        result[str(class_id)] = {
            "deciles_present": sorted(counts),
            "decile_counts": dict(sorted(counts.items())),
            "decile_count_range": [min(counts.values()), max(counts.values())],
        }
    return result


def loss_percent_arg(value):
    loss = float(value)
    if not 0 <= loss <= 100:
        raise argparse.ArgumentTypeError("link loss must be finite and between 0 and 100 percent")
    return loss


def make_config(session_seconds, link_loss_percent=None):
    config = dict(P2_CONFIG)
    config["Duration (s)"] = int(session_seconds)
    if link_loss_percent is not None:
        loss = loss_percent_arg(link_loss_percent)
        config['satellite link loss ("X"% )'] = loss
        config['sat-ground loss ("X"% )'] = loss
    return config


FIXED_SCENARIOS = {
    "base": {"delay_ms": 0.0, "jitter_ms": 0.0, "loss_percent": 0.0},
    "delay25": {"delay_ms": 25.0, "jitter_ms": 0.0, "loss_percent": 0.0},
    "jitter25_10": {"delay_ms": 25.0, "jitter_ms": 10.0, "loss_percent": 0.0},
    "loss0p1": {"delay_ms": 0.0, "jitter_ms": 0.0, "loss_percent": 0.1},
}


def selected_files_by_id(files, ids_path):
    requested = json.loads(Path(ids_path).read_text(encoding="utf-8"))
    if isinstance(requested, dict):
        requested = requested.get("sample_ids")
    if not isinstance(requested, list) or not requested:
        raise ReplayError("sample ID list must be a nonempty JSON array")
    if len(requested) != len(set(requested)):
        raise ReplayError("sample ID list contains duplicates")
    available = {path.name: path for path in files}
    missing = sorted(set(requested) - set(available))
    if missing:
        raise ReplayError("sample ID list contains missing sources: " + ", ".join(missing[:10]))
    # Preserve the exact frozen order from the shared batch list.
    return [available[sample_id] for sample_id in requested]


def build_manifest(args, files, sessions, run_dir, mode):
    source_digest = hashlib.sha256()
    source_rows = []
    source_total_bytes = 0
    for path in files:
        digest = sha256_file(path)
        source_bytes = path.stat().st_size
        source_total_bytes += source_bytes
        source_digest.update(path.name.encode("utf-8"))
        source_digest.update(b"\0")
        source_digest.update(digest.encode("ascii"))
        source_rows.append({"sample_id": path.name, "source_path": str(path.resolve()),
                            "source_sha256": digest, "source_bytes": source_bytes})
    topology_mode = getattr(args, "topology_mode", "dynamic")
    condition = getattr(args, "scenario", None)
    tcp_completion_timeout = float(getattr(
        args, "tcp_completion_seconds", TCP_COMPLETION_TIMEOUT_SECONDS))
    fixed_config = topology_mode == "fixed"
    link_loss = 0 if fixed_config else getattr(args, "link_loss_percent", None)
    return {
        "schema_version": SCHEMA_VERSION,
        "plan_version": PLAN_VERSION,
        "dataset_id": ("E_v4_fixed_replay_tcp" if fixed_config and
                       getattr(args, "transport", "tcp") == "tcp" else
                       "E_v4_dynamic_replay_tcp" if getattr(args, "transport", "tcp") == "tcp"
                       else "E_v4_dynamic_replay"),
        "created_utc": utc_now(),
        "mode": mode,
        "transport": getattr(args, "transport", "tcp"),
        "docker_bridge_masquerade": getattr(args, "transport", "tcp") != "tcp",
        "transport_ports": list(UDP_PORTS),
        "tcp_completion_timeout_seconds": tcp_completion_timeout,
        "tcp_coordinator_wait_seconds": TCP_COORDINATOR_WAIT_SECONDS,
        "tcp_connect_timeout_seconds": TCP_CONNECT_TIMEOUT_SECONDS,
        "tcp_state_interval_seconds": (TCP_STATE_INTERVAL_SECONDS
                                       if getattr(args, "transport", "tcp") == "tcp" else None),
        "trace_semantics": "client_application_events",
        "run_id": run_dir.name,
        "input_root": str(Path(args.input).resolve()),
        "dataset_output": str(Path(args.dataset_output).resolve()),
        "source_count": len(files),
        "source_total_bytes": source_total_bytes,
        "source_total_event_count": sum(
            sample["event_count"] for session in sessions
            for sample in session["samples"]),
        "source_digest_sha256": source_digest.hexdigest(),
        "generator_sha256": sha256_file(Path(__file__).resolve()),
        "agent_sha256": sha256_file(AGENT_SOURCE),
        "runtime_source_sha256": runtime_source_hashes(),
        "source_rows": source_rows,
        "seed": args.seed,
        "speed": args.speed,
        "session_seconds": args.session_seconds,
        "guard_seconds": args.guard_seconds,
        "warmup_seconds": WARMUP_SECONDS,
        "session_tail_seconds": SESSION_TAIL_SECONDS,
        "tail_seconds": TAIL_SECONDS,
        "dispatch_lead_seconds": DISPATCH_LEAD_SECONDS,
        "sample_timeout_margin_seconds": SAMPLE_TIMEOUT_MARGIN_SECONDS,
        "session_timeout_margin_seconds": SESSION_TIMEOUT_MARGIN_SECONDS,
        "route_ready_timeout_policy": "automatic_session_rollover_after_120_seconds",
        "timestamp_tolerance_seconds": TIMESTAMP_TOLERANCE,
        "payload_bytes": PAYLOAD_BYTES,
        "udp_port": UDP_PORT,
        "udp_ports": list(UDP_PORTS),
        "topology": {
            "ground_stations": GS,
            "config": make_config(args.session_seconds, link_loss),
            "mode": topology_mode,
            "dynamic_required": topology_mode == "dynamic",
            "fixed_snapshot_required": fixed_config,
            "scenario": condition,
            "engineering_pipeline_verified": False,
            "scientific_fidelity_verified": False,
        },
        "scenario": condition,
        "batch_id": getattr(args, "batch_id", None),
        "batch_manifest_path": (str(Path(args.batch_manifest).resolve())
                                 if getattr(args, "batch_manifest", None) else None),
        "owner_id": getattr(args, "owner_id", None),
        "service_name": getattr(args, "service_name", None),
        "diagnostic_mode": getattr(args, "diagnostic_mode", None),
        "source_ids_sha256": (sha256_file(args.sample_ids)
                               if getattr(args, "sample_ids", None) else None),
        "cohort_key": getattr(args, "cohort_key", None),
        "sessions": sessions,
        "coverage": coverage_report(sessions),
        "attempt_policy": {"max_infrastructure_retries": 2,
                            "network_loss_is_measurement": True,
                            "failed_attempts_are_append_only": True},
        "status": "planned",
    }


def next_run_dir(run_root):
    run_root = Path(run_root).resolve()
    run_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime_module.datetime.now(datetime_module.timezone.utc).strftime(
        "%Y%m%dT%H%M%S_%fZ")
    path = run_root / stamp
    path.mkdir()
    return path


def cmd_plan(args):
    if args.session_seconds is None:
        args.session_seconds = 900 if args.pilot else 9000
    files = source_files(args.input)
    if getattr(args, "sample_ids", None):
        files = selected_files_by_id(files, args.sample_ids)
    else:
        files = selected_files(files, args.pilot, args.max_samples)
    if getattr(args, "topology_mode", "dynamic") == "fixed":
        if args.transport != "tcp":
            raise ReplayError("fixed research-content-2 conditions require TCP replay")
        if args.scenario not in FIXED_SCENARIOS:
            raise ReplayError("fixed topology requires a named controlled condition")
        if (not args.batch_manifest or not args.batch_id or not args.owner_id
                or not args.service_name or not args.sample_ids or not args.cohort_key):
            raise ReplayError("fixed plans require shared sample IDs, batch/cohort manifest identity, batch ID, owner ID, and service name")
    diagnostic_mode = getattr(args, "diagnostic_mode", None)
    tcp_completion = getattr(args, "tcp_completion_seconds", TCP_COMPLETION_TIMEOUT_SECONDS)
    if tcp_completion != TCP_COMPLETION_TIMEOUT_SECONDS and not (
            diagnostic_mode == "deadline" and
            getattr(args, "topology_mode", "dynamic") == "fixed" and
            args.scenario == "base" and args.sample_ids):
        raise ReplayError("non-120 second completion windows are allowed only for the paired baseline deadline diagnostic")
    if diagnostic_mode == "deadline" and not (
            getattr(args, "topology_mode", "dynamic") == "fixed" and
            args.scenario == "base" and args.sample_ids):
        raise ReplayError("deadline diagnostic requires fixed baseline TCP and frozen sample IDs")
    if diagnostic_mode in ("stable", "crossing") and not (
            getattr(args, "topology_mode", "dynamic") == "dynamic" and args.sample_ids
            and args.cohort_key and args.batch_manifest and args.batch_id
            and args.owner_id and args.service_name):
        raise ReplayError("dynamic pair diagnostic requires a dynamic topology and batch-scoped shared sample IDs")
    if diagnostic_mode == "deadline" and not (
            args.cohort_key and args.batch_manifest and args.batch_id
            and args.owner_id and args.service_name):
        raise ReplayError("deadline diagnostic requires a frozen batch cohort identity")
    sessions = build_sessions(files, args.seed, args.session_seconds,
                              args.speed, args.guard_seconds)
    coverage = coverage_report(sessions)
    # A reduced dry-run (for example --max-samples) is useful for engineering
    # checks and cannot satisfy the formal per-class coverage contract.  Apply
    # the eight-decile gate only to the full 6000-sample production plan.
    if not args.pilot and len(files) == 6000:
        insufficient = {
            class_id: value["deciles_present"]
            for class_id, value in coverage.items()
            if len(value["deciles_present"]) < 8
        }
        if insufficient:
            raise ReplayError(
                "formal schedule does not cover eight time deciles per class: "
                + json.dumps(insufficient, sort_keys=True))
    run_dir = next_run_dir(args.run_root)
    manifest_mode = ("diagnostic" if diagnostic_mode else
                     "pilot" if args.pilot else "formal")
    manifest = build_manifest(args, files, sessions, run_dir, manifest_mode)
    source_dir = run_dir / "source"
    source_dir.mkdir()
    atomic_write_json(source_dir / "manifest.json", {
        "schema_version": SCHEMA_VERSION,
        "input_root": manifest["input_root"],
        "source_count": manifest["source_count"],
        "source_total_bytes": manifest["source_total_bytes"],
        "source_digest_sha256": manifest["source_digest_sha256"],
        "rows": manifest["source_rows"],
    })
    manifest["source_manifest_sha256"] = sha256_file(source_dir / "manifest.json")
    atomic_write_json(run_dir / "manifest.json", manifest)
    frozen_config = run_dir / "frozen_config.json"
    atomic_write_json(frozen_config,
                      {"schema_version": 1, "config": manifest["topology"]["config"],
                       "ground_stations": GS, "payload_bytes": PAYLOAD_BYTES,
                       "udp_port": UDP_PORT, "udp_ports": list(UDP_PORTS),
                       "agent_header_schema": "EV4-v1",
                       "transport": manifest["transport"],
                       "docker_bridge_masquerade": manifest["docker_bridge_masquerade"],
                       "transport_ports": manifest["transport_ports"],
                       "tcp_completion_timeout_seconds": manifest["tcp_completion_timeout_seconds"],
                       "tcp_coordinator_wait_seconds": TCP_COORDINATOR_WAIT_SECONDS,
                       "tcp_connect_timeout_seconds": TCP_CONNECT_TIMEOUT_SECONDS,
                       "tcp_state_interval_seconds": manifest["tcp_state_interval_seconds"],
                       "trace_semantics": "client_application_events",
                       "topology_mode": manifest["topology"]["mode"],
                       "scenario": manifest["scenario"],
                       "batch_id": manifest["batch_id"],
                       "owner_id": manifest["owner_id"],
                       "service_name": manifest["service_name"],
                       "cohort_key": manifest["cohort_key"],
                       "diagnostic_mode": manifest["diagnostic_mode"]})
    manifest["frozen_config_sha256"] = sha256_file(frozen_config)
    atomic_write_json(run_dir / "manifest.json", manifest)
    (run_dir / "attempts.jsonl").touch()
    print(json.dumps({"planned": True, "manifest": str(run_dir / "manifest.json"),
                      "sample_count": len(files), "session_count": len(sessions),
                      "coverage": manifest["coverage"]}, indent=2, sort_keys=True))
    return 0


def load_manifest(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise ReplayError("manifest does not exist: " + str(path))
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("transport", "udp") not in ("tcp", "udp"):
        raise ReplayError("unsupported replay transport")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("plan_version") != PLAN_VERSION:
        raise ReplayError("unsupported E_v4 manifest schema or plan version")
    value["manifest_path"] = str(path)
    value["run_dir"] = str(path.parent)
    return value


def append_attempt(manifest, row):
    path = Path(manifest["run_dir"]) / "attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    _ATTEMPT_FILE_CACHE.pop(str(path.resolve()), None)


def read_attempts(manifest):
    path = Path(manifest["run_dir"]) / "attempts.jsonl"
    if not path.exists():
        return []
    stat = path.stat()
    cache_key = str(path.resolve())
    signature = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    cached = _ATTEMPT_FILE_CACHE.get(cache_key)
    if cached is not None and cached[0] == signature:
        return cached[1]
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    _ATTEMPT_FILE_CACHE[cache_key] = (signature, rows)
    return rows


def sample_root(manifest, sample_id):
    return Path(manifest["run_dir"]) / "samples" / sample_id


def active_sessions(manifest):
    return [session for session in manifest["sessions"]
            if not session.get("superseded_by")]


def allocate_recovery_session(manifest, session, evidence_recovery_sample=None):
    # Keep the directory name bounded across repeated automatic rollovers.
    # Appending each parent ID eventually exceeds Linux NAME_MAX.
    recovery_id = "recovery-{0}".format(
        datetime_module.datetime.now(datetime_module.timezone.utc).strftime(
            "%Y%m%dT%H%M%S_%fZ"))
    recovery = dict(session)
    recovery.pop("superseded_by", None)
    recovery["session_id"] = recovery_id
    recovery["recovery_of"] = session["session_id"]
    recovery["samples"] = [dict(sample) for sample in session["samples"]]
    if evidence_recovery_sample is not None:
        recovery["session_evidence_recovery_sample"] = evidence_recovery_sample
    else:
        recovery.pop("session_evidence_recovery_sample", None)
    session["superseded_by"] = recovery_id
    manifest["sessions"].append(recovery)
    return recovery


def session_setup_retry_allowed(summary, attempt_number):
    """Return whether a clean, sample-free setup failure may be rebuilt."""
    return (attempt_number < MAX_SESSION_SETUP_ATTEMPTS
            and summary.get("status") == "aborted"
            and summary.get("cleanup_verified") is True
            and not summary.get("sample_results")
            and summary.get("phase") in {
                "inventory", "create_nodes", "create_links", "routing",
                "topology_validation", "route_before", "capture_agents"})


def storage_guard(manifest):
    gate_path = manifest.get("capacity_gate_path")
    if gate_path:
        gate_path = Path(gate_path).resolve()
        batch_path = Path(manifest.get("batch_manifest_path", "")).resolve()
        if not batch_path.is_file() or gate_path.parent != batch_path.parent:
            raise ReplayError("capacity gate is outside the frozen batch artifact directory")
        if not gate_path.is_file():
            raise ReplayError("capacity gate artifact is missing: " + str(gate_path))
        expected_gate_hash = manifest.get("capacity_gate_sha256")
        if not expected_gate_hash or sha256_file(gate_path) != expected_gate_hash:
            raise ReplayError("capacity gate hash differs from the frozen full manifest")
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        if gate.get("passed") is not True:
            raise ReplayError("capacity gate has not passed")
        if gate.get("batch_id") != manifest.get("batch_id"):
            raise ReplayError("capacity gate belongs to a different batch")
        entries = gate.get("full_manifests", [])
        identity = {"run_id": manifest.get("run_id"),
                    "scenario": manifest.get("scenario"),
                    "batch_id": manifest.get("batch_id"),
                    "owner_id": manifest.get("owner_id"),
                    "service_name": manifest.get("service_name"),
                    "source_digest_sha256": manifest.get("source_digest_sha256"),
                    "frozen_config_sha256": manifest.get("frozen_config_sha256"),
                    "cohort_key": manifest.get("cohort_key")}
        matched = [row for row in entries
                   if all(row.get(key) == value for key, value in identity.items())]
        if len(matched) != 1:
            raise ReplayError("capacity gate lacks this full plan's frozen identity")
        pending_estimate = 0
        for row in entries:
            plan_path = Path(row["manifest_path"])
            try:
                current = json.loads(plan_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ReplayError("capacity gate full manifest is unavailable: " + str(exc))
            if current.get("status") not in ("run_completed", "finalized"):
                pending_estimate += int(row.get("estimated_bytes", 0))
        required = int(math.ceil(pending_estimate * 1.5)) + 20 * 1024**3
        free = shutil.disk_usage(manifest["run_dir"]).free
        if free < required:
            raise ReplayError("insufficient free disk space after capacity gate: free={0} required={1}".format(free, required))
        return {"capacity_gate_path": str(gate_path),
                "capacity_gate_sha256": expected_gate_hash,
                "remaining_full_estimate_bytes": pending_estimate,
                "required_free_bytes": required, "free_bytes": free,
                "checked_utc": utc_now()}
    if manifest.get("mode") == "formal":
        raise ReplayError("formal run requires a pilot-measured capacity gate")
    # Before the pilot has produced measured artifact sizes, use event counts
    # with a deliberately high conservative floor. This protects pilot output
    # from silently assuming that source text size approximates TCP/PCAP logs.
    events = int(manifest.get("source_total_event_count", 0))
    if events <= 0:
        events = max(1, int(manifest.get("source_total_bytes", 0) // 20))
    # The bound reserves 4 KiB per event before compression for both endpoint
    # JSON records, TCP framing/capture and mapping, plus session metadata.
    estimate = events * 4096 + len(active_sessions(manifest)) * 128 * 1024**2
    required = int(estimate * 1.5) + 20 * 1024**3
    free = shutil.disk_usage(manifest["run_dir"]).free
    if free < required:
        raise ReplayError(
            "insufficient free disk space: free={0} required={1}".format(free, required))
    return {"source_total_event_count": events, "estimated_bytes": estimate,
            "required_free_bytes": required, "free_bytes": free}


def pilot_capacity_measurement(manifest):
    root = Path(manifest["run_dir"])
    total_bytes = 0
    event_bytes = 0
    event_names = {"client_agent.jsonl.gz", "remote_agent.jsonl.gz",
                   "client.pcap.gz", "remote.pcap.gz", "trace_mapping.jsonl.gz"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        size = path.stat().st_size
        total_bytes += size
        if (path.name in event_names or
                (path.name == "trace" and "samples" in path.parts)):
            event_bytes += size
    source_events = int(manifest.get("source_total_event_count", 0))
    session_count = len(active_sessions(manifest))
    if source_events <= 0 or session_count <= 0 or event_bytes <= 0:
        raise ReplayError("pilot has no measurable event artifacts")
    fixed_bytes = max(0, total_bytes - event_bytes)
    return {"run_id": manifest["run_id"], "scenario": manifest.get("scenario"),
            "sample_count": manifest.get("source_count"),
            "source_total_event_count": source_events,
            "session_count": session_count, "total_artifact_bytes": total_bytes,
            "event_artifact_bytes": event_bytes,
            "fixed_artifact_bytes": fixed_bytes,
            "measured_bytes_per_event": event_bytes / float(source_events),
            "measured_fixed_bytes_per_session": fixed_bytes / float(session_count)}


def cmd_capacity(args):
    batch_path = Path(args.batch_manifest).resolve()
    if not batch_path.is_file():
        raise ReplayError("batch manifest is missing: " + str(batch_path))
    batch = json.loads(batch_path.read_text(encoding="utf-8"))
    if not isinstance(batch.get("cohorts"), dict):
        raise ReplayError("batch manifest lacks frozen source cohorts")
    for field in ("batch_id", "owner_id", "service_name"):
        if not batch.get(field):
            raise ReplayError("batch manifest lacks " + field)
    pilots = [load_manifest(path) for path in args.pilot_manifests]
    full = [load_manifest(path) for path in args.full_manifests]
    if len(pilots) != 4 or len(full) != 4:
        raise ReplayError("capacity estimation requires exactly four pilot and four full plans")
    expected_scenarios = ["base", "delay25", "jitter25_10", "loss0p1"]
    expected_ids = None
    pilot_measurements = []
    frozen_snapshot_hash = None
    for manifest, scenario in zip(pilots, expected_scenarios):
        check_frozen_config(manifest)
        load_batch_manifest(manifest)
        if (manifest.get("mode") != "pilot" or manifest.get("scenario") != scenario
                or manifest.get("topology", {}).get("mode") != "fixed"
                or manifest.get("source_count") != 150
                or manifest.get("status") not in ("run_completed", "finalized")):
            raise ReplayError("pilot is incomplete or mismatched for scenario " + scenario)
        ids = [row["sample_id"] for row in manifest.get("source_rows", [])]
        if expected_ids is None:
            expected_ids = ids
        elif ids != expected_ids:
            raise ReplayError("four pilots do not share the exact source ID order")
        verification_path = Path(manifest["run_dir"]) / "verification.json"
        if not verification_path.is_file():
            raise ReplayError("pilot lacks verification.json: " + scenario)
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        if verification.get("passed") is not True:
            raise ReplayError("pilot verification did not pass: " + scenario)
        topology = manifest.get("topology", {}).get("frozen_snapshot") or {}
        if not topology.get("sha256"):
            raise ReplayError("pilot lacks a frozen topology snapshot")
        if frozen_snapshot_hash is None:
            frozen_snapshot_hash = topology["sha256"]
        elif topology["sha256"] != frozen_snapshot_hash:
            raise ReplayError("pilot conditions do not share the same frozen topology")
        pilot_measurements.append(pilot_capacity_measurement(manifest))
    if batch.get("fixed_route_baseline") is None:
        raise ReplayError("pilot batch has no observed fixed bidirectional route baseline")
    full_ids = None
    for manifest, scenario in zip(full, expected_scenarios):
        check_frozen_config(manifest)
        load_batch_manifest(manifest)
        if (manifest.get("mode") != "formal" or manifest.get("cohort_key") != "full"
                or manifest.get("scenario") != scenario
                or manifest.get("topology", {}).get("mode") != "fixed"
                or manifest.get("source_count") != 6000):
            raise ReplayError("full plan is incomplete or mismatched for scenario " + scenario)
        ids = [row["sample_id"] for row in manifest.get("source_rows", [])]
        if full_ids is None:
            full_ids = ids
        elif ids != full_ids:
            raise ReplayError("four full plans do not share the exact source ID order")
        if manifest.get("topology", {}).get("frozen_snapshot", {}).get("sha256") not in (
                None, frozen_snapshot_hash):
            raise ReplayError("full plan names a different frozen topology snapshot")
        if any(manifest.get(field) != batch.get(field)
               for field in ("batch_id", "owner_id", "service_name")):
            raise ReplayError("full plan identity differs from capacity batch")
    max_bytes_per_event = max(row["measured_bytes_per_event"]
                              for row in pilot_measurements)
    max_fixed_per_session = max(row["measured_fixed_bytes_per_session"]
                                for row in pilot_measurements)
    full_estimates = []
    for manifest, scenario in zip(full, expected_scenarios):
        estimate = int(math.ceil(
            max_bytes_per_event * int(manifest["source_total_event_count"])
            + max_fixed_per_session * len(active_sessions(manifest))))
        full_estimates.append({
            "run_id": manifest["run_id"], "scenario": scenario,
            "manifest_path": manifest["manifest_path"],
            "batch_id": manifest.get("batch_id"),
            "source_digest_sha256": manifest["source_digest_sha256"],
            "frozen_config_sha256": manifest["frozen_config_sha256"],
            "owner_id": manifest.get("owner_id"),
            "service_name": manifest.get("service_name"),
            "cohort_key": manifest.get("cohort_key"),
            "estimated_bytes": estimate,
            "session_count": len(active_sessions(manifest)),
            "source_total_event_count": manifest["source_total_event_count"]})
    estimate_total = sum(row["estimated_bytes"] for row in full_estimates)
    required = int(math.ceil(estimate_total * 1.5)) + 20 * 1024**3
    output = Path(args.output).resolve() if args.output else batch_path.parent / "capacity_gate.json"
    if output.parent != batch_path.parent:
        raise ReplayError("capacity gate must be written inside its batch artifact directory")
    devices = {os.stat(Path(item["run_dir"])).st_dev for item in full}
    if len(devices) != 1 or os.stat(output.parent).st_dev not in devices:
        raise ReplayError("all full plans and capacity artifacts must share one filesystem")
    free = shutil.disk_usage(output.parent).free
    gate = {
        "schema_version": 1, "batch_id": batch.get("batch_id"),
        "owner_id": batch.get("owner_id"), "service_name": batch.get("service_name"),
        "cohort_key": "full", "full_cohort_sha256": batch["cohorts"]["full"]["sha256"],
        "pilot_source_ids_sha256": batch["cohorts"]["pilot"]["sha256"],
        "frozen_snapshot_sha256": frozen_snapshot_hash,
        "fixed_route_baseline": batch["fixed_route_baseline"],
        "pilot_measurements": pilot_measurements,
        "max_measured_bytes_per_event": max_bytes_per_event,
        "max_measured_fixed_bytes_per_session": max_fixed_per_session,
        "full_manifests": full_estimates,
        "estimated_full_bytes": estimate_total,
        "headroom_multiplier": 1.5,
        "safety_margin_bytes": 20 * 1024**3,
        "required_free_bytes": required,
        "free_bytes_at_gate": free,
        "passed": free >= required,
        "created_utc": utc_now()}
    atomic_write_json(output, gate)
    gate_hash = sha256_file(output)
    for manifest in full:
        manifest["capacity_gate_path"] = str(output)
        manifest["capacity_gate_sha256"] = gate_hash
        atomic_write_json(manifest["manifest_path"], {
            key: value for key, value in manifest.items()
            if key not in ("manifest_path", "run_dir")})
    report = dict(gate, path=str(output), sha256=gate_hash)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if gate["passed"] else 1


def check_frozen_config(manifest):
    if manifest.get("generator_sha256") != sha256_file(Path(__file__).resolve()):
        raise ReplayError("replay generator source changed since plan")
    if manifest.get("agent_sha256") != sha256_file(AGENT_SOURCE):
        raise ReplayError("replay agent source changed since plan")
    expected_runtime_sources = manifest.get("runtime_source_sha256")
    if (expected_runtime_sources is not None
            and expected_runtime_sources != runtime_source_hashes()):
        raise ReplayError("StarryNet runtime source changed since plan")
    path = Path(manifest["run_dir"]) / "frozen_config.json"
    if not path.is_file():
        raise ReplayError("missing frozen configuration: " + str(path))
    if manifest.get("frozen_config_sha256") != sha256_file(path):
        raise ReplayError("frozen configuration hash changed")
    value = json.loads(path.read_text(encoding="utf-8"))
    config = value.get("config", {})
    if config != manifest.get("topology", {}).get("config"):
        raise ReplayError("frozen configuration differs from manifest topology")
    for key in ("transport", "docker_bridge_masquerade", "transport_ports", "tcp_completion_timeout_seconds",
                "tcp_coordinator_wait_seconds",
                "tcp_connect_timeout_seconds", "tcp_state_interval_seconds", "trace_semantics"):
        if manifest.get(key) != value.get(key):
            raise ReplayError("frozen transport configuration differs: " + key)
    for key in ("scenario", "batch_id", "owner_id", "service_name",
                "cohort_key", "diagnostic_mode"):
        if manifest.get(key) != value.get(key):
            raise ReplayError("frozen batch configuration differs: " + key)
    if manifest.get("topology", {}).get("mode", "dynamic") != value.get("topology_mode"):
        raise ReplayError("frozen batch configuration differs: topology_mode")
    if any(config.get(key) for key in (
            "remote_machine_IP", "remote_machine_username",
            "remote_machine_password")):
        raise ReplayError("frozen configuration contains remote credentials")
    return value


def sample_is_valid(manifest, sample_id):
    root = sample_root(manifest, sample_id)
    trace = root / "trace"
    evidence = root / "evidence.json"
    if not trace.is_file() or not evidence.is_file():
        return False
    try:
        row = json.loads(evidence.read_text(encoding="utf-8"))
        return row.get("status") == "success" and row.get("trace_sha256") == sha256_file(trace)
    except (OSError, ValueError, TypeError):
        return False


def replay_capture_count(pcap, transport):
    # TCP packets can contain partial/multiple frames, ACKs and retransmissions.
    # Its payload-packet count proves capture activity, not application delivery.
    key = "tcp_payload_packet_count" if transport == "tcp" else "ev4_packet_count"
    return int(pcap.get(key, 0))


def session_evidence_is_valid(manifest, session):
    """Check the evidence needed to retain a completed session on resume."""
    session_dir = Path(manifest["run_dir"]) / "sessions" / session["session_id"]
    summary_path = session_dir / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        pcap = summary.get("pcap", {})
        pcap_compression = summary.get("pcap_compression", {})
        pcap_path = Path(pcap_compression.get("path", ""))
        pcap_valid = (pcap_path.is_file()
                      and sha256_file(pcap_path) == pcap_compression.get("compressed_sha256"))
        return (summary.get("status") == "completed"
                and summary.get("cleanup_verified") is True
                and replay_capture_count(pcap, manifest.get("transport", "udp")) > 0
                and int(pcap.get("bytes", 0)) >= 24
                and pcap_valid
                and pcap_compression.get("original_sha256") == pcap.get("sha256")
                and (session_dir / "route_snapshots" / "before.json").is_file()
                and (session_dir / "route_snapshots" / "after.json").is_file()
                and (session_dir / "logs" / "tcpdump.log").is_file())
    except (OSError, ValueError, TypeError):
        return False


def max_infrastructure_attempts(manifest):
    return 1 + int(manifest.get("attempt_policy", {}).get(
        "max_infrastructure_retries", 1))


def docker_command(*args, capture=True, timeout=60, check=True, stdin=None):
    # ``text=`` was added as an alias for ``universal_newlines`` in Python
    # 3.7.  Keep Docker output in bytes (the callers decode it explicitly),
    # and encode optional input ourselves so this also works on Python 3.6.
    run_kwargs = {
        "stdout": subprocess.PIPE if capture else None,
        "stderr": subprocess.PIPE if capture else None,
        "timeout": timeout,
    }
    if stdin is not None:
        run_kwargs["input"] = (stdin.encode("utf-8")
                                if isinstance(stdin, str) else stdin)
    result = subprocess.run(["docker"] + [str(arg) for arg in args],
                            **run_kwargs)
    if check and result.returncode:
        stderr = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
        raise ReplayError("docker command failed: " + stderr.strip())
    return result


def inspect_replay_bridges(owner_id="constellation-test"):
    result = docker_command("network", "ls", "--filter",
                            "label=starrynet.owner=" + str(owner_id), "--quiet")
    identifiers = result.stdout.decode().split()
    if not identifiers:
        raise ReplayError("no StarryNet bridges available for routed TCP replay")
    result = docker_command("network", "inspect", *identifiers)
    networks = json.loads(result.stdout.decode())
    rows = [{"name": n["Name"], "id": n["Id"], "driver": n["Driver"],
             "options": n.get("Options") or {}} for n in networks]
    bad = [n["name"] for n in rows if n["driver"] != "bridge" or
           n["options"].get("com.docker.network.bridge.enable_ip_masquerade") != "false"]
    if bad:
        raise ReplayError("routed TCP replay requires no masquerade on bridges: " + ", ".join(bad))
    return rows


def docker_exec(cid, *args, timeout=60, check=True):
    result = docker_command("exec", str(cid), *args, timeout=timeout, check=check)
    if result.stdout is None:
        return ""
    return result.stdout.decode(errors="replace").strip() if isinstance(result.stdout, bytes) else result.stdout.strip()


def docker_cp(source, destination, timeout=120):
    docker_command("cp", str(source), str(destination), timeout=timeout)


def docker_inventory(owner_id="constellation-test", service_name="constellation-test"):
    def lines_raw(*args):
        return docker_command(*args).stdout.decode().split()
    def lines(*args):
        return sorted(lines_raw(*args))
    return {"containers": lines("ps", "-aq"),
            "networks": lines("network", "ls", "-q"),
            "services": lines("service", "ls", "--format", "{{.Name}}"),
            "starrynet_service_containers": lines(
                "ps", "-aq", "--filter",
                "label=com.docker.swarm.service.name=" + str(service_name)),
            "starrynet_owner_networks": lines(
                "network", "ls", "-q", "--filter",
                "label=starrynet.owner=" + str(owner_id))}


def starrynet_resources_cleared(inventory, owner_id="constellation-test",
                                service_name="constellation-test"):
    """Return whether this replay's named/labelled Docker resources are gone.

    Full Docker inventories remain in the session summary for audit evidence,
    but unrelated containers and networks may legitimately change during a
    multi-hour replay.  Cleanup acceptance must therefore be scoped to the
    resources owned by this StarryNet session.
    """
    if not inventory:
        return False
    return (service_name not in inventory.get("services", [])
            and not inventory.get("starrynet_service_containers", [])
            and not inventory.get("starrynet_owner_networks", []))


def wait_for_starrynet_cleanup(owner_id="constellation-test",
                              service_name="constellation-test", timeout=30.0):
    """Wait for asynchronous Swarm removal and return the last inventory."""
    deadline = time.monotonic() + timeout
    inventory = None
    while True:
        inventory = docker_inventory(owner_id, service_name)
        if starrynet_resources_cleared(inventory, owner_id, service_name):
            return inventory
        if time.monotonic() >= deadline:
            return inventory
        time.sleep(0.5)


def check_docker_capabilities(owner_id=None):
    docker_command("info", timeout=30)
    if docker_command("info", "--format", "{{.Swarm.ControlAvailable}}").stdout.decode().strip().lower() != "true":
        raise ReplayError("Docker Swarm manager is required")
    image = "lwsen/starlab_node:1.0"
    docker_command("image", "inspect", image, timeout=30)
    owner_id = owner_id or "research2-capability-check"
    name = "research2-check-" + hashlib.sha256(
        (owner_id + str(time.time_ns() if hasattr(time, "time_ns")
         else time.time())).encode("utf-8")).hexdigest()[:12]
    result = docker_command("run", "--rm", "--name", name,
                            "--label", "starrynet.owner=" + owner_id,
                            "--network", "none", image,
                            "sh", "-c", "command -v python3 && command -v tcpdump",
                            timeout=90, check=False)
    if result.returncode:
        raise ReplayError("StarryNet image must contain python3 and tcpdump")
    return {"image": image, "capabilities": result.stdout.decode(errors="replace")}


def make_runtime_config(session_dir, session_seconds, frozen_config=None):
    path = Path(session_dir) / "config.json"
    # Preflight has a shorter duration, but all link/routing settings must
    # come from the same frozen plan as the full and recovery sessions.
    config = dict(P2_CONFIG if frozen_config is None else frozen_config)
    config["Duration (s)"] = int(session_seconds)
    atomic_write_json(path, config)
    return path


def get_container_ids(sn):
    if len(sn.container_id_list) != 27:
        raise ReplayError("expected 27 StarryNet containers, got {0}".format(
            len(sn.container_id_list)))
    return str(sn.container_id_list[CLIENT_NODE - 1]), str(sn.container_id_list[REMOTE_NODE - 1])


def get_ipv4_addresses(cid):
    value = docker_exec(cid, "ip", "-4", "-o", "addr", "show")
    return re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", value)


def get_node_link_ipv4_addresses(cid, node):
    value = docker_exec(cid, "ip", "-4", "-o", "addr", "show")
    rows = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        interface = fields[1].split("@", 1)[0]
        if not re.fullmatch(r"B{0}-eth[0-9]+".format(node), interface):
            continue
        for index, field in enumerate(fields[:-1]):
            if field == "inet" and index + 1 < len(fields):
                address = fields[index + 1].split("/", 1)[0]
                if not ipaddress.ip_address(address).is_loopback:
                    rows.setdefault(interface, []).append(address)
    return rows


def find_peer_ip(remote_cid):
    addresses = get_ipv4_addresses(remote_cid)
    for address in addresses:
        if address.startswith("9.27.27."):
            return address
    if addresses:
        return addresses[-1]
    raise ReplayError("could not find GS27 IPv4 address")


def find_client_ip(client_cid):
    addresses = get_ipv4_addresses(client_cid)
    for address in addresses:
        if address.startswith("9.26.26."):
            return address
    if addresses:
        return addresses[-1]
    raise ReplayError("could not find GS26 IPv4 address")


def actual_satellite_route_chain(sn, source_node, destination_node, node_ips=None):
    """Resolve the kernel's actual next hop at each node; reject host/default paths."""
    containers = list(getattr(sn, "container_id_list", []))
    if len(containers) != 27:
        raise ReplayError("route-chain validation requires all 27 StarryNet nodes")
    if node_ips is None:
        node_ips = {}
        for node, cid in enumerate(containers, 1):
            node_ips[node] = [address
                              for addresses in get_node_link_ipv4_addresses(cid, node).values()
                              for address in addresses]
        node_ips[CLIENT_NODE].append(find_client_ip(containers[CLIENT_NODE - 1]))
        node_ips[REMOTE_NODE].append(find_peer_ip(containers[REMOTE_NODE - 1]))
    else:
        # The route map may have been assembled from interface addresses by a
        # caller. Include stable GS endpoint addresses explicitly: they live
        # on B26-default/B27-default and are not satellite next-hop IPs.
        node_ips = {node: list(addresses) for node, addresses in node_ips.items()}
        if CLIENT_NODE not in node_ips:
            node_ips[CLIENT_NODE] = []
        if REMOTE_NODE not in node_ips:
            node_ips[REMOTE_NODE] = []
        node_ips[CLIENT_NODE].append(find_client_ip(containers[CLIENT_NODE - 1]))
        node_ips[REMOTE_NODE].append(find_peer_ip(containers[REMOTE_NODE - 1]))
    ip_to_node = {}
    for node, addresses in node_ips.items():
        for address in addresses:
            if ipaddress.ip_address(address).is_loopback:
                continue
            if address in ip_to_node and ip_to_node[address] != node:
                raise ReplayError("duplicate IPv4 address across StarryNet nodes: " + address)
            ip_to_node[address] = node
    expected_prefix = "9.{0}.{0}.".format(destination_node)
    destination_ip = next((address for address in node_ips[destination_node]
                           if address.startswith(expected_prefix)), None)
    if destination_ip is None:
        raise ReplayError("could not resolve destination GS address for node "
                          + str(destination_node))
    chain = [source_node]
    hops = []
    current = source_node
    while current != destination_node:
        cid = containers[current - 1]
        route = docker_exec(cid, "ip", "route", "get", destination_ip)
        dev_match = re.search(r"\bdev\s+(\S+)", route)
        via_match = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", route)
        interface = dev_match.group(1) if dev_match else None
        interface_match = re.fullmatch(r"B{0}-eth([0-9]+)".format(current),
                                       interface or "")
        if not interface_match:
            raise ReplayError("node {0} route to {1} bypasses a satellite-facing link: {2}".format(
                current, destination_ip, route))
        next_node = int(interface_match.group(1))
        if next_node < 1 or next_node > 27 or next_node == current:
            raise ReplayError("invalid next-node interface in route: " + route)
        via = via_match.group(1) if via_match else None
        if via:
            via_node = ip_to_node.get(via)
            if via_node is None or via_node != next_node:
                raise ReplayError("route next-hop address does not map to its StarryNet interface: " + route)
        if next_node not in range(1, 26) and next_node != destination_node:
            raise ReplayError("actual path traverses a non-satellite intermediate node: " + route)
        hops.append({"source_node": current, "next_node": next_node,
                     "interface": interface, "via_ip": via, "route": route})
        if next_node in chain:
            raise ReplayError("loop in actual satellite route chain: "
                              + "->".join(map(str, chain + [next_node])))
        chain.append(next_node)
        current = next_node
        if len(chain) > 27:
            raise ReplayError("actual satellite route exceeds node count")
    return {"source_node": source_node, "destination_node": destination_node,
            "destination_ip": destination_ip, "nodes": chain, "hops": hops,
            "passed": True}


def register_fixed_route_baseline(manifest, forward, reverse):
    """Freeze the observed bidirectional route once for all four fixed conditions."""
    path, batch = load_batch_manifest(manifest)
    route = {"forward_nodes": forward["nodes"],
             "reverse_nodes": reverse["nodes"]}
    baseline = batch.get("fixed_route_baseline")
    snapshot_hash = (batch.get("frozen_topology") or {}).get("sha256")
    if baseline is None:
        batch["fixed_route_baseline"] = {
            "routes": route, "snapshot_sha256": snapshot_hash,
            "created_utc": utc_now()}
        batch["updated_utc"] = utc_now()
        atomic_write_json(path, batch)
        return route
    if baseline.get("snapshot_sha256") != snapshot_hash:
        raise ReplayError("fixed route baseline is bound to a different frozen snapshot")
    if baseline.get("routes") != route:
        raise ReplayError("actual fixed route chain differs from the batch baseline")
    return baseline["routes"]


def route_snapshot(client_cid, peer_ip):
    route = docker_exec(client_cid, "ip", "route", "get", peer_ip)
    interfaces = docker_exec(client_cid, "ip", "-o", "link")
    qdisc = docker_exec(client_cid, "sh", "-c", "for d in /sys/class/net/B26-*; do [ -e \"$d\" ] || continue; i=${d##*/}; echo ===$i===; tc -s qdisc show dev \"$i\"; done", timeout=30, check=False)
    return {"route": route, "interfaces": interfaces, "qdisc": qdisc,
            "satellite_route": bool(re.search(r"\bdev\s+B26-eth\d+\b", route))}


def wait_for_satellite_route(client_cid, peer_ip, timeout=30.0):
    """Wait through a handover convergence gap and return a valid route."""
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            snapshot = route_snapshot(client_cid, peer_ip)
            if snapshot["satellite_route"]:
                return snapshot
            last_error = "route does not use a GS26 satellite interface"
        except ReplayError as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            raise SatelliteRouteUnavailable(
                "GS26 satellite route unavailable after {0:.0f}s: {1}".format(
                timeout, last_error))
        time.sleep(1.0)


def rebase_runtime_schedule(sample_specs, guard_seconds):
    """Pack the samples supplied to this runtime from the warmup boundary.

    A resume normally contains only the unfinished suffix of a planned
    session.  Reusing its original absolute offsets can put the first pending
    sample directly into the same later coverage gap that ended the previous
    process.  Runtime evidence retains these rebased offsets.
    """
    cursor = WARMUP_SECONDS
    result = []
    for sample in sample_specs:
        runtime_sample = dict(sample)
        runtime_sample["start_second"] = round(cursor, 6)
        result.append(runtime_sample)
        cursor += (float(runtime_sample["duration_seconds"])
                   + TAIL_SECONDS + float(guard_seconds)
                   + float(runtime_sample.get(
                       "dispatch_lead_seconds", DISPATCH_LEAD_SECONDS)))
    return result


def final_route_snapshot(client_cid, peer_ip, timeout=30.0):
    """Record end-of-session route state without invalidating collected data."""
    try:
        return wait_for_satellite_route(client_cid, peer_ip, timeout)
    except ReplayError as exc:
        return {"route": None, "interfaces": None, "qdisc": None,
                "satellite_route": False, "unavailable": True,
                "error": str(exc)}


def topology_summary(path):
    try:
        import numpy as np
    except ImportError as exc:
        raise ReplayError("numpy is required for topology validation") from exc
    delay_dir = Path(path) / "delay"
    matrices = sorted(delay_dir.glob("*.txt"), key=lambda item: int(item.stem))
    if not matrices:
        raise ReplayError("no generated delay matrices: " + str(delay_dir))
    ground_stations = (CLIENT_NODE, REMOTE_NODE)
    previous_attachments = {}
    first_attachments = {}
    last_attachments = {}
    attachments_by_second = {}
    attachments_by_ground_station = {str(node): {} for node in ground_stations}
    handover_ground_stations_by_second = {}
    handovers = []
    changed = 0
    previous_matrix = None
    for matrix_path in matrices:
        matrix = np.loadtxt(matrix_path, delimiter=",")
        if matrix.shape != (27, 27) or not np.isfinite(matrix).all() or (matrix < 0).any():
            raise ReplayError("invalid delay matrix: " + str(matrix_path))
        second = int(matrix_path.stem)
        second_attachments = {}
        changed_ground_stations = []
        for node in ground_stations:
            attachment = tuple(np.flatnonzero(matrix[node - 1, :25]).tolist())
            second_attachments[str(node)] = list(attachment)
            attachments_by_ground_station[str(node)][str(second)] = list(attachment)
            if node not in first_attachments:
                first_attachments[node] = attachment
            if (node in previous_attachments
                    and attachment != previous_attachments[node]):
                changed_ground_stations.append(node)
            previous_attachments[node] = attachment
            last_attachments[node] = attachment
        # Keep the historical top-level mapping as the GS26 view because the
        # client-side trace remains anchored at GS26.
        attachments_by_second[str(second)] = second_attachments[str(CLIENT_NODE)]
        if changed_ground_stations:
            handovers.append(second)
            handover_ground_stations_by_second[str(second)] = changed_ground_stations
        if previous_matrix is not None and not np.array_equal(matrix, previous_matrix):
            changed += 1
        previous_matrix = matrix
    return {"matrix_count": len(matrices), "matrix_changed_count": changed,
            "handover_seconds": handovers,
            "handover_count": len(handovers),
            "handover_ground_stations_by_second": handover_ground_stations_by_second,
            "ground_stations": list(ground_stations),
            "first_attachment_zero_based": list(first_attachments.get(CLIENT_NODE, ())),
            "last_attachment_zero_based": list(last_attachments.get(CLIENT_NODE, ())),
            "first_attachments_zero_based": {
                str(node): list(first_attachments.get(node, ()))
                for node in ground_stations},
            "last_attachments_zero_based": {
                str(node): list(last_attachments.get(node, ()))
                for node in ground_stations},
            "attachments_by_second": attachments_by_second,
            "attachments_by_ground_station": attachments_by_ground_station}


def matrix_satellite_path(matrix):
    """Return the first GS26-to-GS27 path through satellite nodes, if any."""
    try:
        import numpy as np
    except ImportError as exc:
        raise ReplayError("numpy is required for frozen topology selection") from exc
    matrix = np.asarray(matrix, dtype=float)
    if matrix.shape != (27, 27) or not np.isfinite(matrix).all() or (matrix < 0).any():
        return None
    # StarryNet creates links only for entries above its 0.01 ms threshold.
    adjacency = matrix > 0.01
    start, goal = CLIENT_NODE - 1, REMOTE_NODE - 1
    queue = deque([(start, [start + 1])])
    visited = {start}
    while queue:
        node, path = queue.popleft()
        if node == goal:
            if len(path) >= 3 and all(1 <= item <= 25 for item in path[1:-1]):
                return path
            continue
        for nxt in np.flatnonzero(adjacency[node]):
            nxt = int(nxt)
            if nxt in visited or (nxt != goal and nxt not in range(25)):
                continue
            visited.add(nxt)
            queue.append((nxt, path + [nxt + 1]))
    return None


def select_first_connected_snapshot(delay_dir):
    """Select the lowest indexed generated matrix joining both GS via LEO."""
    try:
        import numpy as np
    except ImportError as exc:
        raise ReplayError("numpy is required for frozen topology selection") from exc
    matrices = sorted(Path(delay_dir).glob("*.txt"), key=lambda item: int(item.stem))
    for path in matrices:
        matrix = np.loadtxt(path, delimiter=",")
        route = matrix_satellite_path(matrix)
        if route:
            return {"source_path": str(path), "time_index": int(path.stem),
                    "sha256": sha256_file(path), "satellite_path": route,
                    "matrix": matrix}
    raise ReplayError("no generated delay matrix provides GS26-to-GS27 satellite connectivity")


def fixed_topology_summary(snapshot_path):
    """Summarize the one matrix used for every fixed-condition session."""
    try:
        import numpy as np
    except ImportError as exc:
        raise ReplayError("numpy is required for frozen topology validation") from exc
    matrix = np.loadtxt(snapshot_path, delimiter=",")
    route = matrix_satellite_path(matrix)
    if not route:
        raise ReplayError("frozen topology does not join GS26 to GS27 via satellites")
    attachments = {}
    for node in (CLIENT_NODE, REMOTE_NODE):
        attachments[str(node)] = [int(index) for index in
                                  np.flatnonzero(matrix[node - 1, :25])]
        if len(attachments[str(node)]) != 1:
            raise ReplayError("frozen snapshot must have exactly one satellite attachment for GS" + str(node))
    return {"matrix_count": 1, "matrix_changed_count": 0,
            "handover_seconds": [], "handover_count": 0,
            "handover_ground_stations_by_second": {},
            "ground_stations": [CLIENT_NODE, REMOTE_NODE],
            "first_attachment_zero_based": attachments[str(CLIENT_NODE)],
            "last_attachment_zero_based": attachments[str(CLIENT_NODE)],
            "first_attachments_zero_based": attachments,
            "last_attachments_zero_based": attachments,
            "attachments_by_second": {"1": attachments[str(CLIENT_NODE)]},
            "attachments_by_ground_station": {
                str(node): {"1": attachments[str(node)]}
                for node in (CLIENT_NODE, REMOTE_NODE)},
            "satellite_path": route,
            "matrix_sha256": sha256_file(snapshot_path)}


def load_batch_manifest(manifest):
    path = manifest.get("batch_manifest_path")
    if not path:
        raise ReplayError("fixed topology plan has no shared batch manifest")
    path = Path(path)
    if not path.is_file():
        raise ReplayError("shared batch manifest is missing: " + str(path))
    try:
        batch = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReplayError("cannot read shared batch manifest: " + str(exc)) from exc
    for field in ("batch_id", "owner_id", "service_name"):
        expected = manifest.get(field)
        if expected is not None and batch.get(field) != expected:
            raise ReplayError("shared batch identity mismatch for " + field)
    if manifest.get("source_ids_sha256"):
        cohort_key = manifest.get("cohort_key")
        cohorts = batch.get("cohorts")
        if not cohort_key or not isinstance(cohorts, dict) or cohort_key not in cohorts:
            raise ReplayError("shared batch manifest is missing cohort " + str(cohort_key))
        cohort = cohorts[cohort_key]
        if cohort.get("sha256") != manifest["source_ids_sha256"]:
            raise ReplayError("shared batch cohort hash mismatch for " + cohort_key)
        ids_path = cohort.get("ids_file") or cohort.get("sample_ids_file")
        if ids_path:
            ids_path = Path(ids_path)
            if not ids_path.is_absolute():
                ids_path = path.parent / ids_path
            if not ids_path.is_file() or sha256_file(ids_path) != cohort.get("sha256"):
                raise ReplayError("shared batch cohort ID file missing or changed: " + str(ids_path))
            cohort_ids = json.loads(ids_path.read_text(encoding="utf-8"))
            if isinstance(cohort_ids, dict):
                cohort_ids = cohort_ids.get("sample_ids")
        else:
            cohort_ids = cohort.get("sample_ids")
        manifest_ids = [row["sample_id"] for row in manifest.get("source_rows", [])]
        if not isinstance(cohort_ids, list) or cohort_ids != manifest_ids:
            raise ReplayError("shared batch cohort sample IDs differ from plan: " + cohort_key)
    return path, batch


def ensure_frozen_snapshot(manifest, delay_dir, session_dir):
    """Freeze once at batch scope and install that exact matrix as initial links."""
    batch_path, batch = load_batch_manifest(manifest)
    snapshot = batch.get("frozen_topology")
    manifest_snapshot = manifest.get("topology", {}).get("frozen_snapshot")
    if manifest_snapshot and not snapshot:
        raise ReplayError("plan names a frozen snapshot missing from the shared batch manifest")
    if snapshot:
        if manifest_snapshot and any(manifest_snapshot.get(key) != snapshot.get(key)
                                     for key in ("path", "sha256", "time_index")):
            raise ReplayError("plan's frozen topology identity differs from the batch snapshot")
        source = Path(snapshot["path"])
        if not source.is_file() or sha256_file(source) != snapshot.get("sha256"):
            raise ReplayError("shared frozen topology snapshot is missing or changed")
    else:
        selected = select_first_connected_snapshot(delay_dir)
        output = batch_path.parent / "frozen_topology" / (
            "matrix_{0}.txt".format(selected["time_index"]))
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() and sha256_file(output) != selected["sha256"]:
            raise ReplayError("refusing to replace an existing frozen topology snapshot")
        if not output.exists():
            shutil.copyfile(selected["source_path"], output)
        snapshot = {"path": str(output.resolve()), "sha256": sha256_file(output),
                    "time_index": selected["time_index"],
                    "satellite_path": selected["satellite_path"],
                    "source_sha256": selected["sha256"],
                    "selection": "earliest indexed matrix with GS26-GS27 satellite path"}
        if snapshot["sha256"] != selected["sha256"]:
            raise ReplayError("frozen snapshot copy hash mismatch")
        batch["frozen_topology"] = snapshot
        batch["updated_utc"] = utc_now()
        atomic_write_json(batch_path, batch)
    local_initial = Path(delay_dir) / "1.txt"
    original_initial_hash = sha256_file(local_initial) if local_initial.is_file() else None
    shutil.copyfile(snapshot["path"], local_initial)
    if sha256_file(local_initial) != snapshot["sha256"]:
        raise ReplayError("could not install the shared snapshot as StarryNet initial topology")
    atomic_write_json(Path(session_dir) / "frozen_topology.json", {
        "batch_id": manifest.get("batch_id"), "snapshot_path": snapshot["path"],
        "snapshot_sha256": snapshot["sha256"],
        "snapshot_time_index": snapshot["time_index"],
        "satellite_path": snapshot["satellite_path"],
        "original_generated_delay_1_sha256": original_initial_hash,
        "installed_initial_delay_sha256": sha256_file(local_initial)})
    manifest["topology"]["frozen_snapshot"] = snapshot
    atomic_write_json(manifest["manifest_path"], {
        key: value for key, value in manifest.items()
        if key not in ("manifest_path", "run_dir")})
    return snapshot


def qdisc_profile_text(cid, iface):
    return docker_exec(cid, "tc", "-s", "qdisc", "show", "dev", iface)


def parse_netem_profile(text):
    delay = re.search(r"\bdelay\s+([0-9.]+)(us|ms|s)(?:\s+([0-9.]+)(us|ms|s))?", text)
    loss = re.search(r"\bloss\s+([0-9.]+)%", text)
    rate = re.search(r"\brate\s+([0-9.]+)\s*([KMGT]?bit)", text, re.IGNORECASE)
    def milliseconds(value, unit):
        factor = {"us": 0.001, "ms": 1.0, "s": 1000.0}[unit.lower()]
        return float(value) * factor
    unit_factor = {"bit": 1, "kbit": 1000, "mbit": 1000000,
                   "gbit": 1000000000, "tbit": 1000000000000}
    rate_value = (int(round(float(rate.group(1)) * unit_factor[rate.group(2).lower()]))
                  if rate else None)
    root_netem = bool(re.search(r"\bqdisc\s+netem\s+\S+:\s+root\b", text))
    return {"root_netem": root_netem,
            "delay_ms": milliseconds(delay.group(1), delay.group(2)) if delay else None,
            "jitter_ms": (milliseconds(delay.group(3), delay.group(4))
                          if delay and delay.group(3) else 0.0),
            "distribution": (re.search(r"\bdistribution\s+(\w+)", text).group(1)
                             if re.search(r"\bdistribution\s+(\w+)", text) else None),
            "loss_percent": float(loss.group(1)) if loss else (0.0 if root_netem else None),
            "rate_bps": rate_value,
            "rate": rate.group(1) + rate.group(2) if rate else None}


def apply_gs_condition(sn, gs_cids, snapshot_path, scenario, session_dir):
    """Replace the complete netem root profile on both frozen GS interfaces."""
    if scenario not in FIXED_SCENARIOS:
        raise ReplayError("unknown fixed link condition: " + str(scenario))
    try:
        import numpy as np
    except ImportError as exc:
        raise ReplayError("numpy is required to map GS satellite interfaces") from exc
    matrix = np.loadtxt(snapshot_path, delimiter=",")
    specification = FIXED_SCENARIOS[scenario]
    evidence = []
    for node, cid in zip((CLIENT_NODE, REMOTE_NODE), gs_cids):
        satellites = [int(index) + 1 for index in np.flatnonzero(matrix[node - 1, :25])]
        if len(satellites) != 1:
            raise ReplayError("expected one frozen satellite attachment at GS" + str(node))
        satellite = satellites[0]
        iface = "B{0}-eth{1}".format(node, satellite)
        base_delay = float(matrix[node - 1, satellite - 1])
        before = qdisc_profile_text(cid, iface)
        current = parse_netem_profile(before)
        if (not current["root_netem"] or current["delay_ms"] is None or
                abs(current["delay_ms"] - base_delay) > 0.1 or
                current["jitter_ms"] != 0 or current["loss_percent"] != 0 or
                current["rate_bps"] != 5000000000 or current["distribution"] is not None):
            raise ReplayError("unexpected initial GS qdisc profile for " + iface + ": " + before)
        center = base_delay + specification["delay_ms"]
        command = ["tc", "qdisc", "replace", "dev", iface, "root", "netem",
                   "delay", "{0:.6f}ms".format(center)]
        if specification["jitter_ms"]:
            command += ["{0:.6f}ms".format(specification["jitter_ms"]),
                        "distribution", "normal"]
        command += ["loss", "{0:g}%".format(specification["loss_percent"]),
                    "rate", "5Gbit"]
        docker_exec(cid, *command)
        after = qdisc_profile_text(cid, iface)
        actual = parse_netem_profile(after)
        expected_distribution = "normal" if specification["jitter_ms"] else None
        if (not actual["root_netem"] or actual["delay_ms"] is None or
                abs(actual["delay_ms"] - center) > 0.1 or
                abs(actual["jitter_ms"] - specification["jitter_ms"]) > 0.1 or
                actual["loss_percent"] != specification["loss_percent"] or
                actual["rate_bps"] != 5000000000 or
                actual["distribution"] not in (expected_distribution, None) or
                (expected_distribution is None and actual["distribution"] is not None)):
            raise ReplayError("effective GS qdisc differs from frozen condition for " + iface + ": " + after)
        evidence.append({"ground_station": node, "container_id": str(cid),
                         "interface": iface, "satellite_node": satellite,
                         "base_propagation_delay_ms": base_delay,
                         "condition": dict(specification),
                         "expected_center_delay_ms": center,
                         "before": before, "command": command, "after": after,
                         "after_parsed": actual})
    output = Path(session_dir) / "gs_qdisc_profiles.json"
    atomic_write_json(output, {"scenario": scenario, "profiles": evidence})
    return {"path": str(output), "sha256": sha256_file(output),
            "scenario": scenario, "profiles": evidence}


def attachment_for_second(topology, second, ground_station=CLIENT_NODE):
    """Return the most recent attachment for a ground station."""
    if ground_station == CLIENT_NODE and topology.get("attachments_by_second"):
        mapping = topology["attachments_by_second"]
    else:
        mapping = topology.get("attachments_by_ground_station", {}).get(
            str(ground_station), {})
    values = [(int(key), value) for key, value in mapping.items()
              if int(key) <= float(second)]
    if not values:
        if ground_station == CLIENT_NODE:
            return topology.get("first_attachment_zero_based", [])
        return topology.get("first_attachments_zero_based", {}).get(
            str(ground_station), [])
    return max(values, key=lambda item: item[0])[1]


class AgentProcess:
    def __init__(self, cid, role, peer_ip, session_dir, listen_port, peer_port,
                 transport="udp", bind_address="0.0.0.0",
                 completion_timeout_seconds=TCP_COMPLETION_TIMEOUT_SECONDS):
        self.cid = str(cid)
        self.role = role
        self.peer_ip = peer_ip
        self.session_dir = Path(session_dir)
        self.listen_port = int(listen_port)
        self.peer_port = int(peer_port)
        self.transport = transport
        self.bind_address = bind_address
        self.completion_timeout_seconds = float(completion_timeout_seconds)
        self.process = None
        self.output = deque()
        self.output_lock = threading.Lock()
        self.errors = []
        self._thread = None
        self._log_handle = None
        self.log_path = self.session_dir / (self.role + "_agent.jsonl")
        self.remote_state_log = "/tmp/e-replay-v4/" + self.role + "_tcp_state.jsonl"

    def start(self):
        remote_script = "/tmp/e_replay_agent.py"
        docker_cp(AGENT_SOURCE, self.cid + ":" + remote_script)
        command = ["docker", "exec", "-i", self.cid, "python3", remote_script,
                   "--role", self.role, "--peer", self.peer_ip,
                   "--listen-port", str(self.listen_port),
                   "--peer-port", str(self.peer_port),
                   "--payload-bytes", str(PAYLOAD_BYTES),
                   "--tail-seconds", str(TAIL_SECONDS),
                   "--transport", self.transport, "--bind-address", self.bind_address,
                   "--tcp-completion-timeout", str(self.completion_timeout_seconds),
                   "--tcp-connect-timeout", str(TCP_CONNECT_TIMEOUT_SECONDS)]
        if self.transport == "tcp":
            command += ["--tcp-state-log", self.remote_state_log,
                        "--tcp-state-interval", str(TCP_STATE_INTERVAL_SECONDS)]
        # ``text=`` is not accepted by Python 3.6's Popen; the older
        # ``universal_newlines`` spelling provides the same line-oriented
        # text I/O used by the agent command channel.
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=1)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("a", encoding="utf-8", buffering=1)
        self._thread = threading.Thread(target=self._read_output, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with self.output_lock:
                output = list(self.output)
            for row in output:
                if row.get("type") == "ready":
                    return
                if row.get("type") == "agent_error":
                    raise ReplayError("agent failed to start: " + row.get("error", ""))
            if self.process.poll() is not None:
                raise ReplayError("agent exited before ready")
            time.sleep(0.05)
        raise ReplayError("agent did not become ready")

    def _read_output(self):
        assert self.process is not None
        for line in self.process.stdout:
            try:
                row = json.loads(line)
                with self.output_lock:
                    self.output.append(row)
                if self._log_handle:
                    self._log_handle.write(json.dumps(row, sort_keys=True) + "\n")
                    self._log_handle.flush()
            except ValueError:
                self.errors.append("invalid agent output: " + line.strip())
        stderr = self.process.stderr.read()
        if stderr.strip():
            self.errors.append(stderr.strip())

    def prepare_sample(self, sample_id, token, events):
        """Transfer a sample and wait for an explicit start command.

        The old protocol embedded ``start_ns`` in the first line and made the
        agent begin as soon as it received the final event.  For dense traces
        the coordinator could still be writing the second endpoint's event
        list when that deadline elapsed.  Preparation is now a separate phase;
        both endpoints retain the event list until the coordinator sends the
        common start timestamp.
        """
        if self.process is None or self.process.stdin is None:
            raise ReplayError("agent is not running")
        def send(value):
            self.process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        send({"op": "begin", "sample_id": sample_id, "sample_token": token})
        for event in events:
            send({"op": "event", "sample_id": sample_id,
                  "sequence": event["sequence"], "direction": event["direction"],
                  "offset_ns": event["offset_ns"]})
        send({"op": "end", "sample_id": sample_id})
        self.process.stdin.flush()

    def start_sample(self, sample_id, start_ns):
        if self.process is None or self.process.stdin is None:
            raise ReplayError("agent is not running")
        self.process.stdin.write(json.dumps(
            {"op": "start", "sample_id": sample_id,
             "start_ns": int(start_ns)}, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def wait_prepared(self, sample_id, timeout=60.0):
        deadline = time.monotonic() + timeout
        deferred = []
        try:
            while time.monotonic() < deadline:
                with self.output_lock:
                    row = self.output.popleft() if self.output else None
                if row is not None:
                    if row.get("type") == "prepared":
                        if row.get("sample_id") == sample_id:
                            return row
                        deferred.append(row)
                        continue
                    if row.get("type") == "agent_error":
                        raise ReplayError("agent error: " + row.get("error", ""))
                    deferred.append(row)
                    continue
                if self.process.poll() is not None:
                    raise ReplayError("agent exited while preparing sample")
                time.sleep(0.05)
            raise ReplayError("agent preparation timeout: " + sample_id)
        finally:
            if deferred:
                with self.output_lock:
                    for row in reversed(deferred):
                        self.output.appendleft(row)

    def wait_sample(self, sample_id, timeout):
        deadline = time.monotonic() + timeout
        # A long sample_done JSON record can arrive while the coordinator is
        # waiting for an earlier record (or while the other endpoint is being
        # checked).  Do not discard records for a different sample: doing so
        # makes a completed sample look like a timeout and breaks resume.
        deferred = []
        try:
            while time.monotonic() < deadline:
                with self.output_lock:
                    row = self.output.popleft() if self.output else None
                if row is not None:
                    if row.get("type") == "sample_done":
                        if row.get("sample_id") == sample_id:
                            return row
                        deferred.append(row)
                        continue
                    if row.get("type") == "agent_error":
                        raise ReplayError("agent error: " + row.get("error", ""))
                    # Keep lifecycle/diagnostic rows available for the next
                    # wait instead of silently consuming them.
                    deferred.append(row)
                    continue
                if self.process.poll() is not None:
                    raise ReplayError("agent exited while running sample")
                time.sleep(0.05)
            raise ReplayError("agent sample timeout: " + sample_id)
        finally:
            if deferred:
                with self.output_lock:
                    for row in reversed(deferred):
                        self.output.appendleft(row)

    def stop(self):
        if self.process is None:
            return
        try:
            if self.process.stdin:
                self.process.stdin.write(json.dumps({"op": "stop"}) + "\n")
                self.process.stdin.flush()
                self.process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self._thread:
            self._thread.join(timeout=5)
        if self._log_handle:
            for error in self.errors:
                self._log_handle.write(json.dumps({"type": "agent_stderr",
                                                    "role": self.role,
                                                    "error": error}, sort_keys=True) + "\n")
            self._log_handle.flush()
            self._log_handle.close()
            self._log_handle = None

    def write_log(self):
        if self._log_handle:
            self._log_handle.flush()
            self._log_handle.close()
            self._log_handle = None
        if not self.log_path.exists():
            self.log_path.touch()
        return self.log_path

    def write_tcp_state_log(self):
        path = self.session_dir / (self.role + "_tcp_state.jsonl")
        docker_cp(self.cid + ":" + self.remote_state_log, path)
        return validate_tcp_state_log(path, self.role)


def validate_tcp_state_log(path, role):
    path = Path(path)
    samples, valid_samples, errors = set(), set(), set()
    count = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("type") != "tcp_state" or row.get("role") != role:
                raise ReplayError("invalid TCP state log identity: " + str(path))
            count += 1
            samples.add(row["sample_id"])
            errors.update(row.get("errors", []))
            info = row.get("tcp_info") or {}
            if (all(info.get(k) is not None for k in (
                    "rto_us", "unacked_segments", "snd_cwnd_segments", "total_retrans"))
                    and row.get("outq_bytes") is not None
                    and row.get("sndbuf_bytes") is not None):
                valid_samples.add(row["sample_id"])
    return {"path": str(path), "sha256": sha256_file(path), "rows": count,
            "sample_ids": sorted(samples), "valid_sample_ids": sorted(valid_samples),
            "errors": sorted(errors)}


def require_tcp_state_diagnostics(summary):
    if summary.get("tcp_state_errors"):
        raise ReplayError("TCP state sampling failed: " + "; ".join(summary["tcp_state_errors"]))
    expected = {row["sample_id"] for row in summary.get("sample_results", [])}
    logs = summary.get("tcp_state_logs", {})
    for role in ("client", "remote"):
        if (not expected or not expected.issubset(set(logs.get(role, {}).get("valid_sample_ids", [])))
                or logs.get(role, {}).get("errors")):
            raise ReplayError("TCP state diagnostics incomplete: " + role)


def start_capture(cid, session_dir, interface, transport="udp"):
    remote_dir = "/tmp/e-replay-v4"
    docker_exec(cid, "mkdir", "-p", remote_dir)
    remote_pcap = remote_dir + "/client.pcap"
    remote_log = remote_dir + "/tcpdump.log"
    capture_filter = "{0} port {1} or {0} port {2}".format(transport, *UDP_PORTS)
    docker_exec(cid, "sh", "-c", "rm -f {0} {1}; tcpdump -i {4} -n -s 0 -U -w {0} '({2})' >{1} 2>&1 & echo $! >{3}".format(
        remote_pcap, remote_log, capture_filter, remote_dir + "/tcpdump.pid", interface))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            size = int(docker_exec(cid, "sh", "-c", "wc -c < " + remote_pcap))
            if size >= 24:
                return {"cid": str(cid), "remote_pcap": remote_pcap,
                        "remote_log": remote_log, "remote_dir": remote_dir,
                        "interface": interface,
                        "started": True}
        except (ReplayError, ValueError):
            pass
        time.sleep(0.2)
    detail = docker_exec(cid, "cat", remote_log, check=False)
    raise ReplayError("tcpdump did not initialize: " + detail)


def stop_capture(capture, session_dir):
    if not capture:
        return None
    cid = capture["cid"]
    docker_exec(cid, "sh", "-c", "kill -INT $(cat {0}) 2>/dev/null || true".format(
        capture["remote_dir"] + "/tcpdump.pid"), check=False)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        alive = docker_exec(
            cid, "sh", "-c",
            "if test -s {0} && kill -0 $(cat {0}) 2>/dev/null; "
            "then echo alive; fi".format(
                capture["remote_dir"] + "/tcpdump.pid"), check=False)
        if alive.strip() != "alive":
            break
        time.sleep(0.2)
    else:
        docker_exec(cid, "sh", "-c", "kill -TERM $(cat {0}) 2>/dev/null || true".format(
            capture["remote_dir"] + "/tcpdump.pid"), check=False)
        # Give tcpdump a final opportunity to close the PCAP after SIGTERM.
        time.sleep(0.5)
    local = Path(session_dir) / "client.pcap"
    docker_cp(cid + ":" + capture["remote_pcap"], local)
    log = docker_exec(cid, "cat", capture["remote_log"], check=False)
    logs_dir = Path(session_dir) / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "tcpdump.log").write_text(log + "\n", encoding="utf-8")
    (Path(session_dir) / "tcpdump.log").write_text(log + "\n", encoding="utf-8")
    return local


EV4_MAGIC = b"EV4\0"


def _transport_payload_from_frame(frame, link_type, expected_ports, transport):
    """Return an IPv4 TCP/UDP payload from a classic PCAP frame.

    StarryNet captures normally use Ethernet (DLT_EN10MB).  The additional
    Linux cooked, raw-IP and loopback layouts make the offline verifier useful
    on hosts whose tcpdump selects a different link type.  Unsupported link
    types remain format-valid but simply contribute no identifiable EV4 packet.
    """
    offset = None
    if link_type == 1:  # DLT_EN10MB
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], "big")
        offset = 14
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
        if ether_type != 0x0800:
            return None
    elif link_type == 113:  # DLT_LINUX_SLL
        if len(frame) < 16 or int.from_bytes(frame[14:16], "big") != 0x0800:
            return None
        offset = 16
    elif link_type == 276:  # DLT_LINUX_SLL2
        if len(frame) < 20 or int.from_bytes(frame[0:2], "big") != 0x0800:
            return None
        offset = 20
    elif link_type == 101:  # DLT_RAW
        offset = 0
    elif link_type == 0:  # DLT_NULL / DLT_LOOP
        if len(frame) < 4:
            return None
        offset = 4
    else:
        return None
    if len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_bytes = (version_ihl & 0x0F) * 4
    if ip_header_bytes < 20 or len(frame) < offset + ip_header_bytes + 8:
        return None
    if frame[offset + 9] != (6 if transport == "tcp" else 17):
        return None
    transport_offset = offset + ip_header_bytes
    source_port = int.from_bytes(frame[transport_offset:transport_offset + 2], "big")
    destination_port = int.from_bytes(frame[transport_offset + 2:transport_offset + 4], "big")
    if {source_port, destination_port}.isdisjoint(set(expected_ports)):
        return None
    if transport == "tcp":
        if len(frame) < transport_offset + 20:
            return None
        header_bytes = (frame[transport_offset + 12] >> 4) * 4
        ip_length = int.from_bytes(frame[offset + 2:offset + 4], "big")
        if (header_bytes < 20 or ip_length < ip_header_bytes + header_bytes
                or len(frame) < transport_offset + header_bytes
                or int.from_bytes(frame[offset + 6:offset + 8], "big") & 0x1FFF):
            return None
        return frame[transport_offset + header_bytes:min(len(frame), offset + ip_length)]
    udp_length = int.from_bytes(frame[transport_offset + 4:transport_offset + 6], "big")
    if udp_length < 8:
        return None
    payload_end = min(len(frame), transport_offset + udp_length)
    return frame[transport_offset + 8:payload_end]


def _classic_pcap_event_counts(path, expected_ports=UDP_PORTS):
    path = Path(path)
    with path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) < 24:
            raise ReplayError("PCAP global header is truncated: " + str(path))
        magic = global_header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            return None
        _magic, _major, _minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack(
            endian + "IHHiiii", global_header)
    packet_count = 0
    udp_packet_count = 0
    ev4_packet_count = 0
    tcp_packet_count = 0
    tcp_payload_packet_count = 0
    with path.open("rb") as handle:
        handle.seek(24)
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) < 16:
                raise ReplayError("truncated PCAP packet header: " + str(path))
            _sec, _usec, captured_length, _original_length = struct.unpack(
                endian + "IIII", packet_header)
            frame = handle.read(captured_length)
            if len(frame) != captured_length:
                raise ReplayError("truncated PCAP packet payload: " + str(path))
            packet_count += 1
            payload = _transport_payload_from_frame(frame, link_type, expected_ports, "udp")
            if payload is not None:
                udp_packet_count += 1
                if payload.startswith(EV4_MAGIC):
                    ev4_packet_count += 1
            payload = _transport_payload_from_frame(frame, link_type, expected_ports, "tcp")
            if payload is not None:
                tcp_packet_count += 1
                tcp_payload_packet_count += bool(payload)
    return {"packet_count": packet_count,
            "udp_packet_count": udp_packet_count,
            "ev4_packet_count": ev4_packet_count,
            "tcp_packet_count": tcp_packet_count,
            "tcp_payload_packet_count": tcp_payload_packet_count,
            "link_type": link_type}


def validate_pcap(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size < 24:
        raise ReplayError("PCAP is missing or too small: " + str(path))
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x0a\x0d\x0d\x0a"}:
        raise ReplayError("unrecognized PCAP/PCAPNG header: " + str(path))
    tshark = shutil.which("tshark")
    event_counts = _classic_pcap_event_counts(path)
    # The built-in classic-PCAP parser already checks record boundaries and
    # understands Linux cooked v2.  Older installed tshark builds may reject
    # DLT_LINUX_SLL2 even though the capture is valid, so use an external
    # parser only for formats (notably PCAPNG) not handled above.
    if event_counts is None and tshark:
        result = subprocess.run([tshark, "-r", str(path), "-c", "1", "-q"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60)
        if result.returncode:
            raise ReplayError("tshark could not parse PCAP: " + str(path))
    elif event_counts is None:
        tcpdump = shutil.which("tcpdump")
        if tcpdump:
            result = subprocess.run([tcpdump, "-r", str(path), "-c", "1", "-nn"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=60)
            # A valid empty capture can exit with no packet; reject only a
            # parser error, not the normal end-of-file status.
            if result.returncode not in (0, 1):
                raise ReplayError("tcpdump could not parse PCAP: " + str(path))
    result = {"path": str(path.resolve()), "bytes": path.stat().st_size,
              "sha256": sha256_file(path), "magic": magic.hex()}
    if event_counts is not None:
        result.update(event_counts)
    return result


def sample_token(sample_id):
    return int.from_bytes(hashlib.sha256(sample_id.encode("utf-8")).digest()[:8], "big")


def load_sample_events(sample):
    info = read_trace(sample["source_path"])
    if info["sha256"] != sample["source_sha256"]:
        raise ReplayError("source hash changed: " + sample["sample_id"])
    return info["events"], info


def sample_attempt_rows(manifest, sample_id):
    return [row for row in read_attempts(manifest)
            if row.get("sample_id") == sample_id]


def retry_allowed(manifest, sample_id):
    """Return whether an incomplete sample may be scheduled again.

    A missing or corrupted successful root is retryable because it is an
    artifact/infrastructure problem.  An explicitly non-retryable measurement
    result (for example, a sample with no client observation after network
    loss) is left in the ledger and is never silently re-collected by
    ``--resume``.
    """
    rows = sample_attempt_rows(manifest, sample_id)
    if not rows:
        return True
    def attempt_number(row):
        match = re.fullmatch(r"attempt-(\d+)", str(row.get("attempt_id", "")))
        return int(match.group(1)) if match else 0
    latest = max(rows, key=attempt_number)
    if latest.get("status") == "success":
        return True
    # Older coordinator versions classified a zero-observation sample as a
    # non-retryable network measurement even when sendto() returned an endpoint
    # error such as ENETUNREACH for every packet.  Those packets never entered
    # the emulated network, so this is an infrastructure failure.  Read the
    # immutable attempt evidence to make existing formal runs recoverable
    # without rewriting their append-only ledger.
    if latest.get("status") == "failure":
        evidence_path = (sample_root(manifest, sample_id) / "attempts"
                         / str(latest.get("attempt_id")) / "evidence.json")
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            endpoint_errors = (evidence.get("client_send_errors", [])
                               + evidence.get("remote_send_errors", [])
                               + evidence.get("client_receive_errors", [])
                               + evidence.get("remote_receive_errors", []))
            if (evidence.get("transport", "udp") == "udp"
                    and not evidence.get("client_observed_event_count", 0)
                    and endpoint_errors):
                return True
        except (OSError, ValueError, TypeError):
            pass
    return latest.get("retryable") is True


def next_attempt_number(manifest, sample_id):
    numbers = []
    for row in sample_attempt_rows(manifest, sample_id):
        match = re.fullmatch(r"attempt-(\d+)", str(row.get("attempt_id", "")))
        if match:
            numbers.append(int(match.group(1)))
    attempt_root = sample_root(manifest, sample_id) / "attempts"
    if attempt_root.is_dir():
        for path in attempt_root.iterdir():
            match = re.fullmatch(r"attempt-(\d+)", path.name)
            if match:
                numbers.append(int(match.group(1)))
    return max(numbers, default=0) + 1


def write_sample_result(manifest, sample, session_id, attempt_id, client_row,
                        remote_row, session_anchor_ns, runtime_meta,
                        status_override=None, error_type=None,
                        error_message=None):
    sample_id = sample["sample_id"]
    root = sample_root(manifest, sample_id)
    root.mkdir(parents=True, exist_ok=True)
    attempt_root = root / "attempts" / attempt_id
    if attempt_root.exists():
        raise ReplayError("attempt artifact already exists: " + str(attempt_root))
    attempt_root.mkdir(parents=True, exist_ok=False)
    client_row = client_row or {}
    remote_row = remote_row or {}
    source_events, source_info = load_sample_events(sample)
    scheduled_events = runtime_meta.get("scheduled_events")
    if scheduled_events is None:
        speed = float(manifest.get("speed", 1.0))
        scheduled_events = [dict(event, offset_ns=int(round(event["offset_ns"] / speed)))
                            for event in source_events]
    expected_token = sample_token(sample_id)
    actual_token = runtime_meta.get("sample_token", expected_token)
    if manifest.get("transport", "udp") == "tcp":
        verification = verify_events(source_events=scheduled_events,
                                     client_row=client_row, remote_row=remote_row,
                                     payload_bytes=PAYLOAD_BYTES)
        verification_errors = list(verification.get("errors", []))
        if verification.get("sample_id") != sample_id:
            verification_errors.append("sample ID differs from current manifest sample")
        if (actual_token != expected_token
                or verification.get("sample_token") != expected_token):
            verification_errors.append("sample token differs from current dispatch token")
        verification["errors"] = verification_errors
        verification["passed"] = not verification_errors
        verification["transport_scope"] = "strict_tcp_application_events"
    else:
        verification = {"passed": True, "errors": [],
                        "transport_scope": "legacy_udp_observed_packets",
                        "event_count": len(scheduled_events),
                        "client_record_count": len(client_row.get("records", [])),
                        "remote_record_count": len(remote_row.get("records", [])),
                        "sample_id": sample_id, "sample_token": expected_token}
    client_records = client_row.get("records", [])
    remote_records = remote_row.get("records", [])
    output_records = []
    trace_text = ""
    mapping_metadata = None
    if verification["passed"]:
        try:
            if manifest.get("transport", "udp") == "tcp":
                trace_text, output_records = build_client_trace(client_row)
            else:
                trace_text, output_records = build_legacy_udp_trace(client_row)
            mapping_metadata = write_gzip_jsonl(
                attempt_root / "trace_mapping.jsonl.gz", output_records)
        except (TypeError, ValueError, KeyError) as exc:
            verification["passed"] = False
            verification["errors"].append("client trace export failed: " + str(exc))
    trace_path = attempt_root / "trace"
    trace_path.write_text(trace_text, encoding="utf-8")
    observed = [record for record in client_records
                if ((record.get("action") == "send" and record.get("direction") == 1)
                    or (record.get("action") == "recv" and record.get("direction") == -1))]
    reorder_count = sum(1 for previous, current in zip(observed, observed[1:])
                        if int(current.get("observed_ns", 0)) <
                        int(previous.get("observed_ns", 0)))
    expected_plus = sum(event["direction"] == 1 for event in source_events)
    expected_minus = sum(event["direction"] == -1 for event in source_events)
    remote_records = remote_row.get("records", [])
    remote_plus = sum(row.get("action") == "recv" and row.get("direction") == 1
                      for row in remote_records)
    remote_minus = sum(row.get("action") == "send" and row.get("direction") == -1
                       for row in remote_records)
    client_plus = sum(row.get("action") == "send" and row.get("direction") == 1
                      for row in client_records)
    client_minus = sum(row.get("action") == "recv" and row.get("direction") == -1
                       for row in client_records)
    sequence_pairs = [(row["sequence"], row["direction"]) for row in observed]
    remote_pairs = [(row.get("sequence"), row.get("direction"))
                    for row in remote_records
                    if row.get("action") in ("recv", "send")]
    duplicate_count = max(len(sequence_pairs) - len(set(sequence_pairs)),
                          len(remote_pairs) - len(set(remote_pairs)))
    invalid_direction_count = sum(
        1 for row in client_records
        if row.get("action") in ("send", "recv")
        and ((row.get("action") == "send" and row.get("direction") != 1)
             or (row.get("action") == "recv" and row.get("direction") != -1)))
    endpoint_errors = (client_row.get("send_errors", [])
                       + remote_row.get("send_errors", [])
                       + client_row.get("receive_errors", [])
                       + remote_row.get("receive_errors", []))
    tcp_submitted = (bool(remote_records) or any(
        int(row.get("bytes_submitted", 0)) > 0 for row in endpoint_errors
        if isinstance(row, dict)))
    if status_override:
        result_status = status_override
        result_error_type = error_type
        result_error_message = error_message
    elif manifest.get("transport") == "tcp" and tcp_submitted and (
            not observed or remote_plus != expected_plus
            or client_minus != expected_minus):
        result_status = "failure"
        result_error_type = "tcp_incomplete_reception"
        result_error_message = "TCP application frames were not fully received"
    elif observed and remote_plus == 0 and client_minus == 0:
        result_status = "failure"
        result_error_type = "no_endpoint_reception"
        result_error_message = "no packet reception was recorded at either endpoint"
    elif observed and endpoint_errors:
        result_status = "failure"
        result_error_type = "endpoint_transport_error"
        result_error_message = "endpoint transport errors occurred during the sample"
    elif (manifest.get("transport") == "tcp" and observed and
          (remote_plus != expected_plus or client_minus != expected_minus)):
        result_status = "failure"
        result_error_type = "tcp_incomplete_reception"
        result_error_message = "TCP application frames were not fully received"
    elif not verification["passed"]:
        result_status = "failure"
        result_error_type = "event_evidence_invalid"
        result_error_message = "; ".join(verification["errors"][:10])
    elif observed:
        result_status = "success"
        result_error_type = None
        result_error_message = None
    elif manifest.get("transport") == "tcp" and tcp_submitted:
        result_status = "failure"
        result_error_type = "tcp_incomplete_reception"
        result_error_message = "TCP traffic was submitted but no complete client events remained"
    elif endpoint_errors:
        result_status = "infrastructure_failure"
        result_error_type = "endpoint_transport_error"
        result_error_message = "endpoint could not submit packets to the emulated network"
    else:
        result_status = "failure"
        result_error_type = "empty_client_observation"
        result_error_message = "no client-side observed events"
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "sample_id": sample_id,
        "class_id": sample["class_id"],
        "repeat_id": sample["repeat_id"],
        "source_path": sample["source_path"],
        "source_sha256": sample["source_sha256"],
        "run_id": manifest["run_id"],
        "session_id": session_id,
        "attempt_id": attempt_id,
        "transport": manifest.get("transport", "udp"),
        "trace_semantics": "client_application_events",
        "client_finished_ns": client_row.get("finished_ns"),
        "client_tcp_state_summary": client_row.get("tcp_state_summary"),
        "remote_tcp_state_summary": remote_row.get("tcp_state_summary"),
        "remote_finished_ns": remote_row.get("finished_ns"),
        "sample_token": expected_token,
        "simulation_start_second": sample["start_second"],
        "simulation_end_second": sample["start_second"] + sample["duration_seconds"],
        "wall_start_ns": runtime_meta.get("wall_start_ns"),
        "wall_end_ns": runtime_meta.get("wall_end_ns"),
        "route_before_sample": runtime_meta.get("route_before_sample"),
        "route_wait_seconds": runtime_meta.get("route_wait_seconds"),
        "route_wait_timeout_seconds": runtime_meta.get("route_wait_timeout_seconds"),
        "source_event_count": len(source_events),
        "scheduled_event_count": len(source_events),
        "client_observed_event_count": len(observed),
        "remote_observed_event_count": len(remote_records),
        "outbound_sent": client_plus,
        "outbound_send_failed": max(0, expected_plus - client_plus),
        "outbound_received": remote_plus,
        "outbound_lost": max(0, client_plus - remote_plus),
        "inbound_sent": remote_minus,
        "inbound_send_failed": max(0, expected_minus - remote_minus),
        "inbound_received": client_minus,
        "inbound_lost": max(0, remote_minus - client_minus),
        "expected_outbound": expected_plus,
        "expected_inbound": expected_minus,
        "duplicate_count": duplicate_count,
        "reorder_count": reorder_count,
        "invalid_direction_count": invalid_direction_count,
        "small_timestamp_correction_count": source_info["small_reversal_count"],
        "large_timestamp_reversal_count": 0,
        "handover_count": runtime_meta.get("handover_count", 0),
        "source_satellite_before": runtime_meta.get("source_satellite_before"),
        "source_satellite_after": runtime_meta.get("source_satellite_after"),
        "remote_satellite_before": runtime_meta.get("remote_satellite_before"),
        "remote_satellite_after": runtime_meta.get("remote_satellite_after"),
        "actual_route_chains_before": runtime_meta.get("actual_route_chains_before"),
        "actual_route_chains_after": runtime_meta.get("actual_route_chains_after"),
        "event_verification": verification,
        "client_record_count": len(client_records),
        "remote_record_count": len(remote_records),
        "trace_mapping": mapping_metadata,
        "trace_sha256": sha256_file(trace_path),
        "status": result_status,
        "error_type": result_error_type,
        "error_message": result_error_message,
        "attempt_artifact_dir": str(attempt_root),
        "client_send_errors": client_row.get("send_errors", []),
        "client_receive_errors": client_row.get("receive_errors", []),
        "remote_send_errors": remote_row.get("send_errors", []),
        "remote_receive_errors": remote_row.get("receive_errors", []),
    }
    if runtime_meta.get("handover_control") is not None:
        evidence["handover_control"] = runtime_meta["handover_control"]
    atomic_write_json(attempt_root / "evidence.json", evidence)
    if evidence["status"] == "success":
        # The root artifact is the latest successful attempt.  Previous
        # attempts remain immutable below samples/<id>/attempts/.
        shutil.copy2(trace_path, root / "trace")
        atomic_write_json(root / "evidence.json", evidence)
    return evidence


def write_failure_stub(manifest, sample, session_id, attempt_id, error):
    """Persist an attempt even when failure happened before event parsing."""
    root = sample_root(manifest, sample["sample_id"])
    root.mkdir(parents=True, exist_ok=True)
    attempt_root = root / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    trace = attempt_root / "trace"
    if not trace.exists():
        trace.write_text("", encoding="utf-8")
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "sample_id": sample["sample_id"],
        "class_id": sample.get("class_id"),
        "repeat_id": sample.get("repeat_id"),
        "source_path": sample.get("source_path"),
        "source_sha256": sample.get("source_sha256"),
        "run_id": manifest["run_id"],
        "session_id": session_id,
        "attempt_id": attempt_id,
        "source_event_count": sample.get("event_count"),
        "transport": manifest.get("transport", "udp"),
        "trace_semantics": "client_application_events",
        "scheduled_event_count": 0,
        "client_observed_event_count": 0,
        "remote_observed_event_count": 0,
        "large_timestamp_reversal_count": None,
        "trace_sha256": sha256_file(trace),
        "status": "infrastructure_failure",
        "error_type": type(error).__name__,
        "error_message": str(error),
        "attempt_artifact_dir": str(attempt_root),
    }
    atomic_write_json(attempt_root / "evidence.json", evidence)
    return evidence


def find_handover_for_second(topology, second):
    values = topology.get("handover_seconds", [])
    before = [value for value in values if value <= second]
    return before[-1] if before else None


def start_heartbeat(session_dir, session_id, worker_errors):
    stop_event = threading.Event()
    path = Path(session_dir) / "heartbeat.jsonl"

    def write_row():
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id,
                "utc": utc_now(),
                "monotonic_ns": monotonic_ns(),
                "worker_errors": list(worker_errors),
            }, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    write_row()

    def loop():
        while not stop_event.wait(10.0):
            try:
                write_row()
            except OSError:
                # The session cleanup path still records the failure in its
                # summary; a heartbeat thread must never mask it.
                return

    thread = threading.Thread(target=loop, name="e-v4-heartbeat", daemon=True)
    thread.start()
    return stop_event, thread, path


def run_session(manifest, session, sample_specs, session_dir, session_seconds,
                session_tail_seconds=SESSION_TAIL_SECONDS, sample_start_resolver=None):
    session_dir = Path(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)
    config_path = make_runtime_config(session_dir, session_seconds,
                                      manifest["topology"]["config"])
    sys.path.insert(0, str(ROOT))
    from starrynet.sn_synchronizer import StarryNet
    from starrynet.sn_thread import WORKER_ERRORS
    WORKER_ERRORS.clear()
    sn = None
    client_agent = None
    remote_agent = None
    capture = None
    remote_capture = None
    emulation_thread = None
    emulation_error = []
    session_anchor_ns = None
    sample_specs = rebase_runtime_schedule(
        sample_specs, manifest.get("guard_seconds", GUARD_SECONDS))
    summary = {"schema_version": SCHEMA_VERSION, "session_id": session["session_id"],
               "status": "running",
               "dynamic_required": manifest.get("topology", {}).get("mode", "dynamic") == "dynamic",
               "sample_count": len(sample_specs), "sample_results": [],
               "worker_errors": []}
    owner_id = manifest.get("owner_id") or "constellation-test"
    service_name = manifest.get("service_name") or "constellation-test"
    topology_mode = manifest.get("topology", {}).get("mode", "dynamic")
    summary["topology_mode"] = topology_mode
    summary["scenario"] = manifest.get("scenario")
    cleanup_failure = None
    lock_root = ROOT / "artifacts" / "research2_tcp_drift"
    lock_root.mkdir(parents=True, exist_ok=True)
    resource_lock = (lock_root / ".starrynet-resource.lock").open("a")
    try:
        fcntl.flock(resource_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        resource_lock.close()
        raise ReplayError("another research2 session holds the shared StarryNet resource lock") from exc
    heartbeat_stop, heartbeat_thread, heartbeat_path = start_heartbeat(
        session_dir, session["session_id"], WORKER_ERRORS)
    summary["heartbeat"] = str(heartbeat_path)
    emulation_stop_requested = False
    try:
        summary["phase"] = "inventory"
        inventory_before = docker_inventory(owner_id, service_name)
        summary["resource_inventory_before"] = inventory_before
        if not starrynet_resources_cleared(inventory_before, owner_id, service_name):
            raise ReplayError("batch-owned StarryNet resources already exist; refusing to overlap a session")
        sn = StarryNet(str(config_path), GS, 1, [[1, 27]], local=True, argv=[])
        sn.docker_service_name = service_name
        # Pass this only to this run's local worker subprocesses. The flag
        # also reaches GSL creation during handover; unrelated runs and the
        # host Docker firewall retain their existing settings.
        sn.remote_ssh.env_overrides["STARRYNET_DISABLE_MASQUERADE"] = (
            "0" if manifest.get("docker_bridge_masquerade", True) else "1")
        sn.remote_ssh.env_overrides["STARRYNET_OWNER"] = owner_id
        sn.remote_ssh.env_overrides["STARRYNET_SERVICE"] = service_name
        snapshot = None
        if topology_mode == "fixed":
            summary["phase"] = "fixed_snapshot"
            delay_dir = Path(sn.configuration_file_path) / sn.file_path / "delay"
            snapshot = ensure_frozen_snapshot(manifest, delay_dir, session_dir)
            # StarryNet's constructor already generated router configs from
            # delay/1.txt. Regenerate them after installing the frozen matrix
            # so the initial links and the routing daemon use the same snapshot.
            sn.observer.generate_conf(sn.remote_ssh, sn.remote_ftp)
        summary["docker_bridge_masquerade"] = manifest.get("docker_bridge_masquerade", True)
        summary["phase"] = "create_nodes"
        sn.create_nodes()
        summary["phase"] = "create_links"
        sn.create_links()
        if WORKER_ERRORS:
            raise ReplayError("StarryNet worker error: " + str(WORKER_ERRORS))
        if not manifest.get("docker_bridge_masquerade", True):
            networks = inspect_replay_bridges(owner_id)
            atomic_write_json(session_dir / "bridge_networks.json", networks)
            summary["bridge_networks"] = str(session_dir / "bridge_networks.json")
            summary["bridge_networks_sha256"] = sha256_file(
                session_dir / "bridge_networks.json")
        summary["phase"] = "routing"
        sn.run_routing_deamon()
        if WORKER_ERRORS:
            raise ReplayError("routing worker error: " + str(WORKER_ERRORS))
        client_cid, remote_cid = get_container_ids(sn)
        peer_ip = find_peer_ip(remote_cid)
        node_ips = {node: [address for addresses in
                           get_node_link_ipv4_addresses(cid, node).values()
                           for address in addresses]
                    for node, cid in enumerate(sn.container_id_list, 1)}
        node_ips[CLIENT_NODE].append(find_client_ip(client_cid))
        node_ips[REMOTE_NODE].append(find_peer_ip(remote_cid))
        summary["phase"] = "topology_validation"
        if topology_mode == "fixed":
            topology = fixed_topology_summary(snapshot["path"])
            if topology["matrix_sha256"] != snapshot["sha256"]:
                raise ReplayError("session topology matrix differs from shared frozen snapshot")
        else:
            topology = topology_summary(Path(sn.configuration_file_path) / sn.file_path)
        summary["topology"] = topology
        if topology_mode == "dynamic" and (
                topology["matrix_changed_count"] < 1 or topology["handover_count"] < 1):
            raise ReplayError("dynamic topology has no matrix changes or handover")
        if session["session_id"] == "preflight" and topology_mode == "dynamic":
            first_handover = topology["handover_seconds"][0]
            preflight_starts = [max(15.0, first_handover - 30.0),
                                max(15.0, first_handover - 2.0),
                                first_handover + 20.0]
            for sample, start_second in zip(sample_specs, preflight_starts):
                sample["start_second"] = round(start_second, 6)
            summary["preflight_handover_second"] = first_handover
        if topology_mode == "fixed":
            summary["gs_qdisc_before_after_apply"] = apply_gs_condition(
                sn, [client_cid, remote_cid], snapshot["path"],
                manifest["scenario"], session_dir)
        summary["phase"] = "route_before"
        summary["route_before"] = wait_for_satellite_route(client_cid, peer_ip)
        client_ip = find_client_ip(client_cid)
        reverse_route = docker_exec(remote_cid, "ip", "route", "get", client_ip)
        if not re.search(r"\bdev\s+B27-eth\d+\b", reverse_route):
            raise ReplayError("GS27 return route does not use a satellite-facing interface: "
                              + reverse_route)
        summary["route_before"]["remote_route"] = reverse_route
        summary["route_before"]["remote_satellite_route"] = True
        route_forward = actual_satellite_route_chain(sn, CLIENT_NODE, REMOTE_NODE,
                                                     node_ips)
        route_reverse = actual_satellite_route_chain(sn, REMOTE_NODE, CLIENT_NODE,
                                                     node_ips)
        summary["actual_route_chains_before"] = {
            "forward": route_forward, "reverse": route_reverse}
        if topology_mode == "fixed":
            summary["fixed_route_baseline"] = register_fixed_route_baseline(
                manifest, route_forward, route_reverse)
        route_dir = session_dir / "route_snapshots"
        route_dir.mkdir(parents=True, exist_ok=True)
        summary["route_before"]["actual_route_chains"] = summary["actual_route_chains_before"]
        atomic_write_json(route_dir / "before.json", summary["route_before"])
        handover_path = session_dir / "handover_events.jsonl"
        with handover_path.open("w", encoding="utf-8") as handle:
            if topology_mode == "fixed":
                handle.write(json.dumps({"event_type": "fixed_topology_snapshot",
                                         "snapshot_sha256": snapshot["sha256"],
                                         "time_index": snapshot["time_index"],
                                         "handover_count": 0}, sort_keys=True) + "\n")
            for second in topology["handover_seconds"]:
                ground_stations = topology.get(
                    "handover_ground_stations_by_second", {}).get(
                        str(second), [CLIENT_NODE, REMOTE_NODE])
                handle.write(json.dumps({
                    "simulation_second": second,
                    "ground_stations": ground_stations,
                    "attachment_before": attachment_for_second(
                        topology, second - 0.001, CLIENT_NODE),
                    "attachment_after": attachment_for_second(
                        topology, second, CLIENT_NODE),
                    "attachments_before": {
                        str(node): attachment_for_second(
                            topology, second - 0.001, node)
                        for node in ground_stations},
                    "attachments_after": {
                        str(node): attachment_for_second(topology, second, node)
                        for node in ground_stations},
                }, sort_keys=True) + "\n")
        summary["handover_events"] = str(handover_path)
        # A GS26 handover deletes the old B26-eth* interface.  Binding tcpdump
        # to that initial device silently truncates a multi-hour capture after
        # the first GS26 handover. Capture the EV4 transport ports on
        # every interface in the GS26 namespace; the route snapshots above and
        # below still prove that their remote endpoint uses a satellite link.
        summary["capture_interface"] = "any"
        transport = manifest.get("transport", "udp")
        summary["transport"] = transport
        summary["trace_semantics"] = "client_application_events"
        summary["capture_scope"] = "GS26 namespace, EV4 " + transport.upper() + " ports"
        summary["phase"] = "capture_agents"
        capture = start_capture(client_cid, session_dir, "any", transport)
        if transport == "tcp" and session["session_id"] == "preflight":
            (session_dir / "remote_capture").mkdir(parents=True, exist_ok=True)
            remote_capture = start_capture(
                remote_cid, session_dir / "remote_capture", "any", transport)
        if transport == "tcp" and not (
                client_ip.startswith("9.26.26.") and peer_ip.startswith("9.27.27.")):
            raise ReplayError("TCP replay requires stable GS26/GS27 endpoint addresses")
        client_agent = AgentProcess(client_cid, "client", peer_ip, session_dir,
                                    UDP_PORT, REMOTE_UDP_PORT, transport,
                                    client_ip if transport == "tcp" else "0.0.0.0",
                                    manifest.get("tcp_completion_timeout_seconds",
                                                 TCP_COMPLETION_TIMEOUT_SECONDS))
        remote_agent = AgentProcess(remote_cid, "remote", client_ip,
                                    session_dir, REMOTE_UDP_PORT, UDP_PORT, transport,
                                    peer_ip if transport == "tcp" else "0.0.0.0",
                                    manifest.get("tcp_completion_timeout_seconds",
                                                 TCP_COMPLETION_TIMEOUT_SECONDS))
        client_agent.start()
        remote_agent.start()
        if topology_mode == "dynamic":
            emulation_thread = threading.Thread(
                target=lambda: _run_emulation(sn, emulation_error), daemon=True)
            emulation_thread.start()
        else:
            summary["dynamic_scheduler_started"] = False
        # Anchor both agents only after the dynamic scheduler has been started;
        # setup time must not consume the planned simulation seconds.
        session_anchor_ns = monotonic_ns()
        summary["session_anchor_monotonic_ns"] = session_anchor_ns
        time.sleep(WARMUP_SECONDS)
        summary["phase"] = "samples"
        rollover_requested = False
        for sample in sample_specs:
            if emulation_error:
                raise ReplayError("dynamic emulation failed: " + str(emulation_error[0]))
            # Do not consume an attempt while the endpoint has no route at
            # all.  A packet rejected locally with ENETUNREACH never entered
            # the emulated network and is not a network-loss measurement.
            route_wait_started = monotonic_ns()
            try:
                sample_route = wait_for_satellite_route(
                    client_cid, peer_ip, ROUTE_ROLLOVER_TIMEOUT_SECONDS)
            except SatelliteRouteUnavailable as exc:
                # BIRD has repeatedly failed to restore the end-to-end route
                # after a long GSL outage even though later GSLs were added.
                # Preserve all completed samples, clean this topology, and let
                # cmd_run immediately continue the remaining suffix in a new
                # topology instance.  No sample attempt has been allocated.
                summary["status"] = "rollover_required"
                summary["rollover_reason"] = str(exc)
                summary["rollover_before_sample"] = sample["sample_id"]
                rollover_requested = True
                break
            route_wait_seconds = (monotonic_ns() - route_wait_started) / 1e9
            attempt_number = next_attempt_number(manifest, sample["sample_id"])
            if attempt_number > max_infrastructure_attempts(manifest):
                raise ReplayError("maximum infrastructure attempts exceeded for "
                                  + sample["sample_id"])
            attempt_id = "attempt-{0}".format(attempt_number)
            runtime_sample = dict(sample)
            runtime_meta = {"wall_start_ns": monotonic_ns(),
                            "route_before_sample": sample_route["route"],
                            "route_wait_timeout_seconds":
                                ROUTE_ROLLOVER_TIMEOUT_SECONDS,
                            "route_wait_seconds": route_wait_seconds}
            try:
                events, source_info = load_sample_events(sample)
                runtime_sample["duration_seconds"] = (
                    source_info["duration_seconds"] / manifest["speed"])
                scheduled_events = [dict(
                    event, offset_ns=int(round(event["offset_ns"] / manifest["speed"])))
                    for event in events]
                token = sample_token(sample["sample_id"])
                # Event transfer is deliberately a preparation phase.  It may
                # take longer than the source trace's dispatch lead for dense
                # samples, but neither endpoint starts until both have
                # acknowledged the complete event list.
                client_agent.prepare_sample(sample["sample_id"], token,
                                            scheduled_events)
                remote_agent.prepare_sample(sample["sample_id"], token,
                                            scheduled_events)
                prepare_timeout = max(
                    60.0, dispatch_lead_seconds(len(events)) * 4.0 + 5.0)
                client_agent.wait_prepared(sample["sample_id"], prepare_timeout)
                remote_agent.wait_prepared(sample["sample_id"], prepare_timeout)
                if emulation_error:
                    raise ReplayError("dynamic emulation failed: " +
                                      str(emulation_error[0]))
                if manifest.get("diagnostic_mode") in ("stable", "crossing"):
                    runtime_meta["actual_route_chains_before"] = {
                        "forward": actual_satellite_route_chain(
                            sn, CLIENT_NODE, REMOTE_NODE),
                        "reverse": actual_satellite_route_chain(
                            sn, REMOTE_NODE, CLIENT_NODE)}
                planned_start_ns = session_anchor_ns + int(sample["start_second"] * 1e9)
                # Only the tiny start command remains after preparation, so a
                # bounded lead is sufficient and is shared by both agents.
                start_ns = max(planned_start_ns,
                               monotonic_ns() + int(DISPATCH_LEAD_SECONDS * 1e9))
                if sample_start_resolver is not None:
                    # A diagnostic may anchor an already-prepared connection
                    # to an observed event. The topology scheduler keeps running.
                    start_ns, anchor_meta = sample_start_resolver({
                        "session_dir": session_dir, "topology": topology,
                        "session_anchor_ns": session_anchor_ns, "sample": sample,
                        "client_cid": client_cid, "remote_cid": remote_cid,
                        "emulation_errors": emulation_error})
                    if start_ns < monotonic_ns() + int(DISPATCH_LEAD_SECONDS * 1e9):
                        raise ReplayError("diagnostic start anchor was missed; refusing to shift it")
                    runtime_meta["handover_control"] = anchor_meta
                runtime_sample["start_second"] = round(
                    (start_ns - session_anchor_ns) / 1e9, 6)
                if runtime_sample["start_second"] + runtime_sample["duration_seconds"] > (
                        session_seconds - session_tail_seconds):
                    raise ReplayError(
                        "runtime scheduling exceeded usable session window for "
                        + sample["sample_id"])
                runtime_meta.update({
                    "handover_count": (sum(
                        1 for value in topology["handover_seconds"]
                        if runtime_sample["start_second"] <= value <=
                        runtime_sample["start_second"] + runtime_sample["duration_seconds"])
                        if topology_mode == "dynamic" else 0),
                    "source_satellite_before": attachment_for_second(
                        topology, runtime_sample["start_second"]),
                    "source_satellite_after": attachment_for_second(
                        topology, runtime_sample["start_second"] +
                        runtime_sample["duration_seconds"]),
                    "remote_satellite_before": attachment_for_second(
                        topology, runtime_sample["start_second"], REMOTE_NODE),
                    "remote_satellite_after": attachment_for_second(
                        topology, runtime_sample["start_second"] +
                        runtime_sample["duration_seconds"], REMOTE_NODE),
                })
                client_agent.start_sample(sample["sample_id"], start_ns)
                remote_agent.start_sample(sample["sample_id"], start_ns)
                # The command is sent before the common absolute start time.
                # A timeout based only on trace duration would therefore
                # expire while a deliberately scheduled pre-handover sample is
                # still waiting to start.  Use one absolute deadline for both
                # endpoints and recompute the remaining time for the second
                # wait, retaining the specified duration + tail + margin
                # after the last scheduled event.
                last_offset_ns = max(
                    (int(event["offset_ns"]) for event in scheduled_events),
                    default=0)
                receive_grace = (float(manifest.get("tcp_completion_timeout_seconds",
                                                     TCP_COMPLETION_TIMEOUT_SECONDS))
                                 if transport == "tcp"
                                 else TAIL_SECONDS)
                coordinator_wait = (TCP_COORDINATOR_WAIT_SECONDS
                                    if transport == "tcp" else SAMPLE_TIMEOUT_MARGIN_SECONDS)
                sample_deadline_ns = (start_ns + last_offset_ns
                                      + int((receive_grace + coordinator_wait) * 1e9))
                timeout = max(
                    1.0, (sample_deadline_ns - monotonic_ns()) / 1e9)
                client_row = client_agent.wait_sample(sample["sample_id"], timeout)
                timeout = max(
                    1.0, (sample_deadline_ns - monotonic_ns()) / 1e9)
                remote_row = remote_agent.wait_sample(sample["sample_id"], timeout)
                if manifest.get("diagnostic_mode") in ("stable", "crossing"):
                    runtime_meta["actual_route_chains_after"] = {
                        "forward": actual_satellite_route_chain(
                            sn, CLIENT_NODE, REMOTE_NODE),
                        "reverse": actual_satellite_route_chain(
                            sn, REMOTE_NODE, CLIENT_NODE)}
                if manifest.get("tcp_state_interval_seconds") is not None:
                    for role, row in (("client", client_row), ("remote", remote_row)):
                        state = row.get("tcp_state_summary") or {}
                        if not state.get("tcp_info_rows") or state.get("errors"):
                            summary.setdefault("tcp_state_errors", []).append(
                                sample["sample_id"] + "/" + role + ": " + str(state))
                runtime_meta["wall_end_ns"] = monotonic_ns()
                runtime_meta["sample_token"] = token
                runtime_meta["scheduled_events"] = scheduled_events
                evidence = write_sample_result(
                    manifest, runtime_sample, session["session_id"], attempt_id,
                    client_row, remote_row, session_anchor_ns, runtime_meta)
            except BaseException as exc:
                runtime_meta["wall_end_ns"] = monotonic_ns()
                evidence = write_failure_stub(
                    manifest, runtime_sample, session["session_id"], attempt_id, exc)
                append_attempt(manifest, {"schema_version": SCHEMA_VERSION,
                                          "sample_id": sample["sample_id"],
                                          "session_id": session["session_id"],
                                          "attempt_id": attempt_id,
                                          "status": evidence["status"],
                                          "retryable": True,
                                          "network_loss_is_measurement": False,
                                          "trace_sha256": evidence.get("trace_sha256"),
                                          "timestamp": utc_now()})
                summary["sample_results"].append({
                    "sample_id": sample["sample_id"], "status": evidence["status"],
                    "source_sample_id": sample.get("source_sample_id", sample["sample_id"]),
                    "attempt_id": evidence.get("attempt_id"),
                    "event_verification": evidence.get("event_verification"),
                    "observed_events": evidence.get("client_observed_event_count", 0)})
                raise
            attempt_retryable = evidence["status"] == "infrastructure_failure"
            append_attempt(manifest, {"schema_version": SCHEMA_VERSION,
                                      "sample_id": sample["sample_id"],
                                      "session_id": session["session_id"],
                                      "attempt_id": evidence["attempt_id"],
                                      "status": evidence["status"],
                                      "retryable": attempt_retryable,
                                      "network_loss_is_measurement": not attempt_retryable,
                                      "trace_sha256": evidence["trace_sha256"],
                                      "timestamp": utc_now()})
            summary["sample_results"].append({"sample_id": sample["sample_id"],
                                               "status": evidence["status"],
                                               "source_sample_id": sample.get(
                                                   "source_sample_id", sample["sample_id"]),
                                               "attempt_id": evidence.get("attempt_id"),
                                               "event_verification": evidence.get(
                                                   "event_verification"),
                                               "observed_events": evidence["client_observed_event_count"]})
        if emulation_error:
            raise ReplayError("dynamic emulation failed: " + str(emulation_error[0]))
        # A session is complete once every supplied sample has been collected.
        # StarryNet's topology-update operations can make simulation seconds
        # lag behind wall time substantially during long runs.  Waiting for
        # the configured duration after the last sample adds no evidence and
        # can produce a false timeout, so retain the final live route here and
        # let the common finally block stop the emulator and clean resources.
        summary["emulation_stopped_after_samples"] = not rollover_requested
        summary["route_after"] = final_route_snapshot(
            client_cid, peer_ip, 1.0 if rollover_requested else 30.0)
        if not summary["route_after"].get("unavailable"):
            reverse_after = docker_exec(remote_cid, "ip", "route", "get", client_ip,
                                        check=False)
            summary["route_after"]["remote_route"] = reverse_after
            summary["route_after"]["remote_satellite_route"] = bool(
                re.search(r"\bdev\s+B27-eth\d+\b", reverse_after))
            if topology_mode == "fixed":
                chains_after = {
                    "forward": actual_satellite_route_chain(
                        sn, CLIENT_NODE, REMOTE_NODE, node_ips),
                    "reverse": actual_satellite_route_chain(
                        sn, REMOTE_NODE, CLIENT_NODE, node_ips)}
                summary["actual_route_chains_after"] = chains_after
                if {key: value["nodes"] for key, value in chains_after.items()} != {
                        key: value["nodes"] for key, value in
                        summary["actual_route_chains_before"].items()}:
                    raise ReplayError("fixed topology actual satellite route changed during session")
                summary["route_after"]["actual_route_chains"] = chains_after
        atomic_write_json(route_dir / "after.json", summary["route_after"])
        if not rollover_requested:
            summary["status"] = "completed"
            summary["phase"] = "completed"
        summary["dynamic_matrix_changed"] = (
            topology["matrix_changed_count"] > 0 if topology_mode == "dynamic" else False)
        summary["handover_count"] = topology["handover_count"]
        summary["fixed_snapshot_sha256"] = snapshot["sha256"] if snapshot else None
        if topology_mode == "fixed" and summary.get("gs_qdisc_before_after_apply"):
            final_profiles = []
            for profile in summary["gs_qdisc_before_after_apply"]["profiles"]:
                final_text = qdisc_profile_text(profile["container_id"], profile["interface"])
                actual = parse_netem_profile(final_text)
                expected = profile["after_parsed"]
                keys = ("delay_ms", "jitter_ms", "distribution", "loss_percent", "rate_bps")
                if any(actual.get(key) != expected.get(key) for key in keys):
                    # Some kernels omit the stored distribution name after
                    # printing the configured jitter; the successful command
                    # and numeric jitter remain required evidence.
                    mismatch = [key for key in keys if key != "distribution" and
                                actual.get(key) != expected.get(key)]
                    if (mismatch or actual.get("distribution") not in
                            (expected.get("distribution"), None)):
                        raise ReplayError("GS egress qdisc changed during replay: "
                                          + profile["interface"])
                final_profiles.append({"ground_station": profile["ground_station"],
                                       "interface": profile["interface"],
                                       "qdisc": final_text, "parsed": actual})
            summary["gs_qdisc_after_session"] = final_profiles
        summary["session_tail_seconds"] = session_tail_seconds
    except BaseException as exc:
        summary["status"] = "aborted"
        summary["error"] = str(exc)
        raise
    finally:
        # Agents and tcpdump live inside the StarryNet containers.  Close and
        # copy their evidence before removing the Swarm service; deleting the
        # containers first makes an otherwise completed session fail with
        # "No such container" and can leave the PCAP footer unflushed.
        if summary.get("bridge_networks"):
            try:
                networks = inspect_replay_bridges(owner_id)
                path = session_dir / "bridge_networks_after.json"
                atomic_write_json(path, networks)
                summary["bridge_networks_after"] = str(path)
                summary["bridge_networks_after_sha256"] = sha256_file(path)
                initial = json.loads(Path(summary["bridge_networks"]).read_text())
                initial_names = {n["name"] for n in initial}
                summary["new_bridge_names"] = sorted(
                    n["name"] for n in networks if n["name"] not in initial_names)
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
        for role, agent in (("client", client_agent), ("remote", remote_agent)):
            if not agent:
                continue
            try:
                agent.stop()
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
            try:
                raw_log = agent.write_log()
                summary[role + "_agent_log"] = gzip_artifact(raw_log)
            except (OSError, ReplayError) as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
            if agent.transport == "tcp":
                try:
                    summary.setdefault("tcp_state_logs", {})[role] = agent.write_tcp_state_log()
                except Exception as exc:
                    cleanup_failure = cleanup_failure or exc
                    summary.setdefault("cleanup_errors", []).append(str(exc))
        if capture:
            try:
                pcap = stop_capture(capture, session_dir)
                if pcap is not None:
                    summary["pcap"] = validate_pcap(pcap)
                    summary["pcap_compression"] = gzip_artifact(pcap)
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
        if remote_capture:
            try:
                pcap = stop_capture(remote_capture, session_dir / "remote_capture")
                if pcap is not None:
                    summary["remote_pcap"] = validate_pcap(pcap)
                    summary["remote_pcap_compression"] = gzip_artifact(pcap)
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
        if sn is not None:
            try:
                if not emulation_stop_requested:
                    emulation_stop_requested = True
                    sn.stop_emulation()
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
        if emulation_thread is not None and emulation_thread.is_alive():
            emulation_thread.join(timeout=30)
            if emulation_thread.is_alive():
                cleanup_failure = cleanup_failure or ReplayError(
                    "dynamic emulation thread did not stop")
                summary.setdefault("cleanup_errors", []).append(
                    "dynamic emulation thread did not stop")
        if summary.get("resource_inventory_before") is not None:
            try:
                summary["resource_inventory_after"] = wait_for_starrynet_cleanup(
                    owner_id, service_name)
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
            after = summary.get("resource_inventory_after")
            summary["cleanup_verified"] = starrynet_resources_cleared(
                after, owner_id, service_name)
            if not summary["cleanup_verified"]:
                cleanup_failure = cleanup_failure or ReplayError(
                    "StarryNet-owned Docker resources remain after cleanup")
                summary.setdefault("cleanup_errors", []).append(
                    "StarryNet-owned Docker resources remain after cleanup")
        summary["worker_errors"] = list(WORKER_ERRORS)
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=5)
        atomic_write_json(session_dir / "summary.json", summary)
        if (cleanup_failure is not None
                and summary.get("status") in ("completed", "rollover_required")):
            raise ReplayError("session cleanup failed: " + str(cleanup_failure))
        fcntl.flock(resource_lock.fileno(), fcntl.LOCK_UN)
        resource_lock.close()
    return summary


def _run_emulation(sn, errors):
    try:
        sn.start_emulation()
    except BaseException as exc:
        errors.append(exc)


def cmd_preflight(args):
    manifest = load_manifest(args.manifest)
    check_frozen_config(manifest)
    if manifest.get("batch_manifest_path"):
        load_batch_manifest(manifest)
    check_docker_capabilities(manifest.get("owner_id"))
    # The actual dynamic preflight is intentionally a short run.  It uses the
    # first three planned traces and stores evidence under the run directory.
    run_dir = Path(manifest["run_dir"])
    preflight_dir = run_dir / "preflight"
    preflight_dir.mkdir(exist_ok=True)
    sources = []
    for row in manifest["source_rows"]:
        info = read_trace(row["source_path"])
        if set(info["direction_counts"]) == {-1, 1}:
            sources.append(row)
        if len(sources) == 3:
            break
    if len(sources) < 3:
        raise ReplayError("dynamic preflight needs three bidirectional source traces")
    if manifest.get("diagnostic_mode") == "deadline" and len(sources) != 3:
        raise ReplayError("deadline diagnostic requires exactly three frozen baseline sources")
    samples = []
    for index, row in enumerate(sources):
        info = read_trace(row["source_path"])
        # Prefix preflight IDs so that their evidence can never be mistaken
        # for a formally completed sample during --resume.
        samples.append({"sample_id": "preflight-" + row["sample_id"],
                        "source_sample_id": row["sample_id"],
                        "source_path": row["source_path"],
                        "source_sha256": row["source_sha256"], "class_id": info["class_id"],
                        "repeat_id": info["repeat_id"], "start_second": 15 + index * 35,
                        "duration_seconds": info["duration_seconds"] / manifest["speed"],
                        "source_duration_seconds": info["duration_seconds"],
                        "event_count": info["event_count"]})
    # Permit the three real source traces to complete sequentially even when
    # all are near the source maximum. The TCP completion allowance applies
    # after each trace's final scheduled event; it is not part of source time.
    preflight_window = int(math.ceil(
        WARMUP_SECONDS
        + sum(float(sample["duration_seconds"]) for sample in samples)
        + float(manifest.get("tcp_completion_timeout_seconds", 0))
        + TCP_COORDINATOR_WAIT_SECONDS
        + len(samples) * (TAIL_SECONDS + DISPATCH_LEAD_SECONDS)
        + 120.0))
    preflight_window = max(900, preflight_window)
    session = {"session_id": "preflight", "samples": samples}
    summary = run_session(manifest, session, samples, preflight_dir, preflight_window,
                          session_tail_seconds=0.0)
    if summary.get("status") != "completed":
        raise ReplayError("dynamic preflight did not complete")
    if manifest.get("transport") == "tcp" and (
            len(summary.get("sample_results", [])) != 3 or
            (manifest.get("diagnostic_mode") != "deadline" and
             any(row.get("status") != "success" for row in summary["sample_results"]))):
        raise ReplayError("TCP preflight samples incomplete; inspect preserved evidence")
    if manifest.get("tcp_state_interval_seconds") is not None:
        require_tcp_state_diagnostics(summary)
        if not summary.get("bridge_networks_after"):
            raise ReplayError("TCP preflight missing bridge options evidence")
        if manifest.get("topology", {}).get("mode") == "fixed":
            before_path = Path(summary["bridge_networks"])
            after_path = Path(summary["bridge_networks_after"])
            if (not before_path.is_file() or not after_path.is_file()
                    or sha256_file(before_path) != summary.get("bridge_networks_sha256")
                    or sha256_file(after_path) != summary.get("bridge_networks_after_sha256")):
                raise ReplayError("fixed TCP preflight bridge scope evidence is incomplete")
            before = json.loads(before_path.read_text(encoding="utf-8"))
            after = json.loads(after_path.read_text(encoding="utf-8"))
            before_by_name = {row["name"]: row for row in before}
            after_by_name = {row["name"]: row for row in after}
            if set(before_by_name) != set(after_by_name):
                raise ReplayError("fixed topology created unexpected bridge resources during replay")
            if before_by_name != after_by_name:
                raise ReplayError("fixed topology bridge options changed during replay")
        elif not summary.get("new_bridge_names"):
            raise ReplayError("dynamic bridge preflight missing new bridge scope evidence")
    if manifest.get("topology", {}).get("mode") == "fixed":
        batch_path, batch = load_batch_manifest(manifest)
        shared = batch.get("frozen_topology") or {}
        shared_path = Path(shared.get("path", ""))
        manifest_snapshot = manifest.get("topology", {}).get("frozen_snapshot") or {}
        snapshot_file_valid = (
            bool(shared.get("sha256")) and shared_path.is_file() and
            sha256_file(shared_path) == shared.get("sha256"))
        manifest_snapshot_matches = (
            not manifest_snapshot or all(
                manifest_snapshot.get(key) == shared.get(key)
                for key in ("path", "sha256", "time_index")))
        if (not snapshot_file_valid or not manifest_snapshot_matches or
                summary.get("fixed_snapshot_sha256") != shared.get("sha256") or
                summary.get("dynamic_matrix_changed") is not False or
                summary.get("handover_count") != 0):
            raise ReplayError("fixed preflight did not prove the shared frozen topology")
        if (summary.get("route_before", {}).get("remote_satellite_route") is not True or
                len(summary.get("gs_qdisc_before_after_apply", {}).get("profiles", [])) != 2):
            raise ReplayError("fixed preflight lacks bidirectional route or both GS qdisc proofs")
    elif not summary.get("dynamic_matrix_changed") or summary.get("handover_count", 0) < 1:
        raise ReplayError("dynamic preflight did not observe a changing topology")
    if manifest.get("diagnostic_mode") == "deadline":
        results = summary.get("sample_results", [])
        by_source = {row.get("source_sample_id"): row for row in results}
        source_ids = [row["sample_id"] for row in sources]
        endpoint_rows = []
        endpoint_complete = True
        for source_id in source_ids:
            result = by_source.get(source_id)
            if not result:
                endpoint_complete = False
                continue
            prefixed_id = "preflight-" + source_id
            token = sample_token(prefixed_id)
            try:
                client_event_row = read_agent_sample(
                    Path(summary["client_agent_log"]["path"]), prefixed_id, token)
                remote_event_row = read_agent_sample(
                    Path(summary["remote_agent_log"]["path"]), prefixed_id, token)
                complete = (client_event_row.get("sample_id") == prefixed_id
                            and remote_event_row.get("sample_id") == prefixed_id
                            and client_event_row.get("sample_token") == token
                            and remote_event_row.get("sample_token") == token)
            except (OSError, ReplayError, ValueError):
                complete = False
                client_event_row = remote_event_row = None
            endpoint_complete = endpoint_complete and complete
            endpoint_rows.append({"sample_id": source_id,
                                  "prefixed_sample_id": prefixed_id,
                                  "attempt_id": result.get("attempt_id"),
                                  "status": result.get("status"),
                                  "event_verification": result.get("event_verification"),
                                  "endpoint_evidence_complete": complete})
        execution_complete = (len(results) == 3 and
                              {row.get("source_sample_id") for row in results} ==
                              set(source_ids))
        diagnostic = {
            "schema_version": 1, "run_id": manifest["run_id"],
            "scenario": manifest.get("scenario"),
            "tcp_completion_seconds": manifest["tcp_completion_timeout_seconds"],
            "sample_ids": source_ids, "planned_samples": 3,
            "successful_samples": sum(row.get("status") == "success" for row in results),
            "execution_complete": execution_complete,
            "endpoint_evidence_complete": endpoint_complete,
            "cleanup_verified": summary.get("cleanup_verified") is True,
            "all_samples_success": bool(results) and all(
                row.get("status") == "success" for row in results),
            "sample_rows": endpoint_rows,
            "summary_path": str(preflight_dir / "summary.json"),
            "created_utc": utc_now(),
        }
        atomic_write_json(run_dir / "deadline_diagnostic.json", diagnostic)
        if not (diagnostic["execution_complete"] and
                diagnostic["endpoint_evidence_complete"] and
                diagnostic["cleanup_verified"]):
            raise ReplayError("deadline diagnostic execution evidence is incomplete")
        manifest["preflight"] = {"status": "diagnostic_completed",
                                  "summary": str(preflight_dir / "summary.json"),
                                  "completed_utc": utc_now()}
        manifest["status"] = "diagnostic_execution_complete"
    else:
        manifest["preflight"] = {"status": "passed", "summary": str(preflight_dir / "summary.json"),
                                  "completed_utc": utc_now()}
        manifest["status"] = "preflight_passed"
    atomic_write_json(manifest["manifest_path"], {k: v for k, v in manifest.items()
                                                   if k not in ("manifest_path", "run_dir")})
    print(json.dumps({"preflight_passed": manifest["preflight"]["status"] == "passed",
                      "diagnostic_execution_complete": manifest["preflight"]["status"] == "diagnostic_completed",
                      "summary": str(preflight_dir / "summary.json")},
                     indent=2, sort_keys=True))
    return 0


def run_sample_counts(manifest, successful_sample_ids, nonretryable_sample_ids):
    """Display unique sample outcomes without changing completion or retry gates.

    Attempted means a ledger entry or an existing valid success, not verified
    collection quality. Only explicitly recorded measurement failures count as
    interruptions; infrastructure/unknown outcomes remain separate.
    """
    planned = {sample["sample_id"] for session in active_sessions(manifest)
               for sample in session["samples"]}
    latest = {}
    for row in read_attempts(manifest):
        sample_id = row.get("sample_id")
        if sample_id not in planned:
            continue
        match = re.fullmatch(r"attempt-(\d+)", str(row.get("attempt_id", "")))
        number = int(match.group(1)) if match else 0
        if sample_id not in latest or number >= latest[sample_id][0]:
            latest[sample_id] = (number, row)
    successful = set(successful_sample_ids) & planned
    attempted = set(latest) | successful
    interrupted = set()
    for sample_id in (set(nonretryable_sample_ids) & set(latest)) - successful:
        row = latest[sample_id][1]
        if (row.get("status") == "failure" and row.get("retryable") is False
                and row.get("network_loss_is_measurement") is True):
            interrupted.add(sample_id)
    return {"planned_samples": len(planned),
            "attempted_samples": len(attempted),
            "successful_samples": len(successful),
            "interrupted_samples": len(interrupted),
            "other_attempted_samples": len(attempted - successful - interrupted),
            "unattempted_samples": len(planned - attempted)}


def dynamic_pair_resolver(manifest):
    mode = manifest.get("diagnostic_mode")
    if mode not in ("stable", "crossing"):
        return None
    state = {"cursor": 2.0, "handover_index": 0}

    def resolve(context):
        topology = context["topology"]
        handovers = [float(value) for value in topology.get("handover_seconds", [])]
        anchor = int(context["session_anchor_ns"])
        now_second = (monotonic_ns() - anchor) / 1e9
        sample = context["sample"]
        duration = float(sample.get("duration_seconds", 0.0)) / float(manifest.get("speed", 1.0))
        if mode == "stable":
            edges = [2.0] + handovers + [float(manifest.get("session_seconds", 9000))]
            for left, right in zip(edges, edges[1:]):
                target = max(state["cursor"], left + 1.0, now_second + DISPATCH_LEAD_SECONDS + 0.1)
                if target + duration + 0.5 < right - 1.0:
                    state["cursor"] = target + duration + 1.0
                    return (anchor + int(target * 1e9), {
                        "mode": mode, "stable_interval_seconds": [left, right],
                        "target_start_second": target,
                        "target_end_second": target + duration,
                        "crossing_handover_second": None})
            raise ReplayError("no remaining stable topology interval can contain "
                              + sample["sample_id"])
        for index in range(state["handover_index"], len(handovers)):
            crossing = handovers[index]
            affected = topology.get("handover_ground_stations_by_second", {}).get(
                str(int(crossing)), topology.get(
                    "handover_ground_stations_by_second", {}).get(str(crossing),
                    [CLIENT_NODE, REMOTE_NODE]))
            changes_endpoint = any(
                attachment_for_second(topology, crossing - 0.001, node) !=
                attachment_for_second(topology, crossing, node)
                for node in affected if node in (CLIENT_NODE, REMOTE_NODE))
            if not changes_endpoint:
                continue
            target = crossing - min(2.0, max(0.5, duration / 3.0))
            if target < state["cursor"] or target < now_second + DISPATCH_LEAD_SECONDS + 0.1:
                continue
            if target + duration <= crossing + 0.1:
                continue
            state["handover_index"] = index + 1
            state["cursor"] = crossing + 1.0
            return (anchor + int(target * 1e9), {
                "mode": mode, "target_start_second": target,
                "target_end_second": target + duration,
                "crossing_handover_second": crossing})
        raise ReplayError("no future handover can be crossed by " + sample["sample_id"])
    return resolve


def cmd_run(args):
    manifest = load_manifest(args.manifest)
    check_frozen_config(manifest)
    if manifest.get("preflight", {}).get("status") != "passed":
        raise ReplayError("run requires a passed real StarryNet preflight")
    manifest["storage_guard"] = storage_guard(manifest)
    atomic_write_json(manifest["manifest_path"],
                      {k: v for k, v in manifest.items()
                       if k not in ("manifest_path", "run_dir")})
    lock_path = Path(manifest["run_dir"]) / ".run.lock"
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReplayError("another E_v4 run is active") from exc
        pending = []
        manifest_changed = False
        for session in list(active_sessions(manifest)):
            sample_specs = []
            for sample in session["samples"]:
                if sample_is_valid(manifest, sample["sample_id"]):
                    continue
                if retry_allowed(manifest, sample["sample_id"]):
                    sample_specs.append(sample)
            evidence_recovery = False
            if not sample_specs and not session_evidence_is_valid(manifest, session):
                # A previous cleanup failure can leave every per-sample trace
                # intact but lose the session PCAP.  Replaying the earliest
                # valid sample supplies fresh session-level route, capture and
                # cleanup evidence without rerunning the whole session.
                candidates = [sample for sample in session["samples"]
                              if sample_is_valid(manifest, sample["sample_id"])
                              and next_attempt_number(
                                  manifest, sample["sample_id"])
                              <= max_infrastructure_attempts(manifest)]
                if candidates:
                    sample_specs = [min(
                        candidates, key=lambda item: item["start_second"])]
                    evidence_recovery = True
            for sample in sample_specs:
                if (next_attempt_number(manifest, sample["sample_id"])
                        > max_infrastructure_attempts(manifest)):
                    raise ReplayError("maximum infrastructure attempts exceeded for "
                                      + sample["sample_id"])
            if not sample_specs:
                continue
            session_dir = Path(manifest["run_dir"]) / "sessions" / session["session_id"]
            if session_dir.exists():
                recovery = allocate_recovery_session(
                    manifest, session,
                    sample_specs[0]["sample_id"] if evidence_recovery else None)
                pending.append((recovery, sample_specs))
                manifest_changed = True
            else:
                pending.append((session, sample_specs))
        if manifest_changed:
            atomic_write_json(manifest["manifest_path"],
                              {k: v for k, v in manifest.items()
                               if k not in ("manifest_path", "run_dir")})
        summaries = []
        for session, sample_specs in pending:
            setup_attempt = 0
            while sample_specs:
                session_dir = (Path(manifest["run_dir"]) / "sessions"
                               / session["session_id"])
                setup_attempt += 1
                try:
                    summary = run_session(
                        manifest, session, sample_specs, session_dir,
                        manifest["session_seconds"],
                        sample_start_resolver=dynamic_pair_resolver(manifest))
                    summaries.append(summary)
                except BaseException:
                    # A clean failure before the first sample is safe to
                    # rebuild.  This covers transient Swarm scheduling stalls
                    # during the automatic rollover path without consuming a
                    # sample attempt or requiring another user command.
                    try:
                        failed_summary = json.loads(
                            (session_dir / "summary.json").read_text(
                                encoding="utf-8"))
                    except (OSError, ValueError, TypeError):
                        failed_summary = {}
                    if session_setup_retry_allowed(failed_summary, setup_attempt):
                        recovery = allocate_recovery_session(manifest, session)
                        atomic_write_json(
                            manifest["manifest_path"],
                            {k: v for k, v in manifest.items()
                             if k not in ("manifest_path", "run_dir")})
                        print("E_v4 INFO: setup attempt {0}/{1} failed cleanly; "
                              "retrying in {2}".format(
                                  setup_attempt, MAX_SESSION_SETUP_ATTEMPTS,
                                  recovery["session_id"]))
                        session = recovery
                        time.sleep(min(30.0, setup_attempt * 5.0))
                        continue
                    # Preserve the aborted summary after the bounded retries.
                    raise
                if summary.get("status") != "rollover_required":
                    break
                setup_attempt = 0
                remaining = [
                    sample for sample in session["samples"]
                    if (not sample_is_valid(manifest, sample["sample_id"])
                        and retry_allowed(manifest, sample["sample_id"]))]
                if not remaining:
                    break
                if len(remaining) >= len(sample_specs):
                    raise ReplayError(
                        "automatic session rollover made no sample progress before "
                        + summary.get("rollover_before_sample", "unknown"))
                recovery = allocate_recovery_session(manifest, session)
                atomic_write_json(
                    manifest["manifest_path"],
                    {k: v for k, v in manifest.items()
                     if k not in ("manifest_path", "run_dir")})
                print("E_v4 INFO: route did not recover; continuing {0} remaining "
                      "samples in {1}".format(len(remaining), recovery["session_id"]))
                session = recovery
                sample_specs = remaining
        # Recompute completion after running.  A session can finish cleanly
        # while one of its samples records an endpoint transport failure; the
        # old code then incorrectly marked the whole manifest run_completed.
        retryable_samples = []
        exhausted_samples = []
        nonretryable_samples = []
        successful_sample_ids = set()
        for session in active_sessions(manifest):
            for sample in session["samples"]:
                sample_id = sample["sample_id"]
                if sample_is_valid(manifest, sample_id):
                    successful_sample_ids.add(sample_id)
                    continue
                if retry_allowed(manifest, sample_id):
                    if (next_attempt_number(manifest, sample_id)
                            <= max_infrastructure_attempts(manifest)):
                        retryable_samples.append(sample_id)
                    else:
                        exhausted_samples.append(sample_id)
                else:
                    nonretryable_samples.append(sample_id)
        sample_counts = run_sample_counts(
            manifest, successful_sample_ids, nonretryable_samples)
        if retryable_samples or exhausted_samples or nonretryable_samples:
            if exhausted_samples:
                manifest["status"] = "incomplete_retry_exhausted"
            elif retryable_samples:
                manifest["status"] = "incomplete_retryable"
            else:
                manifest["status"] = "incomplete_nonretryable"
            manifest["retryable_samples"] = sorted(set(retryable_samples))
            manifest["retry_exhausted_samples"] = sorted(set(exhausted_samples))
            manifest["nonretryable_samples"] = sorted(set(nonretryable_samples))
            manifest["last_run_utc"] = utc_now()
            atomic_write_json(manifest["manifest_path"], {k: v for k, v in manifest.items()
                                                           if k not in ("manifest_path", "run_dir")})
            result = {"run_completed": False,
                      "retryable_samples": manifest["retryable_samples"],
                      "retry_exhausted_samples": manifest["retry_exhausted_samples"],
                      "nonretryable_samples": manifest["nonretryable_samples"]}
            result.update(sample_counts)
            print(json.dumps(result, indent=2))
            return 1
        manifest["status"] = "run_completed"
        manifest["last_run_utc"] = utc_now()
        atomic_write_json(manifest["manifest_path"], {k: v for k, v in manifest.items()
                                                       if k not in ("manifest_path", "run_dir")})
    result = {"run_completed": True, "sessions": len(summaries)}
    result.update(sample_counts)
    print(json.dumps(result, indent=2))
    return 0


def validate_trace(path):
    timestamps = []
    directions = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        fields = re.split(r"\s+", line.strip())
        if len(fields) != 2:
            raise ReplayError("invalid output line {0}:{1}".format(path, line_number))
        timestamp = float(fields[0])
        direction = int(fields[1])
        if timestamp != timestamp or timestamp < 0 or direction not in (-1, 1):
            raise ReplayError("invalid output value {0}:{1}".format(path, line_number))
        timestamps.append(timestamp)
        directions.append(direction)
    for previous, current in zip(timestamps, timestamps[1:]):
        if current + 1e-9 < previous:
            raise ReplayError("output timestamp reversal: " + str(path))
    return {"rows": len(timestamps), "direction_counts": dict(Counter(directions)),
            "max_timestamp": max(timestamps) if timestamps else None}


def verification_traffic_summary(evidence_rows, output_direction_counts):
    """Summarize observed directions and endpoint packet accounting."""
    successful = [row for row in evidence_rows if row.get("status") == "success"]
    direction_totals = {"1": 0, "-1": 0}
    one_direction_ids = []
    positive_only = 0
    negative_only = 0
    empty = 0
    for row in successful:
        sample_id = row.get("sample_id")
        counts = output_direction_counts.get(sample_id, {})
        positive = int(counts.get("1", counts.get(1, 0)))
        negative = int(counts.get("-1", counts.get(-1, 0)))
        direction_totals["1"] += positive
        direction_totals["-1"] += negative
        if positive and negative:
            continue
        if positive:
            positive_only += 1
            one_direction_ids.append(sample_id)
        elif negative:
            negative_only += 1
            one_direction_ids.append(sample_id)
        else:
            empty += 1

    def delivery(direction):
        sent = sum(int(row.get(direction + "_sent", 0)) for row in successful)
        received = sum(int(row.get(direction + "_received", 0)) for row in successful)
        lost = sum(int(row.get(direction + "_lost", 0)) for row in successful)
        send_failed = sum(int(row.get(direction + "_send_failed", 0))
                          for row in successful)
        expected = sum(int(row.get("expected_" + direction, 0))
                       for row in successful)
        return {"expected": expected, "sent": sent, "received": received,
                "lost": lost, "send_failed": send_failed,
                "loss_rate_among_sent": lost / float(sent) if sent else None}

    return {
        "successful_sample_count": len(successful),
        "observed_output_event_counts": direction_totals,
        "bidirectional_output_sample_count": (
            len(successful) - positive_only - negative_only - empty),
        "single_direction_output_sample_count": positive_only + negative_only,
        "single_direction_output_sample_ids": sorted(one_direction_ids),
        "single_direction_breakdown": {"positive_only": positive_only,
                                        "negative_only": negative_only,
                                        "empty": empty},
        "outbound": delivery("outbound"),
        "inbound": delivery("inbound"),
    }


def cmd_verify(args):
    manifest = load_manifest(args.manifest)
    if manifest.get("diagnostic_mode") == "deadline":
        errors = []
        try:
            check_frozen_config(manifest)
        except (OSError, ReplayError, ValueError) as exc:
            errors.append("frozen configuration check failed: " + str(exc))
        diagnostic_path = Path(manifest["run_dir"]) / "deadline_diagnostic.json"
        if not diagnostic_path.is_file():
            errors.append("missing deadline diagnostic execution artifact")
            diagnostic = {}
        else:
            diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))
        expected_ids = [row["sample_id"] for row in manifest.get("source_rows", [])]
        if diagnostic.get("sample_ids") != expected_ids:
            errors.append("deadline diagnostic sample IDs differ from its frozen cohort")
        if (diagnostic.get("run_id") != manifest.get("run_id")
                or diagnostic.get("scenario") != manifest.get("scenario")):
            errors.append("deadline diagnostic identity differs from its frozen plan")
        if diagnostic.get("tcp_completion_seconds") != manifest.get(
                "tcp_completion_timeout_seconds"):
            errors.append("deadline diagnostic timeout differs from its frozen manifest")
        for key in ("execution_complete", "endpoint_evidence_complete", "cleanup_verified"):
            if diagnostic.get(key) is not True:
                errors.append("deadline diagnostic lacks " + key)
        diagnostic_rows = diagnostic.get("sample_rows", [])
        if (diagnostic.get("planned_samples") != 3 or len(diagnostic_rows) != 3
                or [row.get("sample_id") for row in diagnostic_rows] != expected_ids):
            errors.append("deadline diagnostic does not contain three actual source attempts")
        if any(not row.get("attempt_id") or
               row.get("endpoint_evidence_complete") is not True
               for row in diagnostic_rows):
            errors.append("deadline diagnostic sample rows lack endpoint attempt evidence")
        if diagnostic.get("successful_samples") != sum(
                row.get("status") == "success" for row in diagnostic_rows):
            errors.append("deadline diagnostic successful sample count is inconsistent")
        if diagnostic.get("all_samples_success") is not all(
                row.get("status") == "success" for row in diagnostic_rows):
            errors.append("deadline diagnostic all-samples outcome is inconsistent")
        try:
            _batch_path, batch = load_batch_manifest(manifest)
            topology = manifest.get("topology", {}).get("frozen_snapshot") or {}
            shared = batch.get("frozen_topology") or {}
            if any(topology.get(key) != shared.get(key)
                   for key in ("path", "sha256", "time_index")):
                errors.append("deadline diagnostic does not use the shared frozen topology")
            summary_path = Path(diagnostic.get("summary_path", ""))
            expected_summary = Path(manifest["run_dir"]) / "preflight" / "summary.json"
            if summary_path.resolve() != expected_summary.resolve() or not summary_path.is_file():
                raise ReplayError("deadline diagnostic summary path is missing or unbound")
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if (summary.get("status") != "completed"
                    or summary.get("cleanup_verified") is not True
                    or summary.get("fixed_snapshot_sha256") != shared.get("sha256")):
                errors.append("deadline diagnostic session summary is incomplete")
            for role in ("client", "remote"):
                artifact = summary.get(role + "_agent_log") or {}
                log_path = Path(artifact.get("path", ""))
                if (not log_path.is_file()
                        or sha256_file(log_path) != artifact.get("compressed_sha256")):
                    raise ReplayError("deadline diagnostic {0} agent log is invalid".format(role))
            for source_id in expected_ids:
                prefixed_id = "preflight-" + source_id
                token = sample_token(prefixed_id)
                client_row = read_agent_sample(
                    summary["client_agent_log"]["path"], prefixed_id, token)
                remote_row = read_agent_sample(
                    summary["remote_agent_log"]["path"], prefixed_id, token)
                if (client_row.get("sample_token") != token
                        or remote_row.get("sample_token") != token):
                    raise ReplayError("deadline diagnostic endpoint identity mismatch")
            pcap_compression = summary.get("pcap_compression") or {}
            pcap_path = Path(pcap_compression.get("path", ""))
            pcap = compressed_pcap_info(pcap_path, pcap_compression)
            if replay_capture_count(pcap, "tcp") < 1:
                raise ReplayError("deadline diagnostic PCAP has no TCP application payload")
        except (OSError, EOFError, ValueError, KeyError, ReplayError) as exc:
            errors.append("deadline diagnostic endpoint/session evidence invalid: " + str(exc))
        # `passed` intentionally stays false: this command verifies that the
        # paired measurement was executed and recorded, not that 30 or 120
        # seconds improved the outcome.
        result = {"schema_version": SCHEMA_VERSION, "tool": "replay_trace_over_starrynet",
                  "manifest": manifest["manifest_path"],
                  "verification_kind": "deadline_diagnostic_execution",
                  "execution_verified": not errors,
                  "all_samples_success": diagnostic.get("all_samples_success") is True,
                  "successful_samples": diagnostic.get("successful_samples", 0),
                  "planned_samples": diagnostic.get("planned_samples", 0),
                  "tcp_completion_seconds": diagnostic.get("tcp_completion_seconds"),
                  "passed": False, "errors": errors,
                  "engineering_pipeline_verified": False,
                  "scientific_fidelity_verified": False}
        diagnostic["verification"] = result
        diagnostic["verified_utc"] = utc_now()
        if not errors:
            atomic_write_json(diagnostic_path, diagnostic)
        atomic_write_json(Path(manifest["run_dir"]) / "verification.json", result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not errors else 1
    errors = []
    try:
        check_frozen_config(manifest)
    except (OSError, ReplayError, ValueError) as exc:
        errors.append("frozen configuration check failed: " + str(exc))
    source_map = {item["sample_id"]: item["source_sha256"]
                  for item in manifest["source_rows"]}
    expected = []
    sessions = active_sessions(manifest)
    for session in sessions:
        for sample in session["samples"]:
            expected.append(sample["sample_id"])
    if len(expected) != len(set(expected)):
        errors.append("duplicate planned sample IDs")
    if manifest.get("mode") == "formal" and manifest.get("cohort_key") == "full":
        class_counts = Counter(sample.split("-", 1)[0] for sample in expected)
        if len(expected) != 6000:
            errors.append("formal plan does not contain 6000 samples")
        if len(class_counts) != 75 or set(class_counts.values()) != {80}:
            errors.append("formal plan is not 75 classes x 80 repeats")
    elif manifest.get("mode") == "diagnostic":
        planned_source_ids = [row["sample_id"] for row in manifest.get("source_rows", [])]
        if set(expected) != set(planned_source_ids) or len(expected) != len(planned_source_ids):
            errors.append("diagnostic plan does not exactly cover its frozen source cohort")
    successes = 0
    evidence_rows = []
    evidence_ids = set()
    output_direction_counts = {}
    for sample_id in expected:
        root = sample_root(manifest, sample_id)
        trace = root / "trace"
        evidence = root / "evidence.json"
        if not trace.is_file() or not evidence.is_file():
            errors.append("missing artifact: " + sample_id)
            continue
        try:
            row = json.loads(evidence.read_text(encoding="utf-8"))
            stats = validate_trace(trace)
            output_direction_counts[sample_id] = {
                str(direction): count
                for direction, count in stats["direction_counts"].items()}
            if row.get("sample_id") != sample_id:
                errors.append("sample ID mismatch: " + sample_id)
            evidence_key = (row.get("sample_id"), row.get("session_id"),
                            row.get("attempt_id"))
            if evidence_key in evidence_ids:
                errors.append("duplicate evidence identity: " + sample_id)
            evidence_ids.add(evidence_key)
            class_id, repeat_id = parse_sample_id(Path(sample_id))
            if row.get("class_id") != class_id or row.get("repeat_id") != repeat_id:
                errors.append("label mismatch: " + sample_id)
            if row.get("status") != "success":
                errors.append("sample not successful: " + sample_id)
            if manifest.get("tcp_state_interval_seconds") is not None:
                for role in ("client", "remote"):
                    state = row.get(role + "_tcp_state_summary") or {}
                    if not state.get("tcp_info_rows") or state.get("errors"):
                        errors.append("TCP state sampling incomplete: " + sample_id + "/" + role)
            if row.get("large_timestamp_reversal_count") != 0:
                errors.append("large reversal evidence: " + sample_id)
            if row.get("invalid_direction_count", 0) != 0:
                errors.append("invalid direction evidence: " + sample_id)
            if row.get("duplicate_count", 0) != 0:
                errors.append("duplicate event evidence: " + sample_id)
            if row.get("trace_sha256") != sha256_file(trace):
                errors.append("trace hash mismatch: " + sample_id)
            if row.get("source_sha256") != source_map.get(sample_id):
                errors.append("source hash mismatch: " + sample_id)
            if manifest.get("diagnostic_mode") in ("stable", "crossing"):
                before_chain = row.get("actual_route_chains_before") or {}
                after_chain = row.get("actual_route_chains_after") or {}
                if (not all((before_chain.get(direction) or {}).get("passed") is True
                            for direction in ("forward", "reverse"))
                        or not all((after_chain.get(direction) or {}).get("passed") is True
                                   for direction in ("forward", "reverse"))):
                    errors.append("dynamic diagnostic lacks actual bidirectional route chains: "
                                  + sample_id)
                source_changed = (row.get("source_satellite_before") !=
                                  row.get("source_satellite_after"))
                remote_changed = (row.get("remote_satellite_before") !=
                                  row.get("remote_satellite_after"))
                if manifest.get("diagnostic_mode") == "stable":
                    if (int(row.get("handover_count", 0)) != 0
                            or source_changed or remote_changed):
                        errors.append("stable diagnostic sample crossed a GS handover: "
                                      + sample_id)
                elif (int(row.get("handover_count", 0)) < 1
                      or not (source_changed or remote_changed)):
                    errors.append("crossing diagnostic sample lacks an observed GS handover: "
                                  + sample_id)
            if stats["rows"] == 0:
                errors.append("empty trace: " + sample_id)
            expected_events = int(row.get("source_event_count", -1))
            expected_scheduled = int(row.get("scheduled_event_count", -1))
            if expected_events != expected_scheduled:
                errors.append("source/scheduled event mismatch: " + sample_id)
            if (int(row.get("outbound_received", 0))
                    + int(row.get("outbound_lost", 0))
                    != int(row.get("outbound_sent", 0))):
                errors.append("outbound accounting mismatch: " + sample_id)
            if (int(row.get("inbound_received", 0))
                    + int(row.get("inbound_lost", 0))
                    != int(row.get("inbound_sent", 0))):
                errors.append("inbound accounting mismatch: " + sample_id)
            if (int(row.get("outbound_sent", 0))
                    + int(row.get("outbound_send_failed", 0))
                    != int(row.get("expected_outbound", 0))):
                errors.append("outbound scheduling accounting mismatch: " + sample_id)
            if (int(row.get("inbound_sent", 0))
                    + int(row.get("inbound_send_failed", 0))
                    != int(row.get("expected_inbound", 0))):
                errors.append("inbound scheduling accounting mismatch: " + sample_id)
            if int(row.get("client_observed_event_count", 0)) != (
                    int(row.get("outbound_sent", 0))
                    + int(row.get("inbound_received", 0))):
                errors.append("client observation accounting mismatch: " + sample_id)
            evidence_rows.append(row)
            if row.get("status") == "success" and stats["rows"] > 0:
                successes += 1
        except (OSError, ValueError, ReplayError, StopIteration) as exc:
            errors.append("{0}: {1}".format(sample_id, exc))
    if manifest.get("transport", "udp") == "tcp":
        by_session = defaultdict(list)
        for row in evidence_rows:
            if row.get("status") == "success":
                by_session[row.get("session_id")].append(row)
        for session_id, rows in by_session.items():
            try:
                verify_session_endpoint_logs(manifest, session_id, rows)
            except (OSError, EOFError, ValueError, KeyError, ReplayError) as exc:
                errors.append("TCP endpoint evidence invalid for session {0}: {1}".format(
                    session_id, exc))
    session_summaries = []
    for session in sessions:
        session_dir = Path(manifest["run_dir"]) / "sessions" / session["session_id"]
        summary_path = session_dir / "summary.json"
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            session_summaries.append(summary)
            if manifest.get("tcp_state_interval_seconds") is not None:
                try:
                    checked = dict(summary, tcp_state_logs={
                        role: validate_tcp_state_log(
                            summary["tcp_state_logs"][role]["path"], role)
                        for role in ("client", "remote")})
                    require_tcp_state_diagnostics(checked)
                    for role in ("client", "remote"):
                        if checked["tcp_state_logs"][role]["sha256"] != summary["tcp_state_logs"][role]["sha256"]:
                            errors.append("TCP state log hash mismatch: " + session["session_id"] + "/" + role)
                    if not summary.get("bridge_networks_after"):
                        errors.append("missing final bridge options: " + session["session_id"])
                    elif sha256_file(summary["bridge_networks_after"]) != summary.get("bridge_networks_after_sha256"):
                        errors.append("final bridge options hash mismatch: " + session["session_id"])
                    if manifest.get("topology", {}).get("mode") == "fixed":
                        before_path = Path(summary.get("bridge_networks", ""))
                        after_path = Path(summary.get("bridge_networks_after", ""))
                        if not before_path.is_file() or not after_path.is_file():
                            errors.append("fixed session bridge scope files are missing: "
                                          + session["session_id"])
                        else:
                            before = json.loads(before_path.read_text(encoding="utf-8"))
                            after = json.loads(after_path.read_text(encoding="utf-8"))
                            if before != after:
                                errors.append("fixed session bridge resources changed: "
                                              + session["session_id"])
                except (OSError, KeyError, ValueError, ReplayError) as exc:
                    errors.append("TCP state verification failed: " + str(exc))
            if summary.get("status") not in ("completed",):
                errors.append("session not completed: " + session["session_id"])
            topology_mode = manifest.get("topology", {}).get("mode", "dynamic")
            if topology_mode == "fixed":
                try:
                    _batch_path, batch = load_batch_manifest(manifest)
                    frozen_hash = (batch.get("frozen_topology") or {}).get("sha256")
                    expected_routes = (batch.get("fixed_route_baseline") or {}).get("routes")
                    before = summary.get("actual_route_chains_before") or {}
                    after = summary.get("actual_route_chains_after") or {}
                    def route_nodes(value):
                        return {key: (value.get(key) or {}).get("nodes")
                                for key in ("forward", "reverse")}
                    if (summary.get("dynamic_matrix_changed") is not False
                            or int(summary.get("handover_count", -1)) != 0
                            or summary.get("fixed_snapshot_sha256") != frozen_hash):
                        errors.append("fixed topology identity/zero-handover check failed: "
                                      + session["session_id"])
                    if (not expected_routes
                            or route_nodes(before) != expected_routes
                            or route_nodes(after) != expected_routes):
                        errors.append("fixed session route chain differs from batch baseline: "
                                      + session["session_id"])
                    qdisc = summary.get("gs_qdisc_before_after_apply") or {}
                    qdisc_path = session_dir / "gs_qdisc_profiles.json"
                    if (qdisc.get("scenario") != manifest.get("scenario")
                            or len(qdisc.get("profiles", [])) != 2
                            or not qdisc_path.is_file()
                            or sha256_file(qdisc_path) != qdisc.get("sha256")):
                        errors.append("fixed session lacks two-GS qdisc evidence: "
                                      + session["session_id"])
                    else:
                        qdisc_file = json.loads(qdisc_path.read_text(encoding="utf-8"))
                        if (qdisc_file.get("scenario") != manifest.get("scenario")
                                or qdisc_file.get("profiles") != qdisc.get("profiles")):
                            errors.append("fixed session qdisc artifact differs from summary: "
                                          + session["session_id"])
                        for profile in qdisc.get("profiles", []):
                            spec = FIXED_SCENARIOS[manifest["scenario"]]
                            expected_center = (float(profile["base_propagation_delay_ms"])
                                               + float(spec["delay_ms"]))
                            actual = profile.get("after_parsed") or {}
                            expected_command = [
                                "tc", "qdisc", "replace", "dev", profile["interface"],
                                "root", "netem", "delay", "{0:.6f}ms".format(expected_center)]
                            if spec["jitter_ms"]:
                                expected_command += ["{0:.6f}ms".format(spec["jitter_ms"]),
                                                     "distribution", "normal"]
                            expected_command += ["loss", "{0:g}%".format(spec["loss_percent"]),
                                                 "rate", "5Gbit"]
                            if (abs(float(profile.get("expected_center_delay_ms", -1))
                                    - expected_center) > 0.1
                                    or profile.get("command") != expected_command
                                    or abs(float(actual.get("delay_ms", -1000))
                                           - expected_center) > 0.1
                                    or abs(float(actual.get("jitter_ms", -1000))
                                           - float(spec["jitter_ms"])) > 0.1
                                    or float(actual.get("loss_percent", -1000))
                                       != float(spec["loss_percent"])
                                    or int(actual.get("rate_bps", -1)) != 5000000000):
                                errors.append("fixed session qdisc profile differs from frozen "
                                              "scenario: " + session["session_id"])
                                break
                except (OSError, ValueError, ReplayError, KeyError, TypeError) as exc:
                    errors.append("fixed session topology verification failed: " + str(exc))
            else:
                if summary.get("dynamic_matrix_changed") is not True:
                    errors.append("session lacks dynamic matrix evidence: " + session["session_id"])
                if int(summary.get("handover_count", 0)) < 1:
                    errors.append("session lacks handover evidence: " + session["session_id"])
            if summary.get("cleanup_verified") is not True:
                errors.append("session cleanup did not return to baseline: " + session["session_id"])
            heartbeat_path = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "heartbeat.jsonl"
            if not heartbeat_path.is_file() or heartbeat_path.stat().st_size == 0:
                errors.append("missing session heartbeat: " + session["session_id"])
            for role in ("client", "remote"):
                agent = summary.get(role + "_agent_log") or {}
                agent_log = Path(agent.get("path", ""))
                if (not agent_log.is_file()
                        or sha256_file(agent_log) != agent.get("compressed_sha256")):
                    errors.append("missing or mismatched compressed {0} agent log: {1}".format(
                        role, session["session_id"]))
            route_dir = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "route_snapshots"
            if not (route_dir / "before.json").is_file() or not (route_dir / "after.json").is_file():
                errors.append("missing route snapshots: " + session["session_id"])
            if not (Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "logs" / "tcpdump.log").is_file():
                errors.append("missing tcpdump log: " + session["session_id"])
            handover_log = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "handover_events.jsonl"
            if not handover_log.is_file() or handover_log.stat().st_size == 0:
                errors.append("missing handover event log: " + session["session_id"])
            pcap_compression = summary.get("pcap_compression") or {}
            pcap_path = Path(pcap_compression.get("path", ""))
            try:
                expected_pcap_path = session_dir / "client.pcap.gz"
                if pcap_path.resolve() != expected_pcap_path.resolve():
                    raise ReplayError("compressed PCAP path is not bound to this session")
                pcap_info = compressed_pcap_info(pcap_path, pcap_compression)
                if summary.get("pcap", {}).get("sha256") != pcap_info["sha256"]:
                    errors.append("session PCAP hash mismatch: " + session["session_id"])
                if replay_capture_count(pcap_info, manifest.get("transport", "udp")) < 1:
                    errors.append("session PCAP has no replay transport payload: "
                                  + session["session_id"])
            except (OSError, EOFError, ReplayError) as exc:
                errors.append("invalid session PCAP {0}: {1}".format(session["session_id"], exc))
        else:
            errors.append("missing session summary: " + session["session_id"])
    attempts = read_attempts(manifest)
    planned_ids = set(expected)
    attempt_ids = [(row.get("sample_id"), row.get("attempt_id")) for row in attempts]
    if len(attempt_ids) != len(set(attempt_ids)):
        errors.append("duplicate attempt identity")
    if (manifest.get("mode") == "pilot"
            and manifest.get("topology", {}).get("mode") == "dynamic"
            and not manifest.get("diagnostic_mode")
            and not any(int(row.get("handover_count", 0)) > 0
                        for row in evidence_rows)):
        errors.append("pilot has no sample interval crossing a handover")
    formal_attempts = [row for row in attempts if row.get("sample_id") in planned_ids]
    first_attempts = [row for row in formal_attempts
                      if row.get("attempt_id") == "attempt-1"]
    retry_attempts = [row for row in formal_attempts
                      if row.get("attempt_id") == "attempt-2"]
    first_successes = sum(row.get("status") == "success" for row in first_attempts)
    retry_successes = sum(row.get("status") == "success" for row in retry_attempts)
    result = {"schema_version": SCHEMA_VERSION, "tool": "replay_trace_over_starrynet",
              "manifest": manifest["manifest_path"], "planned_samples": len(expected),
              "successful_samples": successes, "session_count": len(session_summaries),
              "errors": errors, "passed": not errors and successes == len(expected),
              "engineering_pipeline_verified": not errors and successes == len(expected),
              "scientific_fidelity_verified": False,
              "attempt_count": len(formal_attempts),
              "first_attempt_count": len(first_attempts),
              "retry_attempt_count": len(retry_attempts),
              "first_attempt_success_count": first_successes,
              "retry_success_count": retry_successes,
              "first_success_rate": (first_successes / len(expected)
                                     if expected else 0.0),
              "retry_success_rate": (retry_successes / len(retry_attempts)
                                     if retry_attempts else None),
              "evidence_count": len(evidence_rows),
              "traffic_accounting": verification_traffic_summary(
                  evidence_rows, output_direction_counts)}
    atomic_write_json(Path(manifest["run_dir"]) / "verification.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


def cmd_finalize(args):
    manifest = load_manifest(args.manifest)
    verify_args = argparse.Namespace(manifest=args.manifest)
    if cmd_verify(verify_args) != 0:
        raise ReplayError("cannot finalize a dataset that fails verify")
    target = Path(manifest["dataset_output"]).resolve()
    if target.exists():
        if any(target.iterdir()):
            raise ReplayError("refusing to overwrite non-empty dataset output: " + str(target))
        target.rmdir()
    staging = target.with_name(target.name + ".staging-" + manifest["run_id"])
    if staging.exists():
        raise ReplayError("staging output already exists: " + str(staging))
    staging.mkdir(parents=True)
    dataset_rows = []
    try:
        for session in active_sessions(manifest):
            for sample in session["samples"]:
                source = sample_root(manifest, sample["sample_id"]) / "trace"
                shutil.copy2(source, staging / sample["sample_id"])
                evidence = json.loads((sample_root(manifest, sample["sample_id"])
                                       / "evidence.json").read_text(encoding="utf-8"))
                dataset_rows.append({
                    "sample_id": sample["sample_id"],
                    "class_id": sample["class_id"],
                    "repeat_id": sample["repeat_id"],
                    "source_sha256": sample["source_sha256"],
                    "trace_sha256": evidence["trace_sha256"],
                    "session_id": evidence["session_id"],
                    "attempt_id": evidence["attempt_id"],
                })
        os.replace(str(staging), str(target))
    except BaseException:
        raise
    atomic_write_json(Path(manifest["run_dir"]) / "dataset_manifest.json", {
        "schema_version": SCHEMA_VERSION,
        "dataset_id": manifest["dataset_id"],
        "domain": "E",
        "run_id": manifest["run_id"],
        "source_digest_sha256": manifest["source_digest_sha256"],
        "sample_count": len(dataset_rows),
        "samples": sorted(dataset_rows, key=lambda row: row["sample_id"]),
        "engineering_pipeline_verified": True,
        "scientific_fidelity_verified": False,
    })
    manifest["status"] = "finalized"
    manifest["finalized_utc"] = utc_now()
    atomic_write_json(manifest["manifest_path"], {k: v for k, v in manifest.items()
                                                   if k not in ("manifest_path", "run_dir")})
    print(json.dumps({"finalized": True, "dataset_output": str(target),
                      "sample_count": manifest["source_count"]}, indent=2))
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    # ``required=`` for subparsers was added after Python 3.6.  Validate the
    # selected command explicitly so the CLI has the same fail-fast behavior
    # in the project's Python 3.6 environment.
    sub = parser.add_subparsers(dest="command")
    plan = sub.add_parser("plan")
    plan.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    plan.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    plan.add_argument("--dataset-output", type=Path, default=DEFAULT_DATASET)
    plan.add_argument("--seed", type=int, default=2024)
    plan.add_argument("--speed", type=float, default=1.0)
    plan.add_argument("--session-seconds", type=int, default=None,
                      help="Defaults to 900 seconds for --pilot and 9000 otherwise")
    plan.add_argument("--guard-seconds", type=float, default=GUARD_SECONDS)
    plan.add_argument("--max-samples", type=int)
    plan.add_argument("--pilot", action="store_true")
    plan.add_argument("--sample-ids", type=Path,
                      help="JSON file freezing exact source IDs, shared across scenarios")
    plan.add_argument("--transport", choices=("tcp", "udp"), default="tcp")
    plan.add_argument("--topology-mode", choices=("dynamic", "fixed"), default="dynamic")
    plan.add_argument("--scenario", choices=tuple(sorted(FIXED_SCENARIOS)))
    plan.add_argument("--batch-id")
    plan.add_argument("--batch-manifest", type=Path)
    plan.add_argument("--owner-id")
    plan.add_argument("--service-name")
    plan.add_argument("--cohort-key", choices=("pilot", "full", "dynamic", "deadline"))
    plan.add_argument("--diagnostic-mode", choices=("deadline", "stable", "crossing"))
    plan.add_argument("--tcp-completion-seconds", type=int, choices=(30, 120), default=120,
                      help="Completion window; 30 seconds is restricted to the paired baseline diagnostic")
    plan.add_argument("--link-loss-percent", type=loss_percent_arg, default=None,
                      help="Override both satellite and ground link loss percentages; default keeps 1%%")
    for name in ("preflight", "run", "verify", "finalize"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        if name == "run":
            command.add_argument("--resume", action="store_true",
                                 help="reuse verified sample roots and continue incomplete sessions")
    capacity = sub.add_parser("capacity")
    capacity.add_argument("--batch-manifest", type=Path, required=True)
    capacity.add_argument("--pilot-manifests", type=Path, nargs=4, required=True)
    capacity.add_argument("--full-manifests", type=Path, nargs=4, required=True)
    capacity.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.error("the following arguments are required: command")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.command == "plan":
            if args.session_seconds is None:
                args.session_seconds = 900 if args.pilot else 9000
            if args.speed <= 0 or args.session_seconds < 180 or args.guard_seconds < 0:
                raise ReplayError("speed positive, session-seconds >=180, guard nonnegative")
            return cmd_plan(args)
        if args.command == "preflight":
            return cmd_preflight(args)
        if args.command == "run":
            return cmd_run(args)
        if args.command == "verify":
            return cmd_verify(args)
        if args.command == "capacity":
            return cmd_capacity(args)
        return cmd_finalize(args)
    except (ReplayError, OSError, ValueError) as exc:
        print("E_v4 ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
