#!/usr/bin/env python3
"""Generate auditable dynamic StarryNet replay traces (E_v4).

The command has two deliberately separate responsibilities.  ``plan`` and
``verify`` are offline and safe to run without Docker.  ``run`` is the only
subcommand that creates StarryNet resources.  It runs a pair of long-lived UDP
agents in GS26/GS27 and records the client-side observation trace.
"""

import argparse
import datetime as datetime_module
import fcntl
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_RE = re.compile(r"^(?P<class_id>[0-9]+)-(?P<repeat_id>[0-9]+)$")
SCHEMA_VERSION = 1
PLAN_VERSION = "e_replay_v4_plan_2"
AGENT_SOURCE = Path(__file__).with_name("e_replay_agent.py")
RUNTIME_SOURCE_FILES = (
    ROOT / "starrynet" / "sn_orchestrater.py",
    ROOT / "starrynet" / "sn_synchronizer.py",
    ROOT / "starrynet" / "sn_thread.py",
    ROOT / "starrynet" / "sn_utils.py",
)
DEFAULT_INPUT = ROOT / "dataset" / "tor_fiber"
# Keep generated artifacts and the finalized E dataset together on the
# requested large-volume mount.  The source F dataset remains in the repo.
DEFAULT_OUTPUT_ROOT = Path("/mnt/HDD4T/shy/StarryNet_E_v4")
DEFAULT_RUN_ROOT = DEFAULT_OUTPUT_ROOT / "artifacts" / "e_replay_v4"
DEFAULT_DATASET = DEFAULT_OUTPUT_ROOT / "dataset" / "tor_satellite_replay_v4"
CLIENT_NODE = 26
REMOTE_NODE = 27
UDP_PORT = 19999
REMOTE_UDP_PORT = 20000
UDP_PORTS = (UDP_PORT, REMOTE_UDP_PORT)
PAYLOAD_BYTES = 512
TAIL_SECONDS = 0.5
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
    "Duration (s)": 7200,
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


def runtime_source_hashes():
    return {str(path.relative_to(ROOT)): sha256_file(path)
            for path in RUNTIME_SOURCE_FILES}


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


def make_config(session_seconds):
    config = dict(P2_CONFIG)
    config["Duration (s)"] = int(session_seconds)
    return config


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
    return {
        "schema_version": SCHEMA_VERSION,
        "plan_version": PLAN_VERSION,
        "dataset_id": "E_v4_dynamic_replay",
        "created_utc": utc_now(),
        "mode": mode,
        "run_id": run_dir.name,
        "input_root": str(Path(args.input).resolve()),
        "dataset_output": str(Path(args.dataset_output).resolve()),
        "source_count": len(files),
        "source_total_bytes": source_total_bytes,
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
            "config": make_config(args.session_seconds),
            "dynamic_required": True,
            "engineering_pipeline_verified": False,
            "scientific_fidelity_verified": False,
        },
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
    files = selected_files(source_files(args.input), args.pilot, args.max_samples)
    if args.pilot and args.session_seconds == 7200:
        args.session_seconds = 900
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
    manifest = build_manifest(args, files, sessions, run_dir,
                              "pilot" if args.pilot else "formal")
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
                      {"schema_version": 1, "config": make_config(args.session_seconds),
                       "ground_stations": GS, "payload_bytes": PAYLOAD_BYTES,
                       "udp_port": UDP_PORT, "udp_ports": list(UDP_PORTS),
                       "agent_header_schema": "EV4-v1"})
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
    source_bytes = int(manifest.get("source_total_bytes", 0))
    # A conservative pilot-derived planning envelope: source-sized event
    # artifacts plus 256 MiB per session for PCAP/log overhead, with the
    # required 1.5x headroom and 10 GiB safety margin.
    estimate = source_bytes * 2 + len(active_sessions(manifest)) * 256 * 1024**2
    required = int(estimate * 1.5) + 10 * 1024**3
    free = shutil.disk_usage(manifest["run_dir"]).free
    if free < required:
        raise ReplayError(
            "insufficient free disk space: free={0} required={1}".format(free, required))
    return {"source_bytes": source_bytes, "estimated_bytes": estimate,
            "required_free_bytes": required, "free_bytes": free}


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


def session_evidence_is_valid(manifest, session):
    """Check the evidence needed to retain a completed session on resume."""
    session_dir = Path(manifest["run_dir"]) / "sessions" / session["session_id"]
    summary_path = session_dir / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        pcap = summary.get("pcap", {})
        pcap_path = session_dir / "client.pcap"
        return (summary.get("status") == "completed"
                and summary.get("cleanup_verified") is True
                and int(pcap.get("ev4_packet_count", 0)) > 0
                and int(pcap.get("bytes", 0)) >= 24
                and pcap_path.is_file()
                and pcap_path.stat().st_size == int(pcap.get("bytes", -1))
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


def docker_exec(cid, *args, timeout=60, check=True):
    result = docker_command("exec", str(cid), *args, timeout=timeout, check=check)
    if result.stdout is None:
        return ""
    return result.stdout.decode(errors="replace").strip() if isinstance(result.stdout, bytes) else result.stdout.strip()


def docker_cp(source, destination, timeout=120):
    docker_command("cp", str(source), str(destination), timeout=timeout)


def docker_inventory():
    def lines_raw(*args):
        return docker_command(*args).stdout.decode().split()
    def lines(*args):
        return sorted(lines_raw(*args))
    return {"containers": lines("ps", "-aq"),
            "networks": lines("network", "ls", "-q"),
            "services": lines("service", "ls", "--format", "{{.Name}}"),
            "starrynet_service_containers": lines(
                "ps", "-aq", "--filter",
                "label=com.docker.swarm.service.name=constellation-test"),
            "starrynet_owner_networks": lines(
                "network", "ls", "-q", "--filter",
                "label=starrynet.owner=constellation-test")}


def starrynet_resources_cleared(inventory):
    """Return whether this replay's named/labelled Docker resources are gone.

    Full Docker inventories remain in the session summary for audit evidence,
    but unrelated containers and networks may legitimately change during a
    multi-hour replay.  Cleanup acceptance must therefore be scoped to the
    resources owned by this StarryNet session.
    """
    if not inventory:
        return False
    return ("constellation-test" not in inventory.get("services", [])
            and not inventory.get("starrynet_service_containers", [])
            and not inventory.get("starrynet_owner_networks", []))


def wait_for_starrynet_cleanup(timeout=30.0):
    """Wait for asynchronous Swarm removal and return the last inventory."""
    deadline = time.monotonic() + timeout
    inventory = None
    while True:
        inventory = docker_inventory()
        if starrynet_resources_cleared(inventory):
            return inventory
        if time.monotonic() >= deadline:
            return inventory
        time.sleep(0.5)


def check_docker_capabilities():
    docker_command("info", timeout=30)
    if docker_command("info", "--format", "{{.Swarm.ControlAvailable}}").stdout.decode().strip().lower() != "true":
        raise ReplayError("Docker Swarm manager is required")
    image = "lwsen/starlab_node:1.0"
    docker_command("image", "inspect", image, timeout=30)
    result = docker_command("run", "--rm", "--network", "none", image,
                            "sh", "-c", "command -v python3 && command -v tcpdump",
                            timeout=90, check=False)
    if result.returncode:
        raise ReplayError("StarryNet image must contain python3 and tcpdump")
    return {"image": image, "capabilities": result.stdout.decode(errors="replace")}


def make_runtime_config(session_dir, session_seconds):
    path = Path(session_dir) / "config.json"
    atomic_write_json(path, make_config(session_seconds))
    return path


def get_container_ids(sn):
    if len(sn.container_id_list) != 27:
        raise ReplayError("expected 27 StarryNet containers, got {0}".format(
            len(sn.container_id_list)))
    return str(sn.container_id_list[CLIENT_NODE - 1]), str(sn.container_id_list[REMOTE_NODE - 1])


def get_ipv4_addresses(cid):
    value = docker_exec(cid, "ip", "-4", "-o", "addr", "show")
    return re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", value)


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
    def __init__(self, cid, role, peer_ip, session_dir, listen_port, peer_port):
        self.cid = str(cid)
        self.role = role
        self.peer_ip = peer_ip
        self.session_dir = Path(session_dir)
        self.listen_port = int(listen_port)
        self.peer_port = int(peer_port)
        self.process = None
        self.output = deque()
        self.output_lock = threading.Lock()
        self.errors = []
        self._thread = None
        self._log_handle = None
        self.log_path = self.session_dir / (self.role + "_agent.jsonl")

    def start(self):
        remote_script = "/tmp/e_replay_agent.py"
        docker_cp(AGENT_SOURCE, self.cid + ":" + remote_script)
        command = ["docker", "exec", "-i", self.cid, "python3", remote_script,
                   "--role", self.role, "--peer", self.peer_ip,
                   "--listen-port", str(self.listen_port),
                   "--peer-port", str(self.peer_port),
                   "--payload-bytes", str(PAYLOAD_BYTES),
                   "--tail-seconds", str(TAIL_SECONDS)]
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


def start_capture(cid, session_dir, interface):
    remote_dir = "/tmp/e-replay-v4"
    docker_exec(cid, "mkdir", "-p", remote_dir)
    remote_pcap = remote_dir + "/client.pcap"
    remote_log = remote_dir + "/tcpdump.log"
    capture_filter = "udp port {0} or udp port {1}".format(*UDP_PORTS)
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


def _udp_payload_from_frame(frame, link_type, expected_ports):
    """Return an EV4-candidate UDP payload from a classic PCAP frame.

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
    if frame[offset + 9] != 17:  # UDP
        return None
    udp_offset = offset + ip_header_bytes
    source_port = int.from_bytes(frame[udp_offset:udp_offset + 2], "big")
    destination_port = int.from_bytes(frame[udp_offset + 2:udp_offset + 4], "big")
    if {source_port, destination_port}.isdisjoint(set(expected_ports)):
        return None
    udp_length = int.from_bytes(frame[udp_offset + 4:udp_offset + 6], "big")
    if udp_length < 8:
        return None
    payload_end = min(len(frame), udp_offset + udp_length)
    return frame[udp_offset + 8:payload_end]


def _classic_pcap_event_counts(path, expected_ports=UDP_PORTS):
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise ReplayError("PCAP global header is truncated: " + str(path))
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return None
    _magic, _major, _minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack(
        endian + "IHHiiii", raw[:24])
    cursor = 24
    packet_count = 0
    udp_packet_count = 0
    ev4_packet_count = 0
    while cursor < len(raw):
        if len(raw) - cursor < 16:
            raise ReplayError("truncated PCAP packet header: " + str(path))
        _sec, _usec, captured_length, _original_length = struct.unpack(
            endian + "IIII", raw[cursor:cursor + 16])
        cursor += 16
        if captured_length > len(raw) - cursor:
            raise ReplayError("truncated PCAP packet payload: " + str(path))
        frame = raw[cursor:cursor + captured_length]
        cursor += captured_length
        packet_count += 1
        payload = _udp_payload_from_frame(frame, link_type, expected_ports)
        if payload is not None:
            udp_packet_count += 1
            if payload.startswith(EV4_MAGIC):
                ev4_packet_count += 1
    return {"packet_count": packet_count,
            "udp_packet_count": udp_packet_count,
            "ev4_packet_count": ev4_packet_count,
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
            if (not evidence.get("client_observed_event_count", 0)
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
    client_records = client_row.get("records", [])
    observed = []
    for record in client_records:
        if record.get("action") == "send" and record.get("direction") == 1:
            observed.append(record)
        elif record.get("action") == "recv" and record.get("direction") == -1:
            observed.append(record)
    reorder_count = sum(1 for previous, current in zip(observed, observed[1:])
                        if current["observed_ns"] < previous["observed_ns"])
    observed.sort(key=lambda row: (int(row["observed_ns"]), int(row["sequence"])))
    first_ns = observed[0]["observed_ns"] if observed else None
    trace_lines = []
    output_records = []
    for record in observed:
        timestamp = 0.0 if first_ns is None else (record["observed_ns"] - first_ns) / 1e9
        trace_lines.append("{0:.9f}\t{1}\n".format(timestamp, record["direction"]))
        output_records.append({"timestamp": timestamp, "direction": record["direction"],
                              "sequence": record["sequence"],
                              "scheduled_offset_seconds": record["scheduled_offset_ns"] / 1e9,
                              "observed_ns": record["observed_ns"],
                              "action": record["action"]})
    trace_path = attempt_root / "trace"
    trace_path.write_text("".join(trace_lines), encoding="utf-8")
    source_events, source_info = load_sample_events(sample)
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
    if status_override:
        result_status = status_override
        result_error_type = error_type
        result_error_message = error_message
    elif observed:
        result_status = "success"
        result_error_type = None
        result_error_message = None
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
        "simulation_start_second": sample["start_second"],
        "simulation_end_second": sample["start_second"] + sample["duration_seconds"],
        "wall_start_ns": runtime_meta.get("wall_start_ns"),
        "wall_end_ns": runtime_meta.get("wall_end_ns"),
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
        "client_records": output_records,
        "remote_records": remote_records,
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
                session_tail_seconds=SESSION_TAIL_SECONDS):
    session_dir = Path(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)
    config_path = make_runtime_config(session_dir, session_seconds)
    sys.path.insert(0, str(ROOT))
    from starrynet.sn_synchronizer import StarryNet
    from starrynet.sn_thread import WORKER_ERRORS
    WORKER_ERRORS.clear()
    sn = None
    client_agent = None
    remote_agent = None
    capture = None
    emulation_thread = None
    emulation_error = []
    session_anchor_ns = None
    sample_specs = rebase_runtime_schedule(
        sample_specs, manifest.get("guard_seconds", GUARD_SECONDS))
    summary = {"schema_version": SCHEMA_VERSION, "session_id": session["session_id"],
               "status": "running", "dynamic_required": True,
               "sample_count": len(sample_specs), "sample_results": [],
               "worker_errors": []}
    cleanup_failure = None
    heartbeat_stop, heartbeat_thread, heartbeat_path = start_heartbeat(
        session_dir, session["session_id"], WORKER_ERRORS)
    summary["heartbeat"] = str(heartbeat_path)
    emulation_stop_requested = False
    try:
        summary["phase"] = "inventory"
        inventory_before = docker_inventory()
        summary["resource_inventory_before"] = inventory_before
        if not starrynet_resources_cleared(inventory_before):
            raise ReplayError("constellation-test already exists; refusing to claim an unowned StarryNet resource")
        sn = StarryNet(str(config_path), GS, 1, [[1, 27]], local=True, argv=[])
        summary["phase"] = "create_nodes"
        sn.create_nodes()
        summary["phase"] = "create_links"
        sn.create_links()
        if WORKER_ERRORS:
            raise ReplayError("StarryNet worker error: " + str(WORKER_ERRORS))
        summary["phase"] = "routing"
        sn.run_routing_deamon()
        if WORKER_ERRORS:
            raise ReplayError("routing worker error: " + str(WORKER_ERRORS))
        client_cid, remote_cid = get_container_ids(sn)
        peer_ip = find_peer_ip(remote_cid)
        summary["phase"] = "topology_validation"
        topology = topology_summary(Path(sn.configuration_file_path) / sn.file_path)
        summary["topology"] = topology
        if topology["matrix_changed_count"] < 1 or topology["handover_count"] < 1:
            raise ReplayError("dynamic topology has no matrix changes or handover")
        if session["session_id"] == "preflight":
            first_handover = topology["handover_seconds"][0]
            preflight_starts = [max(15.0, first_handover - 30.0),
                                max(15.0, first_handover - 2.0),
                                first_handover + 20.0]
            for sample, start_second in zip(sample_specs, preflight_starts):
                sample["start_second"] = round(start_second, 6)
            summary["preflight_handover_second"] = first_handover
        summary["phase"] = "route_before"
        summary["route_before"] = wait_for_satellite_route(client_cid, peer_ip)
        route_dir = session_dir / "route_snapshots"
        route_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(route_dir / "before.json", summary["route_before"])
        handover_path = session_dir / "handover_events.jsonl"
        with handover_path.open("w", encoding="utf-8") as handle:
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
        # the first GS26 handover.  Capture the two dedicated EV4 UDP ports on
        # every interface in the GS26 namespace; the route snapshots above and
        # below still prove that their remote endpoint uses a satellite link.
        summary["capture_interface"] = "any"
        summary["capture_scope"] = "GS26 namespace, EV4 UDP ports"
        summary["phase"] = "capture_agents"
        capture = start_capture(client_cid, session_dir, "any")
        client_agent = AgentProcess(client_cid, "client", peer_ip, session_dir,
                                    UDP_PORT, REMOTE_UDP_PORT)
        remote_agent = AgentProcess(remote_cid, "remote", find_client_ip(client_cid),
                                    session_dir, REMOTE_UDP_PORT, UDP_PORT)
        client_agent.start()
        remote_agent.start()
        emulation_thread = threading.Thread(target=lambda: _run_emulation(sn, emulation_error),
                                             daemon=True)
        emulation_thread.start()
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
                planned_start_ns = session_anchor_ns + int(sample["start_second"] * 1e9)
                # Only the tiny start command remains after preparation, so a
                # bounded lead is sufficient and is shared by both agents.
                start_ns = max(planned_start_ns,
                               monotonic_ns() + int(DISPATCH_LEAD_SECONDS * 1e9))
                runtime_sample["start_second"] = round(
                    (start_ns - session_anchor_ns) / 1e9, 6)
                if runtime_sample["start_second"] + runtime_sample["duration_seconds"] > (
                        session_seconds - session_tail_seconds):
                    raise ReplayError(
                        "runtime scheduling exceeded usable session window for "
                        + sample["sample_id"])
                runtime_meta.update({
                    "handover_count": sum(
                        1 for value in topology["handover_seconds"]
                        if runtime_sample["start_second"] <= value <=
                        runtime_sample["start_second"] + runtime_sample["duration_seconds"]),
                    "source_satellite_before": attachment_for_second(
                        topology, runtime_sample["start_second"]),
                    "source_satellite_after": attachment_for_second(
                        topology, runtime_sample["start_second"] +
                        runtime_sample["duration_seconds"]),
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
                sample_deadline_ns = (start_ns + last_offset_ns
                                      + int((TAIL_SECONDS +
                                             SAMPLE_TIMEOUT_MARGIN_SECONDS) * 1e9))
                timeout = max(
                    1.0, (sample_deadline_ns - monotonic_ns()) / 1e9)
                client_row = client_agent.wait_sample(sample["sample_id"], timeout)
                timeout = max(
                    1.0, (sample_deadline_ns - monotonic_ns()) / 1e9)
                remote_row = remote_agent.wait_sample(sample["sample_id"], timeout)
                runtime_meta["wall_end_ns"] = monotonic_ns()
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
        atomic_write_json(route_dir / "after.json", summary["route_after"])
        if not rollover_requested:
            summary["status"] = "completed"
            summary["phase"] = "completed"
        summary["dynamic_matrix_changed"] = topology["matrix_changed_count"] > 0
        summary["handover_count"] = topology["handover_count"]
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
        for role, agent in (("client", client_agent), ("remote", remote_agent)):
            if not agent:
                continue
            try:
                agent.stop()
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
            try:
                summary[role + "_agent_log"] = str(agent.write_log())
            except OSError as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
        if capture:
            try:
                pcap = stop_capture(capture, session_dir)
                if pcap is not None:
                    summary["pcap"] = validate_pcap(pcap)
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
                summary["resource_inventory_after"] = wait_for_starrynet_cleanup()
            except Exception as exc:
                cleanup_failure = cleanup_failure or exc
                summary.setdefault("cleanup_errors", []).append(str(exc))
            after = summary.get("resource_inventory_after")
            summary["cleanup_verified"] = starrynet_resources_cleared(after)
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
    return summary


def _run_emulation(sn, errors):
    try:
        sn.start_emulation()
    except BaseException as exc:
        errors.append(exc)


def cmd_preflight(args):
    manifest = load_manifest(args.manifest)
    check_frozen_config(manifest)
    check_docker_capabilities()
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
    session = {"session_id": "preflight", "samples": samples}
    summary = run_session(manifest, session, samples, preflight_dir, 180,
                          session_tail_seconds=0.0)
    if summary.get("status") != "completed":
        raise ReplayError("dynamic preflight did not complete")
    if not summary.get("dynamic_matrix_changed") or summary.get("handover_count", 0) < 1:
        raise ReplayError("dynamic preflight did not observe a changing topology")
    manifest["preflight"] = {"status": "passed", "summary": str(preflight_dir / "summary.json"),
                              "completed_utc": utc_now()}
    manifest["status"] = "preflight_passed"
    atomic_write_json(manifest["manifest_path"], {k: v for k, v in manifest.items()
                                                   if k not in ("manifest_path", "run_dir")})
    print(json.dumps({"preflight_passed": True, "summary": str(preflight_dir / "summary.json")},
                     indent=2, sort_keys=True))
    return 0


def cmd_run(args):
    manifest = load_manifest(args.manifest)
    check_frozen_config(manifest)
    if manifest.get("preflight", {}).get("status") != "passed":
        raise ReplayError("run requires a passed dynamic preflight")
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
                        manifest["session_seconds"])
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
        for session in active_sessions(manifest):
            for sample in session["samples"]:
                sample_id = sample["sample_id"]
                if sample_is_valid(manifest, sample_id):
                    continue
                if retry_allowed(manifest, sample_id):
                    if (next_attempt_number(manifest, sample_id)
                            <= max_infrastructure_attempts(manifest)):
                        retryable_samples.append(sample_id)
                    else:
                        exhausted_samples.append(sample_id)
                else:
                    nonretryable_samples.append(sample_id)
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
            print(json.dumps({"run_completed": False,
                              "retryable_samples": manifest["retryable_samples"],
                              "retry_exhausted_samples": manifest["retry_exhausted_samples"],
                              "nonretryable_samples": manifest["nonretryable_samples"]},
                             indent=2))
            return 1
        manifest["status"] = "run_completed"
        manifest["last_run_utc"] = utc_now()
        atomic_write_json(manifest["manifest_path"], {k: v for k, v in manifest.items()
                                                       if k not in ("manifest_path", "run_dir")})
    print(json.dumps({"run_completed": True, "sessions": len(summaries)}, indent=2))
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


def cmd_verify(args):
    manifest = load_manifest(args.manifest)
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
    if manifest.get("mode") == "formal":
        class_counts = Counter(sample.split("-", 1)[0] for sample in expected)
        if len(expected) != 6000:
            errors.append("formal plan does not contain 6000 samples")
        if len(class_counts) != 75 or set(class_counts.values()) != {80}:
            errors.append("formal plan is not 75 classes x 80 repeats")
    successes = 0
    evidence_rows = []
    evidence_ids = set()
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
    session_summaries = []
    for session in sessions:
        summary_path = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "summary.json"
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            session_summaries.append(summary)
            if summary.get("status") not in ("completed",):
                errors.append("session not completed: " + session["session_id"])
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
                agent_log = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / (role + "_agent.jsonl")
                if not agent_log.is_file():
                    errors.append("missing {0} agent log: {1}".format(role, session["session_id"]))
            route_dir = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "route_snapshots"
            if not (route_dir / "before.json").is_file() or not (route_dir / "after.json").is_file():
                errors.append("missing route snapshots: " + session["session_id"])
            if not (Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "logs" / "tcpdump.log").is_file():
                errors.append("missing tcpdump log: " + session["session_id"])
            handover_log = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "handover_events.jsonl"
            if not handover_log.is_file() or handover_log.stat().st_size == 0:
                errors.append("missing handover event log: " + session["session_id"])
            pcap_path = Path(manifest["run_dir"]) / "sessions" / session["session_id"] / "client.pcap"
            try:
                pcap_info = validate_pcap(pcap_path)
                if summary.get("pcap", {}).get("sha256") != pcap_info["sha256"]:
                    errors.append("session PCAP hash mismatch: " + session["session_id"])
                if pcap_info.get("ev4_packet_count", 0) < 1:
                    errors.append("session PCAP has no identifiable EV4 packet: "
                                  + session["session_id"])
            except (OSError, ReplayError) as exc:
                errors.append("invalid session PCAP {0}: {1}".format(session["session_id"], exc))
        else:
            errors.append("missing session summary: " + session["session_id"])
    attempts = read_attempts(manifest)
    planned_ids = set(expected)
    attempt_ids = [(row.get("sample_id"), row.get("attempt_id")) for row in attempts]
    if len(attempt_ids) != len(set(attempt_ids)):
        errors.append("duplicate attempt identity")
    if manifest.get("mode") == "pilot" and not any(
            int(row.get("handover_count", 0)) > 0 for row in evidence_rows):
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
              "evidence_count": len(evidence_rows)}
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
    plan.add_argument("--session-seconds", type=int, default=7200)
    plan.add_argument("--guard-seconds", type=float, default=GUARD_SECONDS)
    plan.add_argument("--max-samples", type=int)
    plan.add_argument("--pilot", action="store_true")
    for name in ("preflight", "run", "verify", "finalize"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        if name == "run":
            command.add_argument("--resume", action="store_true",
                                 help="reuse verified sample roots and continue incomplete sessions")
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.error("the following arguments are required: command")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.command == "plan":
            if args.speed <= 0 or args.session_seconds < 180 or args.guard_seconds < 0:
                raise ReplayError("speed positive, session-seconds >=180, guard nonnegative")
            return cmd_plan(args)
        if args.command == "preflight":
            return cmd_preflight(args)
        if args.command == "run":
            return cmd_run(args)
        if args.command == "verify":
            return cmd_verify(args)
        return cmd_finalize(args)
    except (ReplayError, OSError, ValueError) as exc:
        print("E_v4 ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
