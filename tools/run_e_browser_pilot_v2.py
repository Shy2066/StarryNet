#!/usr/bin/env python3
"""Bounded preflight, freeze, run, and audit for the E browser/Tor V2 pilot."""

import argparse
import atexit
import csv
import datetime
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import tempfile
import uuid
from urllib.parse import urlsplit

from e_browser_v2_process import (process_group_exists,
                                  stop_process_group)
import replay_trace_over_starrynet as replay_resources


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT / "artifacts" / "e_browser_tor_pilot_v2_20261021"
PROTOCOL_ID = "starrynet-e-browser-tor-v2-warm-refresh-bounded-pilot"
DATA_DOMAIN = "E_BROWSER_TOR_V2"
TOTAL_BUDGET_SECONDS = 4 * 60 * 60
PREFLIGHT_BUDGET_SECONDS = 45 * 60
MIN_ATTEMPT_RESERVE_SECONDS = 22 * 60
COLLECTOR_TIMEOUT_SECONDS = 20 * 60
RETRY_LIMIT = 1
MAX_CONSECUTIVE_FAILURES = 3
EXPECTED_IMAGE_ID = "sha256:168196aef4661dbe43899fb144428a1c68ccb0391a0bb5520c63d606464aa27c"
ENTRY_BRIDGE_FINGERPRINT = "F99CFE52EDFF8EAA332CD73C1E638035210C0336"

CANDIDATES = [
    (1, "amazon.co.jp", "https://amazon.co.jp/"),
    (19, "facebook.com", "https://facebook.com/"),
    (38, "mozilla.org", "https://mozilla.org/"),
    (57, "stackoverflow.com", "https://stackoverflow.com/"),
    (75, "adobe.com", "https://www.adobe.com/"),
    (3, "apache.org", "https://www.apache.org/"),
    (26, "github.com", "https://github.com/"),
    (65, "w3.org", "https://www.w3.org/"),
    (70, "wikipedia.org", "https://www.wikipedia.org/"),
]
COLLECTION_FATAL_FAILURES = frozenset((
    "proxy", "docker", "cleanup_unverified", "collector_exception",
    "interrupted"))


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read_json(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(target) + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(target)


def append_jsonl(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path):
    root = Path(path)
    digest = hashlib.sha256()
    for current, directories, files in os.walk(str(root), followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in directories:
            item = current_path / name
            relative = item.relative_to(root).as_posix().encode("utf-8")
            if item.is_symlink():
                digest.update(b"L\0" + relative + b"\0")
                digest.update(os.readlink(str(item)).encode("utf-8") + b"\0")
            else:
                digest.update(b"D\0" + relative + b"\0")
                digest.update(("{:o}".format(
                    item.lstat().st_mode & 0o7777).encode("ascii")) + b"\0")
        for name in files:
            item = current_path / name
            relative = item.relative_to(root).as_posix().encode("utf-8")
            if item.is_symlink():
                digest.update(b"L\0" + relative + b"\0")
                digest.update(os.readlink(str(item)).encode("utf-8") + b"\0")
                if item.is_file():
                    digest.update(bytes.fromhex(sha256_file(item)))
            elif item.is_file():
                digest.update(b"F\0" + relative + b"\0")
                digest.update(("{:o}".format(
                    item.lstat().st_mode & 0o7777).encode("ascii")) + b"\0")
                digest.update(bytes.fromhex(sha256_file(item)))
    return digest.hexdigest()


def sha256_path(path):
    target = Path(path)
    if target.is_file():
        return sha256_file(target)
    if target.is_dir():
        return sha256_tree(target)
    return None


def command(argv, timeout=20):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True,
                                timeout=timeout)
        return {"returncode": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc)}


def https_proxy_probe(port, timeout=12):
    result = {"listener_reachable": False, "https_connect_passed": False,
              "target_http_status": None, "error": None}
    try:
        connection = http.client.HTTPSConnection("127.0.0.1", int(port),
                                                 timeout=timeout)
        connection.set_tunnel("example.com", 443)
        connection.request("GET", "/", headers={"Host": "example.com"})
        response = connection.getresponse()
        result["listener_reachable"] = True
        result["https_connect_passed"] = True
        result["target_http_status"] = int(response.status)
        response.read(1024)
        connection.close()
    except Exception as exc:
        result["error"] = "{}: {}".format(type(exc).__name__, str(exc)[:300])
    return result


def runtime_assets(config):
    keys = ("python_executable", "runner", "collector_wrapper", "browser_dir",
            "expert_bundle", "bridge_file", "geckodriver",
            "python_site_packages")
    return {key: {"path": config.get(key),
                  "exists": bool(config.get(key)
                                 and Path(config[key]).exists())}
            for key in keys}


def active_collection_processes():
    result = command(["ps", "-eo", "pid=,args="], timeout=10)
    needles = ("batch_manifest.py run", "run_e_browser_site_sample.py",
               "tor_browser_starrynet_smoke.py run",
               "tor_browser_starrynet_smoke_v2.py run")
    rows = []
    for line in result.get("stdout", "").splitlines():
        if any(needle in line for needle in needles) and "rg " not in line:
            rows.append(line.strip()[:500])
    return rows


def doctor(config, check_network=True):
    findings = {}
    errors = []
    findings["assets"] = runtime_assets(config)
    for name, row in findings["assets"].items():
        if not row["exists"]:
            errors.append("runtime asset missing: " + name)
    required_code = {
        "v2_coordinator": Path(__file__).resolve(),
        "v2_collector": ROOT / "tools" / "run_e_browser_site_sample_v2.py",
        "v2_runner": ROOT / "tools" / "tor_browser_starrynet_smoke_v2.py",
        "v2_browser_helper": ROOT / "tools" / "tor_browser_site_smoke_v2.py",
        "v2_pilot_auditor": ROOT / "tools" / "audit_e_browser_tor_pilot_v2.py",
        "v2_trace_auditor": ROOT / "tools" / "audit_site_trace_repeatability_v2.py",
        "v2_process_helper": ROOT / "tools" / "e_browser_v2_process.py",
    }
    findings["v2_code_assets"] = {
        name: {"path": str(path), "exists": path.is_file()}
        for name, path in required_code.items()}
    for name, row in findings["v2_code_assets"].items():
        if not row["exists"]:
            errors.append("V2 code asset missing: " + name)
    py = command([config["python_executable"], "--version"], timeout=10)
    findings["python"] = py.get("stdout", "").strip() or py.get("stderr", "").strip()
    if py["returncode"] != 0 or "3.6.15" not in findings["python"]:
        errors.append("project Python 3.6.15 check failed")
    tmux = command(["tmux", "has-session", "-t", "starrynet"], timeout=5)
    findings["tmux_starrynet"] = tmux["returncode"] == 0
    if tmux["returncode"] != 0:
        errors.append("tmux starrynet session unavailable: "
                      + (tmux.get("stderr", "").strip() or "access denied or session missing"))
    findings["active_collection_processes"] = active_collection_processes()
    if findings["active_collection_processes"]:
        errors.append("an existing collection process is active")
    docker = command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
    findings["docker"] = {"available": docker["returncode"] == 0,
                          "server_version": docker["stdout"].strip(),
                          "error": docker["stderr"].strip()[-500:]}
    if docker["returncode"] != 0:
        errors.append("Docker daemon unavailable")
    else:
        try:
            inventory = replay_resources.docker_inventory()
            clean = replay_resources.starrynet_resources_cleared(inventory)
            findings["starrynet_resources"] = {
                "clean": clean,
                "starrynet_service_containers": inventory.get(
                    "starrynet_service_containers", []),
                "starrynet_owner_networks": inventory.get(
                    "starrynet_owner_networks", []),
                "constellation_test_service_present": (
                    "constellation-test" in inventory.get("services", [])),
            }
            if not clean:
                errors.append("owned StarryNet resources remain; refusing to start V2")
        except Exception as exc:
            findings["starrynet_resources"] = {
                "clean": False,
                "error": "{}: {}".format(type(exc).__name__, str(exc)[:300]),
            }
            errors.append("StarryNet resource inventory failed")
        image = command(["docker", "image", "inspect", "--format", "{{.Id}}",
                         config["helper_image"]], timeout=15)
        observed = image["stdout"].strip()
        findings["helper_image"] = {"expected": config.get("helper_image_id"),
                                    "observed": observed,
                                    "matches": observed == config.get("helper_image_id")}
        if not findings["helper_image"]["matches"]:
            errors.append("pinned helper Docker image is unavailable or changed")
    if check_network:
        proxy = https_proxy_probe(17897)
        findings["host_proxy"] = proxy
        if not proxy["https_connect_passed"]:
            errors.append("host proxy 127.0.0.1:17897 HTTPS CONNECT failed")
    findings["passed"] = not errors
    findings["errors"] = errors
    findings["observed_utc"] = utc_now()
    return findings


def budget_path(root):
    return Path(root) / "online_budget.json"


def acquire_collection_lock(root, lock_name="v2_online_action_lock.json"):
    path = Path(root) / lock_name
    path.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    payload = {"pid": os.getpid(), "token": token, "started_utc": utc_now()}
    for _attempt in range(2):
        try:
            descriptor = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                                 0o600)
        except OSError as exc:
            if exc.errno != errno.EEXIST or not path.is_file():
                raise
            try:
                existing = read_json(path)
                pid = int(existing.get("pid", -1))
                if pid <= 1:
                    raise ValueError("invalid collection lock PID")
                os.kill(pid, 0)
            except OSError as process_error:
                if process_error.errno != errno.ESRCH:
                    raise RuntimeError("cannot prove the existing collection lock is stale")
                path.unlink()
                continue
            except (ValueError, TypeError):
                raise RuntimeError("collection lock is malformed; inspect before resuming")
            raise RuntimeError("another V2 online action holds the runtime lock")
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return path, token
    raise RuntimeError("could not acquire the V2 collection lock")


def release_collection_lock(lock):
    path, token = lock
    try:
        payload = read_json(path)
        if payload.get("token") == token:
            path.unlink()
            return True
    except (OSError, ValueError):
        return False
    return False


def budget_used(root):
    path = budget_path(root)
    if not path.exists():
        return 0.0
    value = read_json(path)
    used = float(value.get("accrued_seconds", 0.0))
    active = value.get("active_started_utc")
    if active:
        try:
            started = datetime.datetime.strptime(
                active, "%Y-%m-%dT%H:%M:%S.%f%z")
            if started.tzinfo is None:
                started = started.replace(tzinfo=datetime.timezone.utc)
            used += max(0.0, (datetime.datetime.now(datetime.timezone.utc)
                              - started).total_seconds())
        except ValueError:
            pass
    return used


def begin_online_action(root, phase):
    path = budget_path(root)
    state = read_json(path) if path.exists() else {
        "schema_version": 1, "accrued_seconds": 0.0,
        "started_utc": utc_now(), "actions": []}
    if state.get("active_started_utc"):
        state["accrued_seconds"] = budget_used(root)
        state["actions"].append({"phase": state.get("active_phase"),
                                 "started_utc": state.get("active_started_utc"),
                                 "ended_utc": utc_now(), "recovered_after_interruption": True})
    state["active_started_utc"] = utc_now()
    state["active_phase"] = phase
    write_json(path, state)
    return time.monotonic()


def end_online_action(root, phase, monotonic_start, **metadata):
    path = budget_path(root)
    state = read_json(path)
    elapsed = max(0.0, time.monotonic() - monotonic_start)
    state["accrued_seconds"] = float(state.get("accrued_seconds", 0.0)) + elapsed
    state["active_started_utc"] = None
    state["active_phase"] = None
    state.setdefault("actions", []).append({"phase": phase, "elapsed_seconds": elapsed,
                                             "ended_utc": utc_now(), **metadata})
    write_json(path, state)
    return state["accrued_seconds"]


def read_jsonl(path):
    rows = []
    if not Path(path).is_file():
        return rows
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            try:
                if line.strip():
                    rows.append(json.loads(line))
            except ValueError:
                rows.append({"_record_error": "malformed JSONL line {}".format(line_no)})
    return rows


class SiteAccessControl(object):
    """Acknowledge the browser's capture brackets without a network capture."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.stop_event = threading.Event()
        self.seen = set()
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        self.thread.start()

    def _loop(self):
        phases = ("warmup", "start", "stop")
        while not self.stop_event.is_set():
            for phase in phases:
                request_path = self.directory / "capture_{}_request.json".format(phase)
                if not request_path.is_file():
                    continue
                try:
                    request = read_json(request_path)
                    request_id = request.get("request_id")
                    if not request_id or request_id in self.seen:
                        continue
                    self.seen.add(request_id)
                    now = time.monotonic()
                    ack = {"request_id": request_id, "ok": True,
                           "mode": "site_access_only_preflight_no_capture_no_topology",
                           "acknowledged_utc": utc_now()}
                    if phase == "warmup":
                        ack["route_ready_monotonic"] = now
                        ack["route_readiness"] = {
                            "passed": True,
                            "mode": "no_topology_preflight_control_ack",
                            "topology_or_satellite_route_claimed": False}
                    if phase == "start":
                        ack["tcpdump_ready_monotonic"] = now
                    if phase == "stop":
                        ack["tcpdump_stopped_monotonic"] = now
                    write_json(self.directory / "capture_{}_ack.json".format(phase), ack)
                except (OSError, ValueError):
                    pass
            self.stop_event.wait(0.05)

    def stop(self):
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(2.0)


def candidate_rows(source_csv):
    source_hash = sha256_file(source_csv)
    with Path(source_csv).open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    ranks = {str(row.get("序号")): row.get("网站域名") for row in rows}
    result = []
    for preflight_order, (rank, domain, url) in enumerate(CANDIDATES, 1):
        if ranks.get(str(rank)) != domain:
            raise ValueError("candidate/source rank mismatch at rank {}".format(rank))
        result.append({"preflight_order": preflight_order,
                       "source_rank": rank, "source_domain": domain, "url": url})
    candidates_path = Path(source_csv).with_name("source_candidates.csv")
    if candidates_path.is_file():
        with candidates_path.open("r", encoding="utf-8-sig", newline="") as stream:
            declared = [(int(row["source_rank"]), row["source_domain"], row["url"])
                        for row in csv.DictReader(stream)]
        if declared != CANDIDATES:
            raise ValueError("source_candidates.csv differs from the frozen candidate order")
    return result, source_hash


def choose_first_five_passed(candidates, records):
    passed = {row.get("candidate", {}).get("source_domain")
              for row in records if row.get("preflight_passed") is True}
    return [candidate for candidate in candidates
            if candidate["source_domain"] in passed][:5]


def candidate_is_retired(record):
    return record.get("failure_class") not in (
        "runtime_dependency_failed", "tor_check_failed", "timeout",
        "browser_or_tor_failure", "cleanup_unverified",
        "preflight_controller_error")


def remaining_budget_allows_attempt(remaining_seconds):
    return float(remaining_seconds) >= MIN_ATTEMPT_RESERVE_SECONDS


def failure_policy(failure_class, consecutive_failures, attempts_for_sample):
    if failure_class in COLLECTION_FATAL_FAILURES:
        return "pause"
    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
        return "pause"
    if attempts_for_sample <= RETRY_LIMIT:
        return "retry"
    return "next_sample"


def site_preflight_result(returncode, timed_out, cleanup_ok, summary,
                          expected_url=None):
    warmup = summary.get("site_warmup", {})
    visits = summary.get("visits", [])
    visit = visits[0] if visits else {}
    tor_check = summary.get("initial_tor_check") or {}
    tor_response = tor_check.get("tor_check_response") or {}
    tor_ok = (tor_check.get("tor_check_passed") is True
              and (tor_check.get("is_tor") is True
                   or tor_response.get("is_tor") is True))
    target_stream = (visit.get("target_stream_succeeded") is True
                     or warmup.get("target_stream_succeeded") is True)
    challenge_indicators = sorted(set(
        list(warmup.get("access_challenge_indicators", []))
        + list(visit.get("access_challenge_indicators", []))))
    expected_host = (urlsplit(expected_url).hostname or "").lower() \
        if expected_url else ""
    if expected_host.startswith("www."):
        expected_host = expected_host[4:]

    def identity_matches(url, require_https):
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        host_match = bool(expected_host and (
            host == expected_host or host.endswith("." + expected_host)))
        return host_match and (not require_https or parts.scheme.lower() == "https")

    warmup_identity = identity_matches(
        warmup.get("warmup_final_url"), require_https=True)
    refresh_identity = identity_matches(visit.get("final_url"), require_https=True)
    passed = bool(returncode == 0 and not timed_out and cleanup_ok and tor_ok
                  and warmup.get("http_status") == 200
                  and warmup.get("page_loaded") is True
                  and warmup_identity
                  and warmup.get("site_state_cleared") is True
                  and target_stream and visit.get("http_status") == 200
                  and visit.get("page_loaded") is True and refresh_identity
                  and visit.get("site_navigation_action") == "refresh"
                  and summary.get("cleanup_verified") is True)
    if passed:
        failure = None
    elif not cleanup_ok or summary.get("cleanup_verified") is not True:
        failure = "cleanup_unverified"
    elif timed_out:
        failure = "site_timeout"
    elif not tor_ok:
        failure = "tor_check_failed"
    elif warmup.get("http_status") == 403 or visit.get("http_status") == 403:
        failure = "page_access_403"
    elif challenge_indicators:
        failure = "page_access_challenge"
    elif returncode != 0:
        failure = "browser_or_tor_failure"
    else:
        failure = "site_or_target_stream_gate_failed"
    return {"passed": passed, "failure_class": failure,
            "tor_check_passed": tor_ok,
            "warmup_http_status": warmup.get("http_status"),
            "warmup_page_loaded": warmup.get("page_loaded"),
            "site_state_cleared": warmup.get("site_state_cleared"),
            "refresh_http_status": visit.get("http_status"),
            "refresh_page_loaded": visit.get("page_loaded"),
            "refresh_action": visit.get("site_navigation_action"),
            "warmup_page_identity_matches": warmup_identity,
            "refresh_page_identity_matches": refresh_identity,
            "target_stream_succeeded": target_stream,
            "access_challenge_indicators": challenge_indicators,
            "browser_cleanup_verified": summary.get("cleanup_verified")}


def cleanup_named_container(name):
    def list_container_ids():
        return command(["docker", "ps", "-aq", "--filter",
                        "name=^/{}$".format(name)], timeout=10)

    found = list_container_ids()
    if found["returncode"] != 0:
        return False
    container_ids = [line.strip() for line in found["stdout"].splitlines()
                     if line.strip()]
    if container_ids:
        removed = command(["docker", "rm", "-f"] + container_ids, timeout=30)
        if removed["returncode"] != 0:
            return False
    verified = list_container_ids()
    return verified["returncode"] == 0 and not verified["stdout"].strip()


def run_site_preflight(config, candidate, root, site_attempt_number, timeout):
    attempt_root = Path(root) / "preflight" / "attempts" / "{:02d}-{}".format(
        site_attempt_number, candidate["source_domain"].replace(".", "-"))
    attempt_root.mkdir(parents=True, exist_ok=False)
    control_dir = attempt_root / "capture_control"
    control = SiteAccessControl(control_dir)
    control.start()
    selected_bridge = tempfile.NamedTemporaryFile(
        prefix="sn-e2-v2-bridge-", suffix=".txt", delete=False)
    selected_bridge_path = Path(selected_bridge.name)
    bridge_content = Path(config["bridge_file"]).read_text(encoding="utf-8")
    bridge_lines = []
    for line in bridge_content.splitlines():
        fingerprints = re.findall(r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", line)
        if ENTRY_BRIDGE_FINGERPRINT in [item.upper() for item in fingerprints]:
            bridge_lines.append(line)
    if len(bridge_lines) != 1:
        selected_bridge.close()
        selected_bridge_path.unlink()
        control.stop()
        raise RuntimeError("registered V2 WebTunnel entry bridge is missing or ambiguous")
    selected_bridge.write((bridge_lines[0].rstrip() + "\n").encode("utf-8"))
    selected_bridge.close()
    selected_bridge_path.chmod(0o600)
    container_name = "sn-e2-v2-site-" + uuid.uuid4().hex[:12]
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    gid = os.getgid() if hasattr(os, "getgid") else 1000
    helper = Path(__file__).resolve().with_name("tor_browser_site_smoke_v2.py")
    output_mount = str(attempt_root.resolve()) + ":/out:rw"
    command_args = [
        "docker", "run", "--rm", "--name", container_name,
        "--network", "host", "--user", "{}:{}".format(uid, gid),
        "-e", "HOME=/tmp/tor-browser-home", "-e", "TMPDIR=/tmp",
        "-e", "PYTHONPATH=/opt/py312site",
        "-e", "HTTPS_PROXY=http://127.0.0.1:17897",
        "-e", "https_proxy=http://127.0.0.1:17897",
        "-e", "HTTP_PROXY=", "-e", "http_proxy=", "-e", "ALL_PROXY=",
        "-e", "all_proxy=", "-e", "NO_PROXY=", "-e", "no_proxy=",
        "-v", str(Path(config["browser_dir"]).resolve()) + ":/opt/tor-browser:ro",
        "-v", str(Path(config["expert_bundle"]).resolve()) + ":/opt/expert-bundle:ro",
        "-v", str(selected_bridge_path.resolve()) + ":/opt/webtunnel-bridges.txt:ro",
        "-v", str(Path(config["geckodriver"]).resolve()) + ":/usr/local/bin/geckodriver:ro",
        "-v", str(Path(config["python_site_packages"]).resolve()) + ":/opt/py312site:ro",
        "-v", str(helper.resolve()) + ":/opt/tor_browser_site_smoke.py:ro",
        "-v", output_mount,
        "--entrypoint", "python3.11", config["helper_image"],
        "/opt/tor_browser_site_smoke.py",
        "--browser-dir", "/opt/tor-browser",
        "--expert-bundle", "/opt/expert-bundle",
        "--bridge-file", "/opt/webtunnel-bridges.txt",
        "--geckodriver", "/usr/local/bin/geckodriver",
        "--output-root", "/out/browser_runs",
        "--capture-control-dir", "/out/capture_control",
        "--label", "preflight", "--url", candidate["url"],
        "--visits", "1", "--bootstrap-timeout", "300",
        "--page-load-timeout", "240", "--page-content-timeout", "60",
        "--resource-idle-seconds", "4", "--capture-settle-seconds", "0",
        "--fixed-window-seconds", "85", "--warmup-site-visit",
        "--warmup-settle-seconds", "25", "--reuse-check-circuit-for-first-site",
        "--reuse-target-page-between-visits", "--enable-browser-cache-between-visits",
        "--capture-ack-timeout", "30",
    ]
    started_utc = utc_now()
    started = time.monotonic()
    try:
        with (attempt_root / "docker.stdout.log").open("w", encoding="utf-8") as stdout, \
                (attempt_root / "docker.stderr.log").open("w", encoding="utf-8") as stderr:
            process = subprocess.Popen(command_args, stdout=stdout, stderr=stderr)
            try:
                returncode = process.wait(timeout=max(1, int(timeout)))
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                command(["docker", "rm", "-f", container_name], timeout=30)
                try:
                    returncode = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        returncode = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        returncode = process.wait(timeout=5)
    except KeyboardInterrupt:
        command(["docker", "rm", "-f", container_name], timeout=30)
        try:
            returncode = process.wait(timeout=15)
        except Exception:
            returncode = 130
        timed_out = False
    except OSError as exc:
        returncode = 127
        timed_out = False
        (attempt_root / "docker.stderr.log").write_text(str(exc), encoding="utf-8")
    finally:
        control.stop()
        try:
            selected_bridge_path.unlink()
        except OSError:
            pass
    elapsed = time.monotonic() - started
    summaries = sorted(attempt_root.glob("browser_runs/*/summary.json"))
    clean = cleanup_named_container(container_name)
    summary_error = None
    try:
        summary = read_json(summaries[-1]) if summaries else {}
    except (OSError, ValueError) as exc:
        summary = {}
        summary_error = "{}: {}".format(type(exc).__name__, exc)
    gates = site_preflight_result(
        returncode, timed_out, clean, summary, candidate["url"])
    passed = gates["passed"]
    failure = gates["failure_class"]
    record = {
        "schema_version": 1, "candidate": candidate,
        "attempt": site_attempt_number, "started_utc": started_utc,
        "ended_utc": utc_now(), "elapsed_seconds": elapsed,
        "returncode": returncode, "timed_out": timed_out,
        "container_cleanup_verified": clean,
        "tor_check_passed": gates["tor_check_passed"],
        "warmup_http_status": gates["warmup_http_status"],
        "warmup_page_loaded": gates["warmup_page_loaded"],
        "site_state_cleared": gates["site_state_cleared"],
        "refresh_http_status": gates["refresh_http_status"],
        "refresh_page_loaded": gates["refresh_page_loaded"],
        "refresh_action": gates["refresh_action"],
        "warmup_page_identity_matches": gates["warmup_page_identity_matches"],
        "refresh_page_identity_matches": gates["refresh_page_identity_matches"],
        "target_stream_succeeded": gates["target_stream_succeeded"],
        "access_challenge_indicators": gates["access_challenge_indicators"],
        "browser_cleanup_verified": gates["browser_cleanup_verified"],
        "summary_error": summary_error,
        "preflight_passed": passed, "failure_class": failure,
        "summary_path": str(summaries[-1]) if summaries else None,
        "output_dir": str(attempt_root),
    }
    write_json(attempt_root / "preflight_result.json", record)
    return record


def cmd_doctor(args):
    root = Path(args.output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    config = read_json(args.config)
    started = begin_online_action(root, "doctor")
    try:
        result = doctor(config, check_network=True)
        result["active_collections"] = active_collection_processes()
        write_json(root / "diagnostics" / "runtime_preflight.json", result)
    finally:
        end_online_action(root, "doctor", started)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


def write_preflight_report(root, result, ledger):
    lines = [
        "# E Browser/Tor V2 Site Preflight", "",
        "- Passed: `{}`".format(result.get("passed")),
        "- Qualified sites: {}/5".format(result.get("successful_site_count", 0)),
        "- Candidate attempts: {}".format(result.get("preflight_attempt_count", 0)),
        "- Elapsed preflight time: {:.1f} min / {:.1f} min".format(
            float(result.get("site_preflight_elapsed_seconds", 0)) / 60.0,
            float(result.get("preflight_budget_seconds", PREFLIGHT_BUDGET_SECONDS)) / 60.0),
        "- This stage created no StarryNet topology and captured no packets.", "",
        "| Order | Site | Result | HTTP warm-up / refresh | Failure | Cleanup |",
        "|---:|---|---|---|---|---|",
    ]
    seen = {}
    for attempt in read_jsonl(ledger):
        candidate = attempt.get("candidate", {})
        domain = candidate.get("source_domain", "unknown")
        order = candidate.get("preflight_order", "")
        warmup = attempt.get("warmup_http_status", "—")
        refresh = attempt.get("refresh_http_status", "—")
        cleanup = attempt.get("container_cleanup_verified", "—")
        result_label = "PASS" if attempt.get("preflight_passed") else "FAIL"
        failure = attempt.get("failure_class") or "—"
        seen[domain] = seen.get(domain, 0) + 1
        lines.append("| {} | {} | {} (try {}) | {} / {} | {} | {} |".format(
            order, domain, result_label, seen[domain], warmup, refresh, failure, cleanup))
        for indicator in attempt.get("access_challenge_indicators", []):
            lines.append("  - Challenge indicator: `{}`".format(indicator))
    if not result.get("passed"):
        lines.extend(["", "Stopped with fewer than five qualified sites. No collection sample was started."])
    lines.extend(["", "Preflight JSON and full append-only attempts are stored beside this report.", ""])
    path = Path(root) / "preflight" / "PREFLIGHT_REPORT.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def cmd_preflight(args):
    root = Path(args.output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if ((root / "protocol" / "freeze_hashes.json").exists()
            or (root / "batch_manifest.json").exists()):
        raise SystemExit("V2 freeze output exists; site selection cannot change")
    config = read_json(args.config)
    source_csv = Path(args.source_csv).resolve()
    candidates, source_hash = candidate_rows(source_csv)
    ledger = root / "preflight" / "preflight_attempts.jsonl"
    rows = read_jsonl(ledger)
    completed_domains = {row.get("candidate", {}).get("source_domain")
                         for row in rows if candidate_is_retired(row)}
    state_path = root / "preflight" / "preflight_state.json"
    state = read_json(state_path) if state_path.exists() else {
        "started_utc": utc_now(), "completed_candidate_count": 0}
    prior_preflight_seconds = float(state.get("elapsed_seconds", 0.0))
    try:
        preflight_lock = acquire_collection_lock(root)
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    atexit.register(release_collection_lock, preflight_lock)
    preflight_started = begin_online_action(root, "site_preflight")
    preflight_monotonic = time.monotonic()
    report_path = root / "diagnostics" / "runtime_preflight.json"
    initial_doctor = doctor(config, check_network=True)
    write_json(report_path, initial_doctor)
    if not initial_doctor["passed"]:
        end_online_action(root, "site_preflight", preflight_started,
                          stopped_reason="runtime_preflight_failed")
        result = {"passed": False, "stage": "runtime_preflight",
                  "successful_site_count": 0, "preflight_attempt_count": len(rows),
                  "errors": initial_doctor["errors"], "completed_utc": utc_now()}
        write_json(root / "preflight" / "preflight_result.json", result)
        write_preflight_report(root, result, ledger)
        release_collection_lock(preflight_lock)
        print(json.dumps(result, indent=2))
        return 2
    while len([row for row in rows if row.get("preflight_passed") is True]) < 5:
        used = budget_used(root)
        preflight_used = prior_preflight_seconds + (
            time.monotonic() - preflight_monotonic)
        if used >= TOTAL_BUDGET_SECONDS or preflight_used >= PREFLIGHT_BUDGET_SECONDS:
            break
        remaining = min(TOTAL_BUDGET_SECONDS - used,
                        PREFLIGHT_BUDGET_SECONDS - preflight_used)
        next_candidate = next((item for item in candidates
                               if item["source_domain"] not in completed_domains), None)
        if next_candidate is None:
            break
        quick = doctor(config, check_network=True)
        if not quick["passed"]:
            append_jsonl(ledger, {"candidate": next_candidate,
                                  "preflight_passed": False,
                                  "failure_class": "runtime_dependency_failed",
                                  "errors": quick["errors"], "started_utc": utc_now(),
                                  "elapsed_seconds": 0})
            break
        used = budget_used(root)
        preflight_used = prior_preflight_seconds + (
            time.monotonic() - preflight_monotonic)
        remaining = min(TOTAL_BUDGET_SECONDS - used,
                        PREFLIGHT_BUDGET_SECONDS - preflight_used)
        cleanup_reserve = 2 * 60
        if remaining <= cleanup_reserve:
            break
        try:
            record = run_site_preflight(
                config, next_candidate, root, len(rows) + 1,
                timeout=min(int(remaining - cleanup_reserve), 15 * 60))
        except Exception as exc:
            record = {"candidate": next_candidate, "preflight_passed": False,
                      "failure_class": "preflight_controller_error",
                      "failure_cause": "{}: {}".format(type(exc).__name__, exc),
                      "started_utc": utc_now(), "ended_utc": utc_now(),
                      "elapsed_seconds": 0.0}
        record["source_list_sha256"] = source_hash
        append_jsonl(ledger, record)
        rows.append(record)
        if candidate_is_retired(record):
            completed_domains.add(next_candidate["source_domain"])
        state["completed_candidate_count"] = len(rows)
        state["selected_pages"] = [row["candidate"] for row in rows
                                   if row.get("preflight_passed") is True][:5]
        state["elapsed_seconds"] = prior_preflight_seconds + (
            time.monotonic() - preflight_monotonic)
        write_json(state_path, state)
        if record["failure_class"] in ("cleanup_unverified", "tor_check_failed",
                                        "browser_or_tor_failure",
                                        "preflight_controller_error"):
            # Infrastructure failures require a fresh doctor/recovery before
            # another browser or network operation.
            break
        if budget_used(root) >= TOTAL_BUDGET_SECONDS:
            break
    state["elapsed_seconds"] = prior_preflight_seconds + (
        time.monotonic() - preflight_monotonic)
    write_json(state_path, state)
    elapsed = end_online_action(root, "site_preflight", preflight_started)
    successful = choose_first_five_passed(candidates, read_jsonl(ledger))
    result = {"passed": len(successful) == 5,
              "selected_pages": successful,
              "successful_site_count": len(successful),
              "preflight_attempt_count": len(read_jsonl(ledger)),
              "source_list_sha256": source_hash,
              "site_preflight_elapsed_seconds": state["elapsed_seconds"],
              "preflight_budget_seconds": PREFLIGHT_BUDGET_SECONDS,
              "online_budget_used_seconds": elapsed,
              "errors": [] if len(successful) == 5 else [
                  "fewer than five candidate websites passed the site-access preflight"],
              "completed_utc": utc_now()}
    write_json(root / "preflight" / "preflight_result.json", result)
    write_preflight_report(root, result, ledger)
    release_collection_lock(preflight_lock)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


def make_pages(selected, source_hash):
    pages = []
    for index, item in enumerate(selected):
        domain = item["source_domain"]
        rank = int(item["source_rank"])
        slug = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")
        pages.append({"page_id": "eweb-r{:03d}-{}".format(rank, slug),
                      "label": str(index), "class_label": str(index),
                      "source_rank": rank, "source_domain": domain,
                      "url": item["url"], "expected_marker": None,
                      "source_list_sha256": source_hash})
    return pages


def make_manifest(root, config, pages):
    samples = []
    for repetition in range(1, 4):
        for page in pages:
            samples.append({
                "sample_id": "{}-{}-r{:03d}".format(
                    DATA_DOMAIN, page["page_id"], repetition),
                "domain": DATA_DOMAIN, "page_id": page["page_id"],
                "url": page["url"], "label": page["label"],
                "class_label": page["class_label"],
                "source_rank": page["source_rank"],
                "source_domain": page["source_domain"],
                "repetition": repetition, "target": "independent_sample"})
    metadata = {
        "protocol_id": PROTOCOL_ID, "revision": "V2",
        "data_domain": DATA_DOMAIN,
        "objective": "five websites by three independent dynamic StarryNet warm-refresh visits",
        "pilot_only": True, "planned_sample_count": 15,
        "site_preflight_sha256": sha256_file(root / "preflight" / "preflight_result.json"),
        "source_list_sha256": pages[0]["source_list_sha256"],
        "capture_protocol": {
            "topology": "dynamic StarryNet 5x5 satellites and two ground stations",
            "capture_phase": "dynamic second 120 +/- 1.5",
            "measured_window_seconds": 85, "offload_mode": "disable_path",
            "warmup": "uncaptured canonical HTTPS navigation; clear site state; retain page; measured same-tab refresh",
            "browser_profile": "fresh Tor Browser profile and process per independent attempt",
            "tor_path": "single configured WebTunnel entry bridge; Tor default middle and exit",
            "trace": "raw two-column timestamp/direction; no padding or truncation; include page subresources",
        },
        "collection_policy": {
            "concurrency": 1, "pages": 5, "repetitions_per_page": 3,
            "retry_limit": RETRY_LIMIT, "serial_order": "round-robin by repetition then frozen page order",
            "total_online_budget_seconds": TOTAL_BUDGET_SECONDS,
            "site_preflight_budget_seconds": PREFLIGHT_BUDGET_SECONDS,
            "single_attempt_timeout_seconds": COLLECTOR_TIMEOUT_SECONDS,
            "minimum_remaining_budget_to_start_attempt_seconds": MIN_ATTEMPT_RESERVE_SECONDS,
            "stop_after_consecutive_failures": MAX_CONSECUTIVE_FAILURES,
        },
        "acceptance": {
            "page_identity_and_https_canonical_page": True,
            "successful_tor_target_stream": True,
            "complete_three_hop_entry_bridge_path": True,
            "bidirectional_satellite_path_and_capture": True,
            "four_endpoint_offload_gate": True,
            "trace_packet_correspondence_and_hashes": True,
            "verified_cleanup_each_attempt": True,
            "profile_metrics_are_diagnostic_only": True,
            "training_split_created": False,
            "scientific_fidelity_verified": False,
        },
        "runtime_assets": {
            "helper_image": config["helper_image"],
            "helper_image_id": config["helper_image_id"],
            "browser_dir": config["browser_dir"],
            "expert_bundle": config["expert_bundle"],
            "bridge_file": config["bridge_file"],
            "geckodriver": config["geckodriver"],
            "python_executable": config["python_executable"],
        },
        "interpretation_boundary": "E_BROWSER_TOR_V2 is encrypted Tor WebTunnel carrier traffic collected over simulated dynamic StarryNet. It is not real Starlink measurement, existing S-domain data, or a training-ready split.",
    }
    manifest = {
        "schema_version": 1, "manifest_type": "starrynet_browser_batch",
        "run_id": "e-browser-v2-" + uuid.uuid4().hex[:12],
        "created_utc": utc_now(), "domain": DATA_DOMAIN,
        "protocol_metadata": metadata, "pages": pages,
        "repetitions_per_page": 3, "retry_limit": RETRY_LIMIT,
        "sample_count": 15, "samples": samples,
        "semantic_policy": {
            "class_label_namespace": DATA_DOMAIN,
            "E_is_simulation_and_not_automatically_S": True,
            "E_BROWSER_TOR_is_separate_from_controlled_UDP_replay": True,
            "fresh_profile_per_attempt": True,
            "concurrency": 1,
            "sample_order": "round-robin by repetition then page order",
            "failed_attempts_are_retained": True,
            "retry_does_not_increase_independent_sample_count": True,
            "profile_correlations_are_diagnostic_only": True,
        },
    }
    return manifest, metadata


def cmd_freeze(args):
    root = Path(args.output_root).resolve()
    if ((root / "protocol" / "freeze_hashes.json").exists()
            or (root / "batch_manifest.json").exists()):
        raise SystemExit("V2 freeze output already exists; refusing to replace it")
    preflight = read_json(root / "preflight" / "preflight_result.json")
    if preflight.get("passed") is not True or len(preflight.get("selected_pages", [])) != 5:
        raise SystemExit("cannot freeze V2 until five site preflights pass")
    config_path = root / "protocol" / "runtime_config.json"
    config = read_json(config_path)
    config.update({
        "batch_root": str(root), "protocol_id": PROTOCOL_ID,
        "data_domain": DATA_DOMAIN,
        "source_list_sha256": preflight["source_list_sha256"],
        "runner": str(ROOT / "tools" / "tor_browser_starrynet_smoke_v2.py"),
        "collector_wrapper": str(ROOT / "tools" / "run_e_browser_site_sample_v2.py"),
        "collector_timeout_seconds": COLLECTOR_TIMEOUT_SECONDS,
        "cleanup_grace_seconds": 110,
        "concurrency": 1,
    })
    write_json(config_path, config)
    pages = make_pages(preflight["selected_pages"], preflight["source_list_sha256"])
    write_json(root / "protocol" / "pages.json", {"pages": pages})
    manifest, metadata = make_manifest(root, config, pages)
    write_json(root / "protocol" / "protocol_metadata.json", metadata)
    write_json(root / "batch_manifest.json", manifest)
    with (root / "protocol" / "selected_sites.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("class_label", "page_id", "source_rank",
                                  "source_domain", "url", "preflight_result"))
        writer.writeheader()
        for page, item in zip(pages, preflight["selected_pages"]):
            writer.writerow({"class_label": page["class_label"],
                             "page_id": page["page_id"],
                             "source_rank": page["source_rank"],
                             "source_domain": page["source_domain"],
                             "url": page["url"], "preflight_result": "passed"})
    hashes = {}
    files = {
        "manifest": root / "batch_manifest.json",
        "runtime_config": config_path,
        "protocol_metadata": root / "protocol" / "protocol_metadata.json",
        "pages": root / "protocol" / "pages.json",
        "source_list": root / "protocol" / "site_source_list.csv",
        "selected_sites": root / "protocol" / "selected_sites.csv",
        "protocol_document": root / "protocol" / "protocol.md",
        "source_candidates": root / "protocol" / "source_candidates.csv",
        "pre_modification_source_snapshot": root / "protocol" / "source_snapshot",
        "site_preflight_result": root / "preflight" / "preflight_result.json",
        "site_preflight_ledger": root / "preflight" / "preflight_attempts.jsonl",
    }
    for name, path in files.items():
        if path.is_file() or path.is_dir():
            hashes[name] = {
                "kind": "directory" if path.is_dir() else "file",
                "path": str(path), "sha256": sha256_path(path)}
    for name, path in {
            "browser_directory": Path(config["browser_dir"]),
            "expert_bundle": Path(config["expert_bundle"]),
            "browser_helper_packages": Path(config["python_site_packages"]),
            "starrynet_source": ROOT / "starrynet"}.items():
        hashes[name] = {"kind": "directory", "path": str(path),
                        "sha256": sha256_tree(path)}
    source_files = {
        "v2_coordinator": Path(__file__).resolve(),
        "v2_runner": Path(config["runner"]),
        "v2_collector": Path(config["collector_wrapper"]),
        "v2_single_run_auditor": ROOT / "tools" / "audit_site_trace_repeatability_v2.py",
        "v2_pilot_auditor": ROOT / "tools" / "audit_e_browser_tor_pilot_v2.py",
        "v2_browser_helper": ROOT / "tools" / "tor_browser_site_smoke_v2.py",
        "v2_process_helper": ROOT / "tools" / "e_browser_v2_process.py",
        "batch_manifest_dependency": ROOT / "tools" / "batch_manifest.py",
        "trace_extractor": ROOT / "tools" / "extract_starrynet_site_trace.py",
        "replay_helper": ROOT / "tools" / "replay_trace_over_starrynet.py",
        "browser_helper": ROOT / "tools" / "tor_browser_site_smoke.py",
        "starrynet_config": ROOT / "config.json",
        "webtunnel_bridge_file": Path(config["bridge_file"]),
        "python_binary": Path(config["python_executable"]),
        "geckodriver": Path(config["geckodriver"]),
    }
    for name, path in source_files.items():
        hashes[name] = {"kind": "file", "path": str(path), "sha256": sha256_file(path)}
    freeze = {"protocol_id": PROTOCOL_ID, "data_domain": DATA_DOMAIN,
              "planned_sample_count": len(manifest["samples"]),
              "helper_image_id": config["helper_image_id"],
              "directory_hash_algorithm": (
                  "sorted relative paths, entry types, permission bits, and file-content SHA-256"),
              "hashes": hashes}
    write_json(root / "protocol" / "freeze_hashes.json", freeze)
    print(json.dumps({"frozen": True, "manifest": str(root / "batch_manifest.json"),
                      "sample_count": len(manifest["samples"]),
                      "page_ids": [page["page_id"] for page in pages],
                      "freeze_hash_count": len(hashes)}, indent=2, sort_keys=True))
    return 0


def verify_freeze(root):
    freeze_path = Path(root) / "protocol" / "freeze_hashes.json"
    if not freeze_path.is_file():
        return ["protocol/freeze_hashes.json is missing"]
    freeze = read_json(freeze_path)
    errors = []
    for name, item in freeze.get("hashes", {}).items():
        actual = sha256_path(item.get("path", ""))
        if actual != item.get("sha256"):
            errors.append("frozen artifact changed or missing: " + name)
    manifest = read_json(Path(root) / "batch_manifest.json")
    if (freeze.get("protocol_id") != manifest.get("protocol_metadata", {}).get("protocol_id")
            or freeze.get("planned_sample_count") != len(manifest.get("samples", []))):
        errors.append("freeze identity/sample count differs from manifest")
    if freeze.get("helper_image_id") != manifest.get("protocol_metadata", {}).get(
            "runtime_assets", {}).get("helper_image_id"):
        errors.append("helper image identity differs between freeze and manifest")
    return errors


def collector_argv(config, sample, attempt_id, output_dir):
    return [config["python_executable"], config["collector_wrapper"],
            "--config", str(Path(config["batch_root"]) / "protocol" / "runtime_config.json"),
            "--url", sample["url"], "--page-id", sample["page_id"],
            "--class-label", str(sample["class_label"]),
            "--sample-id", sample["sample_id"],
            "--source-rank", str(sample["source_rank"]),
            "--source-domain", sample["source_domain"],
            "--output-root", str(output_dir)]


def cmd_run(args):
    root = Path(args.output_root).resolve()
    config = read_json(root / "protocol" / "runtime_config.json")
    manifest = read_json(root / "batch_manifest.json")
    if manifest.get("protocol_metadata", {}).get("protocol_id") != PROTOCOL_ID:
        raise SystemExit("manifest is not a frozen V2 pilot")
    state_path = root / "execution_state.json"
    ledger = root / "attempts.jsonl"
    rows = read_jsonl(ledger)
    active_path = root / "active_attempt.json"
    if rows and not args.resume:
        raise SystemExit("attempt ledger exists; use --resume to continue this frozen pilot")
    stopped_reason = None
    state = read_json(state_path) if state_path.exists() else {
        "schema_version": 1, "consecutive_failures": 0}
    consecutive = int(state.get("consecutive_failures", 0))
    planned = manifest["samples"]
    successful_ids = {row.get("sample_id") for row in rows
                      if row.get("ok") is True and row.get("artifacts_valid") is True}
    try:
        collection_lock = acquire_collection_lock(root)
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    atexit.register(release_collection_lock, collection_lock)
    try:
        start_online = begin_online_action(root, "collection")
    except Exception:
        release_collection_lock(collection_lock)
        raise
    try:
        errors = verify_freeze(root)
        if errors:
            stopped_reason = "frozen_hash_changed"
            raise SystemExit("freeze check failed: " + "; ".join(errors))
        doctor_result = doctor(config, check_network=True)
        if not doctor_result["passed"]:
            write_json(root / "diagnostics" / "resume_preflight.json", doctor_result)
            stopped_reason = "runtime_preflight_failed"
            raise SystemExit("runtime preflight failed; collector not started")
        if active_collection_processes():
            stopped_reason = "existing_collector_active"
            raise SystemExit("an existing collector is active; refusing a duplicate start")
        if active_path.exists():
            active = read_json(active_path)
            active_root = Path(active["output_dir"])
            summaries = sorted(active_root.rglob("summary.json")) if active_root.exists() else []
            summary = read_json(summaries[-1]) if summaries else {}
            recovered = {
                "schema_version": 1, "run_id": manifest["run_id"],
                "sample_id": active["sample"]["sample_id"],
                "attempt_id": active["attempt_id"], "page_id": active["sample"]["page_id"],
                "class_label": active["sample"]["class_label"],
                "label": active["sample"]["label"],
                "source_rank": active["sample"]["source_rank"],
                "source_domain": active["sample"]["source_domain"],
                "url": active["sample"]["url"], "started_utc": active["started_utc"],
                "ended_utc": utc_now(), "elapsed_seconds": None,
                "returncode": 130, "ok": False, "failure_class": "interrupted",
                "failure_stage": summary.get("phase"),
                "cleanup_verified": summary.get("cleanup_verified"),
                "retry_consumed": True, "artifacts": [],
                "error": "previous V2 coordinator exited while this attempt was active",
            }
            append_jsonl(ledger, recovered)
            rows.append(recovered)
            active_path.unlink()
            if recovered.get("cleanup_verified") is not True:
                stopped_reason = "interrupted_cleanup_unverified"
                raise SystemExit("interrupted attempt cleanup is unverified; stop for scoped recovery")
            consecutive += 1
        for sample in planned:
            if sample["sample_id"] in successful_ids:
                continue
            attempts_for_sample = [row for row in rows
                                   if row.get("sample_id") == sample["sample_id"]]
            while len(attempts_for_sample) < 1 + RETRY_LIMIT:
                if TOTAL_BUDGET_SECONDS - budget_used(root) < MIN_ATTEMPT_RESERVE_SECONDS:
                    stopped_reason = "less_than_22_minutes_remain"
                    break
                online_check = doctor(config, check_network=True)
                if not online_check["passed"]:
                    stopped_reason = "runtime_dependency_failed"
                    write_json(root / "diagnostics" / "collection_halt.json", online_check)
                    break
                hash_errors = verify_freeze(root)
                if hash_errors:
                    stopped_reason = "frozen_hash_changed"
                    write_json(root / "diagnostics" / "hash_halt.json", {"errors": hash_errors})
                    break
                attempt_id = "{}-a{:02d}".format(
                    sample["sample_id"], len(attempts_for_sample) + 1)
                attempt_number = len(attempts_for_sample) + 1
                output_dir = root / "samples" / attempt_id
                active = {"attempt_id": attempt_id, "sample": sample,
                          "attempt_number": attempt_number,
                          "started_utc": utc_now(), "output_dir": str(output_dir)}
                write_json(active_path, active)
                attempt_start = time.monotonic()
                argv = collector_argv(config, sample, attempt_id, output_dir)
                stdout = ""
                stderr = ""
                returncode = 127
                interrupted = False
                outer_timed_out = False
                process_group_forced_termination = False
                process_group_stopped = True
                try:
                    process = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE,
                                               universal_newlines=True,
                                               start_new_session=True)
                except OSError as exc:
                    record = {"ok": False, "failure_class": "collector_exception",
                              "cleanup_verified": True, "artifacts": [],
                              "error": "collector could not start: " + str(exc)}
                    elapsed = time.monotonic() - attempt_start
                else:
                    try:
                        stdout, stderr = process.communicate(
                            timeout=COLLECTOR_TIMEOUT_SECONDS)
                        returncode = process.returncode
                    except subprocess.TimeoutExpired:
                        outer_timed_out = True
                        (returncode, stdout, stderr,
                         process_group_forced_termination,
                         process_group_stopped) = (
                            stop_process_group(process, 110))
                        returncode = process.returncode or 124
                    except KeyboardInterrupt:
                        interrupted = True
                        (returncode, stdout, stderr,
                         process_group_forced_termination,
                         process_group_stopped) = (
                            stop_process_group(process, 110))
                        returncode = process.returncode or 130
                    elapsed = time.monotonic() - attempt_start
                    if process.poll() is not None and process_group_exists(process.pid):
                        (returncode, stdout, stderr,
                         process_group_forced_termination,
                         process_group_stopped) = stop_process_group(process, 0)
                    try:
                        record = json.loads([line for line in stdout.splitlines()
                                             if line.strip()][-1])
                    except (ValueError, IndexError):
                        record = {"ok": False, "failure_class": "collector_exception",
                                  "error": (stderr or stdout)[-2000:], "artifacts": [],
                                  "retry_consumed": attempt_number > 1}
                record.update({
                    "schema_version": 1, "run_id": manifest["run_id"],
                    "sample_id": sample["sample_id"], "attempt_id": attempt_id,
                    "page_id": sample["page_id"], "class_label": sample["class_label"],
                    "label": sample["label"], "source_rank": sample["source_rank"],
                    "source_domain": sample["source_domain"], "url": sample["url"],
                    "repetition": sample["repetition"],
                    "attempt_number": attempt_number,
                    "retry_consumed": attempt_number > 1,
                    "attempt_counts_toward_sample_limit": True,
                    "timed_out": bool(record.get("timed_out") or outer_timed_out),
                    "process_group_forced_termination": process_group_forced_termination,
                    "process_group_cleanup_verified": process_group_stopped,
                    "protocol_id": PROTOCOL_ID, "data_domain": DATA_DOMAIN,
                    "started_utc": active["started_utc"], "ended_utc": utc_now(),
                    "elapsed_seconds": elapsed, "returncode": returncode,
                    "stdout_tail": stdout[-4000:], "stderr_tail": stderr[-4000:],
                })
                record["ok"] = bool(record.get("ok") and returncode == 0)
                from batch_manifest import artifact_ok
                valid, reason = artifact_ok(record, root)
                record["artifacts_valid"] = valid
                if not valid:
                    record["ok"] = False
                    record["artifact_error"] = reason
                if (record.get("cleanup_verified") is not True
                        or not process_group_stopped):
                    record["cleanup_verified"] = False
                    record["failure_class"] = "cleanup_unverified"
                elif not record.get("ok") and not record.get("failure_class"):
                    record["failure_class"] = (
                        "timeout" if record.get("timed_out") or returncode == 124
                        else "sample_quality")
                append_jsonl(ledger, record)
                rows.append(record)
                attempts_for_sample.append(record)
                if active_path.exists():
                    active_path.unlink()
                if record.get("ok") is True:
                    consecutive = 0
                    successful_ids.add(sample["sample_id"])
                else:
                    consecutive += 1
                    decision = failure_policy(
                        record.get("failure_class"), consecutive,
                        len(attempts_for_sample))
                    if decision == "pause" and record.get("failure_class") in COLLECTION_FATAL_FAILURES:
                        stopped_reason = record.get("failure_class")
                    elif decision == "pause":
                        stopped_reason = "three_consecutive_attempt_failures"
                state["consecutive_failures"] = consecutive
                state["stopped_reason"] = stopped_reason
                write_json(state_path, state)
                if interrupted:
                    stopped_reason = "operator_interrupt"
                if stopped_reason or record.get("ok") is True:
                    break
                if budget_used(root) >= TOTAL_BUDGET_SECONDS:
                    stopped_reason = "four_hour_online_budget_exhausted"
                    break
            if stopped_reason:
                break
    finally:
        current_state = read_json(budget_path(root))
        if current_state.get("active_started_utc"):
            end_online_action(root, "collection", start_online,
                              stopped_reason=stopped_reason)
    state["consecutive_failures"] = consecutive
    state["stopped_reason"] = stopped_reason
    state["updated_utc"] = utc_now()
    write_json(state_path, state)
    result = {"protocol_id": PROTOCOL_ID, "planned_samples": len(planned),
              "successful_samples": len(successful_ids),
              "attempt_count": len(rows), "consecutive_failures": consecutive,
              "stopped_reason": stopped_reason,
              "online_budget_used_seconds": budget_used(root),
              "remaining_online_budget_seconds": max(
                  0, TOTAL_BUDGET_SECONDS - budget_used(root))}
    write_json(root / "execution_summary.json", result)
    release_collection_lock(collection_lock)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if len(successful_ids) == len(planned) else 1


def cmd_audit(args):
    root = Path(args.output_root).resolve()
    errors = verify_freeze(root)
    if errors:
        raise SystemExit("freeze check failed: " + "; ".join(errors))
    auditor = Path(__file__).resolve().with_name("audit_e_browser_tor_pilot_v2.py")
    command_args = [sys.executable, str(auditor),
                    "--manifest", str(root / "batch_manifest.json"),
                    "--attempts", str(root / "attempts.jsonl"),
                    "--output-dir", str(root / "final_audit"),
                    "--auditor", str(Path(__file__).resolve().with_name(
                        "audit_site_trace_repeatability_v2.py"))]
    result = subprocess.run(command_args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    print(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_ROOT))
    sub = parser.add_subparsers(dest="command")
    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--config", default=str(
        DEFAULT_ROOT / "protocol" / "runtime_config.json"))
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--config", default=str(
        DEFAULT_ROOT / "protocol" / "runtime_config.json"))
    preflight.add_argument("--source-csv", default=str(
        DEFAULT_ROOT / "protocol" / "site_source_list.csv"))
    sub.add_parser("freeze")
    run = sub.add_parser("run")
    run.add_argument("--resume", action="store_true")
    sub.add_parser("audit")
    args = parser.parse_args(argv)
    if not args.command:
        parser.error("a subcommand is required")
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "preflight":
        return cmd_preflight(args)
    if args.command == "freeze":
        return cmd_freeze(args)
    if args.command == "run":
        return cmd_run(args)
    return cmd_audit(args)


if __name__ == "__main__":
    sys.exit(main())
