#!/usr/bin/env python3
"""Run and single-run-audit one frozen E browser/Tor pilot sample."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from urllib.parse import urlsplit

from audit_site_trace_repeatability_v2 import audit_one
from e_browser_v2_process import (process_group_exists,
                                  stop_process_group)


DEFAULT_PROTOCOL_ID = "starrynet-e-browser-tor-v1-v27-warm-refresh"
E_BROWSER_V1_2_PROTOCOL_ID = "starrynet-e-browser-tor-v1-2-warm-refresh-canonical-domain"
E_BROWSER_V1_3_PROTOCOL_ID = "starrynet-e-browser-tor-v1-3-warm-refresh-auditor-corrected"
E_BROWSER_V1_4_PROTOCOL_ID = "starrynet-e-browser-tor-v1-4-warm-refresh-failure-finalization"
E_BROWSER_V2_PROTOCOL_ID = "starrynet-e-browser-tor-v2-warm-refresh-bounded-pilot"
DEFAULT_DATA_DOMAIN = "E_BROWSER_TOR"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")


def artifact_rows(paths, batch_root):
    rows = []
    seen = set()
    for path in paths:
        path = Path(path)
        if not path.is_file():
            continue
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(batch_root.resolve())
        except ValueError:
            continue
        key = str(relative)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"path": key, "sha256": sha256_file(resolved)})
    return rows


def classify_failure(timed_out, summary, browser_summary, cause_text, ok):
    lower_cause = cause_text.lower()
    if summary.get("cleanup_verified") is not True:
        return "cleanup_unverified"
    if ok:
        return None
    if "docker" in lower_cause or "container" in lower_cause:
        return "docker"
    proxy_failure_cause = any(marker in lower_cause for marker in (
        "proxyerror", "unable to connect to proxy", "proxy connection refused"))
    proxy_failure_cause = proxy_failure_cause or (
        ("proxy" in lower_cause or "127.0.0.1:17897" in lower_cause)
        and any(marker in lower_cause for marker in (
            "refused", "unavailable", "failed", "timed out")))
    if proxy_failure_cause:
        return "proxy"
    if timed_out:
        return "timeout"
    challenge = list((browser_summary.get("site_warmup") or {}).get(
        "access_challenge_indicators", []))
    challenge.extend(indicator for visit in browser_summary.get("visits", [])
                     for indicator in visit.get("access_challenge_indicators", []))
    if (any(visit.get("http_status") == 403
            for visit in browser_summary.get("visits", []))
            or (browser_summary.get("site_warmup") or {}).get("http_status") == 403
            or challenge or "http 403" in lower_cause):
        return "page_access"
    return None if ok else "sample_quality"


def run(args):
    config_path = Path(args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    batch_root = Path(config["batch_root"]).resolve()
    protocol_id = config.get("protocol_id", DEFAULT_PROTOCOL_ID)
    data_domain = config.get("data_domain", DEFAULT_DATA_DOMAIN)
    output_root = Path(args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    parsed = urlsplit(args.url)
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password):
        raise ValueError("sample URL must be an absolute HTTPS URL")
    if args.class_label not in {str(value) for value in range(5)}:
        raise ValueError("class label is outside the frozen five-class E browser pilot")
    if not args.page_id or not args.sample_id or not args.source_domain:
        raise ValueError("page, sample, and source-domain identities are required")

    runner = Path(config["runner"]).resolve()
    controller = Path(__file__).resolve()
    command = [
        config["python_executable"], str(runner), "run",
        "--browser-dir", config["browser_dir"],
        "--expert-bundle", config["expert_bundle"],
        "--bridge-file", config["bridge_file"],
        "--geckodriver", config["geckodriver"],
        "--python-site-packages", config["python_site_packages"],
        "--helper-image", config["helper_image"],
        "--output-root", str(output_root),
        "--url", args.url,
        "--protocol-id", protocol_id,
        "--data-domain", data_domain,
        "--page-id", args.page_id,
        "--sample-id", args.sample_id,
        "--class-label", args.class_label,
        "--source-rank", str(args.source_rank),
        "--source-domain", args.source_domain,
        "--source-list-sha256", config["source_list_sha256"],
        "--pilot-controller", str(controller),
        "--bootstrap-timeout", "300",
        "--visits", "1",
        "--fixed-window-seconds", "85",
        "--page-load-timeout", "240",
        "--page-content-timeout", "60",
        "--resource-idle-seconds", "4",
        "--capture-settle-seconds", "2",
        "--browser-timeout", "1200",
        "--offload-mode", "disable_path",
        "--route-ready-stable-seconds", "5",
        "--route-ready-timeout-seconds", "90",
        "--warmup-site-visit",
        "--warmup-settle-seconds", "25",
        "--reuse-check-circuit",
        "--reuse-target-page-between-visits",
        "--defer-emulation-until-after-warmup",
        "--reaudit-active-route-before-phase-window",
        "--enable-browser-cache-between-visits",
        "--matched-dynamic-phase-seconds", "120",
        "--matched-dynamic-phase-tolerance-seconds", "1.5",
    ]
    if protocol_id in (E_BROWSER_V1_2_PROTOCOL_ID, E_BROWSER_V1_3_PROTOCOL_ID,
                       E_BROWSER_V1_4_PROTOCOL_ID, E_BROWSER_V2_PROTOCOL_ID):
        expected_image_id = config.get("helper_image_id", "")
        if not expected_image_id:
            raise ValueError("E browser runtime config lacks the frozen helper image ID")
        command.extend(["--expected-helper-image-id", expected_image_id])
    command.extend(config.get("runner_flags", [
        "--pin-tor-path-diagnostic",
        "--pin-tor-entry-bridge-diagnostic",
    ]))
    stdout_path = output_root / "collector.stdout.log"
    stderr_path = output_root / "collector.stderr.log"
    started = time.monotonic()
    timed_out = False
    process_group_forced_termination = False
    process_group_stopped = True
    returncode = 127
    process = None
    def forward_interrupt(_signum, _frame):
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGINT)
            except OSError:
                pass
    previous_sigint = signal.signal(signal.SIGINT, forward_interrupt)
    try:
        with stdout_path.open("w", encoding="utf-8") as stdout, \
                stderr_path.open("w", encoding="utf-8") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            try:
                returncode = process.wait(
                    timeout=int(config.get("collector_timeout_seconds", 1200)))
            except subprocess.TimeoutExpired:
                timed_out = True
                (returncode, _stdout, _stderr, process_group_forced_termination,
                 process_group_stopped) = (
                    stop_process_group(
                        process,
                        int(config.get("cleanup_grace_seconds", 110))))
            stdout.flush()
            stderr.flush()
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = 124
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
    if process is not None and process.poll() is not None \
            and process_group_exists(process.pid):
        (returncode, _stdout, _stderr, process_group_forced_termination,
         process_group_stopped) = stop_process_group(process, 0)
    elapsed = time.monotonic() - started

    summaries = sorted(output_root.rglob("summary.json"),
                       key=lambda path: (len(path.parts), str(path)))
    run_dirs = [path.parent for path in summaries
                if (path.parent / "acquisition_protocol.json").is_file()]
    run_dir = run_dirs[-1] if run_dirs else None
    if run_dir:
        try:
            audit = audit_one(run_dir)
        except Exception as exc:
            audit = {
                "run_dir": str(run_dir),
                "passed": False,
                "failures": ["single-run auditor raised {}: {}".format(
                    type(exc).__name__, exc)],
            }
    else:
        audit = {
            "run_dir": None, "passed": False,
            "failures": ["runner did not produce a run summary and protocol"]}
    if run_dir:
        write_json(run_dir / "single_run_audit.json", audit)
        summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
        identity_matches = (
            summary.get("sample_id") == args.sample_id
            and summary.get("page_id") == args.page_id
            and str(summary.get("class_label")) == args.class_label
            and summary.get("site_url") == args.url
            and summary.get("source_domain") == args.source_domain
            and summary.get("source_rank") == args.source_rank
        )
    else:
        summary = {}
        identity_matches = False
    if not process_group_stopped:
        summary["cleanup_verified"] = False

    candidate_paths = [stdout_path, stderr_path]
    if run_dir:
        candidate_paths.extend([
            run_dir / "summary.json",
            run_dir / "acquisition_protocol.json",
            run_dir / "config.json",
            run_dir / "single_run_audit.json",
        ])
        extraction = summary.get("trace_extraction", {})
        for key in ("trace_path", "packet_audit_path", "manifest_path", "source_pcap"):
            value = extraction.get(key)
            if value:
                candidate_paths.append(Path(value))
        for value in extraction.get("visits", []):
            if isinstance(value, dict):
                candidate_paths.extend(Path(item) for item in value.values()
                                       if isinstance(item, str))
        candidate_paths.extend(run_dir.rglob("AUDIT.md"))
    artifacts = artifact_rows(candidate_paths, batch_root)
    trace_path = None
    if run_dir:
        raw_trace_path = (summary.get("trace_extraction") or {}).get("trace_path")
        if raw_trace_path:
            try:
                trace_path = str(Path(raw_trace_path).resolve().relative_to(batch_root))
            except ValueError:
                trace_path = None
    ok = bool(returncode == 0 and not timed_out and audit.get("passed")
              and summary.get("passed") is True and identity_matches
              and artifacts)
    errors = "\n".join(str(value) for value in summary.get("errors", []))
    browser_summary = summary.get("browser_summary", {})
    visit_errors = "\n".join(
        str(error) for visit in browser_summary.get("visits", [])
        for error in visit.get("errors", []))
    with stderr_path.open("r", encoding="utf-8", errors="replace") as log:
        stderr_text = log.read()[-4000:]
    with stdout_path.open("r", encoding="utf-8", errors="replace") as log:
        stdout_text = log.read()[-4000:]
    cause_text = errors + "\n" + visit_errors + "\n" + stdout_text + "\n" + stderr_text
    failure_class = classify_failure(
        timed_out, summary, browser_summary, cause_text, ok)
    return {
        "ok": ok,
        "protocol_id": protocol_id,
        "data_domain": data_domain,
        "sample_id": args.sample_id,
        "page_id": args.page_id,
        "run_dir": str(run_dir) if run_dir else None,
        "trace_path": trace_path,
        "class_label": args.class_label,
        "source_rank": args.source_rank,
        "source_domain": args.source_domain,
        "url": args.url,
        "runner_returncode": returncode,
        "timed_out": timed_out,
        "process_group_forced_termination": process_group_forced_termination,
        "process_group_cleanup_verified": process_group_stopped,
        "elapsed_seconds": elapsed,
        "summary_passed": summary.get("passed"),
        "identity_matches": identity_matches,
        "single_run_audit_passed": audit.get("passed"),
        "single_run_audit_failures": audit.get("failures", []),
        "target_circuit_paths": audit.get("target_circuit_paths", []),
        "trace_row_count": (audit.get("metrics") or {}).get("event_count"),
        "trace_metrics": audit.get("metrics"),
        "cleanup_verified": summary.get("cleanup_verified"),
        "runner_timing": summary.get("timing"),
        "failure_stage": summary.get("phase"),
        "failure_class": failure_class,
        "failure_cause": cause_text[-2000:] if not ok else None,
        "retry_consumed": failure_class in ("page_access", "sample_quality"),
        "artifacts": artifacts,
        "error": ("collector exceeded frozen wall-clock timeout" if timed_out
                  else None),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--page-id", required=True)
    parser.add_argument("--class-label", required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--source-rank", required=True, type=int)
    parser.add_argument("--source-domain", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    try:
        result = run(args)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["ok"] else 1
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "sample_id": args.sample_id,
            "page_id": args.page_id,
            "error": "{}: {}".format(type(exc).__name__, exc),
            "artifacts": [],
        }, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
