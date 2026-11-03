#!/usr/bin/env python3
"""Offline safety and policy tests for the bounded E browser/Tor V2 pilot."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import audit_e_browser_tor_pilot_v2 as pilot_audit
import audit_site_trace_repeatability_v2 as repeatability_audit
import run_e_browser_pilot_v2 as coordinator
import run_e_browser_site_sample_v2 as collector
from e_browser_v2_process import (process_group_exists,
                                  stop_process_group)


def clean_preflight_summary():
    return {
        "initial_tor_check": {"tor_check_passed": True,
                               "tor_check_response": {"is_tor": True}},
        "site_warmup": {
            "http_status": 200, "page_loaded": True,
            "site_state_cleared": True,
            "warmup_final_url": "https://example.org/",
            "target_stream_succeeded": True,
        },
        "visits": [{
            "http_status": 200, "page_loaded": True,
            "final_url": "https://example.org/",
            "site_navigation_action": "refresh",
            "target_stream_succeeded": True,
        }],
        "cleanup_verified": True,
    }


class V2PilotTests(unittest.TestCase):
    def test_candidate_order_and_first_five_passed(self):
        candidates, source_hash = coordinator.candidate_rows(
            coordinator.DEFAULT_ROOT / "protocol" / "site_source_list.csv")
        self.assertEqual(len(source_hash), 64)
        self.assertEqual([row["source_domain"] for row in candidates], [
            "amazon.co.jp", "facebook.com", "mozilla.org", "stackoverflow.com",
            "adobe.com", "apache.org", "github.com", "w3.org", "wikipedia.org",
        ])
        records = [
            {"candidate": candidates[0], "preflight_passed": False,
             "failure_class": "page_access_403"},
            {"candidate": candidates[1], "preflight_passed": True},
            {"candidate": candidates[2], "preflight_passed": True},
            {"candidate": candidates[3], "preflight_passed": True},
            {"candidate": candidates[4], "preflight_passed": True},
            {"candidate": candidates[5], "preflight_passed": True},
        ]
        self.assertEqual(
            [row["source_domain"] for row in coordinator.choose_first_five_passed(
                candidates, records)],
            ["facebook.com", "mozilla.org", "stackoverflow.com", "adobe.com",
             "apache.org"])

    def test_preflight_hard_gates_page_identity_and_403(self):
        result = coordinator.site_preflight_result(
            0, False, True, clean_preflight_summary(), "https://example.org/")
        self.assertTrue(result["passed"])
        self.assertTrue(result["tor_check_passed"])
        self.assertTrue(result["warmup_page_identity_matches"])
        self.assertTrue(result["refresh_page_identity_matches"])

        summary = clean_preflight_summary()
        summary["visits"][0]["http_status"] = 403
        result = coordinator.site_preflight_result(
            1, False, True, summary, "https://example.org/")
        self.assertFalse(result["passed"])
        self.assertEqual(result["failure_class"], "page_access_403")
        self.assertTrue(coordinator.candidate_is_retired(result))

    def test_preflight_rejects_access_challenge_and_cleanup_failure(self):
        summary = clean_preflight_summary()
        summary["visits"][0]["access_challenge_indicators"] = ["captcha"]
        result = coordinator.site_preflight_result(
            1, False, True, summary, "https://example.org/")
        self.assertFalse(result["passed"])
        self.assertEqual(result["failure_class"], "page_access_challenge")
        self.assertEqual(result["access_challenge_indicators"], ["captcha"])

        result = coordinator.site_preflight_result(
            1, True, False, {}, "https://example.org/")
        self.assertEqual(result["failure_class"], "cleanup_unverified")

    def test_proxy_unavailable_in_doctor_blocks_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            asset = Path(temp) / "asset"
            asset.write_text("ready")
            config = {key: str(asset) for key in (
                "python_executable", "runner", "collector_wrapper", "browser_dir",
                "expert_bundle", "bridge_file", "geckodriver",
                "python_site_packages")}
            config.update({"helper_image": "test:image", "helper_image_id": "image-id"})

            def fake_command(argv, timeout=20):
                if argv[0] == config["python_executable"]:
                    return {"returncode": 0, "stdout": "Python 3.6.15", "stderr": ""}
                if argv[:2] == ["tmux", "has-session"]:
                    return {"returncode": 0, "stdout": "", "stderr": ""}
                if argv[:2] == ["ps", "-eo"]:
                    return {"returncode": 0, "stdout": "", "stderr": ""}
                if argv[:2] == ["docker", "info"]:
                    return {"returncode": 0, "stdout": "25.0", "stderr": ""}
                if argv[:3] == ["docker", "image", "inspect"]:
                    return {"returncode": 0, "stdout": "image-id", "stderr": ""}
                raise AssertionError("unexpected command: {}".format(argv))

            with mock.patch.object(coordinator, "command", side_effect=fake_command), \
                    mock.patch.object(coordinator, "https_proxy_probe", return_value={
                        "listener_reachable": False, "https_connect_passed": False,
                        "target_http_status": None, "error": "connection refused"}), \
                    mock.patch.object(coordinator.replay_resources,
                                      "docker_inventory", return_value={
                                          "containers": [], "networks": [],
                                          "services": [],
                                          "starrynet_service_containers": [],
                                          "starrynet_owner_networks": []}), \
                    mock.patch.object(coordinator.replay_resources,
                                      "starrynet_resources_cleared", return_value=True):
                result = coordinator.doctor(config)
        self.assertFalse(result["passed"])
        self.assertTrue(any("HTTPS CONNECT" in error for error in result["errors"]))

    def test_mid_collection_proxy_disconnect_is_fatal(self):
        failure = collector.classify_failure(
            False, {"cleanup_verified": True}, {},
            "ProxyError: 127.0.0.1:17897 connection refused", False)
        self.assertEqual(failure, "proxy")
        self.assertEqual(coordinator.failure_policy(failure, 1, 1), "pause")

    def test_retry_exhaustion_three_failures_and_timeout_policy(self):
        self.assertEqual(coordinator.failure_policy("page_access", 1, 1), "retry")
        self.assertEqual(coordinator.failure_policy("sample_quality", 2, 2),
                         "next_sample")
        self.assertEqual(coordinator.failure_policy("timeout", 1, 1), "retry")
        self.assertEqual(coordinator.failure_policy("sample_quality", 3, 1), "pause")

    def test_cleanup_query_failure_is_not_treated_as_clean(self):
        with mock.patch.object(coordinator, "command", return_value={
                "returncode": 1, "stdout": "", "stderr": "daemon unavailable"}):
            self.assertFalse(coordinator.cleanup_named_container("sn-v2-test"))

    def test_process_group_timeout_reaps_child(self):
        process = subprocess.Popen(
            [sys.executable, "-c",
             "import subprocess,sys,time; "
             "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
             "time.sleep(30)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, start_new_session=True)
        returncode, _stdout, _stderr, _forced, group_stopped = stop_process_group(
            process, 0.1, terminate_grace_seconds=0.2,
            kill_grace_seconds=0.2)
        self.assertIsNotNone(returncode)
        self.assertIsNotNone(process.poll())
        self.assertTrue(group_stopped)
        self.assertFalse(process_group_exists(process.pid))

    def test_resume_lock_and_stale_lock_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            first = coordinator.acquire_collection_lock(temp)
            with self.assertRaises(RuntimeError):
                coordinator.acquire_collection_lock(temp)
            self.assertTrue(coordinator.release_collection_lock(first))
            lock_path = Path(temp) / "v2_online_action_lock.json"
            lock_path.write_text(json.dumps({"pid": 99999999, "token": "stale"}))
            recovered = coordinator.acquire_collection_lock(temp)
            self.assertTrue(coordinator.release_collection_lock(recovered))

    def test_budget_reserve_and_freeze_hash_change(self):
        self.assertTrue(coordinator.remaining_budget_allows_attempt(22 * 60))
        self.assertFalse(coordinator.remaining_budget_allows_attempt(22 * 60 - 1))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = {"protocol_metadata": {"protocol_id": coordinator.PROTOCOL_ID,
                                                "runtime_assets": {
                                                    "helper_image_id": "image-id"}},
                        "samples": []}
            (root / "batch_manifest.json").write_text(json.dumps(manifest))
            frozen = root / "frozen.txt"
            frozen.write_text("original")
            (root / "protocol").mkdir()
            hashes = {"hashes": {"input": {"path": str(frozen),
                                               "sha256": coordinator.sha256_file(frozen)}},
                      "protocol_id": coordinator.PROTOCOL_ID,
                      "planned_sample_count": 0,
                      "helper_image_id": "image-id"}
            (root / "protocol" / "freeze_hashes.json").write_text(
                json.dumps(hashes))
            self.assertEqual(coordinator.verify_freeze(root), [])
            frozen.write_text("changed")
            self.assertTrue(any("changed" in error
                                for error in coordinator.verify_freeze(root)))

    def test_coordinator_and_auditor_directory_hashes_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "tree"
            root.mkdir()
            (root / "sub").mkdir()
            data = root / "sub" / "input"
            data.write_bytes(b"frozen bytes")
            os.chmod(data, 0o640)
            self.assertEqual(coordinator.sha256_tree(root),
                             pilot_audit.sha256_path(root))

    def test_low_profile_correlation_does_not_reject_protocol_valid_pilot(self):
        pages = [{"page_complete": True, "repeatability": {
            "capture_protocol_reproducible": True,
            "profile_stable_in_run_set": False}} for _ in range(5)]
        complete, protocol_consistent = pilot_audit.pilot_completion(
            True, True, True, pages)
        self.assertTrue(complete)
        self.assertTrue(protocol_consistent)
        pages[2]["repeatability"]["capture_protocol_reproducible"] = False
        complete, protocol_consistent = pilot_audit.pilot_completion(
            True, True, True, pages)
        self.assertFalse(complete)
        self.assertFalse(protocol_consistent)

    def test_v2_offload_gate_requires_four_endpoints_and_keeps_v14_rule(self):
        features = {
            name: {"state": "off"}
            for name in repeatability_audit.OFFLOAD_FEATURES
        }
        endpoints = [{
            "interface": "test-{}".format(index),
            "after": {"features": dict(features)},
        } for index in range(4)]
        summary = {
            "acquisition_protocol": {"protocol_id": coordinator.PROTOCOL_ID},
            "packetization_offload_audit": {
                "mode": "disable_path", "verified_disabled": True,
                "endpoints": endpoints,
            },
        }
        self.assertEqual(repeatability_audit.offload_is_disabled(summary),
                         (True, None))

        summary["packetization_offload_audit"]["endpoints"] = endpoints[:2]
        passed, error = repeatability_audit.offload_is_disabled(summary)
        self.assertFalse(passed)
        self.assertEqual(error, "offload audit does not contain 4 route endpoints")

        summary["acquisition_protocol"]["protocol_id"] = (
            repeatability_audit.E_BROWSER_V1_4_PROTOCOL_ID)
        summary["packetization_offload_audit"]["endpoints"] = endpoints
        self.assertEqual(repeatability_audit.offload_is_disabled(summary),
                         (True, None))

    def test_v14_source_snapshot_is_byte_identical(self):
        snapshot = coordinator.DEFAULT_ROOT / "protocol" / "source_snapshot"
        names = ("batch_manifest.py", "run_e_browser_site_sample.py",
                 "audit_site_trace_repeatability.py", "audit_e_browser_tor_pilot.py",
                 "tor_browser_starrynet_smoke.py", "tor_browser_site_smoke.py")
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(coordinator.sha256_file(TOOLS / name),
                                 coordinator.sha256_file(snapshot / name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
