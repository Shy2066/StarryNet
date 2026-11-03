import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import satellite_wf_v3_browser_tor_collector as collector
import tor_browser_site_smoke_v2 as browser_helper


class ProxyModeTests(unittest.TestCase):
    def test_direct_tor_proxy_mode_keeps_browser_environment_empty(self):
        args = SimpleNamespace(
            direct_network=True,
            https_proxy="172.20.0.1:43123",
            wait_for_capture_gate=True,
            capture_control_dir="/out/capture_control")
        proxy = browser_helper.validate_proxy_mode(args, {})
        self.assertEqual(proxy.netloc, "172.20.0.1:43123")

    def test_direct_tor_proxy_mode_rejects_browser_proxy_environment(self):
        args = SimpleNamespace(
            direct_network=True,
            https_proxy="172.20.0.1:43123",
            wait_for_capture_gate=True,
            capture_control_dir="/out/capture_control")
        with self.assertRaisesRegex(ValueError, "environment variables"):
            browser_helper.validate_proxy_mode(args, {"HTTPS_PROXY": "http://127.0.0.1:17897"})

    def test_direct_tor_proxy_mode_requires_capture_gate(self):
        args = SimpleNamespace(
            direct_network=True, https_proxy="172.20.0.1:43123",
            wait_for_capture_gate=False, capture_control_dir="/out/capture_control")
        with self.assertRaisesRegex(ValueError, "capture control"):
            browser_helper.validate_proxy_mode(args, {})

    def test_legacy_proxy_mode_still_requires_loopback_https_proxy(self):
        args = SimpleNamespace(
            direct_network=False, https_proxy=None,
            wait_for_capture_gate=False, capture_control_dir=None)
        proxy = browser_helper.validate_proxy_mode(
            args, {"HTTPS_PROXY": "http://127.0.0.1:17897"})
        self.assertEqual(proxy.port, 17897)
        with self.assertRaisesRegex(ValueError, "loopback HTTPS_PROXY"):
            browser_helper.validate_proxy_mode(args, {"HTTPS_PROXY": "http://10.0.0.2:17897"})


class ProxyPreflightTests(unittest.TestCase):
    def _doctor(self, passed=True):
        return {
            "passed": passed,
            "python": "Python 3.6.15",
            "tmux_starrynet": True,
            "active_collection_processes": [],
            "docker": {"available": True, "server_version": "test"},
            "starrynet_resources": {"clean": True},
            "helper_image": {"matches": True},
            "errors": [] if passed else ["doctor failed"],
        }

    def test_preflight_requires_three_sequential_http_200_results(self):
        probes = [
            {"listener_reachable": True, "https_connect_passed": True,
             "target_http_status": 200}
            for _ in range(3)]
        with mock.patch.object(collector.proxy_runtime, "read_json", return_value={}), \
                mock.patch.object(collector.proxy_runtime, "doctor",
                                  return_value=self._doctor()), \
                mock.patch.object(collector, "active_v3_collectors", return_value=[]), \
                mock.patch.object(collector.proxy_runtime, "https_proxy_probe",
                                  side_effect=probes) as probe:
            result = collector.proxy_preflight()
        self.assertTrue(result["passed"])
        self.assertEqual(result["https_connect_probe"]["consecutive_count"], 3)
        self.assertEqual(probe.call_count, 3)
        self.assertFalse(result["interpretation"]["topology_started"])

    def test_preflight_stops_on_first_failed_connect(self):
        probes = [
            {"listener_reachable": True, "https_connect_passed": True,
             "target_http_status": 200},
            {"listener_reachable": True, "https_connect_passed": False,
             "target_http_status": None},
            {"listener_reachable": True, "https_connect_passed": True,
             "target_http_status": 200},
        ]
        with mock.patch.object(collector.proxy_runtime, "read_json", return_value={}), \
                mock.patch.object(collector.proxy_runtime, "doctor",
                                  return_value=self._doctor()), \
                mock.patch.object(collector, "active_v3_collectors", return_value=[]), \
                mock.patch.object(collector.proxy_runtime, "https_proxy_probe",
                                  side_effect=probes) as probe:
            result = collector.proxy_preflight()
        self.assertFalse(result["passed"])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(result["https_connect_probe"]["consecutive_count"], 2)

    def test_preflight_never_probes_when_doctor_fails(self):
        with mock.patch.object(collector.proxy_runtime, "read_json", return_value={}), \
                mock.patch.object(collector.proxy_runtime, "doctor",
                                  return_value=self._doctor(False)), \
                mock.patch.object(collector, "active_v3_collectors", return_value=[]), \
                mock.patch.object(collector.proxy_runtime, "https_proxy_probe") as probe:
            result = collector.proxy_preflight()
        self.assertFalse(result["passed"])
        probe.assert_not_called()


class AttemptLedgerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.plan = {"runs": [
            {"sample_id": "r001"},
            {"sample_id": "r002"},
            {"sample_id": "r003"},
        ]}

    def test_first_attempt_does_not_reserve_retry(self):
        number, retry = collector._attempt_retry_policy(
            self.plan, 1, "plan-a", [], 1)
        self.assertEqual(number, 1)
        self.assertFalse(retry)

    def test_infrastructure_failure_does_not_consume_site_retry(self):
        records = [{"event": "started", "attempt_id": "a1", "sample_id": "r001"},
                   {"event": "finished", "attempt_id": "a1", "sample_id": "r001",
                    "sample_status": "failed", "failure_class": "infrastructure",
                    "retry_consumed": False, "plan_sha256": "plan-a"}]
        with self.assertRaisesRegex(RuntimeError, "re-frozen plan"):
            collector._attempt_retry_policy(self.plan, 1, "plan-a", records, 1)
        number, retry = collector._attempt_retry_policy(
            self.plan, 1, "plan-b", records, 1)
        self.assertEqual(number, 2)
        self.assertFalse(retry)

    def test_site_gate_failure_allows_one_retry_after_plan_revision(self):
        records = [{"event": "started", "attempt_id": "a1", "sample_id": "r001"},
                   {"event": "finished", "attempt_id": "a1", "sample_id": "r001",
                    "sample_status": "failed", "failure_class": "sample_gate",
                    "retry_consumed": False, "plan_sha256": "plan-a"}]
        number, retry = collector._attempt_retry_policy(
            self.plan, 1, "plan-b", records, 1)
        self.assertEqual(number, 2)
        self.assertTrue(retry)
        records[-1]["retry_consumed"] = True
        with self.assertRaisesRegex(RuntimeError, "retry limit"):
            collector._attempt_retry_policy(self.plan, 1, "plan-c", records, 1)

    def test_next_index_is_blocked_until_previous_sample_passes(self):
        with self.assertRaisesRegex(RuntimeError, "sequential"):
            collector._attempt_retry_policy(self.plan, 2, "plan-a", [], 1)
        records = [{"event": "finished", "attempt_id": "a1", "sample_id": "r001",
                    "sample_status": "passed", "failure_class": None,
                    "retry_consumed": False, "plan_sha256": "plan-a"}]
        number, retry = collector._attempt_retry_policy(
            self.plan, 2, "plan-a", records, 1)
        self.assertEqual(number, 1)
        self.assertFalse(retry)

    def test_unfinished_attempt_blocks_restart(self):
        records = [{"event": "started", "attempt_id": "a1", "sample_id": "r001"}]
        with self.assertRaisesRegex(RuntimeError, "unfinished"):
            collector._attempt_retry_policy(self.plan, 1, "plan-b", records, 1)

    def test_failure_before_capture_and_browser_is_infrastructure(self):
        summary = {
            "errors": [""],
            "tracebacks": ["p0_smoke.topology_report AssertionError"],
            "captures": [],
            "browser_tor": None,
        }
        self.assertEqual(
            "infrastructure",
            collector._classify_attempt_failure(
                summary, RuntimeError("PCAP does not exist"), True))

    def test_relay_cleanup_placeholder_does_not_imply_browser_started(self):
        summary = {
            "errors": ["HTTPS CONNECT through V3 GRE/NAT to the host proxy failed"],
            "tracebacks": [],
            "captures": [],
            "browser_tor": {
                "cleanup_verified": False,
                "host_relay_cleanup_verified": True,
            },
        }
        self.assertEqual(
            "infrastructure",
            collector._classify_attempt_failure(
                summary, RuntimeError("GRE/NAT HTTPS CONNECT timed out"), True))

    def test_reviewed_infrastructure_failure_preserves_reserved_site_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "attempt_ledger.jsonl"
            correction_path = Path(directory) / "attempt_ledger_corrections.jsonl"
            records = [
                {"event": "finished", "attempt_id": "a1", "sample_id": "r001",
                 "sample_status": "failed", "failure_class": "infrastructure",
                 "retry_consumed": False, "plan_sha256": "plan-a"},
                {"event": "finished", "attempt_id": "a2", "sample_id": "r001",
                 "sample_status": "failed", "failure_class": "sample_gate",
                 "retry_consumed": False, "plan_sha256": "plan-a"},
                {"event": "finished", "attempt_id": "a3", "sample_id": "r001",
                 "sample_status": "failed", "failure_class": "sample_gate",
                 "retry_consumed": True, "plan_sha256": "plan-b"},
            ]
            ledger_path.write_text("".join(
                json.dumps(row) + "\n" for row in records), encoding="utf-8")
            correction_path.write_text(json.dumps({
                "event": "classification_review", "review_id": "review-a3",
                "attempt_id": "a3", "recorded_failure_class": "sample_gate",
                "recorded_retry_consumed": True,
                "reviewed_failure_class": "infrastructure",
                "reviewed_retry_consumed": False,
                "reason": "topology audit failed before capture or Browser/Tor startup",
            }) + "\n", encoding="utf-8")

            effective = collector._read_attempt_ledger(
                ledger_path, correction_path)
            reviewed = [row for row in effective
                        if row.get("attempt_id") == "a3"][0]
            self.assertEqual("sample_gate", reviewed["recorded_failure_class"])
            self.assertEqual("infrastructure", reviewed["failure_class"])
            self.assertFalse(reviewed["retry_consumed"])
            number, retry_reserved = collector._attempt_retry_policy(
                self.plan, 1, "plan-c", effective, 1)
            self.assertEqual(4, number)
            self.assertTrue(retry_reserved)

class CaptureControlTests(unittest.TestCase):
    def test_start_and_stop_requests_are_acknowledged_after_capture_flush(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            session = collector.BrowserTorSession({}, {"sample_id": "test"}, {})
            session.control_dir = Path(temp_dir)
            captures = [{"label": "gs26-wf-gre0", "stopped": False}]
            summary = {"time_boundaries": {}}
            run_dir = Path(temp_dir)
            start_request = {"request_id": "start-1", "visit_index": 1}
            collector.write_json(session.control_dir / "capture_start_request.json",
                                  start_request)
            session.service_capture_control(captures, summary, run_dir, 45.0)
            start_ack = collector.load_json(
                session.control_dir / "capture_start_ack.json")
            self.assertTrue(start_ack["ok"])
            self.assertEqual(start_ack["request_id"], "start-1")

            stop_request = {"request_id": "stop-1", "visit_index": 1}
            collector.write_json(session.control_dir / "capture_stop_request.json",
                                 stop_request)
            with mock.patch.object(collector.dynamic.fixed, "stop_capture",
                                   side_effect=lambda item: item.update(stopped=True)):
                session.service_capture_control(captures, summary, run_dir, 77.0)
            stop_ack = collector.load_json(
                session.control_dir / "capture_stop_ack.json")
            self.assertTrue(stop_ack["ok"])
            self.assertTrue(session.capture_stop_acknowledged)
            self.assertTrue(captures[0]["stopped"])
            self.assertIn("raw_capture_end_monotonic", summary["time_boundaries"])


class SampleManifestTests(unittest.TestCase):
    def test_sample_manifest_pins_three_hops_and_all_navigation_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            captures_dir = run_dir / "captures"
            captures_dir.mkdir()
            (captures_dir / "gs26-wf-gre0.pcap").write_bytes(b"test pcap")
            class_id = "1"
            planned_run = {
                "sample_id": "v3-class-1-r001",
                "session_id": "v3-class-1-session-001",
                "class_id": class_id,
                "requested_url": "http://amazon.co.jp",
            }
            stream = {
                "id": "7", "status": "SUCCEEDED", "circuit_id": "42",
                "address": "amazon.co.jp", "port": "443",
            }
            fingerprints = ["A" * 40, "B" * 40, "C" * 40]
            visit = {
                "passed": True, "page_loaded": True,
                "http_200_confirmed": True, "http_status": 200,
                "final_url": "https://www.amazon.co.jp/",
                "access_challenge_indicators": [],
                "title": "Amazon", "document_domain": "www.amazon.co.jp",
                "target_stream_succeeded": True,
                "capture_window": {
                    "site_stream_events": [stream],
                    "navigation_started": {"utc": "2026-10-22T03:00:01+00:00",
                                            "monotonic": 1001.0},
                    "navigation_completed": {"utc": "2026-10-22T03:00:30+00:00",
                                              "monotonic": 1030.0},
                },
                "target_circuit_path_events": [{
                    "circuit_id": "42", "status": "BUILT",
                    "path": [{"fingerprint": value} for value in fingerprints],
                }],
            }
            labels = {
                "gs26-wf-gre0": "wf-gre0",
                "gs27-wf-gre0": "wf-gre0",
                "gs27-b27-default": "B27-default",
                "gs26-gre-outer": "any",
                "gs27-gre-outer": "any",
            }
            captures = [{
                "label": label,
                "interface": interface,
                "capture_kind": "gre_outer" if "gre-outer" in label else "ip",
                "zero_kernel_drops": True,
                "ip_packet_count": 10,
            } for label, interface in labels.items()]
            network_summary = {
                "browser_tor": {
                    "passed": True, "cleanup_verified": True,
                    "browser_version": "15.0.25", "tor_version": "0.4.9.11",
                    "browser_tree_sha256": "1" * 64,
                    "tor_binary_sha256": "2" * 64,
                    "helper_image_id": "sha256:" + "3" * 64,
                },
                "visits": [visit],
                "captures": captures,
                "route_samples": [{
                    "selected_routes": {
                        "client_underlay_route": {"dev": "B26-eth1"},
                        "egress_underlay_route": {"dev": "B27-eth2"},
                    }
                }],
                "checks": {
                    "capture_window_has_expected_topology_events": True,
                    "dynamic_route_samples_use_satellite_interfaces": True,
                },
                "initial_route_nat_verification": {
                    "status": "passed",
                    "checks": {"capture_offloads_disabled": True},
                },
                "handover_verification": {"status": "passed"},
                "topology_events": [{"logical_second": 70}],
                "observed_topology_events": [],
                "simulation_clock": [{"event": "started"}],
                "planned_window": {"capture_window_logical_seconds": [32, 62]},
                "time_boundaries": {
                    "raw_capture_start_utc": "2026-10-22T03:00:00+00:00",
                    "navigation_start_utc": "2026-10-22T03:00:01+00:00",
                    "navigation_complete_utc": "2026-10-22T03:00:30+00:00",
                    "raw_capture_end_utc": "2026-10-22T03:00:32+00:00",
                    "raw_capture_start_monotonic": 1000.0,
                    "navigation_start_monotonic": 1001.0,
                    "navigation_complete_monotonic": 1030.0,
                    "raw_capture_end_monotonic": 1032.0,
                    "clock_anchor_utc": "2026-10-22T03:00:00+00:00",
                    "clock_anchor_monotonic": 1000.0,
                    "topology_start_seconds": 32.0,
                    "topology_end_seconds": 64.0,
                },
                "cleanup_verified": True,
            }

            def fake_extract(pcap, boundaries_path, client_ip, output_dir):
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True)
                trace_path = output_dir / "trace.tsv"
                trace_path.write_text("timestamp_s\tdirection\tpacket_size_bytes\n0.0\t1\t512\n")
                audit_path = output_dir / "packet_audit.json"
                audit = {"passed": True, "trace_row_count": 1}
                audit_path.write_text(json.dumps(audit))
                return {"passed": True, "packet_audit_data": audit}

            with mock.patch.object(collector.trace_extractor, "extract",
                                   side_effect=fake_extract):
                sample = collector.sample_from_summary(
                    {}, planned_run, run_dir, network_summary,
                    collector.pilot_plan.DEFAULT_SOURCE_AUDIT)
            self.assertEqual(sample["sample_status"], "passed")
            self.assertTrue(all(sample["gates"].values()))
            self.assertFalse(sample["training_eligible"])
            self.assertEqual(sample["split"], "pilot_only")
            self.assertEqual(sample["tor_path"]["circuit_id"], "42")


if __name__ == "__main__":
    unittest.main()
