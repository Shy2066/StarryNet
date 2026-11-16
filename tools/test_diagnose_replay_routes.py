#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from diagnose_replay_routes import annotate, load_session


class RouteDiagnosisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        (self.directory / "summary.json").write_text(json.dumps(
            {"session_anchor_monotonic_ns": 0}))
        self.logs = {}
        for role, node, peer in (("client", 26, 27), ("remote", 27, 26)):
            common = {"role": role, "peer": "9.{0}.{0}.10".format(peer),
                      "clock_domain": "CLOCK_MONOTONIC"}
            self.logs[role] = [
                dict(common, type="route_monitor_started", observed_ns=0),
                dict(common, type="route_snapshot", observed_ns=1, returncode=0,
                     command=["ip", "-4", "route", "show"],
                     output="9.{0}.{0}.0/24 via 9.1.7.50 dev B{1}-eth7 proto bird".format(peer, node)),
                dict(common, type="route_snapshot", observed_ns=2, returncode=0,
                     command=["ip", "-o", "link", "show"],
                     output="6: B{}-eth7@if10: <BROADCAST,UP,LOWER_UP> state UP".format(node)),
                dict(common, type="route_monitor_stopped", observed_ns=100000000000),
            ]
        self.evidence = {"sample_id": "37-1", "session_id": "session-0001",
                         "attempt_id": "attempt-1", "status": "failure",
                         "handover_count": 0, "simulation_start_second": 11.0,
                         "simulation_end_second": 15.0,
                         "client_send_errors": [self.error(12)], "remote_send_errors": []}

    def error(self, second):
        return {"observed_ns": int(second * 1e9), "clock_domain": "CLOCK_MONOTONIC",
                "error": "[Errno 101] Network is unreachable"}

    def event(self, role, second, raw):
        self.logs[role].append({"type": "route_change", "role": role,
                                "observed_ns": int(second * 1e9),
                                "clock_domain": "CLOCK_MONOTONIC", "event": raw})

    def diagnose(self):
        for role, rows in self.logs.items():
            (self.directory / (role + "_agent.jsonl")).write_text(
                "\n".join(json.dumps(x) for x in rows))
        return annotate(self.evidence, load_session(self.directory))

    def route_gap(self, role="client", restore=True):
        peer = 27 if role == "client" else 26
        prefix = "9.{0}.{0}.0/24 via 9.1.7.50 dev B26-eth7 proto bird".format(peer)
        self.event(role, 10, "Deleted " + prefix)
        if restore:
            self.event(role, 16, prefix)

    def test_gap_spanning_sample_is_associated_without_rewriting_planned_count(self):
        before = copy.deepcopy(self.evidence)
        self.route_gap()
        result = self.diagnose()
        self.assertEqual(result["anomaly_labels"], ["route_convergence_gap"])
        self.assertEqual(result["planned_handover_count"], 0)
        self.assertEqual(result["actual_event_count"], 0)
        self.assertEqual(len(result["related_intervals"]), 1)
        interval = result["related_intervals"][0]
        self.assertEqual(interval["unreachable_error_count"], 1)
        self.assertTrue(interval["start"]["log_path"].endswith("client_agent.jsonl"))
        self.assertGreater(interval["start"]["line"], 0)
        self.assertEqual(self.evidence, before)

    def test_other_endpoint_error_does_not_prove_local_route_gap(self):
        self.route_gap(role="remote")
        self.assertEqual(self.diagnose()["anomaly_labels"], ["unknown"])

    def test_unrestored_route_is_not_labelled_converged(self):
        self.route_gap(restore=False)
        self.assertEqual(self.diagnose()["anomaly_labels"], ["peer_route_unavailable"])

    def test_last_access_link_down_correlates_error_even_after_default_route_added(self):
        self.event("client", 11.5, "6: B26-eth7@if10: <BROADCAST,MULTICAST> state DOWN")
        self.event("client", 13, "default via 9.26.26.1 dev B26-default")
        result = self.diagnose()
        self.assertEqual(result["anomaly_labels"], ["access_link_interruption"])
        self.assertEqual(result["actual_event_count"], 2)
        self.assertEqual(result["related_events"][-1]["kind"], "default_route_added")
        self.assertIsNone(result["related_intervals"][0]["end"])

    def test_old_link_down_with_alternate_link_up_is_not_access_outage(self):
        self.event("client", 10, "8: B26-eth13@if11: <BROADCAST,UP,LOWER_UP> state UP")
        self.event("client", 11.5, "6: B26-eth7@if10: <BROADCAST,MULTICAST> state DOWN")
        self.assertEqual(self.diagnose()["anomaly_labels"], ["unknown"])

    def test_down_link_does_not_match_error_after_access_recovery(self):
        self.event("client", 10, "6: B26-eth7@if10: <BROADCAST> state DOWN")
        self.event("client", 11, "6: B26-eth7@if10: <BROADCAST,UP,LOWER_UP> state UP")
        self.assertEqual(self.diagnose()["anomaly_labels"], ["unknown"])

    def test_monitor_failure_and_clock_mismatch_preserve_unknown(self):
        self.route_gap()
        base = copy.deepcopy(self.logs)
        for change in ("error", "clock", "missing_stop"):
            with self.subTest(change=change):
                self.logs = copy.deepcopy(base)
                if change == "error":
                    self.logs["remote"].append({"type": "route_monitor_error",
                        "observed_ns": 20000000000, "clock_domain": "CLOCK_MONOTONIC"})
                elif change == "clock":
                    self.logs["remote"][0]["clock_domain"] = "CLOCK_REALTIME"
                else:
                    self.logs["remote"] = [x for x in self.logs["remote"]
                                           if x["type"] != "route_monitor_stopped"]
                result = self.diagnose()
                self.assertEqual(result["diagnostic_status"], "unavailable")
                self.assertIsNone(result["actual_event_count"])
                self.assertEqual(result["anomaly_labels"], ["unknown"])

    def test_error_clock_or_timestamp_missing_does_not_establish_cause(self):
        self.route_gap()
        for key in ("clock_domain", "observed_ns"):
            with self.subTest(key=key):
                self.evidence["client_send_errors"] = [self.error(12)]
                del self.evidence["client_send_errors"][0][key]
                self.assertEqual(self.diagnose()["anomaly_labels"], ["unknown"])

    def test_missing_sample_timing_or_monitor_coverage_is_unknown(self):
        self.route_gap()
        self.evidence["simulation_end_second"] = None
        self.assertEqual(self.diagnose()["diagnostic_status"], "unavailable")
        self.evidence["simulation_end_second"] = 101
        self.assertIsNone(self.diagnose()["actual_event_count"])


if __name__ == "__main__":
    unittest.main()
