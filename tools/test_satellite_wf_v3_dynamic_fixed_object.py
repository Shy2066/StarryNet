import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from starrynet.sn_observer import Observer
from starrynet.sn_utils import sn_get_param, sn_load_file
import p0_smoke
import satellite_wf_v3_dynamic_fixed_object as dynamic

from satellite_wf_v3_dynamic_fixed_object import (
    CAPTURE_LABELS, kernel_capture_drop_gate, measure_handover_interruption,
    parse_topology_events, scenario_window, finalize_capture_artifacts)


class DynamicFixedObjectScheduleTests(unittest.TestCase):
    def test_post_capture_route_check_precedes_pcap_analysis(self):
        events = []
        summary = {"time_boundaries": {
            "capture_end_logical_second_estimate": 262.25}}
        def verify(_state):
            events.append("verify_route")
            return {"status": "passed"}
        def analyze(_capture, _run):
            events.append("analyze_pcap")
            return {"label": "gs26-wf-gre0", "pcap_sha256": "a" * 64}
        with mock.patch.object(dynamic, "verify_route_state", side_effect=verify):
            finalize_capture_artifacts(
                "route-state.json", [{"label": "gs26-wf-gre0"}], ".",
                summary, analyze, 67.0, dynamic.time.monotonic() - 195.5)
        self.assertEqual(["verify_route", "analyze_pcap"], events)
        self.assertEqual("passed", summary["handover_verification"]["status"])
        self.assertGreater(
            summary["handover_verification"]["verification_logical_second_estimate"],
            summary["time_boundaries"]["capture_end_logical_second_estimate"])

    def test_parse_topology_handover_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Topo_leo_change.txt"
            path.write_text(
                "time 53:\nduration 60:\nadd:\n7-27\ndel:\n13-27\n"
                "time 100:\nend of the emulation!\n", encoding="utf-8")
            self.assertEqual(parse_topology_events(path), [{
                "logical_second": 53,
                "added_links": ["7-27"],
                "removed_links": ["13-27"],
            }])

    def test_no_handover_window_ends_before_first_transition(self):
        events = [{"logical_second": 53, "added_links": ["7-27"],
                   "removed_links": ["13-27"]}]
        window = scenario_window("dynamic_no_handover", events)
        self.assertEqual(window["capture_window_logical_seconds"], [15, 45])
        self.assertNotIn(53, range(15, 46))
        self.assertEqual(window["transfer_logical_seconds"], [20, 30, 40])

    def test_browser_window_fits_long_navigation_before_handover(self):
        events = [{"logical_second": 272, "added_links": [],
                   "removed_links": ["7-26"]}]
        window = scenario_window(
            "dynamic_no_handover", events, duration=300,
            browser_capture_seconds=180)
        self.assertEqual(window["capture_window_logical_seconds"], [67, 264])
        self.assertNotIn(272, range(67, 265))
        self.assertEqual(window["first_topology_handover_logical_second"], 272)

    def test_frozen_browser_epoch_generates_connected_167_second_window(self):
        config = json.loads(Path("config.json").read_text(encoding="utf-8"))
        config.update({"Name": "v3-browser-window-test",
                       "Duration (s)": 300,
                       "Simulation start UTC": "2022-01-01T01:02:00Z"})
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            args = sn_load_file(str(config_path), p0_smoke.GS, argv=[])
            self.assertEqual(args.simulation_start_utc, "2022-01-01T01:02:00Z")
            topology = Path(directory) / "topology"
            (topology / "delay").mkdir(parents=True)
            (topology / "position").mkdir()
            observer = Observer(
                "topology", directory, args.inclination, args.satellite_altitude,
                args.orbit_number, args.sat_number, args.duration,
                args.antenna_number, p0_smoke.GS, args.antenna_inclination,
                args.intra_routing, 10, [], args.simulation_start_utc)
            observer.calculate_delay()
            events = parse_topology_events(topology / "Topo_leo_change.txt")
            self.assertEqual([event["logical_second"] for event in events], [272])
            window = scenario_window(
                "dynamic_no_handover", events, duration=args.duration,
                browser_capture_seconds=180)
            self.assertEqual(window["capture_window_logical_seconds"], [67, 264])
            for second in (67, 264):
                matrix = sn_get_param(str(topology / "delay" / ("%d.txt" % second)))
                self.assertGreater(float(matrix[25][6]), 0)
                self.assertGreater(float(matrix[26][6]), 0)

    def test_dynamic_handover_window_spans_transition_and_recovery(self):
        events = [{"logical_second": 53, "added_links": ["7-27"],
                   "removed_links": ["13-27"]}]
        window = scenario_window("dynamic_handover", events)
        self.assertEqual(window["capture_window_logical_seconds"], [41, 75])
        self.assertIn(53, range(41, 76))
        self.assertEqual(window["transfer_logical_seconds"], [45, 61, 71])

    def test_rejects_missing_or_out_of_window_handover(self):
        with self.assertRaises(RuntimeError):
            scenario_window("dynamic_handover", [])
        with self.assertRaises(RuntimeError):
            scenario_window("dynamic_handover", [{
                "logical_second": 90, "added_links": ["7-27"],
                "removed_links": ["13-27"]}])

    def test_interruption_spanning_topology_event_counts_pre_event_losses(self):
        samples = [{"started_monotonic": 5.5 + index,
                    "finished_monotonic": 5.9 + index,
                    "passed": False}
                   for index in range(4)]
        samples.append({"started_monotonic": 10.0,
                        "finished_monotonic": 10.2,
                        "passed": True})

        record = measure_handover_interruption(
            samples, topology_event_monotonic=9.0,
            route_change_monotonic=7.0)

        self.assertEqual(record["probe_failures_in_outage"], 4)
        self.assertEqual(record["outage_start_monotonic"], 5.5)
        self.assertEqual(record["route_recovered_monotonic"], 10.2)
        self.assertAlmostEqual(record["interruption_ms"], 4700)
        self.assertTrue(record["outage_spans_topology_event"])
        self.assertTrue(record["outage_spans_gre_retarget"])

    def test_interruption_reports_probe_resolution_when_no_loss_is_seen(self):
        record = measure_handover_interruption(
            [{"started_monotonic": 4.0, "finished_monotonic": 4.2, "passed": True},
             {"started_monotonic": 6.0, "finished_monotonic": 6.2, "passed": True}],
            topology_event_monotonic=5.0)

        self.assertEqual(record["interruption_ms"], 0.0)
        self.assertEqual(record["probe_failures_in_outage"], 0)
        self.assertIn("one-second probe resolution",
                      record["interruption_measurement"])

    def test_kernel_drop_gate_does_not_conflate_tcpdump_counters(self):
        captures = [{"label": label, "zero_kernel_drops": True,
                     "capture_counters_consistent": label != "gs26-wf-gre0"}
                    for label in CAPTURE_LABELS]
        self.assertTrue(kernel_capture_drop_gate(captures))

        captures[0]["zero_kernel_drops"] = False
        self.assertFalse(kernel_capture_drop_gate(captures))

        self.assertFalse(kernel_capture_drop_gate(captures[:-1]))


if __name__ == "__main__":
    unittest.main()
