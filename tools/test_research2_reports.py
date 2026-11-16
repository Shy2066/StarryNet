import csv
import json
import tempfile
import unittest
from pathlib import Path

from research2_reports import empirical_ks_distance, generate_reports


SCENARIOS = ("base", "delay25", "jitter25_10", "loss0p1")
VALID_TRACE = "0.0\t1\n0.1\t1\n0.3\t-1\n0.6\t-1\n0.7\t1\n"


def scenario_dirs(root):
    return {name: root / name for name in SCENARIOS}


def create_scenario_roots(root):
    paths = scenario_dirs(root)
    for path in paths.values():
        path.mkdir(parents=True)
    return paths


def write_trace(paths, scenario, sample_id, contents):
    path = paths[scenario] / sample_id
    path.write_text(contents, encoding="utf-8")
    return path


class Research2ReportsTests(unittest.TestCase):
    def test_valid_fixture_metrics_hash_outputs_and_fixed_comparisons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = create_scenario_roots(root)
            for scenario in SCENARIOS:
                multiplier = 2 if scenario == "delay25" else 1
                lines = []
                for row in VALID_TRACE.splitlines():
                    timestamp, direction = row.split()
                    lines.append("{0}\t{1}".format(float(timestamp) * multiplier, direction))
                write_trace(paths, scenario, "0-0", "\n".join(lines) + "\n")
                (paths[scenario] / "manifest.json").write_text("{}", encoding="utf-8")
            output = root / "reports"
            summary = generate_reports(paths, output, expected_ids=["0-0"])

            self.assertTrue(summary["complete"])
            self.assertEqual(summary["common_source_ids"], ["0-0"])
            self.assertEqual(set(summary["comparisons"]), {
                "delay25_vs_base", "jitter25_10_vs_delay25", "loss0p1_vs_base"})
            delay_feature = summary["comparisons"]["delay25_vs_base"]["features"]
            self.assertEqual(delay_feature["duration_seconds"]["paired_mean_difference_a_minus_b"],
                             0.7)
            with open(str(output / "per_trace_features.csv"), newline="",
                      encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            base = next(row for row in rows if row["scenario"] == "base")
            self.assertEqual(base["status"], "valid")
            self.assertEqual(base["source_group_id"], "0-0")
            self.assertEqual(base["line_count"], "5")
            self.assertEqual(base["event_count"], "5")
            self.assertEqual(base["positive_events"], "3")
            self.assertEqual(base["negative_events"], "2")
            self.assertAlmostEqual(float(base["duration_seconds"]), 0.7)
            self.assertAlmostEqual(float(base["iat_mean_seconds"]), 0.175)
            self.assertAlmostEqual(float(base["iat_median_seconds"]), 0.15)
            self.assertAlmostEqual(float(base["iat_p90_seconds"]), 0.3)
            self.assertEqual(base["burst_count"], "3")
            self.assertAlmostEqual(float(base["mean_burst_events"]), 5 / 3.0)
            self.assertEqual(len(base["sha256"]), 64)
            with open(str(output / "source_groups.csv"), newline="",
                      encoding="utf-8") as stream:
                groups = list(csv.DictReader(stream))
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["source_group_id"], "0-0")
            self.assertEqual(groups[0]["valid_scenarios"], ";".join(SCENARIOS))
            saved = json.loads((output / "distribution_summary.json").read_text(
                encoding="utf-8"))
            self.assertTrue(saved["complete"])
            self.assertIn("descriptive", saved["interpretation"])

    def test_single_direction_infinite_and_backward_traces_are_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = create_scenario_roots(root)
            write_trace(paths, "base", "0-0", "0.0\t1\n0.1\t1\n")
            write_trace(paths, "delay25", "0-0", "0.0\t1\ninf\t-1\n")
            write_trace(paths, "jitter25_10", "0-0", "0.2\t1\n0.1\t-1\n")
            write_trace(paths, "loss0p1", "0-0", VALID_TRACE)
            summary = generate_reports(paths, root / "reports")
            self.assertFalse(summary["complete"])
            invalid_by_scenario = {row["scenario"]: row
                                   for row in summary["invalid_trajectories"]}
            self.assertIn("both directions", invalid_by_scenario["base"]["error"])
            self.assertIn("finite and nonnegative", invalid_by_scenario["delay25"]["error"])
            self.assertIn("moved backwards", invalid_by_scenario["jitter25_10"]["error"])

    def test_incomplete_expected_coverage_cannot_be_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = create_scenario_roots(root)
            for scenario in SCENARIOS:
                write_trace(paths, scenario, "0-0", VALID_TRACE)
            write_trace(paths, "base", "0-1", VALID_TRACE)
            summary = generate_reports(paths, root / "reports",
                                       expected_ids=["0-0", "0-1"])
            self.assertFalse(summary["complete"])
            self.assertEqual(summary["scenario_coverage"]["delay25"]["missing_ids"], ["0-1"])
            self.assertEqual(summary["scenario_coverage"]["base"]["valid_count"], 2)

    def test_unplanned_trace_id_is_reported_and_blocks_complete_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = create_scenario_roots(root)
            for scenario in SCENARIOS:
                write_trace(paths, scenario, "0-0", VALID_TRACE)
            write_trace(paths, "base", "0-1", VALID_TRACE)
            write_trace(paths, "delay25", "0-1", VALID_TRACE)
            summary = generate_reports(paths, root / "reports", expected_ids=["0-0"])
            self.assertFalse(summary["complete"])
            self.assertEqual(summary["scenario_coverage"]["base"]["unexpected_ids"], ["0-1"])
            self.assertEqual(summary["comparisons"]["delay25_vs_base"]["common_source_ids"],
                             ["0-0"])

    def test_pairwise_comparison_uses_only_valid_source_intersection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = create_scenario_roots(root)
            write_trace(paths, "base", "0-0", VALID_TRACE)
            write_trace(paths, "base", "0-1", VALID_TRACE)
            write_trace(paths, "delay25", "0-1", VALID_TRACE)
            write_trace(paths, "delay25", "0-2", VALID_TRACE)
            write_trace(paths, "jitter25_10", "0-0", VALID_TRACE)
            write_trace(paths, "loss0p1", "0-0", VALID_TRACE)
            summary = generate_reports(paths, root / "reports")
            comparison = summary["comparisons"]["delay25_vs_base"]
            self.assertEqual(comparison["common_source_ids"], ["0-1"])
            self.assertEqual(comparison["common_source_count"], 1)
            self.assertFalse(summary["complete"])

    def test_empirical_ks_distance_simple_exact_cases(self):
        self.assertEqual(empirical_ks_distance([0, 1], [2, 3]), 1.0)
        self.assertEqual(empirical_ks_distance([1, 2], [2, 3]), 0.5)
        self.assertEqual(empirical_ks_distance([1, 1], [1, 1, 1]), 0.0)
        self.assertIsNone(empirical_ks_distance([], [1]))


if __name__ == "__main__":
    unittest.main()
