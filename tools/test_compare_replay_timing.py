"""Hand-calculated checks for the offline timing audit; no networking."""
from pathlib import Path
import sys
import unittest
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent))
import compare_replay_timing as timing


class TimingAuditTests(unittest.TestCase):
    def test_ecdf_includes_simultaneous_event_mass(self):
        self.assertEqual(timing.ks_distance([0, 0, 1], [0, 1, 1]), 1.0 / 3)
        self.assertEqual(timing.ks_distance([0, 1], [0, 1]), 0)
        self.assertIsNone(timing.ks_distance([], [1]))

    def test_directional_bursts_and_idle_sensitivity_have_distinct_definitions(self):
        t = [0, .005, .006, .2, .201]
        d = [-1, -1, 1, 1, 1]
        self.assertEqual(list(timing.burst_sizes(t, d)), [2, 3])
        self.assertEqual(list(timing.burst_sizes(t, d, .1)), [2, 1, 2])
        self.assertEqual(list(timing.burst_sizes([0, .1], [1, 1], .1)), [2])

    def test_shape_change_with_unchanged_direction_counts(self):
        t = np.asarray([0., .1, .2]); d = np.asarray([-1, -1, 1])
        result = timing.compare_shape(t, d, t * 2, np.asarray([-1, 1, -1]))
        self.assertEqual(result['duration_ratio'], 2)
        self.assertEqual(result['source_burst_count'], 2)
        self.assertEqual(result['replay_burst_count'], 3)
        self.assertAlmostEqual(result['direction_position_mismatch_fraction'], 2.0/3)
        self.assertAlmostEqual(result['iat_wasserstein_ms'], 100)
        self.assertEqual(result['iat_ecdf_ks'], 1)

    def test_interval_shape_rejects_unpaired_or_nonmonotonic_data(self):
        with self.assertRaises(ValueError):
            timing.compare_shape(np.asarray([0., 1]), np.asarray([1, 1]),
                                 np.asarray([0., 1]), np.asarray([1, -1]))
        with self.assertRaises(ValueError):
            timing.compare_shape(np.asarray([0., -1]), np.asarray([1, -1]),
                                 np.asarray([0., 1]), np.asarray([1, -1]))

    def test_resolution_sensitivity_does_not_label_microgaps_as_long_delays(self):
        d = np.asarray([-1, -1, 1])
        row = timing.compare_shape(np.asarray([0., 0., .1]), d,
                                   np.asarray([0., .00002, .10002]), d)
        self.assertEqual(row['iat_ecdf_ks'], .5)
        self.assertEqual(row['iat_ecdf_ks_1ms_bins'], 0)

    def test_true_source_order_inversions_are_not_thread_append_order(self):
        self.assertEqual(timing.inversion_count([0, 1, 2]), 0)
        self.assertEqual(timing.inversion_count([2, 0, 1]), 2)
        self.assertEqual(timing.inversion_count([2, 1, 0]), 3)
        with self.assertRaises(ValueError):
            timing.inversion_count([0, 0, 1])

    def pair_fixture(self):
        events = [{'sequence': i, 'direction': d, 'offset_ns': i*100}
                  for i, d in enumerate([-1, 1, -1])]
        client = [{'sequence': 1, 'direction': 1, 'action': 'send', 'observed_ns': 1110, 'send_completed_ns': 1120},
                  {'sequence': 0, 'direction': -1, 'action': 'recv', 'observed_ns': 1300},
                  {'sequence': 2, 'direction': -1, 'action': 'recv', 'observed_ns': 1500}]
        remote = [{'sequence': 2, 'direction': -1, 'action': 'send', 'observed_ns': 1210, 'send_completed_ns': 1220, 'scheduled_offset_ns': 200},
                  {'sequence': 0, 'direction': -1, 'action': 'send', 'observed_ns': 1010, 'send_completed_ns': 1020, 'scheduled_offset_ns': 0},
                  {'sequence': 1, 'direction': 1, 'action': 'recv', 'observed_ns': 1150, 'scheduled_offset_ns': 100}]
        return events, client, remote

    def test_identity_pairing_separates_sender_lag_from_application_delivery(self):
        events, client, remote = self.pair_fixture()
        result = timing.event_timings(events, client, remote, 1000)
        self.assertEqual([x['sequence'] for x in result], [0, 1, 2])
        self.assertAlmostEqual(result[0]['application_transfer_ms'], 290/1e6)
        self.assertAlmostEqual(result[1]['application_transfer_ms'], 40/1e6)
        self.assertAlmostEqual(result[1]['sender_start_lag_ms'], 10/1e6)
        self.assertAlmostEqual(result[0]['sender_write_duration_ms'], 10/1e6)
        self.assertAlmostEqual(result[0]['replay_offset_seconds'], 190/1e9)
        self.assertAlmostEqual(result[1]['aligned_shift_ms'], -100/1e6)

    def test_pairing_rejects_duplicate_direction_and_offset_mismatches(self):
        for kind in ['duplicate', 'direction', 'offset']:
            events, client, remote = self.pair_fixture()
            if kind == 'duplicate': client[1]['sequence'] = 1
            elif kind == 'direction': remote[0]['direction'] = 1
            else: remote[0]['scheduled_offset_ns'] = 201
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                timing.event_timings(events, client, remote, 1000)


if __name__ == '__main__':
    unittest.main()
