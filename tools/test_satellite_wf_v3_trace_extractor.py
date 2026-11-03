import unittest
import json
from pathlib import Path
import tempfile

from satellite_wf_v3_trace_extractor import (
    extract, extract_trace_rows, parse_utc_epoch)


class V3TraceExtractorTests(unittest.TestCase):
    def setUp(self):
        self.boundaries = {
            "time_boundaries": {
                "raw_capture_start_utc": "2026-10-22T00:00:00.000000+00:00",
                "navigation_start_utc": "2026-10-22T00:00:01.000000+00:00",
                "navigation_complete_utc": "2026-10-22T00:00:03.000000+00:00",
                "raw_capture_end_utc": "2026-10-22T00:00:04.000000+00:00",
                "raw_capture_start_monotonic": 10.0,
                "navigation_start_monotonic": 11.0,
                "navigation_complete_monotonic": 13.0,
                "raw_capture_end_monotonic": 14.0,
                "clock_anchor_utc": "2026-10-22T00:00:00.000000+00:00",
                "clock_anchor_monotonic": 10.0,
                "topology_start_seconds": 0.0,
                "topology_end_seconds": 100.0,
            }
        }

    def test_parses_utc_offsets_with_colon_and_z_suffix(self):
        utc = parse_utc_epoch("2026-10-22T00:00:00.000000Z")
        offset = parse_utc_epoch("2026-10-22T08:00:00.000000+08:00")
        self.assertEqual(utc, offset)

    def test_extracts_bidirectional_packets_only_inside_navigation_window(self):
        capture = "\n".join([
            "1792627200.500000\t10.255.253.1\t1.1.1.1\t100",
            "1792627201.250000\t10.255.253.1\t1.1.1.1\t120",
            "1792627202.500000\t1.1.1.1\t10.255.253.1\t140",
            "1792627203.500000\t1.1.1.1\t10.255.253.1\t160",
        ])
        rows, audit = extract_trace_rows(
            capture, self.boundaries, "10.255.253.1")
        self.assertEqual(rows, [(0.25, 1, 120), (1.5, -1, 140)])
        self.assertEqual(audit["outside_navigation_window_packet_count"], 2)
        self.assertEqual(audit["direction_counts"], {
            "client_to_network": 1, "network_to_client": 1})

    def test_unclassified_in_window_packets_are_reported(self):
        capture = "1792627201.500000\t10.255.253.2\t1.1.1.1\t100"
        rows, audit = extract_trace_rows(
            capture, self.boundaries, "10.255.253.1")
        self.assertEqual(rows, [])
        self.assertEqual(audit["unclassified_navigation_window_packet_count"], 1)

    def test_rejects_non_monotonic_capture_window(self):
        self.boundaries["time_boundaries"]["navigation_start_monotonic"] = 14.5
        with self.assertRaisesRegex(ValueError, "monotonic"):
            extract_trace_rows("", self.boundaries, "10.255.253.1")

    def test_writes_hash_bound_trace_and_packet_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"test-pcap-bytes")
            boundaries = root / "time_boundaries.json"
            boundaries.write_text(json.dumps(self.boundaries))
            tshark = root / "tshark-fixture"
            tshark.write_text(
                "#!/bin/sh\n"
                "printf '1792627201.250000\\t10.255.253.1\\t1.1.1.1\\t120\\n'\n"
                "printf '1792627202.500000\\t1.1.1.1\\t10.255.253.1\\t140\\n'\n")
            tshark.chmod(0o755)
            result = extract(pcap, boundaries, "10.255.253.1",
                             root / "out", str(tshark))
            audit = result["packet_audit_data"]
            self.assertTrue(result["passed"])
            self.assertEqual(audit["capture_packet_count"], 2)
            self.assertEqual(audit["trace_row_count"], 2)
            self.assertEqual(len(audit["pcap_sha256"]), 64)
            self.assertEqual(len(audit["trace_sha256"]), 64)
            self.assertEqual(len(audit["auditor_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
