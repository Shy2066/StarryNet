import copy
import unittest

from research2_evidence import build_client_trace, verify_events


def fixture_rows():
    events = [
        {"sequence": 0, "direction": 1, "offset_ns": 0},
        {"sequence": 1, "direction": -1, "offset_ns": 100000000},
        {"sequence": 2, "direction": 1, "offset_ns": 200000000},
        {"sequence": 3, "direction": -1, "offset_ns": 300000000},
    ]
    client = {
        "type": "sample_done", "role": "client", "sample_id": "0-0",
        "sample_token": 7123, "send_errors": [], "receive_errors": [],
        "records": [
            {"sequence": 0, "direction": 1, "scheduled_offset_ns": 0,
             "action": "send", "observed_ns": 1000,
             "send_completed_ns": 1100, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
            {"sequence": 1, "direction": -1, "scheduled_offset_ns": 100000000,
             "action": "recv", "observed_ns": 2000, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
            {"sequence": 2, "direction": 1, "scheduled_offset_ns": 200000000,
             "action": "send", "observed_ns": 3000,
             "send_completed_ns": 3100, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
            {"sequence": 3, "direction": -1, "scheduled_offset_ns": 300000000,
             "action": "recv", "observed_ns": 4000, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
        ],
    }
    remote = {
        "type": "sample_done", "role": "remote", "sample_id": "0-0",
        "sample_token": 7123, "send_errors": [], "receive_errors": [],
        "records": [
            {"sequence": 0, "direction": 1, "scheduled_offset_ns": 0,
             "action": "recv", "observed_ns": 1200, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
            {"sequence": 1, "direction": -1, "scheduled_offset_ns": 100000000,
             "action": "send", "observed_ns": 1900,
             "send_completed_ns": 1950, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
            {"sequence": 2, "direction": 1, "scheduled_offset_ns": 200000000,
             "action": "recv", "observed_ns": 3200, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
            {"sequence": 3, "direction": -1, "scheduled_offset_ns": 300000000,
             "action": "send", "observed_ns": 3900,
             "send_completed_ns": 3950, "bytes": 512,
             "sample_token": 7123, "sample_id": "0-0"},
        ],
    }
    return events, client, remote


class Research2EvidenceTests(unittest.TestCase):
    def test_complete_bidirectional_evidence_passes(self):
        events, client, remote = fixture_rows()
        result = verify_events(events, client, remote)
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(result["event_count"], 4)
        self.assertEqual(result["client_record_count"], 4)
        self.assertEqual(result["remote_record_count"], 4)
        self.assertEqual(result["sample_id"], "0-0")
        self.assertEqual(result["sample_token"], 7123)

    def test_missing_duplicate_extra_and_forged_offset_fail(self):
        mutations = []
        events, client, remote = fixture_rows()
        missing_client = copy.deepcopy(client)
        missing_client["records"].pop(2)
        mutations.append(("missing", missing_client, remote))

        duplicate_remote = copy.deepcopy(remote)
        duplicate_remote["records"].append(copy.deepcopy(duplicate_remote["records"][0]))
        mutations.append(("duplicate", client, duplicate_remote))

        extra_client = copy.deepcopy(client)
        extra = copy.deepcopy(extra_client["records"][0])
        extra["sequence"] = 99
        extra_client["records"].append(extra)
        mutations.append(("extra", extra_client, remote))

        forged_offset = copy.deepcopy(remote)
        forged_offset["records"][1]["scheduled_offset_ns"] += 1
        mutations.append(("forged offset", client, forged_offset))

        for name, changed_client, changed_remote in mutations:
            with self.subTest(case=name):
                result = verify_events(events, changed_client, changed_remote)
                self.assertFalse(result["passed"])
                self.assertTrue(result["errors"])

    def test_wrong_action_or_direction_fails(self):
        events, client, remote = fixture_rows()
        changed = copy.deepcopy(client)
        changed["records"][0]["direction"] = -1
        result = verify_events(events, changed, remote)
        self.assertFalse(result["passed"])
        self.assertTrue(any("direction mismatch" in error for error in result["errors"]))

        changed = copy.deepcopy(client)
        changed["records"][0]["direction"] = True
        result = verify_events(events, changed, remote)
        self.assertFalse(result["passed"])

    def test_endpoint_transport_errors_fail(self):
        events, client, remote = fixture_rows()
        changed = copy.deepcopy(remote)
        changed["receive_errors"] = ["TCP EOF before complete event set"]
        result = verify_events(events, client, changed)
        self.assertFalse(result["passed"])
        self.assertTrue(any("receive_errors" in error for error in result["errors"]))

    def test_send_blocked_until_completion_uses_completion_time_for_export(self):
        row = {"records": [
            {"sequence": 0, "direction": 1, "action": "send",
             "observed_ns": 1000, "send_completed_ns": 5000,
             "scheduled_offset_ns": 0},
            {"sequence": 1, "direction": -1, "action": "recv",
             "observed_ns": 3000, "scheduled_offset_ns": 100000000},
        ]}
        trace, mapping = build_client_trace(row)
        self.assertEqual(trace.splitlines()[0].split("\t")[1], "-1")
        self.assertEqual(trace.splitlines()[1].split("\t")[1], "1")
        self.assertEqual(mapping[0]["selected_ns"], 3000)
        self.assertEqual(mapping[1]["selected_ns"], 5000)
        self.assertEqual(mapping[1]["timestamp"], 0.000002)

    def test_infinite_observation_time_fails(self):
        events, client, remote = fixture_rows()
        changed = copy.deepcopy(client)
        changed["records"][0]["observed_ns"] = float("inf")
        result = verify_events(events, changed, remote)
        self.assertFalse(result["passed"])
        self.assertTrue(any("observed_ns" in error for error in result["errors"]))

    def test_empty_source_is_rejected(self):
        _, client, remote = fixture_rows()
        result = verify_events([], client, remote)
        self.assertFalse(result["passed"])
        self.assertTrue(any("must not be empty" in error for error in result["errors"]))

    def test_bad_payload_token_and_sample_id_fail(self):
        events, client, remote = fixture_rows()
        cases = []
        wrong_payload = copy.deepcopy(client)
        wrong_payload["records"][0]["bytes"] = 511
        cases.append((wrong_payload, remote, "payload"))

        wrong_token = copy.deepcopy(remote)
        wrong_token["records"][0]["sample_token"] = 99
        cases.append((client, wrong_token, "token"))

        wrong_sample = copy.deepcopy(remote)
        wrong_sample["sample_id"] = "0-1"
        cases.append((client, wrong_sample, "sample_id"))

        for changed_client, changed_remote, reason in cases:
            with self.subTest(reason=reason):
                result = verify_events(events, changed_client, changed_remote)
                self.assertFalse(result["passed"])
                self.assertTrue(result["errors"])

    def test_missing_endpoint_identity_evidence_fails(self):
        events, client, remote = fixture_rows()
        for row in (client, remote):
            row.pop("sample_token")
            row.pop("sample_id")
            for record in row["records"]:
                record.pop("sample_token")
                record.pop("sample_id")
        result = verify_events(events, client, remote)
        self.assertFalse(result["passed"])
        self.assertTrue(any("missing required sample_token" in error
                            for error in result["errors"]))

    def test_export_mapping_matches_each_trace_line_and_uses_observations(self):
        _, client, _ = fixture_rows()
        trace, mapping = build_client_trace(client)
        lines = trace.splitlines()
        self.assertEqual(len(lines), len(mapping))
        for line, item in zip(lines, mapping):
            timestamp_text, direction_text = line.split("\t")
            self.assertEqual(float(timestamp_text), item["timestamp"])
            self.assertEqual(int(direction_text), item["direction"])
            self.assertIn(item["action"], ("send", "recv"))
            selected = item["selected_ns"]
            self.assertEqual(item["timestamp"], (selected - mapping[0]["selected_ns"]) / 1e9)
            if item["action"] == "send":
                source_record = next(record for record in client["records"]
                                     if record["sequence"] == item["sequence"])
                self.assertEqual(selected, source_record["send_completed_ns"])
            else:
                source_record = next(record for record in client["records"]
                                     if record["sequence"] == item["sequence"])
                self.assertEqual(selected, source_record["observed_ns"])

    def test_export_rejects_invalid_or_nonfinite_time(self):
        invalid_rows = [
            {"records": [{"sequence": 0, "direction": 1, "action": "send",
                          "observed_ns": 0, "send_completed_ns": float("inf"),
                          "scheduled_offset_ns": 0}]},
            {"records": [{"sequence": 0, "direction": 0, "action": "send",
                          "observed_ns": 0, "send_completed_ns": 1,
                          "scheduled_offset_ns": 0}]},
            {"records": [{"sequence": 0, "direction": True, "action": "send",
                          "observed_ns": 0, "send_completed_ns": 1,
                          "scheduled_offset_ns": 0}]},
            {"records": [{"sequence": 0, "direction": 1, "action": "send",
                          "observed_ns": 100, "send_completed_ns": 99,
                          "scheduled_offset_ns": 0}]},
        ]
        for row in invalid_rows:
            with self.assertRaises(ValueError):
                build_client_trace(row)


if __name__ == "__main__":
    unittest.main()
