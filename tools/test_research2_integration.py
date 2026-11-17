"""Exercise the real planning boundary without creating network resources."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import replay_trace_over_starrynet as replay


class Research2PlanningIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.ids = ["0-0", "18-0", "74-0"]
        for sample_id in self.ids:
            (self.sources / sample_id).write_text("0\t1\n0.1\t-1\n")
        self.ids_file = self.root / "deadline_ids.json"
        self.ids_file.write_text(json.dumps({"sample_ids": self.ids}))
        self.batch_file = self.root / "batch_manifest.json"
        self.batch = {
            "batch_id": "planning-test", "owner_id": "planning-test",
            "service_name": "planning-test", "cohorts": {
                "deadline": {"ids_file": str(self.ids_file),
                             "sha256": replay.sha256_file(self.ids_file),
                             "sample_ids": self.ids}}}
        self.batch_file.write_text(json.dumps(self.batch))

    def plan(self, extra):
        arguments = ["plan", "--input", str(self.sources),
                     "--run-root", str(self.root / "runs"),
                     "--dataset-output", str(self.root / "dataset")]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = replay.main(arguments + extra)
        self.assertEqual(result, 0, output.getvalue())
        planned = json.loads(output.getvalue())
        return replay.load_manifest(planned["manifest"])

    def diagnostic_arguments(self, seconds):
        return ["--sample-ids", str(self.ids_file), "--cohort-key", "deadline",
                "--topology-mode", "fixed", "--scenario", "base",
                "--batch-id", "planning-test", "--owner-id", "planning-test",
                "--service-name", "planning-test", "--batch-manifest",
                str(self.batch_file), "--diagnostic-mode", "deadline",
                "--tcp-completion-seconds", str(seconds)]

    def test_default_session_duration_is_applied_before_cli_validation(self):
        manifest = self.plan(["--max-samples", "3"])
        self.assertEqual(manifest["session_seconds"], 9000)
        replay.check_frozen_config(manifest)

    def test_fixed_deadline_arms_freeze_distinct_windows_and_same_cohort(self):
        manifests = [self.plan(self.diagnostic_arguments(seconds))
                     for seconds in (30, 120)]
        for manifest, seconds in zip(manifests, (30, 120)):
            frozen = replay.check_frozen_config(manifest)
            self.assertEqual(manifest["topology"]["mode"], "fixed")
            self.assertEqual(manifest["scenario"], "base")
            self.assertEqual(manifest["tcp_completion_timeout_seconds"], seconds)
            self.assertEqual(frozen["tcp_completion_timeout_seconds"], seconds)
            self.assertEqual(manifest["tcp_coordinator_wait_seconds"], 15)
            self.assertEqual(manifest["cohort_key"], "deadline")
            replay.load_batch_manifest(manifest)
        self.assertEqual(manifests[0]["source_digest_sha256"],
                         manifests[1]["source_digest_sha256"])
        self.assertNotEqual(manifests[0]["run_dir"], manifests[1]["run_dir"])

    def test_diagnostic_verify_does_not_apply_formal_6000_sample_gate(self):
        manifest = self.plan(self.diagnostic_arguments(120))
        with contextlib.redirect_stdout(io.StringIO()):
            result = replay.main(["verify", "--manifest", manifest["manifest_path"]])
        self.assertNotEqual(result, 0)  # No real trajectories have been collected.
        verification = json.loads((Path(manifest["run_dir"]) /
                                   "verification.json").read_text())
        self.assertFalse(verification["passed"])
        self.assertTrue(verification["errors"])
        self.assertFalse(any("formal plan" in item for item in verification["errors"]),
                         verification["errors"])

    def test_changed_cohort_identity_is_rejected(self):
        manifest = self.plan(self.diagnostic_arguments(120))
        self.batch["cohorts"]["deadline"]["sha256"] = "0" * 64
        self.batch_file.write_text(json.dumps(self.batch))
        with self.assertRaises(replay.ReplayError):
            replay.load_batch_manifest(manifest)

    def fixed_preflight_fixture(self):
        manifest = self.plan(self.diagnostic_arguments(120))
        matrix = self.root / "matrix.txt"
        matrix.write_text("frozen snapshot fixture\n")
        self.batch["frozen_topology"] = {
            "path": str(matrix), "sha256": replay.sha256_file(matrix),
            "time_index": 1}
        self.batch_file.write_text(json.dumps(self.batch))
        bridges = self.root / "bridges.json"
        bridges.write_text("[]")
        summary = {
            "status": "completed", "cleanup_verified": True,
            # This is the field actually produced by run_session.
            "fixed_snapshot_sha256": replay.sha256_file(matrix),
            "dynamic_matrix_changed": False, "handover_count": 0,
            "bridge_networks": str(bridges),
            "bridge_networks_after": str(bridges),
            "bridge_networks_sha256": replay.sha256_file(bridges),
            "bridge_networks_after_sha256": replay.sha256_file(bridges),
            "route_before": {"remote_satellite_route": True},
            "gs_qdisc_before_after_apply": {"profiles": [{}, {}]},
            "client_agent_log": {"path": str(self.root / "client.jsonl")},
            "remote_agent_log": {"path": str(self.root / "remote.jsonl")},
            "sample_results": [
                {"sample_id": "preflight-" + item,
                 "source_sample_id": item, "status": "success",
                 "attempt_id": "attempt-1"} for item in self.ids]}
        return manifest, summary

    def invoke_preflight_fixture(self, manifest, summary):
        def endpoint(path, sample_id, token):
            return {"sample_id": sample_id, "sample_token": token}
        with mock.patch.object(replay, "check_docker_capabilities"), \
                mock.patch.object(replay, "run_session", return_value=summary), \
                mock.patch.object(replay, "require_tcp_state_diagnostics"), \
                mock.patch.object(replay, "read_agent_sample", side_effect=endpoint), \
                contextlib.redirect_stdout(io.StringIO()):
            return replay.cmd_preflight(SimpleNamespace(
                manifest=manifest["manifest_path"]))

    def test_preflight_accepts_snapshot_hash_written_by_session(self):
        manifest, summary = self.fixed_preflight_fixture()
        self.assertNotIn("frozen_topology", summary)
        self.assertEqual(self.invoke_preflight_fixture(manifest, summary), 0)
        diagnostic = json.loads((Path(manifest["run_dir"]) /
                                 "deadline_diagnostic.json").read_text())
        self.assertTrue(diagnostic["execution_complete"])
        self.assertTrue(diagnostic["cleanup_verified"])

    def test_preflight_rejects_changed_session_snapshot_hash(self):
        manifest, summary = self.fixed_preflight_fixture()
        summary["fixed_snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(replay.ReplayError, "shared frozen topology"):
            self.invoke_preflight_fixture(manifest, summary)


class Research2ForwardingIntegrationTests(unittest.TestCase):
    def test_recorded_route_schema_matches_registered_baseline(self):
        # Producer and frozen-baseline formats from the real 0745 pilot.
        observed = {
            "forward": {"nodes": [26, 7, 12, 13, 27], "passed": True},
            "reverse": {"nodes": [27, 13, 8, 7, 26], "passed": True}}
        baseline = {"forward_nodes": [26, 7, 12, 13, 27],
                    "reverse_nodes": [27, 13, 8, 7, 26]}
        self.assertEqual(replay.fixed_route_nodes(observed), baseline)
        observed["reverse"]["nodes"] = [27, 13, 12, 7, 26]
        self.assertNotEqual(replay.fixed_route_nodes(observed), baseline)
        del observed["reverse"]
        self.assertNotEqual(replay.fixed_route_nodes(observed), baseline)

    def fixture(self, include_loopback=True):
        sn = SimpleNamespace(container_id_list=["node{0}".format(n)
                                                for n in range(1, 28)])
        addresses = {n: (["127.0.0.1"] if include_loopback else []) +
                     ["10.0.0.{0}".format(n)] for n in range(1, 28)}
        addresses[26].append("9.26.26.10")
        addresses[27].append("9.27.27.10")
        routes = {
            "node26": "9.27.27.10 via 10.0.0.1 dev B26-eth1",
            "node1": "9.27.27.10 via 10.0.0.2 dev B1-eth2",
            "node2": "9.27.27.10 via 10.0.0.27 dev B2-eth27"}
        return sn, addresses, routes

    def docker_reply(self, addresses, routes):
        def reply(cid, *arguments):
            if "addr" in arguments:
                node = int(cid[4:])
                return "\n".join(
                    "{0}: {1} inet {2}/24".format(
                        index + 1,
                        "lo" if address.startswith("127.") else
                        "B{0}-default".format(node) if address.startswith("9.")
                        else "B{0}-eth1".format(node), address)
                    for index, address in enumerate(addresses[node]))
            return routes[cid]
        return reply

    def test_common_loopback_addresses_do_not_invalidate_satellite_chain(self):
        sn, addresses, routes = self.fixture()
        with mock.patch.object(replay, "docker_exec",
                               side_effect=self.docker_reply(addresses, routes)):
            result = replay.actual_satellite_route_chain(sn, 26, 27, addresses)
        self.assertTrue(result["passed"])
        self.assertEqual(result["nodes"], [26, 1, 2, 27])

    def test_intermediate_host_shortcut_is_rejected(self):
        sn, addresses, routes = self.fixture(include_loopback=False)
        routes["node1"] = "9.27.27.10 via 172.17.0.1 dev eth0"
        with mock.patch.object(replay, "docker_exec",
                               side_effect=self.docker_reply(addresses, routes)):
            with self.assertRaises(replay.ReplayError):
                replay.actual_satellite_route_chain(sn, 26, 27, addresses)


class Research2ArtifactIntegrationTests(unittest.TestCase):
    def test_gzip_round_trip_and_mapping_corruption_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "agent.jsonl"
            payload = b'{"event":"kept"}\n' * 25
            raw.write_bytes(payload)
            metadata = replay.gzip_artifact(raw)
            compressed = Path(metadata["path"])
            self.assertFalse(raw.exists())
            self.assertEqual(metadata["original_bytes"], len(payload))
            self.assertEqual(metadata["compressed_sha256"],
                             replay.sha256_file(compressed))
            with gzip.open(str(compressed), "rb") as handle:
                self.assertEqual(handle.read(), payload)

            mapping = root / "mapping.jsonl.gz"
            rows = [{"sequence": 0, "selected_ns": 100},
                    {"sequence": 1, "selected_ns": 150}]
            metadata = replay.write_gzip_jsonl(mapping, rows)
            replay.verify_gzip_jsonl_rows(mapping, rows, metadata)
            with mapping.open("ab") as handle:
                handle.write(b"corruption")
            with self.assertRaises(replay.ReplayError):
                replay.verify_gzip_jsonl_rows(mapping, rows, metadata)

    def test_tc_output_units_and_omitted_zero_loss_are_understood(self):
        parsed = replay.parse_netem_profile(
            "qdisc netem 8001: root refcnt 2 limit 1000 delay 500us rate 5000Mbit")
        self.assertTrue(parsed["root_netem"])
        self.assertEqual(parsed["delay_ms"], 0.5)
        self.assertEqual(parsed["loss_percent"], 0)
        self.assertEqual(parsed["rate_bps"], 5000000000)

    def test_jitter_is_applied_to_both_gs_egress_interfaces(self):
        import numpy as np
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = np.zeros((27, 27))
            matrix[25, 0] = matrix[0, 25] = 4
            matrix[26, 1] = matrix[1, 26] = 5
            snapshot = root / "matrix.txt"
            np.savetxt(str(snapshot), matrix, delimiter=",")
            profiles = iter([
                "qdisc netem 1: root limit 1000 delay 4ms rate 5Gbit",
                "qdisc netem 1: root limit 1000 delay 29ms 10ms rate 5Gbit",
                "qdisc netem 1: root limit 1000 delay 5ms rate 5Gbit",
                "qdisc netem 1: root limit 1000 delay 30ms 10ms rate 5Gbit"])
            replacements = []

            def execute(cid, *arguments, **kwargs):
                if "show" in arguments:
                    return next(profiles)
                replacements.append((cid, arguments))
                return ""

            with mock.patch.object(replay, "docker_exec", side_effect=execute):
                result = replay.apply_gs_condition(
                    None, ["gs26", "gs27"], snapshot, "jitter25_10", root)
            self.assertEqual(len(result["profiles"]), 2)
            self.assertEqual([row[1][4] for row in replacements],
                             ["B26-eth1", "B27-eth2"])
            for _cid, command in replacements:
                self.assertIn("normal", command)
                self.assertIn("10.000000ms", command)
                self.assertIn("5Gbit", command)


if __name__ == "__main__":
    unittest.main()
