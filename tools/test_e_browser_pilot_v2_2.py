#!/usr/bin/env python3
"""Offline regression tests for V2.2 continuation safety."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import argparse

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import run_e_browser_pilot_v2 as v21
import run_e_browser_pilot_v2_2 as v22


SOURCE_ROOT = (TOOLS.parent / "artifacts" /
               "e_browser_tor_pilot_v2_1_20261021")


class V22ContinuationTests(unittest.TestCase):
    def test_timeout_always_pauses_without_consuming_retry(self):
        for consecutive, attempts in ((0, 1), (1, 1), (2, 2)):
            self.assertEqual(v22.v22_failure_policy(
                "timeout", consecutive, attempts), "pause")
        self.assertEqual(v22.v22_failure_policy("sample_quality", 1, 1),
                         "retry")
        self.assertEqual(v22.v22_failure_policy("sample_quality", 2, 2),
                         "next_sample")

    def test_timed_out_quality_record_cannot_be_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact"
            artifact.write_text("valid payload")
            record = {"timed_out": True, "returncode": 0, "ok": True,
                      "failure_class": "sample_quality",
                      "artifacts": [{"path": "artifact",
                                     "sha256": v22.sha256(artifact)}]}
            valid, _reason = v22.v22_artifact_ok(record, temp)
            self.assertTrue(valid)
            self.assertFalse(record["ok"])
            self.assertEqual(record["failure_class"], "timeout")

    def test_return_code_124_pauses(self):
        self.assertEqual(v22.v22_failure_policy("timeout", 0, 1), "pause")
        record = {"timed_out": False, "returncode": 124, "ok": True,
                  "artifacts": []}
        v22.v22_artifact_ok(record, "/nonexistent")
        self.assertFalse(record["ok"])
        self.assertEqual(record["failure_class"], "timeout")

    def _run_timeout_through_scheduler(self, outer_timeout):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "protocol").mkdir()
            (root / "protocol" / "runtime_config.json").write_text("{}")
            samples = []
            for index in range(2):
                samples.append({
                    "sample_id": "sample-{}".format(index),
                    "page_id": "page-{}".format(index),
                    "class_label": str(index), "label": str(index),
                    "source_rank": index + 1,
                    "source_domain": "example{}.org".format(index),
                    "url": "https://example{}.org/".format(index),
                    "repetition": 1,
                })
            (root / "batch_manifest.json").write_text(json.dumps({
                "protocol_metadata": {"protocol_id": v21.PROTOCOL_ID},
                "run_id": "test-run", "samples": samples,
            }))

            output_record = {"ok": False, "failure_class": "sample_quality",
                             "cleanup_verified": True, "artifacts": [],
                             "timed_out": not outer_timeout}
            stdout = json.dumps(output_record) + "\n"

            class FakeProcess(object):
                pid = 43210
                returncode = None

                def communicate(self, timeout=None):
                    if outer_timeout:
                        raise v21.subprocess.TimeoutExpired("collector", timeout)
                    self.returncode = 0
                    return stdout, ""

                def poll(self):
                    return self.returncode

            process = FakeProcess()
            if outer_timeout:
                process.returncode = 124
            v22.install_runtime_policy()
            with mock.patch.object(v22, "ORIGINAL_VERIFY_FREEZE", return_value=[]), \
                    mock.patch.object(v21, "doctor", return_value={"passed": True}), \
                    mock.patch.object(v21, "active_collection_processes", return_value=[]), \
                    mock.patch.object(v21, "collector_argv", return_value=["collector"]), \
                    mock.patch.object(v21.subprocess, "Popen", return_value=process), \
                    mock.patch.object(v21, "stop_process_group", return_value=(
                        124 if outer_timeout else 0, stdout, "", True, True)), \
                    mock.patch.object(v21, "process_group_exists", return_value=False):
                result = v22.cmd_run(argparse.Namespace(
                    output_root=str(root), resume=True))
            return result, v21.read_jsonl(root / "attempts.jsonl"), \
                json.loads((root / "execution_summary.json").read_text())

    def test_outer_timeout_with_quality_failure_stops_before_next_sample(self):
        _result, attempts, summary = self._run_timeout_through_scheduler(True)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["failure_class"], "timeout")
        self.assertTrue(attempts[0]["timed_out"])
        self.assertEqual(summary["stopped_reason"], "timeout")

    def test_collector_timeout_with_success_return_code_is_still_rejected(self):
        # The collector's own timeout flag wins even if its wrapper returns 0.
        _result, attempts, summary = self._run_timeout_through_scheduler(False)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["failure_class"], "timeout")
        self.assertTrue(attempts[0]["timed_out"])
        self.assertEqual(summary["stopped_reason"], "timeout")

    def test_continuation_migration_preserves_evidence_and_budget(self):
        self.assertTrue(SOURCE_ROOT.is_dir(), "V2.1 source root is unavailable")
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "continuation"
            result = v22.continue_from(SOURCE_ROOT, target)
            self.assertEqual(result["successful_samples"], 1)
            self.assertEqual(result["attempt_count"], 2)
            self.assertEqual(result["inherited_successful_samples"], 1)
            self.assertEqual(result["new_successful_samples"], 0)
            self.assertAlmostEqual(result["online_budget_used_seconds"],
                                   3394.1996162952855, places=4)

            migration = json.loads((target / "continuation" /
                                    "migration.json").read_text())
            self.assertEqual(migration["source_attempt_ledger_sha256"],
                             migration["copied_original_attempt_ledger_sha256"])
            self.assertTrue(migration["implementation_entrypoint_sha256"])
            self.assertTrue(migration["copied_sample_file_sha256"])
            self.assertTrue(all(value["source_sha256"] ==
                                value["continuation_sha256"]
                                for value in migration[
                                    "copied_sample_file_sha256"].values()))
            self.assertEqual(v22.verify_freeze(target), [])
            source_rows = v21.read_jsonl(SOURCE_ROOT / "attempts.jsonl")
            target_rows = v21.read_jsonl(target / "attempts.jsonl")
            self.assertEqual([row["attempt_id"] for row in source_rows],
                             [row["attempt_id"] for row in target_rows])
            self.assertTrue(all(str(SOURCE_ROOT) not in row.get("run_dir", "")
                                for row in target_rows))
            self.assertEqual(v21.read_json(SOURCE_ROOT / "online_budget.json"),
                             v21.read_json(target / "online_budget.json"))
            with self.assertRaises(RuntimeError):
                v22.continue_from(SOURCE_ROOT, target)

    def test_changed_continuation_config_breaks_freeze(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "continuation"
            v22.continue_from(SOURCE_ROOT, target)
            config = target / "protocol" / "runtime_config.json"
            data = json.loads(config.read_text())
            data["helper_image"] = "changed"
            config.write_text(json.dumps(data))
            self.assertTrue(v22.verify_freeze(target))


if __name__ == "__main__":
    unittest.main(verbosity=2)
